import { PrismaClient } from '@prisma/client';
import jwt from 'jsonwebtoken';
import logger from '../utils/logger.js';
import usersSchema from '../schemas/usuariosSchemas.js';

const prisma = new PrismaClient();

// Controlador de autenticación
const authController = {
  // Registro de usuario
  async register(req, res) {
    try {
      const { error, value } = usersSchema.validate(req.body);

      console.log(value);

      if (error) {
        return res.status(400).json({
          success: false,
          message: 'Datos de entrada inválidos',
          errors: error.details.map(detail => detail.message)
        });
      }

      // Verificar si el email ya existe
      const existingUser = await prisma.usuario.findUnique({
        where: { correo: value.correo }
      });

      if (existingUser) {
        return res.status(409).json({
          success: false,
          message: 'Ya existe un usuario con este email'
        });
      }

      // Verificar carrera si se proporciona
      if (value.carrera_id) {
        const carrera = await prisma.carrera.findUnique({
          where: { id: value.carrera_id }
        });

        if (!carrera) {
          return res.status(400).json({
            success: false,
            message: 'Carrera no encontrada'
          });
        }
      }

      // Crear usuario
      const usuario = await prisma.usuario.create({
        data: {
          ...value,
        },
        select: {
          id: true,
          nombres: true,
          correo: true,
          rol: true,
          carrera_id: true,
        }
      });

      // Generar token JWT
      const token = jwt.sign(
        { userId: usuario.id, correo: usuario.correo, rol: usuario.rol },
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRES_IN || '24h' }
      );

      logger.info(`Usuario registrado: ${usuario.correo} (ID: ${usuario.id})`);

      res.status(201).json({
        success: true,
        message: 'Usuario registrado exitosamente',
        data: {
          usuario,
          token
        }
      });
    } catch (error) {
      logger.error('Error en registro:', error);
      res.status(500).json({
        success: false,
        message: 'Error interno del servidor',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  },

  // Login de usuario con Google accessToken
  async login(req, res) {
    try {
      const { accessToken } = req.body;

      if (!accessToken) {
        return res.status(400).json({
          success: false,
          message: 'Access token es requerido'
        });
      }

      // Decodificar el token de Google (ID token)
      let payload;
      try {
        // El accessToken es en realidad un ID token de Google
        const decoded = jwt.decode(accessToken);
        if (!decoded) {
          throw new Error('Token no válido');
        }
        payload = decoded;
      } catch (error) {
        logger.error('Error decodificando token de Google:', error);
        return res.status(401).json({
          success: false,
          message: 'Token de Google inválido'
        });
      }

      const { email, name, given_name, family_name, picture } = payload;

      // Verificar dominio de email (@uml.edu.ni)
      if (!email.toLowerCase().endsWith('@uml.edu.ni')) {
        return res.status(403).json({
          success: false,
          message: 'Solo se permiten correos electrónicos de la Universidad Martin Lutero (@uml.edu.ni)'
        });
      }

      // Buscar usuario existente
      let usuario = await prisma.usuario.findUnique({
        where: { correo: email },
        include: {
          carrera: {
            select: {
              id: true,
              nombre: true,
              codigo: true
            }
          }
        }
      });

      // Si el usuario no existe, crearlo
      if (!usuario) {
        try {
          // Separar nombres y apellidos
          const fullName = name || `${given_name || ''} ${family_name || ''}`.trim();
          const nameParts = fullName.split(' ');
          const nombres = nameParts[0] || '';
          const apellidos = nameParts.slice(1).join(' ') || '';

          usuario = await prisma.usuario.create({
            data: {
              nombres: nombres,
              apellidos: apellidos,
              correo: email,
              rol: 'estudiante', // Rol por defecto para nuevos usuarios (en minúsculas según el enum)
              // carrera_id se puede actualizar después en el perfil
            },
            include: {
              carrera: {
                select: {
                  id: true,
                  nombre: true,
                  codigo: true
                }
              }
            }
          });

          logger.info(`Nuevo usuario creado: ${email} (ID: ${usuario.id})`);
        } catch (createError) {
          logger.error('Error creando nuevo usuario:', createError);
          return res.status(500).json({
            success: false,
            message: 'Error al crear nuevo usuario'
          });
        }
      } else {
        // Actualizar información del usuario existente si es necesario
        const updateData = {};
        if (name && name !== `${usuario.nombres} ${usuario.apellidos}`.trim()) {
          const nameParts = name.split(' ');
          updateData.nombres = nameParts[0] || '';
          updateData.apellidos = nameParts.slice(1).join(' ') || '';
        }

        if (Object.keys(updateData).length > 0) {
          try {
            usuario = await prisma.usuario.update({
              where: { id: usuario.id },
              data: updateData,
              include: {
                carrera: {
                  select: {
                    id: true,
                    nombre: true,
                    codigo: true
                  }
                }
              }
            });
            logger.info(`Información de usuario actualizada: ${email} (ID: ${usuario.id})`);
          } catch (updateError) {
            logger.error('Error actualizando información de usuario:', updateError);
            // No fallar el login si la actualización falla
          }
        }
      }

      // Generar token JWT de sesión
      const sessionToken = jwt.sign(
        { 
          userId: usuario.id, 
          correo: usuario.correo, 
          rol: usuario.rol 
        },
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRES_IN || '24h' }
      );

      logger.info(`Usuario logueado: ${usuario.correo} (ID: ${usuario.id})`);

      res.json({
        success: true,
        message: 'Login exitoso',
        data: {
          usuario,
          sessionToken
        }
      });
    } catch (error) {
      logger.error('Error en login:', error);
      res.status(500).json({
        success: false,
        message: 'Error interno del servidor',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  },

  // Logout de usuario
  async logout(req, res) {
    try {
      // En JWT, el logout se maneja del lado del cliente
      // Aquí podemos registrar el logout para auditoría
      logger.info(`Usuario deslogueado: ${req.user?.correo} (ID: ${req.user?.id})`);

      res.json({
        success: true,
        message: 'Logout exitoso'
      });
    } catch (error) {
      logger.error('Error en logout:', error);
      res.status(500).json({
        success: false,
        message: 'Error interno del servidor',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  },

  // Obtener perfil del usuario
  async getProfile(req, res) {
    try {
      const usuario = await prisma.usuario.findUnique({
        where: { id: req.user.id },
        select: {
          id: true,
          nombres: true,
          apellidos: true,
          correo: true,
          rol: true,
          carrera_id: true,
          fecha: true,
          nivel: true,
          celular: true,
          telefono: true,
          carnet: true,
          carrera: {
            select: {
              id: true,
              nombre: true,
              codigo: true
            }
          }
        }
      });

      if (!usuario) {
        return res.status(404).json({
          success: false,
          message: 'Usuario no encontrado'
        });
      }

      res.json({
        success: true,
        data: {
          usuario
        }
      });
    } catch (error) {
      logger.error('Error al obtener perfil:', error);
      res.status(500).json({
        success: false,
        message: 'Error interno del servidor',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  },

  // Actualizar perfil del usuario
  async updateProfile(req, res) {
    try {
      const { error, value } = usersSchema.validate(req.body);

      if (error) {
        return res.status(400).json({
          success: false,
          message: 'Datos de entrada inválidos',
          errors: error.details.map(detail => detail.message)
        });
      }

      // Verificar si el email ya existe (si se está actualizando)
      if (value.correo) {
        const existingUser = await prisma.usuario.findFirst({
          where: {
            correo: value.correo,
            id: { not: req.user.id }
          }
        });

        if (existingUser) {
          return res.status(409).json({
            success: false,
            message: 'Ya existe un usuario con este email'
          });
        }
      }

      // Verificar carrera si se proporciona
      if (value.carrera_id) {
        const carrera = await prisma.carrera.findUnique({
          where: { id: value.carrera_id }
        });

        if (!carrera) {
          return res.status(400).json({
            success: false,
            message: 'Carrera no encontrada'
          });
        }
      }

      // Actualizar usuario
      const usuario = await prisma.usuario.update({
        where: { id: req.user.id },
        data: value,
        select: {
          id: true,
          nombres: true,
          apellidos: true,
          correo: true,
          rol: true,
          carrera_id: true,
          fecha: true,
          nivel: true,
          celular: true,
          telefono: true,
          carnet: true,
          carrera: {
            select: {
              id: true,
              nombre: true,
              codigo: true
            }
          }
        }
      });

      logger.info(`Perfil actualizado: ${usuario.correo} (ID: ${usuario.id})`);

      res.json({
        success: true,
        message: 'Perfil actualizado exitosamente',
        data: {
          usuario
        }
      });
    } catch (error) {
      logger.error('Error al actualizar perfil:', error);
      res.status(500).json({
        success: false,
        message: 'Error interno del servidor',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  }
};

export default authController;