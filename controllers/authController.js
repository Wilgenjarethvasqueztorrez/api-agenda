import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import Joi from 'joi';
import logger from '../utils/logger.js';

const prisma = new PrismaClient();

// Esquemas de validación
const registerSchema = Joi.object({
  nombre: Joi.string().min(2).max(100).required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
  rol: Joi.string().valid('admin', 'profesor', 'estudiante', 'oficina').default('estudiante'),
  carrera_id: Joi.number().integer().optional()
});

const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required()
});

const updateProfileSchema = Joi.object({
  nombre: Joi.string().min(2).max(100).optional(),
  email: Joi.string().email().optional(),
  carrera_id: Joi.number().integer().optional()
});

const changePasswordSchema = Joi.object({
  currentPassword: Joi.string().required(),
  newPassword: Joi.string().min(6).required()
});

// Controlador de autenticación
const authController = {
  // Registro de usuario
  async register(req, res) {
    try {
      const { error, value } = registerSchema.validate(req.body);

      if (error) {
        return res.status(400).json({
          success: false,
          message: 'Datos de entrada inválidos',
          errors: error.details.map(detail => detail.message)
        });
      }

      // Verificar si el email ya existe
      const existingUser = await prisma.usuario.findUnique({
        where: { email: value.email }
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

      // Encriptar contraseña
      const saltRounds = 12;
      const hashedPassword = await bcrypt.hash(value.password, saltRounds);

      // Crear usuario
      const usuario = await prisma.usuario.create({
        data: {
          ...value,
          password: hashedPassword
        },
        select: {
          id: true,
          nombre: true,
          email: true,
          rol: true,
          carrera_id: true,
          created_at: true
        }
      });

      // Generar token JWT
      const token = jwt.sign(
        { userId: usuario.id, email: usuario.email, rol: usuario.rol },
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRES_IN || '24h' }
      );

      logger.info(`Usuario registrado: ${usuario.email} (ID: ${usuario.id})`);

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

  // Login de usuario
  async login(req, res) {
    try {
      const { error, value } = loginSchema.validate(req.body);

      if (error) {
        return res.status(400).json({
          success: false,
          message: 'Datos de entrada inválidos',
          errors: error.details.map(detail => detail.message)
        });
      }

      // Buscar usuario por email
      const usuario = await prisma.usuario.findUnique({
        where: { email: value.email },
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

      if (!usuario) {
        return res.status(401).json({
          success: false,
          message: 'Credenciales inválidas'
        });
      }

      // Verificar contraseña
      const isPasswordValid = await bcrypt.compare(value.password, usuario.password);

      if (!isPasswordValid) {
        return res.status(401).json({
          success: false,
          message: 'Credenciales inválidas'
        });
      }

      // Generar token JWT
      const token = jwt.sign(
        { userId: usuario.id, email: usuario.email, rol: usuario.rol },
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRES_IN || '24h' }
      );

      // Remover password de la respuesta
      const {  ...usuarioSinPassword } = usuario;

      logger.info(`Usuario logueado: ${usuario.email} (ID: ${usuario.id})`);

      res.json({
        success: true,
        message: 'Login exitoso',
        token,
        user: usuarioSinPassword
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

  // Obtener perfil del usuario
  async getProfile(req, res) {
    try {
      const usuario = await prisma.usuario.findUnique({
        where: { id: req.user.id },
        select: {
          id: true,
          nombre: true,
          email: true,
          rol: true,
          carrera_id: true,
          carrera: {
            select: {
              id: true,
              nombre: true,
              codigo: true
            }
          },
          created_at: true,
          updated_at: true
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
        user: usuario
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
      const { error, value } = updateProfileSchema.validate(req.body);

      if (error) {
        return res.status(400).json({
          success: false,
          message: 'Datos de entrada inválidos',
          errors: error.details.map(detail => detail.message)
        });
      }

      // Verificar si el email ya existe (si se está actualizando)
      if (value.email) {
        const existingUser = await prisma.usuario.findFirst({
          where: {
            email: value.email,
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
          nombre: true,
          email: true,
          rol: true,
          carrera_id: true,
          carrera: {
            select: {
              id: true,
              nombre: true,
              codigo: true
            }
          },
          created_at: true,
          updated_at: true
        }
      });

      logger.info(`Perfil actualizado: ${usuario.email} (ID: ${usuario.id})`);

      res.json({
        success: true,
        message: 'Perfil actualizado exitosamente',
        user: usuario
      });
    } catch (error) {
      logger.error('Error al actualizar perfil:', error);
      res.status(500).json({
        success: false,
        message: 'Error interno del servidor',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  },

  // Cambiar contraseña
  async changePassword(req, res) {
    try {
      const { error, value } = changePasswordSchema.validate(req.body);

      if (error) {
        return res.status(400).json({
          success: false,
          message: 'Datos de entrada inválidos',
          errors: error.details.map(detail => detail.message)
        });
      }

      // Obtener usuario con contraseña
      const usuario = await prisma.usuario.findUnique({
        where: { id: req.user.id },
        select: { id: true, password: true, email: true }
      });

      if (!usuario) {
        return res.status(404).json({
          success: false,
          message: 'Usuario no encontrado'
        });
      }

      // Verificar contraseña actual
      const isCurrentPasswordValid = await bcrypt.compare(value.currentPassword, usuario.password);

      if (!isCurrentPasswordValid) {
        return res.status(400).json({
          success: false,
          message: 'Contraseña actual incorrecta'
        });
      }

      // Encriptar nueva contraseña
      const saltRounds = 12;
      const hashedNewPassword = await bcrypt.hash(value.newPassword, saltRounds);

      // Actualizar contraseña
      await prisma.usuario.update({
        where: { id: req.user.id },
        data: { password: hashedNewPassword }
      });

      logger.info(`Contraseña cambiada: ${usuario.email} (ID: ${usuario.id})`);

      res.json({
        success: true,
        message: 'Contraseña cambiada exitosamente'
      });
    } catch (error) {
      logger.error('Error al cambiar contraseña:', error);
      res.status(500).json({
        success: false,
        message: 'Error interno del servidor',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  }
};

export default authController;