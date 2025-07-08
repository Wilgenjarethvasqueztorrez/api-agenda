import { PrismaClient } from '@prisma/client';
import Joi from 'joi';
import bcrypt from 'bcryptjs';
import logger from '../utils/logger.js';

const prisma = new PrismaClient();

// Esquemas de validación
const usuarioSchema = Joi.object({
  nombre: Joi.string().min(2).max(100).required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
  rol: Joi.string().valid('admin', 'profesor', 'estudiante', 'oficina').default('estudiante'),
  carrera_id: Joi.number().integer().optional()
});

const usuarioUpdateSchema = Joi.object({
  nombre: Joi.string().min(2).max(100).optional(),
  email: Joi.string().email().optional(),
  password: Joi.string().min(6).optional(),
  rol: Joi.string().valid('admin', 'profesor', 'estudiante', 'oficina').optional(),
  carrera_id: Joi.number().integer().optional()
});

const usuarioController = {
  // Obtener todos los usuarios con filtros y paginación
  async getAll(req, res) {
    try {
      const { 
        page = 1, 
        limit = 10, 
        rol, 
        carrera_id,
        search,
        sortBy = 'nombre',
        sortOrder = 'asc'
      } = req.query;

      const skip = (page - 1) * limit;

      // Construir filtros
      const where = {};
      if (rol) where.rol = rol;
      if (carrera_id) where.carrera_id = parseInt(carrera_id);
      if (search) {
        where.OR = [
          { nombre: { contains: search, mode: 'insensitive' } },
          { email: { contains: search, mode: 'insensitive' } }
        ];
      }

      // Validar ordenamiento
      const validSortFields = ['nombre', 'email', 'rol', 'created_at'];
      const sortField = validSortFields.includes(sortBy) ? sortBy : 'nombre';
      const order = sortOrder === 'desc' ? 'desc' : 'asc';

      const [usuarios, total] = await Promise.all([
        prisma.usuario.findMany({
          where,
          skip: parseInt(skip),
          take: parseInt(limit),
          orderBy: { [sortField]: order },
          select: {
            id: true,
            nombre: true,
            email: true,
            rol: true,
            carrera_id: true,
            created_at: true,
            updated_at: true,
            carrera: {
              select: {
                id: true,
                nombre: true,
                codigo: true
              }
            }
          }
        }),
        prisma.usuario.count({ where })
      ]);

      // const totalPages = Math.ceil(total / limit);

      logger.info(`Usuarios obtenidos: ${usuarios.length} de ${total}`);

      res.json(usuarios);
    } catch (error) {
      logger.error('Error al obtener usuarios:', error);
      res.status(500).json({
        success: false,
        message: 'Error interno del servidor',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  },

  // Obtener usuario por ID
  async getById(req, res) {
    try {
      const { id } = req.params;
      const usuarioId = parseInt(id);

      if (isNaN(usuarioId)) {
        return res.status(400).json({
          success: false,
          message: 'ID de usuario inválido'
        });
      }

      const usuario = await prisma.usuario.findUnique({
        where: { id: usuarioId },
        select: {
          id: true,
          nombre: true,
          email: true,
          rol: true,
          carrera_id: true,
          created_at: true,
          updated_at: true,
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

      logger.info(`Usuario obtenido: ${usuario.nombre} (ID: ${usuarioId})`);

      res.json(usuario);
    } catch (error) {
      logger.error('Error al obtener usuario:', error);
      res.status(500).json({
        success: false,
        message: 'Error interno del servidor',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  },

  // Crear usuario
  async create(req, res) {
    try {
      const { error, value } = usuarioSchema.validate(req.body);

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
          created_at: true,
          carrera: {
            select: {
              id: true,
              nombre: true,
              codigo: true
            }
          }
        }
      });

      logger.info(`Usuario creado: ${usuario.nombre} (ID: ${usuario.id})`);

      res.status(201).json(usuario);
    } catch (error) {
      logger.error('Error al crear usuario:', error);
      res.status(500).json({
        success: false,
        message: 'Error interno del servidor',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  },

  // Actualizar usuario
  async update(req, res) {
    try {
      const { id } = req.params;
      const usuarioId = parseInt(id);

      if (isNaN(usuarioId)) {
        return res.status(400).json({
          success: false,
          message: 'ID de usuario inválido'
        });
      }

      const { error, value } = usuarioUpdateSchema.validate(req.body);

      if (error) {
        return res.status(400).json({
          success: false,
          message: 'Datos de entrada inválidos',
          errors: error.details.map(detail => detail.message)
        });
      }

      // Verificar si el usuario existe
      const existingUser = await prisma.usuario.findUnique({
        where: { id: usuarioId }
      });

      if (!existingUser) {
        return res.status(404).json({
          success: false,
          message: 'Usuario no encontrado'
        });
      }

      // Verificar si el email ya existe (si se está actualizando)
      if (value.email && value.email !== existingUser.email) {
        const emailExists = await prisma.usuario.findFirst({
          where: { 
            email: value.email,
            id: { not: usuarioId }
          }
        });

        if (emailExists) {
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

      // Preparar datos para actualización
      const updateData = { ...value };

      // Encriptar contraseña si se proporciona
      if (value.password) {
        const saltRounds = 12;
        updateData.password = await bcrypt.hash(value.password, saltRounds);
      }

      const usuario = await prisma.usuario.update({
        where: { id: usuarioId },
        data: updateData,
        select: {
          id: true,
          nombre: true,
          email: true,
          rol: true,
          carrera_id: true,
          created_at: true,
          updated_at: true,
          carrera: {
            select: {
              id: true,
              nombre: true,
              codigo: true
            }
          }
        }
      });

      logger.info(`Usuario actualizado: ${usuario.nombre} (ID: ${usuarioId})`);

      res.json(usuario);
    } catch (error) {
      logger.error('Error al actualizar usuario:', error);
      res.status(500).json({
        success: false,
        message: 'Error interno del servidor',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  },

  // Eliminar usuario
  async delete(req, res) {
    try {
      const { id } = req.params;
      const usuarioId = parseInt(id);

      if (isNaN(usuarioId)) {
        return res.status(400).json({
          success: false,
          message: 'ID de usuario inválido'
        });
      }

      // Verificar si el usuario existe
      const usuario = await prisma.usuario.findUnique({
        where: { id: usuarioId },
        include: {
          _count: {
            select: { 
              miembros: true,
              invitaciones: true
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

      // Verificar si tiene relaciones
      if (usuario._count.miembros > 0 || usuario._count.invitaciones > 0) {
        return res.status(409).json({
          success: false,
          message: 'No se puede eliminar el usuario porque tiene relaciones activas'
        });
      }

      await prisma.usuario.delete({
        where: { id: usuarioId }
      });

      logger.info(`Usuario eliminado: ${usuario.nombre} (ID: ${usuarioId})`);

      res.json({
        success: true,
        message: 'Usuario eliminado exitosamente'
      });
    } catch (error) {
      logger.error('Error al eliminar usuario:', error);
      res.status(500).json({
        success: false,
        message: 'Error interno del servidor',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  }
};

export default usuarioController; 