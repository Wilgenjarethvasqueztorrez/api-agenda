import { PrismaClient } from '@prisma/client';
import Joi from 'joi';
import logger from '../utils/logger.js';

const prisma = new PrismaClient();

// Esquemas de validación
const invitacionSchema = Joi.object({
  grupo_id: Joi.number().integer().positive().required(),
  usuario_id: Joi.number().integer().positive().required(),
  estado: Joi.string().valid('pendiente', 'aceptada', 'rechazada').default('pendiente')
});

const invitacionUpdateSchema = Joi.object({
  estado: Joi.string().valid('pendiente', 'aceptada', 'rechazada').required()
});

const invitacionController = {
  // Obtener todas las invitaciones con filtros y paginación
  async getAll(req, res) {
    try {
      const { 
        page = 1, 
        limit = 10, 
        estado, 
        grupo_id,
        usuario_id,
        sortBy = 'created_at',
        sortOrder = 'desc'
      } = req.query;

      const skip = (page - 1) * limit;

      // Construir filtros
      const where = {};
      if (estado) where.estado = estado;
      if (grupo_id) where.grupo_id = parseInt(grupo_id);
      if (usuario_id) where.usuario_id = parseInt(usuario_id);

      // Validar ordenamiento
      const validSortFields = ['created_at', 'updated_at', 'estado'];
      const sortField = validSortFields.includes(sortBy) ? sortBy : 'created_at';
      const order = sortOrder === 'asc' ? 'asc' : 'desc';

      const [invitaciones, total] = await Promise.all([
        prisma.invitacion.findMany({
          where,
          skip: parseInt(skip),
          take: parseInt(limit),
          orderBy: { [sortField]: order },
          include: {
            grupo: {
              select: {
                id: true,
                nombre: true,
                descripcion: true,
                estado: true
              }
            },
            usuario: {
              select: {
                id: true,
                nombre: true,
                email: true,
                rol: true
              }
            }
          }
        }),
        prisma.invitacion.count({ where })
      ]);

      // const totalPages = Math.ceil(total / limit);

      logger.info(`Invitaciones obtenidas: ${invitaciones.length} de ${total}`);

      res.json(invitaciones);
    } catch (error) {
      logger.error('Error al obtener invitaciones:', error);
      res.status(500).json({
        success: false,
        message: 'Error interno del servidor',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  },

  // Obtener invitación por ID
  async getById(req, res) {
    try {
      const { id } = req.params;
      const invitacionId = parseInt(id);

      if (isNaN(invitacionId)) {
        return res.status(400).json({
          success: false,
          message: 'ID de invitación inválido'
        });
      }

      const invitacion = await prisma.invitacion.findUnique({
        where: { id: invitacionId },
        include: {
          grupo: {
            select: {
              id: true,
              nombre: true,
              descripcion: true,
              estado: true,
              created_at: true
            }
          },
          usuario: {
            select: {
              id: true,
              nombre: true,
              email: true,
              rol: true,
              carrera: {
                select: {
                  id: true,
                  nombre: true,
                  codigo: true
                }
              }
            }
          }
        }
      });

      if (!invitacion) {
        return res.status(404).json({
          success: false,
          message: 'Invitación no encontrada'
        });
      }

      logger.info(`Invitación obtenida: ${invitacion.usuario.nombre} en ${invitacion.grupo.nombre} (ID: ${invitacionId})`);

      res.json(invitacion);
    } catch (error) {
      logger.error('Error al obtener invitación:', error);
      res.status(500).json({
        success: false,
        message: 'Error interno del servidor',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  },

  // Crear invitación
  async create(req, res) {
    try {
      const { error, value } = invitacionSchema.validate(req.body);

      if (error) {
        return res.status(400).json({
          success: false,
          message: 'Datos de entrada inválidos',
          errors: error.details.map(detail => detail.message)
        });
      }

      // Verificar si el grupo existe
      const grupo = await prisma.grupo.findUnique({
        where: { id: value.grupo_id }
      });

      if (!grupo) {
        return res.status(404).json({
          success: false,
          message: 'Grupo no encontrado'
        });
      }

      // Verificar si el usuario existe
      const usuario = await prisma.usuario.findUnique({
        where: { id: value.usuario_id }
      });

      if (!usuario) {
        return res.status(404).json({
          success: false,
          message: 'Usuario no encontrado'
        });
      }

      // Verificar si ya existe una invitación para este usuario en este grupo
      const existingInvitacion = await prisma.invitacion.findFirst({
        where: {
          grupo_id: value.grupo_id,
          usuario_id: value.usuario_id
        }
      });

      if (existingInvitacion) {
        return res.status(409).json({
          success: false,
          message: 'Ya existe una invitación para este usuario en este grupo'
        });
      }

      // Verificar si el usuario ya es miembro del grupo
      const existingMiembro = await prisma.miembro.findFirst({
        where: {
          grupo_id: value.grupo_id,
          usuario_id: value.usuario_id
        }
      });

      if (existingMiembro) {
        return res.status(409).json({
          success: false,
          message: 'El usuario ya es miembro de este grupo'
        });
      }

      const invitacion = await prisma.invitacion.create({
        data: value,
        include: {
          grupo: {
            select: {
              id: true,
              nombre: true
            }
          },
          usuario: {
            select: {
              id: true,
              nombre: true,
              email: true
            }
          }
        }
      });

      logger.info(`Invitación creada: ${invitacion.usuario.nombre} invitado a ${invitacion.grupo.nombre} (ID: ${invitacion.id})`);

      res.status(201).json(invitacion);
    } catch (error) {
      logger.error('Error al crear invitación:', error);
      res.status(500).json({
        success: false,
        message: 'Error interno del servidor',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  },

  // Actualizar invitación
  async update(req, res) {
    try {
      const { id } = req.params;
      const invitacionId = parseInt(id);

      if (isNaN(invitacionId)) {
        return res.status(400).json({
          success: false,
          message: 'ID de invitación inválido'
        });
      }

      const { error, value } = invitacionUpdateSchema.validate(req.body);

      if (error) {
        return res.status(400).json({
          success: false,
          message: 'Datos de entrada inválidos',
          errors: error.details.map(detail => detail.message)
        });
      }

      // Verificar si la invitación existe
      const existingInvitacion = await prisma.invitacion.findUnique({
        where: { id: invitacionId },
        include: {
          grupo: {
            select: {
              id: true,
              nombre: true
            }
          },
          usuario: {
            select: {
              id: true,
              nombre: true
            }
          }
        }
      });

      if (!existingInvitacion) {
        return res.status(404).json({
          success: false,
          message: 'Invitación no encontrada'
        });
      }

      // Verificar permisos (solo el usuario invitado puede actualizar el estado)
      if (existingInvitacion.usuario_id !== req.user.id && req.user.rol !== 'admin') {
        return res.status(403).json({
          success: false,
          message: 'No tienes permisos para actualizar esta invitación'
        });
      }

      // Si se está aceptando la invitación, agregar al usuario como miembro
      if (value.estado === 'aceptada') {
        // Verificar que no sea ya miembro
        const existingMiembro = await prisma.miembro.findFirst({
          where: {
            grupo_id: existingInvitacion.grupo_id,
            usuario_id: existingInvitacion.usuario_id
          }
        });

        if (!existingMiembro) {
          await prisma.miembro.create({
            data: {
              grupo_id: existingInvitacion.grupo_id,
              usuario_id: existingInvitacion.usuario_id
            }
          });
        }
      }

      const invitacion = await prisma.invitacion.update({
        where: { id: invitacionId },
        data: value,
        include: {
          grupo: {
            select: {
              id: true,
              nombre: true
            }
          },
          usuario: {
            select: {
              id: true,
              nombre: true,
              email: true
            }
          }
        }
      });

      const action = value.estado === 'aceptada' ? 'aceptada' : value.estado === 'rechazada' ? 'rechazada' : 'actualizada';
      logger.info(`Invitación ${action}: ${existingInvitacion.usuario.nombre} en ${existingInvitacion.grupo.nombre} (ID: ${invitacionId})`);

      res.json(invitacion);
    } catch (error) {
      logger.error('Error al actualizar invitación:', error);
      res.status(500).json({
        success: false,
        message: 'Error interno del servidor',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  },

  // Eliminar invitación
  async delete(req, res) {
    try {
      const { id } = req.params;
      const invitacionId = parseInt(id);

      if (isNaN(invitacionId)) {
        return res.status(400).json({
          success: false,
          message: 'ID de invitación inválido'
        });
      }

      // Verificar si la invitación existe
      const invitacion = await prisma.invitacion.findUnique({
        where: { id: invitacionId },
        include: {
          grupo: {
            select: {
              id: true,
              nombre: true
            }
          },
          usuario: {
            select: {
              id: true,
              nombre: true
            }
          }
        }
      });

      if (!invitacion) {
        return res.status(404).json({
          success: false,
          message: 'Invitación no encontrada'
        });
      }

      // Verificar permisos (solo el usuario invitado o admin puede eliminar)
      if (invitacion.usuario_id !== req.user.id && req.user.rol !== 'admin') {
        return res.status(403).json({
          success: false,
          message: 'No tienes permisos para eliminar esta invitación'
        });
      }

      await prisma.invitacion.delete({
        where: { id: invitacionId }
      });

      logger.info(`Invitación eliminada: ${invitacion.usuario.nombre} de ${invitacion.grupo.nombre} (ID: ${invitacionId})`);

      res.json({
        success: true,
        message: 'Invitación eliminada exitosamente'
      });
    } catch (error) {
      logger.error('Error al eliminar invitación:', error);
      res.status(500).json({
        success: false,
        message: 'Error interno del servidor',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  },

  // Obtener invitaciones de un usuario específico
  async getByUsuario(req, res) {
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
        where: { id: usuarioId }
      });

      if (!usuario) {
        return res.status(404).json({
          success: false,
          message: 'Usuario no encontrado'
        });
      }

      const { 
        page = 1, 
        limit = 10, 
        estado,
        tipo = 'recibidas' // 'recibidas' o 'enviadas'
      } = req.query;

      const skip = (page - 1) * limit;

      // Construir filtros
      const where = {};
      if (estado) where.estado = estado;

      if (tipo === 'enviadas') {
        where.usuario_id = usuarioId;
      } else {
        where.usuario_id = usuarioId;
      }

      const [invitaciones, total] = await Promise.all([
        prisma.invitacion.findMany({
          where,
          skip: parseInt(skip),
          take: parseInt(limit),
          orderBy: { created_at: 'desc' },
          include: {
            grupo: {
              select: {
                id: true,
                nombre: true,
                estado: true
              }
            },
            usuario: {
              select: {
                id: true,
                nombre: true,
                email: true,
                rol: true
              }
            }
          }
        }),
        prisma.invitacion.count({ where })
      ]);

      const totalPages = Math.ceil(total / limit);

      logger.info(`Invitaciones ${tipo} obtenidas para ${usuario.nombre}: ${invitaciones.length} de ${total}`);

      res.json({
        success: true,
        data: invitaciones,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total,
          totalPages
        }
      });
    } catch (error) {
      logger.error('Error al obtener invitaciones del usuario:', error);
      res.status(500).json({
        success: false,
        message: 'Error interno del servidor',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  }
};

export default invitacionController; 