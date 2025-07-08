import { PrismaClient } from '@prisma/client';
import Joi from 'joi';
import logger from '../utils/logger.js';

const prisma = new PrismaClient();

// Esquemas de validación
const grupoSchema = Joi.object({
  nombre: Joi.string().min(3).max(100).required(),
  descripcion: Joi.string().max(500).optional(),
  estado: Joi.string().valid('activo', 'inactivo').default('activo'),
  tipo: Joi.string().valid('academico', 'social', 'deportivo', 'cultural').optional()
});

const grupoUpdateSchema = Joi.object({
  nombre: Joi.string().min(3).max(100).optional(),
  descripcion: Joi.string().max(500).optional(),
  estado: Joi.string().valid('activo', 'inactivo').optional(),
  tipo: Joi.string().valid('academico', 'social', 'deportivo', 'cultural').optional()
});

const miembroSchema = Joi.object({
  usuario_id: Joi.number().integer().positive().required()
});

const grupoController = {
  // Obtener todos los grupos con filtros y paginación
  async getAll(req, res) {
    try {
      const { 
        page = 1, 
        limit = 10, 
        estado, 
        tipo,
        search,
        sortBy = 'nombre',
        sortOrder = 'asc'
      } = req.query;

      const skip = (page - 1) * limit;

      // Construir filtros
      const where = {};
      if (estado) where.estado = estado;
      if (tipo) where.tipo = tipo;
      if (search) {
        where.OR = [
          { nombre: { contains: search, mode: 'insensitive' } },
          { descripcion: { contains: search, mode: 'insensitive' } }
        ];
      }

      // Validar ordenamiento
      const validSortFields = ['nombre', 'tipo', 'estado', 'created_at'];
      const sortField = validSortFields.includes(sortBy) ? sortBy : 'nombre';
      const order = sortOrder === 'desc' ? 'desc' : 'asc';

      const [grupos, total] = await Promise.all([
        prisma.grupo.findMany({
          where,
          skip: parseInt(skip),
          take: parseInt(limit),
          orderBy: { [sortField]: order },
          include: {
            _count: {
              select: { miembros: true }
            }
          }
        }),
        prisma.grupo.count({ where })
      ]);

      // const totalPages = Math.ceil(total / limit);

      logger.info(`Grupos obtenidos: ${grupos.length} de ${total}`);

      res.json(grupos);
    } catch (error) {
      logger.error('Error al obtener grupos:', error);
      res.status(500).json({
        success: false,
        message: 'Error interno del servidor',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  },

  // Obtener grupo por ID
  async getById(req, res) {
    try {
      const { id } = req.params;
      const grupoId = parseInt(id);

      if (isNaN(grupoId)) {
        return res.status(400).json({
          success: false,
          message: 'ID de grupo inválido'
        });
      }

      const grupo = await prisma.grupo.findUnique({
        where: { id: grupoId },
        include: {
          miembros: {
            include: {
              usuario: {
                select: {
                  id: true,
                  nombre: true,
                  email: true,
                  rol: true
                }
              }
            }
          },
          _count: {
            select: { miembros: true }
          }
        }
      });

      if (!grupo) {
        return res.status(404).json({
          success: false,
          message: 'Grupo no encontrado'
        });
      }

      logger.info(`Grupo obtenido: ${grupo.nombre} (ID: ${grupoId})`);

      res.json(grupo);
    } catch (error) {
      logger.error('Error al obtener grupo:', error);
      res.status(500).json({
        success: false,
        message: 'Error interno del servidor',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  },

  // Crear grupo
  async create(req, res) {
    try {
      const { error, value } = grupoSchema.validate(req.body);

      if (error) {
        return res.status(400).json({
          success: false,
          message: 'Datos de entrada inválidos',
          errors: error.details.map(detail => detail.message)
        });
      }

      const grupo = await prisma.grupo.create({
        data: value
      });

      logger.info(`Grupo creado: ${grupo.nombre} (ID: ${grupo.id})`);

      res.status(201).json(grupo);
    } catch (error) {
      logger.error('Error al crear grupo:', error);
      res.status(500).json({
        success: false,
        message: 'Error interno del servidor',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  },

  // Actualizar grupo
  async update(req, res) {
    try {
      const { id } = req.params;
      const grupoId = parseInt(id);

      if (isNaN(grupoId)) {
        return res.status(400).json({
          success: false,
          message: 'ID de grupo inválido'
        });
      }

      const { error, value } = grupoUpdateSchema.validate(req.body);

      if (error) {
        return res.status(400).json({
          success: false,
          message: 'Datos de entrada inválidos',
          errors: error.details.map(detail => detail.message)
        });
      }

      // Verificar si el grupo existe
      const existingGrupo = await prisma.grupo.findUnique({
        where: { id: grupoId }
      });

      if (!existingGrupo) {
        return res.status(404).json({
          success: false,
          message: 'Grupo no encontrado'
        });
      }

      const grupo = await prisma.grupo.update({
        where: { id: grupoId },
        data: value
      });

      logger.info(`Grupo actualizado: ${grupo.nombre} (ID: ${grupoId})`);

      res.json(grupo);
    } catch (error) {
      logger.error('Error al actualizar grupo:', error);
      res.status(500).json({
        success: false,
        message: 'Error interno del servidor',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  },

  // Eliminar grupo
  async delete(req, res) {
    try {
      const { id } = req.params;
      const grupoId = parseInt(id);

      if (isNaN(grupoId)) {
        return res.status(400).json({
          success: false,
          message: 'ID de grupo inválido'
        });
      }

      // Verificar si el grupo existe
      const grupo = await prisma.grupo.findUnique({
        where: { id: grupoId },
        include: {
          _count: {
            select: { miembros: true }
          }
        }
      });

      if (!grupo) {
        return res.status(404).json({
          success: false,
          message: 'Grupo no encontrado'
        });
      }

      // Verificar si tiene miembros
      if (grupo._count.miembros > 0) {
        return res.status(409).json({
          success: false,
          message: 'No se puede eliminar el grupo porque tiene miembros'
        });
      }

      await prisma.grupo.delete({
        where: { id: grupoId }
      });

      logger.info(`Grupo eliminado: ${grupo.nombre} (ID: ${grupoId})`);

      res.json({
        success: true,
        message: 'Grupo eliminado exitosamente'
      });
    } catch (error) {
      logger.error('Error al eliminar grupo:', error);
      res.status(500).json({
        success: false,
        message: 'Error interno del servidor',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  },

  // Obtener miembros de un grupo
  async getMiembros(req, res) {
    try {
      const { id } = req.params;
      const grupoId = parseInt(id);

      if (isNaN(grupoId)) {
        return res.status(400).json({
          success: false,
          message: 'ID de grupo inválido'
        });
      }

      // Verificar si el grupo existe
      const grupo = await prisma.grupo.findUnique({
        where: { id: grupoId }
      });

      if (!grupo) {
        return res.status(404).json({
          success: false,
          message: 'Grupo no encontrado'
        });
      }

      const miembros = await prisma.miembro.findMany({
        where: { grupo_id: grupoId },
        include: {
          usuario: {
            select: {
              id: true,
              nombre: true,
              email: true,
              rol: true
            }
          }
        },
        orderBy: { created_at: 'asc' }
      });

      logger.info(`Miembros obtenidos del grupo ${grupo.nombre}: ${miembros.length}`);

      res.json(miembros);
    } catch (error) {
      logger.error('Error al obtener miembros del grupo:', error);
      res.status(500).json({
        success: false,
        message: 'Error interno del servidor',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  },

  // Agregar miembro a un grupo
  async addMiembro(req, res) {
    try {
      const { id } = req.params;
      const grupoId = parseInt(id);

      if (isNaN(grupoId)) {
        return res.status(400).json({
          success: false,
          message: 'ID de grupo inválido'
        });
      }

      const { error, value } = miembroSchema.validate(req.body);

      if (error) {
        return res.status(400).json({
          success: false,
          message: 'Datos de entrada inválidos',
          errors: error.details.map(detail => detail.message)
        });
      }

      // Verificar si el grupo existe
      const grupo = await prisma.grupo.findUnique({
        where: { id: grupoId }
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

      // Verificar si el usuario ya es miembro del grupo
      const existingMiembro = await prisma.miembro.findFirst({
        where: {
          grupo_id: grupoId,
          usuario_id: value.usuario_id
        }
      });

      if (existingMiembro) {
        return res.status(409).json({
          success: false,
          message: 'El usuario ya es miembro de este grupo'
        });
      }

      const miembro = await prisma.miembro.create({
        data: {
          grupo_id: grupoId,
          usuario_id: value.usuario_id
        },
        include: {
          usuario: {
            select: {
              id: true,
              nombre: true,
              email: true,
              rol: true
            }
          }
        }
      });

      logger.info(`Miembro agregado al grupo ${grupo.nombre}: ${usuario.nombre}`);

      res.status(201).json(miembro);
    } catch (error) {
      logger.error('Error al agregar miembro al grupo:', error);
      res.status(500).json({
        success: false,
        message: 'Error interno del servidor',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  },

  // Eliminar miembro de un grupo
  async removeMiembro(req, res) {
    try {
      const { id, miembro_id } = req.params;
      const grupoId = parseInt(id);
      const miembroId = parseInt(miembro_id);

      if (isNaN(grupoId) || isNaN(miembroId)) {
        return res.status(400).json({
          success: false,
          message: 'IDs inválidos'
        });
      }

      // Verificar si el grupo existe
      const grupo = await prisma.grupo.findUnique({
        where: { id: grupoId }
      });

      if (!grupo) {
        return res.status(404).json({
          success: false,
          message: 'Grupo no encontrado'
        });
      }

      // Verificar si el miembro existe
      const miembro = await prisma.miembro.findFirst({
        where: {
          id: miembroId,
          grupo_id: grupoId
        },
        include: {
          usuario: {
            select: {
              id: true,
              nombre: true
            }
          }
        }
      });

      if (!miembro) {
        return res.status(404).json({
          success: false,
          message: 'Miembro no encontrado en este grupo'
        });
      }

      await prisma.miembro.delete({
        where: { id: miembroId }
      });

      logger.info(`Miembro removido del grupo ${grupo.nombre}: ${miembro.usuario.nombre}`);

      res.json({
        success: true,
        message: 'Miembro removido exitosamente'
      });
    } catch (error) {
      logger.error('Error al remover miembro del grupo:', error);
      res.status(500).json({
        success: false,
        message: 'Error interno del servidor',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  }
};

export default grupoController; 