import { PrismaClient } from '@prisma/client';
import logger from '../utils/logger.js';
import miembroSchema from '../schemas/miembroSchema.js';

const prisma = new PrismaClient();

const miembroController = {
  // Obtener todos los miembros con filtros y paginación
  async getAll(req, res) {
    try {
      const { 
        page = 1, 
        limit = 10, 
        grupo_id, 
        usuario_id,
        sortBy = 'fecha',
        sortOrder = 'desc'
      } = req.query;

      const skip = (page - 1) * limit;

      // Construir filtros
      const where = {};
      if (grupo_id) where.grupo_id = parseInt(grupo_id);
      if (usuario_id) where.usuario_id = parseInt(usuario_id);

      // Validar ordenamiento
      const validSortFields = ['usuario_id', 'grupo_id'];
      const sortField = validSortFields.includes(sortBy) ? sortBy : 'usuario_id';
      const order = sortOrder === 'desc' ? 'desc' : 'asc';

      const [miembros, total] = await Promise.all([
        prisma.miembro.findMany({
          where,
          skip: parseInt(skip),
          take: parseInt(limit),
          orderBy: { [sortField]: order },
          include: {
            usuario: {
              select: {
                id: true,
                nombres: true,
                correo: true,
                rol: true
              }
            },
            grupo: {
              select: {
                id: true,
                nombre: true
              }
            }
          }
        }),
        prisma.miembro.count({ where })
      ]);

      // const totalPages = Math.ceil(total / limit);

      logger.info(`Miembros obtenidos: ${miembros.length} de ${total}`);

      res.json(miembros);
    } catch (error) {
      logger.error('Error al obtener miembros:', error);
      res.status(500).json({
        success: false,
        message: 'Error interno del servidor',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  },

  // Obtener miembro por ID
  async getById(req, res) {
    try {
      const { id } = req.params;
      const miembroId = parseInt(id);

      if (isNaN(miembroId)) {
        return res.status(400).json({
          success: false,
          message: 'ID de miembro inválido'
        });
      }

      const miembro = await prisma.miembro.findUnique({
        where: { id: miembroId },
        include: {
          usuario: {
            select: {
              id: true,
              nombres: true,
              correo: true,
              rol: true
            }
          },
          grupo: {
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
          message: 'Miembro no encontrado'
        });
      }

      logger.info(`Miembro obtenido: ${miembro.usuario.nombres} en ${miembro.grupo.nombre} (ID: ${miembroId})`);

      res.json(miembro);
    } catch (error) {
      logger.error('Error al obtener miembro:', error);
      res.status(500).json({
        success: false,
        message: 'Error interno del servidor',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  },

  // Crear miembro
  async create(req, res) {
    try {
      const { error, value } = miembroSchema.validate(req.body);

      if (error) {
        return res.status(400).json({
          success: false,
          message: 'Datos de entrada inválidos',
          errors: error.details.map(detail => detail.message)
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

      const miembro = await prisma.miembro.create({
        data: {
          grupo_id: value.grupo_id,
          usuario_id: value.usuario_id
        },
        include: {
          usuario: {
            select: {
              id: true,
              nombres: true,
              correo: true,
              rol: true
            }
          },
          grupo: {
            select: {
              id: true,
              nombre: true
            }
          }
        }
      });

      logger.info(`Miembro creado: ${usuario.nombres} en ${grupo.nombre} (ID: ${miembro.id})`);

      res.status(201).json(miembro);
    } catch (error) {
      logger.error('Error al crear miembro:', error);
      res.status(500).json({
        success: false,
        message: 'Error interno del servidor',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  },

  // Eliminar miembro
  async delete(req, res) {
    try {
      const { id } = req.params;
      const miembroId = parseInt(id);

      if (isNaN(miembroId)) {
        return res.status(400).json({
          success: false,
          message: 'ID de miembro inválido'
        });
      }

      // Verificar si el miembro existe
      const miembro = await prisma.miembro.findUnique({
        where: { id: miembroId },
        include: {
          usuario: {
            select: {
              id: true,
              nombres: true
            }
          },
          grupo: {
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
          message: 'Miembro no encontrado'
        });
      }

      await prisma.miembro.delete({
        where: { id: miembroId }
      });

      logger.info(`Miembro eliminado: ${miembro.usuario.nombres} de ${miembro.grupo.nombre} (ID: ${miembroId})`);

      res.json({
        success: true,
        message: 'Miembro eliminado exitosamente'
      });
    } catch (error) {
      logger.error('Error al eliminar miembro:', error);
      res.status(500).json({
        success: false,
        message: 'Error interno del servidor',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  }
};

export default miembroController;