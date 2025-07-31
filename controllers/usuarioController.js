import { PrismaClient } from '@prisma/client';
import logger from '../utils/logger.js';
import usuarioSchema from '../schemas/usuariosSchemas.js';

const prisma = new PrismaClient();

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
        sortBy = 'nombres',
        sortOrder = 'asc'
      } = req.query;

      const skip = (page - 1) * limit;

      // Construir filtros
      const where = {};
      if (rol) where.rol = rol;
      if (carrera_id) where.carrera_id = parseInt(carrera_id);
      if (search) {
        where.OR = [
          { nombres: { contains: search, mode: 'insensitive' } },
          { correo: { contains: search, mode: 'insensitive' } }
        ];
      }

      // Validar ordenamiento
      const validSortFields = ['nombres', 'correo', 'rol'];
      const sortField = validSortFields.includes(sortBy) ? sortBy : 'nombres';
      const order = sortOrder === 'desc' ? 'desc' : 'asc';

      const [usuarios, total] = await Promise.all([
        prisma.usuario.findMany({
          where,
          skip: parseInt(skip),
          take: parseInt(limit),
          orderBy: { [sortField]: order },
          select: {
            id: true,
            nombres: true,
            correo: true,
            rol: true,
            carrera_id: true,
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
          nombres: true,
          correo: true,
          rol: true,
          carrera_id: true,
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

      // Verificar si el correo ya existe
      const existingUser = await prisma.usuario.findUnique({
        where: { correo: value.correo }
      });

      if (existingUser) {
        return res.status(409).json({
          success: false,
          message: 'Ya existe un usuario con este correo'
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

      const usuario = await prisma.usuario.create({
        data: value,
        select: {
          id: true,
          nombres: true,
          correo: true,
          rol: true,
          carrera_id: true,
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

      const { error, value } = usuarioSchema.validate(req.body);

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

      // Verificar si el correo ya existe (si se está actualizando)
      if (value.correo && value.correo !== existingUser.correo) {
        const correoExists = await prisma.usuario.findFirst({
          where: {
            correo: value.correo,
            id: { not: usuarioId }
          }
        });

        if (correoExists) {
          return res.status(409).json({
            success: false,
            message: 'Ya existe un usuario con este correo'
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
      const usuario = await prisma.usuario.update({
        where: { id: usuarioId },
        data: value,
        select: {
          id: true,
          nombres: true,
          correo: true,
          rol: true,
          carrera_id: true,
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
              invitacionesEnviadas: true
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