import { PrismaClient } from '@prisma/client';
import { carreraSchema } from '../schemas/carreraSchemas.js';
import logger from '../utils/logger.js';

const prisma = new PrismaClient();

const carreraController = {
  // Obtener todas las carreras con filtros y paginación
  async getAll(req, res) {
    try {
      const {
        page = 1,
        limit = 10,
        estado,
        search,
        sortBy = 'nombre',
        sortOrder = 'asc'
      } = req.query;

      const skip = (page - 1) * limit;

      // Construir filtros
      const where = {};
      if (estado) where.estado = estado;
      if (search) {
        where.OR = [
          { nombre: { contains: search, mode: 'insensitive' } },
          { codigo: { contains: search, mode: 'insensitive' } },
          { descripcion: { contains: search, mode: 'insensitive' } }
        ];
      }

      // Validar ordenamiento
      const validSortFields = ['nombre', 'codigo', 'duracion_anos', 'creditos_totales', 'estado'];
      const sortField = validSortFields.includes(sortBy) ? sortBy : 'nombre';
      const order = sortOrder === 'desc' ? 'desc' : 'asc';

      const [carreras, total] = await Promise.all([
        prisma.carrera.findMany({
          where,
          skip: parseInt(skip),
          take: parseInt(limit),
          orderBy: { [sortField]: order },
          include: {
            _count: {
              select: { usuarios: true }
            }
          }
        }),
        prisma.carrera.count({ where })
      ]);

      // const totalPages = Math.ceil(total / limit);

      logger.info(`Carreras obtenidas: ${carreras.length} de ${total}`);

      res.json(carreras);
    } catch (error) {
      logger.error('Error al obtener carreras:', error);
      res.status(500).json({
        success: false,
        message: 'Error interno del servidor',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  },

  // Obtener carrera por ID
  async getById(req, res) {
    try {
      const { id } = req.params;
      const carreraId = parseInt(id);

      if (isNaN(carreraId)) {
        return res.status(400).json({
          success: false,
          message: 'ID de carrera inválido'
        });
      }

      const carrera = await prisma.carrera.findUnique({
        where: { id: carreraId },
        include: {
          usuarios: {
            select: {
              id: true,
              nombres: true,
              correo: true
            }
          },
          _count: {
            select: { usuarios: true }
          }
        }
      });

      if (!carrera) {
        return res.status(404).json({
          success: false,
          message: 'Carrera no encontrada'
        });
      }

      logger.info(`Carrera obtenida: ${carrera.nombre} (ID: ${carreraId})`);

      res.json(carrera);
    } catch (error) {
      logger.error('Error al obtener carrera:', error);
      res.status(500).json({
        success: false,
        message: 'Error interno del servidor',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  },

  // Crear carrera
  async create(req, res) {
    try {
      const { error, value } = carreraSchema.validate(req.body);

      if (error) {
        return res.status(400).json({
          success: false,
          message: 'Datos de entrada inválidos',
          errors: error.details.map(detail => detail.message)
        });
      }

      // Verificar si el código ya existe
      const existingCarrera = await prisma.carrera.findFirst({
        where: { codigo: value.codigo }
      });

      if (existingCarrera) {
        return res.status(409).json({
          success: false,
          message: 'Ya existe una carrera con este código'
        });
      }

      const carrera = await prisma.carrera.create({
        data: value
      });

      logger.info(`Carrera creada: ${carrera.nombre} (ID: ${carrera.id})`);

      res.status(201).json(carrera);
    } catch (error) {
      logger.error('Error al crear carrera:', error);
      res.status(500).json({
        success: false,
        message: 'Error interno del servidor',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  },

  // Actualizar carrera
  async update(req, res) {
    try {
      const { id } = req.params;
      const carreraId = parseInt(id);

      if (isNaN(carreraId)) {
        return res.status(400).json({
          success: false,
          message: 'ID de carrera inválido'
        });
      }

      // Usa el mismo esquema para actualizar, pero permite campos opcionales
      const { error, value } = carreraSchema.tailor('update').validate(req.body);

      if (error) {
        return res.status(400).json({
          success: false,
          message: 'Datos de entrada inválidos',
          errors: error.details.map(detail => detail.message)
        });
      }

      // Verificar si la carrera existe
      const existingCarrera = await prisma.carrera.findUnique({
        where: { id: carreraId }
      });

      if (!existingCarrera) {
        return res.status(404).json({
          success: false,
          message: 'Carrera no encontrada'
        });
      }

      // Si se está actualizando el código, verificar que no exista
      if (value.codigo && value.codigo !== existingCarrera.codigo) {
        const codigoExists = await prisma.carrera.findFirst({
          where: {
            codigo: value.codigo,
            id: { not: carreraId }
          }
        });

        if (codigoExists) {
          return res.status(409).json({
            success: false,
            message: 'Ya existe una carrera con este código'
          });
        }
      }

      const carrera = await prisma.carrera.update({
        where: { id: carreraId },
        data: value
      });

      logger.info(`Carrera actualizada: ${carrera.nombre} (ID: ${carreraId})`);

      res.json(carrera);
    } catch (error) {
      logger.error('Error al actualizar carrera:', error);
      res.status(500).json({
        success: false,
        message: 'Error interno del servidor',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  },

  // Eliminar carrera
  async delete(req, res) {
    try {
      const { id } = req.params;
      const carreraId = parseInt(id);

      if (isNaN(carreraId)) {
        return res.status(400).json({
          success: false,
          message: 'ID de carrera inválido'
        });
      }

      // Verificar si la carrera existe
      const carrera = await prisma.carrera.findUnique({
        where: { id: carreraId },
        include: {
          _count: {
            select: { usuarios: true }
          }
        }
      });

      if (!carrera) {
        return res.status(404).json({
          success: false,
          message: 'Carrera no encontrada'
        });
      }

      // Verificar si tiene usuarios asociados
      if (carrera._count.usuarios > 0) {
        return res.status(409).json({
          success: false,
          message: 'No se puede eliminar la carrera porque tiene usuarios asociados'
        });
      }

      await prisma.carrera.delete({
        where: { id: carreraId }
      });

      logger.info(`Carrera eliminada: ${carrera.nombre} (ID: ${carreraId})`);

      res.json({
        success: true,
        message: 'Carrera eliminada exitosamente'
      });
    } catch (error) {
      logger.error('Error al eliminar carrera:', error);
      res.status(500).json({
        success: false,
        message: 'Error interno del servidor',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  }
};

export default carreraController;