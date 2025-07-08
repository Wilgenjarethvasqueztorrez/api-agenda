import jwt from 'jsonwebtoken';
import { PrismaClient } from '@prisma/client';
import logger from '../utils/logger.js';

const prisma = new PrismaClient();

// Middleware para verificar token JWT
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Token de acceso requerido'
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Verificar que el usuario existe
    const usuario = await prisma.usuario.findUnique({
      where: { id: decoded.userId },
      select: { id: true, email: true, rol: true, nombre: true }
    });

    if (!usuario) {
      return res.status(401).json({
        success: false,
        message: 'Usuario no encontrado'
      });
    }

    req.user = usuario;
    next();
  } catch (error) {
    logger.error('Error en autenticación:', error);

    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({
        success: false,
        message: 'Token inválido'
      });
    }

    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        message: 'Token expirado'
      });
    }

    return res.status(500).json({
      success: false,
      message: 'Error interno del servidor'
    });
  }
};

// Middleware para autorización por roles
const authorizeRoles = (allowedRoles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Usuario no autenticado'
      });
    }

    if (!allowedRoles.includes(req.user.rol)) {
      return res.status(403).json({
        success: false,
        message: 'No tienes permisos para realizar esta acción'
      });
    }

    next();
  };
};

// Middleware para verificar que el usuario es propietario del recurso o admin
const authorizeOwnerOrAdmin = (resourceModel, resourceIdField = 'id') => {
  return async (req, res, next) => {
    try {
      if (req.user.rol === 'admin') {
        return next();
      }

      const resourceId = req.params[resourceIdField];
      const resource = await prisma[resourceModel].findUnique({
        where: { id: parseInt(resourceId) },
        select: { usuario_id: true }
      });

      if (!resource) {
        return res.status(404).json({
          success: false,
          message: 'Recurso no encontrado'
        });
      }

      if (resource.usuario_id !== req.user.id) {
        return res.status(403).json({
          success: false,
          message: 'No tienes permisos para acceder a este recurso'
        });
      }

      next();
    } catch (error) {
      logger.error('Error en autorización de propietario:', error);
      return res.status(500).json({
        success: false,
        message: 'Error interno del servidor'
      });
    }
  };
};

export {
  authenticateToken,
  authorizeRoles,
  authorizeOwnerOrAdmin
}; 