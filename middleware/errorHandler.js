import logger from '../utils/logger.js';

function errorHandler(err, req, res, _next) {
  // Log del error
  logger.error('Error no manejado:', {
    message: err.message,
    stack: err.stack,
    url: req.url,
    method: req.method,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });

  // Error de validación de Prisma
  if (err.code === 'P2002') {
    return res.status(409).json({
      success: false,
      message: 'Ya existe un registro con estos datos',
      field: err.meta?.target?.[0] || 'unknown'
    });
  }

  // Error de clave foránea
  if (err.code === 'P2003') {
    return res.status(400).json({
      success: false,
      message: 'No se puede eliminar este registro porque tiene referencias en otros datos'
    });
  }

  // Error de registro no encontrado
  if (err.code === 'P2025') {
    return res.status(404).json({
      success: false,
      message: 'Registro no encontrado'
    });
  }

  // Error de validación de Joi
  if (err.isJoi) {
    return res.status(400).json({
      success: false,
      message: 'Datos de entrada inválidos',
      errors: err.details.map(detail => detail.message)
    });
  }

  // Error de JWT
  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json({
      success: false,
      message: 'Token inválido'
    });
  }

  if (err.name === 'TokenExpiredError') {
    return res.status(401).json({
      success: false,
      message: 'Token expirado'
    });
  }

  // Error de sintaxis JSON
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    return res.status(400).json({
      success: false,
      message: 'JSON inválido en el cuerpo de la petición'
    });
  }

  // Error de límite de tamaño
  if (err.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({
      success: false,
      message: 'Archivo demasiado grande'
    });
  }

  // Error de límite de peticiones
  if (err.status === 429) {
    return res.status(429).json({
      success: false,
      message: 'Demasiadas peticiones, intenta de nuevo más tarde'
    });
  }

  // Error personalizado con status
  if (err.status) {
    return res.status(err.status).json({
      success: false,
      message: err.message || 'Error en la petición'
    });
  }

  // Error interno del servidor (default)
  const statusCode = err.statusCode || 500;
  const message = process.env.NODE_ENV === 'production' 
    ? 'Error interno del servidor' 
    : err.message || 'Error interno del servidor';

  res.status(statusCode).json({
    success: false,
    message,
    ...(process.env.NODE_ENV === 'development' && {
      stack: err.stack,
      details: err
    })
  });
}

export default errorHandler; 