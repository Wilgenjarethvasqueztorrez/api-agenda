// Cargar variables de entorno según el entorno
if (process.env.NODE_ENV === 'test') {
  import('dotenv').then(dotenv => dotenv.config({ path: '.env.test' }));
} else {
  import('dotenv').then(dotenv => dotenv.config());
}

import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import compression from 'compression';
import morgan from 'morgan';
import logger from './utils/logger.js';

// Importar rutas
import authRoutes from './routes/auth.js';
import usuarioRoutes from './routes/usuarios.js';
import carreraRoutes from './routes/carreras.js';
import grupoRoutes from './routes/grupos.js';
import miembroRoutes from './routes/miembros.js';
import invitacionRoutes from './routes/invitaciones.js';

// Importar middleware de manejo de errores
import errorHandler from './middleware/errorHandler.js';

const app = express();

// Middleware de seguridad
app.use(helmet());

// Configuración de CORS
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? ['https://tu-dominio.com'] 
    : ['http://localhost:3001', 'http://localhost:3000'],
  credentials: true
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 100, // máximo 100 requests por ventana
  message: {
    success: false,
    message: 'Demasiadas peticiones desde esta IP, intenta de nuevo en 15 minutos'
  }
});
app.use('/api/', limiter);

// Compresión
app.use(compression());

// Parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Logging
app.use(morgan('combined', { stream: { write: message => logger.info(message.trim()) } }));

// Rutas de salud y información
app.get('/health', (req, res) => {
  res.json({
    success: true,
    message: 'API Agenda - Universidad Martin Lutero',
    status: 'OK',
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

app.get('/info', (req, res) => {
  res.json({
    success: true,
    name: 'API Agenda',
    description: 'Sistema de gestión de datos de contacto de estudiantes y docentes',
    version: '1.0.0',
    author: 'Willgen Jareth Vasquez Torrez',
    endpoints: {
      auth: '/api/auth',
      usuarios: '/api/usuarios',
      carreras: '/api/carreras',
      grupos: '/api/grupos',
      miembros: '/api/miembros',
      invitaciones: '/api/invitaciones'
    }
  });
});

// Rutas de la API
app.use('/api/auth', authRoutes);
app.use('/api/usuarios', usuarioRoutes);
app.use('/api/carreras', carreraRoutes);
app.use('/api/grupos', grupoRoutes);
app.use('/api/miembros', miembroRoutes);
app.use('/api/invitaciones', invitacionRoutes);

// Ruta 404
app.use(/(.*)/, (req, res) => {
  res.status(404).json({
    success: false,
    message: 'Endpoint no encontrado',
    path: req.originalUrl
  });
});

// Middleware de manejo de errores (debe ir al final)
app.use(errorHandler);

export default app;