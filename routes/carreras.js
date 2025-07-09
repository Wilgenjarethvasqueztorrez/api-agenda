import express from 'express';
import carreraController from '../controllers/carreraController.js';
import { authenticateToken, authorizeRoles } from '../middleware/auth.js';

const router = express.Router();

// Middleware de autenticación para todas las rutas
router.use(authenticateToken);

// GET /api/carreras - Obtener todas las carreras
router.get('/', authorizeRoles(['admin', 'profesor', 'estudiante', 'oficina']), carreraController.getAll);

// GET /api/carreras/:id - Obtener carrera por ID
router.get('/:id', authorizeRoles(['admin', 'profesor', 'estudiante', 'oficina']), carreraController.getById);

// POST /api/carreras - Crear carrera
router.post('/', authorizeRoles(['admin']), carreraController.create);

// PUT /api/carreras/:id - Actualizar carrera
router.put('/:id', authorizeRoles(['admin']), carreraController.update);

// DELETE /api/carreras/:id - Eliminar carrera
router.delete('/:id', authorizeRoles(['admin']), carreraController.delete);

export default router; 