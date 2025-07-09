import express from 'express';
import invitacionController from '../controllers/invitacionController.js';
import { authenticateToken, authorizeRoles } from '../middleware/auth.js';

const router = express.Router();

// Middleware de autenticación para todas las rutas
router.use(authenticateToken);

// GET /api/invitaciones - Obtener todas las invitaciones
router.get('/', authorizeRoles(['admin', 'profesor', 'estudiante', 'oficina']), invitacionController.getAll);

// GET /api/invitaciones/usuario/:id - Obtener invitaciones de un usuario específico
router.get('/usuario/:id', authorizeRoles(['admin', 'profesor', 'estudiante', 'oficina']), invitacionController.getByUsuario);

// GET /api/invitaciones/:id - Obtener invitación por ID
router.get('/:id', authorizeRoles(['admin', 'profesor', 'estudiante', 'oficina']), invitacionController.getById);

// POST /api/invitaciones - Crear invitación
router.post('/', authorizeRoles(['admin', 'profesor', 'estudiante']), invitacionController.create);

// PUT /api/invitaciones/:id - Actualizar estado de invitación
router.put('/:id', authorizeRoles(['admin', 'profesor', 'estudiante']), invitacionController.update);

// DELETE /api/invitaciones/:id - Eliminar invitación
router.delete('/:id', authorizeRoles(['admin']), invitacionController.delete);

export default router; 