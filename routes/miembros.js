import express from 'express';
import miembroController from '../controllers/miembroController.js';
import { authenticateToken, authorizeRoles } from '../middleware/auth.js';

const router = express.Router();

// Middleware de autenticación para todas las rutas
router.use(authenticateToken);

// GET /api/miembros - Obtener todos los miembros
router.get('/', authorizeRoles(['admin', 'profesor', 'oficina']), miembroController.getAll);

// GET /api/miembros/:id - Obtener miembro por ID
router.get('/:id', authorizeRoles(['admin', 'profesor', 'oficina']), miembroController.getById);

// POST /api/miembros - Crear miembro
router.post('/', authorizeRoles(['admin', 'profesor']), miembroController.create);

// DELETE /api/miembros/:id - Eliminar miembro
router.delete('/:id', authorizeRoles(['admin']), miembroController.delete);

export default router; 