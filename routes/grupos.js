import express from 'express';
import grupoController from '../controllers/grupoController.js';
import { authenticateToken, authorizeRoles } from '../middleware/auth.js';

const router = express.Router();

// Middleware de autenticación para todas las rutas
router.use(authenticateToken);

// GET /api/grupos - Obtener todos los grupos
router.get('/', authorizeRoles(['admin', 'profesor', 'estudiante', 'oficina']), grupoController.getAll);

// GET /api/grupos/:id - Obtener grupo por ID
router.get('/:id', authorizeRoles(['admin', 'profesor', 'estudiante', 'oficina']), grupoController.getById);

// POST /api/grupos - Crear grupo
router.post('/', authorizeRoles(['admin', 'profesor']), grupoController.create);

// PUT /api/grupos/:id - Actualizar grupo
router.put('/:id', authorizeRoles(['admin', 'profesor']), grupoController.update);

// DELETE /api/grupos/:id - Eliminar grupo
router.delete('/:id', authorizeRoles(['admin']), grupoController.delete);

// Rutas de miembros
// GET /api/grupos/:id/miembros - Obtener miembros de un grupo
router.get('/:id/miembros', authorizeRoles(['admin', 'profesor', 'estudiante', 'oficina']), grupoController.getMiembros);

// POST /api/grupos/:id/miembros - Agregar miembro a un grupo
router.post('/:id/miembros', authorizeRoles(['admin', 'profesor']), grupoController.addMiembro);

// DELETE /api/grupos/:id/miembros/:miembro_id - Eliminar miembro de un grupo
router.delete('/:id/miembros/:miembro_id', authorizeRoles(['admin', 'profesor']), grupoController.removeMiembro);

export default router; 