import express from 'express';
import usuarioController from '../controllers/usuarioController.js';
import { authenticateToken, authorizeRoles } from '../middleware/auth.js';

const router = express.Router();

// Middleware de autenticación para todas las rutas
router.use(authenticateToken);

// GET /api/usuarios - Obtener todos los usuarios
router.get('/', authorizeRoles(['admin', 'profesor', 'oficina']), usuarioController.getAll);

// GET /api/usuarios/:id - Obtener usuario por ID
router.get('/:id', authorizeRoles(['admin', 'profesor', 'oficina']), usuarioController.getById);

// POST /api/usuarios - Crear usuario
router.post('/', authorizeRoles(['admin']), usuarioController.create);

// PUT /api/usuarios/:id - Actualizar usuario
router.put('/:id', authorizeRoles(['admin']), usuarioController.update);

// DELETE /api/usuarios/:id - Eliminar usuario
router.delete('/:id', authorizeRoles(['admin']), usuarioController.delete);

export default router; 