import Joi from 'joi';

const usersSchema = Joi.object({
  nombres: Joi.string().min(2).max(100).required(),
  apellidos: Joi.string().min(2).max(100).required(),
  correo: Joi.string().email().required(),
  fecha: Joi.string().required(),
  nivel: Joi.number().integer().min(1).max(5).required(),
  celular: Joi.string().optional().min(8).max(11),
  telefono: Joi.string().optional().min(8).max(11),
  carnet: Joi.string().min(10).max(12).optional(),
  rol: Joi.string().valid('admin', 'profesor', 'estudiante', 'oficina').default('estudiante'),
  carrera_id: Joi.number().integer().optional()
});


export default usersSchema;