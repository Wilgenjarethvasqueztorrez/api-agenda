import Joi from 'joi';

// Esquemas de validación
const invitacionSchema = Joi.object({
  grupo_id: Joi.number().integer().positive().required(),
  sender_id: Joi.number().integer().positive().required(),
  receiver: Joi.string().min(4).max(100).required(),
  fecha: Joi.string().required(),
  estado: Joi.string().valid('pendiente', 'aceptada', 'rechazada').default('pendiente')
});

const invitacionUpdateSchema = Joi.object({
  estado: Joi.string().valid('pendiente', 'aceptada', 'rechazada').required()
});

export { invitacionSchema, invitacionUpdateSchema }