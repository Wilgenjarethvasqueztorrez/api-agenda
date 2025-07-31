import Joi from 'joi';

// Esquemas de validación
const miembroSchema = Joi.object({
  usuario_id: Joi.number().integer().required(),
  grupo_id: Joi.number().integer().required()
});

export default miembroSchema;