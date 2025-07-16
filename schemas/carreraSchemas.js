import Joi from 'joi';

const carreraSchema = Joi.object({
  // Solo los campos definidos en el modelo Prisma Carrera
  nombre: Joi.string().min(3).max(100).required(),
  codigo: Joi.number().integer().min(10).max(9999999999).required(),
}).tailor('default');

carreraSchema.tailor('update', {
  nombre: Joi.string().min(3).max(100).optional(),
  codigo: Joi.number().integer().min(10).max(9999999999).optional()
});

export { carreraSchema };