import Joi from "joi";

// Esquemas de validación
const grupoSchema = Joi.object({
    nombre: Joi.string().min(3).max(100).required(),
    creador_id: Joi.number().integer().required(),
});


const miembroSchema = Joi.object({
    usuario_id: Joi.number().integer().positive().required()
});

export { grupoSchema, miembroSchema }