import Joi from 'joi';

const loginSchema = Joi.object({
  email: Joi.string().email().required()
});

export default loginSchema;