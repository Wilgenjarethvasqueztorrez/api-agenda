import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
import request from 'supertest';
import app from '../app.js';

// Configurar Prisma para tests
const prisma = new PrismaClient();

// Función para limpiar la base de datos
async function cleanDatabase() {
  try {
    // Eliminar datos en orden inverso para evitar problemas de foreign keys
    await prisma.miembro.deleteMany();
    await prisma.invitacion.deleteMany();
    await prisma.grupo.deleteMany();
    await prisma.usuario.deleteMany();
    await prisma.carrera.deleteMany();
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error('Error limpiando base de datos:', error);
  }
}

// Función para crear datos de prueba usando los mismos datos del seed
async function seedTestData() {
  try {
    // Crear carreras
    const uniqueData1 = generateUniqueData();
    const uniqueData2 = generateUniqueData();
    const carreras = await Promise.all([
      prisma.carrera.upsert({
        where: { codigo: uniqueData1.carrera.codigo },
        update: {},
        create: uniqueData1.carrera
      }),
      prisma.carrera.upsert({
        where: { codigo: uniqueData2.carrera.codigo },
        update: {},
        create: uniqueData2.carrera
      })
    ]);

    // Crear usuarios con contraseñas hasheadas
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash('admin123', saltRounds);

    const usuarios = await Promise.all([
      prisma.usuario.upsert({
        where: { email: 'admin@uml.edu.ni' },
        update: {},
        create: {
          nombre: 'Administrador',
          email: 'admin@uml.edu.ni',
          password: hashedPassword,
          rol: 'admin'
        }
      }),
      prisma.usuario.upsert({
        where: { email: 'profesor@uml.edu.ni' },
        update: {},
        create: {
          nombre: 'Profesor Ejemplo',
          email: 'profesor@uml.edu.ni',
          password: hashedPassword,
          rol: 'profesor',
          carrera_id: carreras[0].id
        }
      }),
      prisma.usuario.upsert({
        where: { email: 'estudiante@uml.edu.ni' },
        update: {},
        create: {
          nombre: 'Estudiante Ejemplo',
          email: 'estudiante@uml.edu.ni',
          password: hashedPassword,
          rol: 'estudiante',
          carrera_id: carreras[1].id
        }
      })
    ]);

    // Crear grupos
    const grupos = await Promise.all([
      prisma.grupo.upsert({
        where: { id: 1 },
        update: {},
        create: {
          id: 1,
          nombre: 'Grupo de Investigación',
          descripcion: 'Grupo de investigación en tecnologías emergentes',
          estado: 'activo'
        }
      })
    ]);

    // Crear miembros
    await Promise.all([
      prisma.miembro.upsert({
        where: { grupo_id_usuario_id: { grupo_id: grupos[0].id, usuario_id: usuarios[0].id } },
        update: {},
        create: {
          grupo_id: grupos[0].id,
          usuario_id: usuarios[0].id
        }
      }),
      prisma.miembro.upsert({
        where: { grupo_id_usuario_id: { grupo_id: grupos[0].id, usuario_id: usuarios[1].id } },
        update: {},
        create: {
          grupo_id: grupos[0].id,
          usuario_id: usuarios[1].id
        }
      }),
      prisma.miembro.upsert({
        where: { grupo_id_usuario_id: { grupo_id: grupos[0].id, usuario_id: usuarios[2].id } },
        update: {},
        create: {
          grupo_id: grupos[0].id,
          usuario_id: usuarios[2].id
        }
      })
    ]);
    // eslint-disable-next-line no-console
    console.log('Datos de prueba creados exitosamente');
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error('Error creando datos de prueba:', error);
  }
}

// Función para generar datos únicos para tests
function generateUniqueData() {
  const hrtime = process.hrtime.bigint();
  const timestamp = Date.now();
  const random = Math.floor(Math.random() * 1000000);
  const uniqueId = `${hrtime}${timestamp}${random}`;

  return {
    carrera: {
      nombre: `Carrera Test ${uniqueId}`,
      codigo: `CT${uniqueId}`.slice(-10),
      descripcion: 'Carrera de prueba',
      duracion_anos: 4,
      creditos_totales: 240,
      estado: 'activa'
    },
    grupo: {
      nombre: `Grupo Test ${uniqueId}`,
      descripcion: 'Grupo de prueba',
      estado: 'activo'
    },
    usuario: {
      nombre: `Usuario Test ${uniqueId}`,
      email: `usuario.test.${uniqueId}@uml.edu.ni`,
      password: 'test123',
      rol: 'estudiante'
    }
  };
}

// Configuración global para Jest
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'supersecretuml2024';
process.env.JWT_EXPIRES_IN = '24h';

// Helper para obtener token de autenticación
async function getAuthToken(email, password) {
  const res = await request(app)
    .post('/api/auth/login')
    .send({ email, password });
  return res.body.token;
}

// Hacer funciones disponibles globalmente
global.getAuthToken = getAuthToken;
global.cleanDatabase = cleanDatabase;
global.seedTestData = seedTestData;
global.prisma = prisma;

export {
  prisma,
  cleanDatabase,
  seedTestData,
  generateUniqueData,
  getAuthToken
}; 
