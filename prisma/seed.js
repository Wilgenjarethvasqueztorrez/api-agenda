import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function main() {
  // eslint-disable-next-line no-console
  console.log('🌱 Iniciando seed de la base de datos...');

  // Crear carreras
  const carreras = await Promise.all([
    prisma.carrera.upsert({
      where: { id: 1 },
      update: {},
      create: {
        id: 1,
        nombre: 'Ingeniería en Sistemas',
        codigo: 1001
      }
    }),
    prisma.carrera.upsert({
      where: { id: 2 },
      update: {},
      create: {
        id: 2,
        nombre: 'Administración de Empresas',
        codigo: 1002
      }
    }),
    prisma.carrera.upsert({
      where: { id: 3 },
      update: {},
      create: {
        id: 3,
        nombre: 'Contabilidad Pública',
        codigo: 1003
      }
    }),
    prisma.carrera.upsert({
      where: { id: 4 },
      update: {},
      create: {
        id: 4,
        nombre: 'Ingeniería Industrial',
        codigo: 1004
      }
    })
  ]);

  // eslint-disable-next-line no-console
  console.log('✅ Carreras creadas:', carreras.length);

  // Crear usuarios
  const usuarios = await Promise.all([
    prisma.usuario.upsert({
      where: { correo: 'admin@uml.edu.ni' },
      update: {},
      create: {
        nombres: 'Administrador',
        apellidos: 'Sistema',
        correo: 'admin@uml.edu.ni',
        rol: 'admin',
        fecha: new Date('1990-01-01'),
        nivel: 1,
        celular: '8888-8888',
        telefono: '2222-2222',
        carnet: 'ADMIN001'
      }
    }),
    prisma.usuario.upsert({
      where: { correo: 'profesor@uml.edu.ni' },
      update: {},
      create: {
        nombres: 'Juan Carlos',
        apellidos: 'González',
        correo: 'profesor@uml.edu.ni',
        rol: 'profesor',
        carrera_id: carreras[0].id,
        fecha: new Date('1985-05-15'),
        nivel: 5,
        celular: '8888-1111',
        telefono: '2222-1111',
        carnet: 'PROF001'
      }
    }),
    prisma.usuario.upsert({
      where: { correo: 'estudiante@uml.edu.ni' },
      update: {},
      create: {
        nombres: 'María Elena',
        apellidos: 'Rodríguez',
        correo: 'estudiante@uml.edu.ni',
        rol: 'estudiante',
        carrera_id: carreras[0].id,
        fecha: new Date('2000-08-20'),
        nivel: 3,
        celular: '8888-2222',
        telefono: '2222-3333',
        carnet: 'EST001'
      }
    }),
    prisma.usuario.upsert({
      where: { correo: 'oficina@uml.edu.ni' },
      update: {},
      create: {
        nombres: 'Ana Patricia',
        apellidos: 'López',
        correo: 'oficina@uml.edu.ni',
        rol: 'oficina',
        fecha: new Date('1988-12-10'),
        nivel: 2,
        celular: '8888-3333',
        telefono: '2222-4444',
        carnet: 'OFI001'
      }
    }),
    prisma.usuario.upsert({
      where: { correo: 'estudiante2@uml.edu.ni' },
      update: {},
      create: {
        nombres: 'Carlos Alberto',
        apellidos: 'Martínez',
        correo: 'estudiante2@uml.edu.ni',
        rol: 'estudiante',
        carrera_id: carreras[1].id,
        fecha: new Date('2001-03-25'),
        nivel: 2,
        celular: '8888-4444',
        telefono: '2222-5555',
        carnet: 'EST002'
      }
    })
  ]);

  // eslint-disable-next-line no-console
  console.log('✅ Usuarios creados:', usuarios.length);

  // Crear grupos
  const grupos = await Promise.all([
    prisma.grupo.upsert({
      where: { id: 1 },
      update: {},
      create: {
        id: 1,
        nombre: 'Grupo de Estudio IS-2024',
        creador_id: usuarios[1].id // profesor
      }
    }),
    prisma.grupo.upsert({
      where: { id: 2 },
      update: {},
      create: {
        id: 2,
        nombre: 'Grupo de Investigación',
        creador_id: usuarios[0].id // admin
      }
    }),
    prisma.grupo.upsert({
      where: { id: 3 },
      update: {},
      create: {
        id: 3,
        nombre: 'Grupo de Programación',
        creador_id: usuarios[1].id // profesor
      }
    })
  ]);

  // eslint-disable-next-line no-console
  console.log('✅ Grupos creados:', grupos.length);

  // Crear miembros
  const miembros = await Promise.all([
    prisma.miembro.upsert({
      where: { id: 1 },
      update: {},
      create: {
        id: 1,
        grupo_id: grupos[0].id,
        usuario_id: usuarios[2].id // estudiante
      }
    }),
    prisma.miembro.upsert({
      where: { id: 2 },
      update: {},
      create: {
        id: 2,
        grupo_id: grupos[0].id,
        usuario_id: usuarios[4].id // estudiante2
      }
    }),
    prisma.miembro.upsert({
      where: { id: 3 },
      update: {},
      create: {
        id: 3,
        grupo_id: grupos[1].id,
        usuario_id: usuarios[1].id // profesor
      }
    }),
    prisma.miembro.upsert({
      where: { id: 4 },
      update: {},
      create: {
        id: 4,
        grupo_id: grupos[2].id,
        usuario_id: usuarios[2].id // estudiante
      }
    })
  ]);

  // eslint-disable-next-line no-console
  console.log('✅ Miembros creados:', miembros.length);

  // Crear invitaciones
  const invitaciones = await Promise.all([
    prisma.invitacion.upsert({
      where: { id: 1 },
      update: {},
      create: {
        id: 1,
        fecha: new Date(),
        sender_id: usuarios[1].id, // profesor envía invitación
        receiver: 'nuevo.estudiante@uml.edu.ni',
        estado: 'pendiente',
        grupo_id: grupos[0].id
      }
    }),
    prisma.invitacion.upsert({
      where: { id: 2 },
      update: {},
      create: {
        id: 2,
        fecha: new Date(),
        sender_id: usuarios[0].id, // admin envía invitación
        receiver: 'investigador@uml.edu.ni',
        estado: 'aceptada',
        grupo_id: grupos[1].id
      }
    }),
    prisma.invitacion.upsert({
      where: { id: 3 },
      update: {},
      create: {
        id: 3,
        fecha: new Date(),
        sender_id: usuarios[1].id, // profesor envía invitación
        receiver: 'programador@uml.edu.ni',
        estado: 'rechazada',
        grupo_id: grupos[2].id
      }
    })
  ]);

  // eslint-disable-next-line no-console
  console.log('✅ Invitaciones creadas:', invitaciones.length);
  // eslint-disable-next-line no-console
  console.log('🎉 Seed completado exitosamente!');
  // eslint-disable-next-line no-console
  console.log('\n📋 Datos de acceso:');
  // eslint-disable-next-line no-console
  console.log('👤 Admin: admin@uml.edu.ni');
  // eslint-disable-next-line no-console
  console.log('👨‍🏫 Profesor: profesor@uml.edu.ni');
  // eslint-disable-next-line no-console
  console.log('👨‍🎓 Estudiante: estudiante@uml.edu.ni');
  // eslint-disable-next-line no-console
  console.log('👨‍🎓 Estudiante 2: estudiante2@uml.edu.ni');
  // eslint-disable-next-line no-console
  console.log('🏢 Oficina: oficina@uml.edu.ni');
  // eslint-disable-next-line no-console
  console.log('\n📊 Resumen de datos creados:');
  // eslint-disable-next-line no-console
  console.log(`   - ${carreras.length} carreras`);
  // eslint-disable-next-line no-console
  console.log(`   - ${usuarios.length} usuarios`);
  // eslint-disable-next-line no-console
  console.log(`   - ${grupos.length} grupos`);
  // eslint-disable-next-line no-console
  console.log(`   - ${miembros.length} miembros`);
  // eslint-disable-next-line no-console
  console.log(`   - ${invitaciones.length} invitaciones`);
}

main()
  .catch((e) => {
    // eslint-disable-next-line no-console
    console.error('❌ Error durante el seed:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  }); 