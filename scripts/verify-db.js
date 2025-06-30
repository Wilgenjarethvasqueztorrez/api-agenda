import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function verifyDatabase() {
  try {
    console.log('🔍 Verificando base de datos...\n');

    // Contar registros
    const carrerasCount = await prisma.carrera.count();
    const usuariosCount = await prisma.usuario.count();
    const gruposCount = await prisma.grupo.count();
    const miembrosCount = await prisma.miembro.count();
    const invitacionesCount = await prisma.invitacion.count();

    console.log('📊 Estadísticas de la base de datos:');
    console.log(`- Carreras: ${carrerasCount}`);
    console.log(`- Usuarios: ${usuariosCount}`);
    console.log(`- Grupos: ${gruposCount}`);
    console.log(`- Miembros: ${miembrosCount}`);
    console.log(`- Invitaciones: ${invitacionesCount}`);

    // Verificar algunos datos específicos
    const admin = await prisma.usuario.findFirst({
      where: { rol: 'admin' }
    });

    if (admin) {
      console.log('\n✅ Admin encontrado:', admin.email);
    }

    const carreras = await prisma.carrera.findMany();
    console.log('\n🎓 Carreras disponibles:');
    carreras.forEach(carrera => {
      console.log(`- ${carrera.codigo}: ${carrera.nombre}`);
    });

    console.log('\n✅ Verificación completada exitosamente!');

  } catch (error) {
    console.error('❌ Error durante la verificación:', error);
  } finally {
    await prisma.$disconnect();
  }
}

verifyDatabase();
