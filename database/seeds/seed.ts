// ═══════════════════════════════════════════════════════════════════════
// CodeGuard AI — Database Seed Script
// Run: npx ts-node database/seeds/seed.ts
// ═══════════════════════════════════════════════════════════════════════

import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function main(): Promise<void> {
  console.log('🌱 Seeding database...');

  // ─── Admin user ────────────────────────────────────────────────────
  const admin = await prisma.user.upsert({
    where: { email: 'admin@codeguard.ai' },
    update: {},
    create: {
      email: 'admin@codeguard.ai',
      name: 'CodeGuard Admin',
      role: 'ADMIN',
    },
  });
  console.log(`✅ Admin user: ${admin.email}`);

  // ─── Demo team ─────────────────────────────────────────────────────
  const team = await prisma.team.upsert({
    where: { slug: 'codeguard-demo' },
    update: {},
    create: {
      name: 'CodeGuard Demo',
      slug: 'codeguard-demo',
      plan: 'FREE',
      members: {
        create: {
          userId: admin.id,
          role: 'OWNER',
        },
      },
    },
  });
  console.log(`✅ Demo team: ${team.name}`);

  // ─── Known hallucinated packages (NPM) ────────────────────────────
  const knownHallucinations: { name: string; ecosystem: 'NPM' | 'PYPI' }[] = [
    { name: 'faker-colors-js', ecosystem: 'NPM' },
    { name: 'lodash-utils-plus', ecosystem: 'NPM' },
    { name: 'react-use-hover-state', ecosystem: 'NPM' },
    { name: 'express-middleware-auth', ecosystem: 'NPM' },
    { name: 'crypto-utils-secure', ecosystem: 'NPM' },
    { name: 'node-fetch-extended', ecosystem: 'NPM' },
    { name: 'typescript-utils-helper', ecosystem: 'NPM' },
    { name: 'aws-sdk-helper', ecosystem: 'NPM' },
    { name: 'mongoose-utils', ecosystem: 'NPM' },
    { name: 'redis-client-helper', ecosystem: 'NPM' },
    { name: 'validate-email-plus', ecosystem: 'NPM' },
    { name: 'date-utils-helper', ecosystem: 'NPM' },
    // PyPI hallucinations
    { name: 'pandas-utils-plus', ecosystem: 'PYPI' },
    { name: 'numpy-helpers', ecosystem: 'PYPI' },
    { name: 'sklearn-utils', ecosystem: 'PYPI' },
    { name: 'flask-auth-helper', ecosystem: 'PYPI' },
    { name: 'django-utils-plus', ecosystem: 'PYPI' },
    { name: 'requests-helper', ecosystem: 'PYPI' },
  ];

  let seeded = 0;
  for (const pkg of knownHallucinations) {
    await prisma.ghinPackage.upsert({
      where: {
        packageName_ecosystem: {
          packageName: pkg.name.toLowerCase(),
          ecosystem: pkg.ecosystem,
        },
      },
      update: {},
      create: {
        packageName: pkg.name.toLowerCase(),
        ecosystem: pkg.ecosystem,
        reportCount: 3,
        status: 'CONFIRMED',
        verifiedAt: new Date(),
      },
    });
    seeded++;
  }
  console.log(`✅ Seeded ${seeded} known hallucinated packages`);

  // ─── Default policy template ───────────────────────────────────────
  await prisma.policyTemplate.upsert({
    where: { id: 'default-policy-template' },
    update: {},
    create: {
      id: 'default-policy-template',
      name: 'Default Security Policy',
      description: 'Baseline security policy for all projects',
      isPublic: true,
      policyJson: {
        version: '1.0',
        rules: {
          blockHallucinations: true,
          maxVulnerabilitySeverity: 'HIGH',
          requireScanners: ['hallucination', 'secrets', 'sast'],
          forbiddenPackages: [],
        },
        actions: {
          onCritical: 'block',
          onHigh: 'warn',
          onMedium: 'warn',
          onLow: 'allow',
        },
      },
    },
  });
  console.log('✅ Default policy template created');

  console.log('\n🎉 Seed complete!');
}

main()
  .catch((e) => {
    console.error('❌ Seed failed:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
