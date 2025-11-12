import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { serveStatic } from '@hono/node-server/serve-static';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse
} from '@simplewebauthn/server';
import { and, desc, eq, gt, isNull, or, sql } from 'drizzle-orm';
import { securityHeaders } from './security';
import type { Config, RuntimeEnv } from './env';
import { getDatabase } from './db/client';
import { challenges, credentials, pastes, users } from './db/schema';
import { clearSessionCookie, createSessionCookie, readSessionCookie, type SessionPayload } from './session';
import { nanoid, isNodeRuntime } from './utils';
import { z } from 'zod';

export type AppBindings = RuntimeEnv & { ASSETS?: Fetcher };
export type AppVariables = {
  db: Awaited<ReturnType<typeof getDatabase>>['db'];
  config: Config;
  session: SessionPayload | null;
  mode: 'd1' | 'sqlite';
};

type AppEnv = {
  Bindings: AppBindings;
  Variables: AppVariables;
};

const pasteInput = z.object({
  title: z.string().trim().max(128).optional().nullable(),
  content: z.string().min(1).max(64 * 1024),
  expiresAt: z.string().datetime().optional().nullable()
});

const runInsert = async (mode: 'd1' | 'sqlite', query: any) => {
  if (mode === 'd1') {
    await query;
  } else {
    query.run();
  }
};

const runMutation = async (mode: 'd1' | 'sqlite', query: any) => {
  if (mode === 'd1') {
    return await query;
  }
  return query.run();
};

const fetchAll = async <T>(mode: 'd1' | 'sqlite', query: any): Promise<T[]> => {
  if (mode === 'd1') {
    return (await query) as T[];
  }
  return query.all() as T[];
};

const fetchOne = async <T>(mode: 'd1' | 'sqlite', query: any): Promise<T | undefined> => {
  if (mode === 'd1') {
    const rows = (await query) as T[];
    return Array.isArray(rows) ? rows[0] : undefined;
  }
  return query.get?.() as T | undefined;
};

const cleanupChallenges = async (db: AppVariables['db']) => {
  const query = sql`DELETE FROM challenges WHERE created_at < datetime('now', '-15 minutes')`;
  const runner = (db as any).run?.bind(db) || (db as any).execute?.bind(db);
  if (runner) {
    await runner(query);
  }
};

const cleanupPastes = async (db: AppVariables['db']) => {
  const query = sql`DELETE FROM pastes WHERE expires_at IS NOT NULL AND expires_at <= datetime('now')`;
  const runner = (db as any).run?.bind(db) || (db as any).execute?.bind(db);
  if (runner) {
    await runner(query);
  }
};

const requireAuth = (c: Hono<AppEnv>['Context']) => {
  const session = c.get('session');
  if (!session) {
    throw new HTTPException(401, { message: 'Unauthorized' });
  }
  return session;
};

const app = new Hono<AppEnv>();

app.use('*', securityHeaders());

app.use('*', async (c, next) => {
  const { db, config, mode } = await getDatabase(c.env);
  const session = await readSessionCookie(c.req.header('Cookie'), config.sessionSecret);
  c.set('db', db);
  c.set('config', config);
  c.set('session', session);
  c.set('mode', mode);

  if (!['GET', 'HEAD', 'OPTIONS'].includes(c.req.method)) {
    const origin = c.req.header('origin');
    if (origin && origin !== config.origin) {
      throw new HTTPException(403, { message: 'Forbidden origin' });
    }
  }

  await cleanupChallenges(db);
  await cleanupPastes(db);

  return next();
});

app.post('/logout', (c) => {
  c.header('Set-Cookie', clearSessionCookie());
  return c.body(null, 204);
});

app.post('/webauthn/registration/options', async (c) => {
  const config = c.get('config');
  const db = c.get('db');
  const mode = c.get('mode');
  const userId = crypto.randomUUID();
  const challengeId = nanoid();
  const options = await generateRegistrationOptions({
    rpID: config.rpId,
    rpName: config.rpName,
    userID: userId,
    userName: userId,
    userDisplayName: 'Keybin user',
    attestationType: 'none',
    authenticatorSelection: {
      residentKey: 'preferred',
      requireResidentKey: false,
      userVerification: 'preferred'
    },
    timeout: 60_000,
    supportedAlgorithmIDs: [-7, -257]
  });

  await runInsert(mode, (db as any).insert(challenges).values({
    id: challengeId,
    type: 'registration',
    userId,
    challenge: options.challenge
  }));

  return c.json({ ...options, userId, challengeId });
});

app.post('/webauthn/registration/verify', async (c) => {
  const config = c.get('config');
  const db = c.get('db');
  const mode = c.get('mode');
  const body = await c.req.json();
  const challengeId = body.challengeId as string | undefined;
  if (!challengeId) {
    throw new HTTPException(400, { message: 'Missing challenge' });
  }

  const challengeRow = await fetchOne<{ id: string; type: string; userId: string; challenge: string }>(
    mode,
    (db as any).select().from(challenges).where(eq(challenges.id, challengeId))
  );

  if (!challengeRow || challengeRow.type !== 'registration') {
    throw new HTTPException(400, { message: 'Invalid challenge' });
  }

  const verification = await verifyRegistrationResponse({
    response: body,
    expectedChallenge: challengeRow.challenge,
    expectedOrigin: config.origin,
    expectedRPID: config.rpId,
    requireUserVerification: true
  });

  if (!verification.verified || !verification.registrationInfo) {
    throw new HTTPException(400, { message: 'Registration failed' });
  }

  const { credentialID, credentialPublicKey, counter, transports } = verification.registrationInfo;

  const existingCredential = await fetchOne<{ id: string }>(
    mode,
    (db as any).select().from(credentials).where(eq(credentials.credentialId, credentialID))
  );
  if (existingCredential) {
    throw new HTTPException(409, { message: 'Credential already registered' });
  }

  const existingUser = await fetchOne<{ id: string }>(
    mode,
    (db as any).select().from(users).where(eq(users.id, challengeRow.userId))
  );
  if (!existingUser) {
    await runInsert(mode, (db as any).insert(users).values({ id: challengeRow.userId }));
  }

  await runInsert(mode, (db as any).insert(credentials).values({
    id: crypto.randomUUID(),
    userId: challengeRow.userId,
    credentialId: credentialID,
    publicKey: credentialPublicKey,
    signCount: counter,
    transports: transports?.join(',') ?? null
  }));

  await runMutation(mode, (db as any).delete(challenges).where(eq(challenges.id, challengeId)));

  const user = await fetchOne<{ id: string; createdAt: string }>(
    mode,
    (db as any).select({ id: users.id, createdAt: users.createdAt }).from(users).where(eq(users.id, challengeRow.userId))
  );

  if (!user) {
    throw new HTTPException(500, { message: 'User not found' });
  }

  c.header('Set-Cookie', await createSessionCookie(user.id, config.sessionSecret));
  return c.json(user);
});

app.post('/webauthn/login/options', async (c) => {
  const config = c.get('config');
  const db = c.get('db');
  const mode = c.get('mode');
  const challengeId = nanoid();

  const options = await generateAuthenticationOptions({
    rpID: config.rpId,
    timeout: 60_000,
    userVerification: 'preferred',
    allowCredentials: []
  });

  await runInsert(mode, (db as any).insert(challenges).values({
    id: challengeId,
    type: 'login',
    challenge: options.challenge
  }));

  return c.json({ ...options, challengeId });
});

app.post('/webauthn/login/verify', async (c) => {
  const config = c.get('config');
  const db = c.get('db');
  const mode = c.get('mode');
  const body = await c.req.json();
  const challengeId = body.challengeId as string | undefined;
  if (!challengeId) {
    throw new HTTPException(400, { message: 'Missing challenge' });
  }

  const challengeRow = await fetchOne<{ id: string; challenge: string; type: string }>(
    mode,
    (db as any).select().from(challenges).where(eq(challenges.id, challengeId))
  );
  if (!challengeRow || challengeRow.type !== 'login') {
    throw new HTTPException(400, { message: 'Invalid challenge' });
  }

  const credential = await fetchOne<{
    id: string;
    userId: string;
    credentialId: string;
    publicKey: string;
    signCount: number;
    transports: string | null;
  }>(mode, (db as any).select().from(credentials).where(eq(credentials.credentialId, body.id)));

  if (!credential) {
    throw new HTTPException(404, { message: 'Credential not found' });
  }

  const verification = await verifyAuthenticationResponse({
    response: body,
    expectedChallenge: challengeRow.challenge,
    expectedOrigin: config.origin,
    expectedRPID: config.rpId,
    authenticator: {
      credentialID: credential.credentialId,
      credentialPublicKey: credential.publicKey,
      counter: credential.signCount,
      transports: credential.transports?.split(',').filter(Boolean)
    },
    requireUserVerification: true
  });

  if (!verification.verified || !verification.authenticationInfo) {
    throw new HTTPException(400, { message: 'Authentication failed' });
  }

  await runMutation(
    mode,
    (db as any)
      .update(credentials)
      .set({ signCount: verification.authenticationInfo.newCounter })
      .where(eq(credentials.id, credential.id))
  );

  await runMutation(mode, (db as any).delete(challenges).where(eq(challenges.id, challengeId)));

  const user = await fetchOne<{ id: string; createdAt: string }>(
    mode,
    (db as any).select({ id: users.id, createdAt: users.createdAt }).from(users).where(eq(users.id, credential.userId))
  );

  if (!user) {
    throw new HTTPException(404, { message: 'User not found' });
  }

  c.header('Set-Cookie', await createSessionCookie(user.id, config.sessionSecret));
  return c.json(user);
});

app.get('/me', async (c) => {
  const session = c.get('session');
  if (!session) {
    return c.json({ user: null }, 401);
  }
  const db = c.get('db');
  const mode = c.get('mode');
  const user = await fetchOne<{ id: string; createdAt: string }>(
    mode,
    (db as any).select({ id: users.id, createdAt: users.createdAt }).from(users).where(eq(users.id, session.userId))
  );
  if (!user) {
    return c.json({ user: null }, 401);
  }
  return c.json(user);
});

app.get('/pastes', async (c) => {
  const session = requireAuth(c);
  const db = c.get('db');
  const mode = c.get('mode');
  const rows = await fetchAll<{
    id: string;
    title: string | null;
    content: string;
    createdAt: string;
    updatedAt: string;
    expiresAt: string | null;
  }>(
    mode,
    (db as any)
      .select({
        id: pastes.id,
        title: pastes.title,
        content: pastes.content,
        createdAt: pastes.createdAt,
        updatedAt: pastes.updatedAt,
        expiresAt: pastes.expiresAt
      })
      .from(pastes)
      .where(and(eq(pastes.userId, session.userId), or(isNull(pastes.expiresAt), gt(pastes.expiresAt, sql`datetime('now')`))))
      .orderBy(desc(pastes.createdAt))
  );
  return c.json(rows);
});

app.post('/pastes', async (c) => {
  const session = requireAuth(c);
  const db = c.get('db');
  const mode = c.get('mode');
  const payload = pasteInput.safeParse(await c.req.json());
  if (!payload.success) {
    throw new HTTPException(400, { message: 'Invalid input' });
  }

  const { content, title, expiresAt } = payload.data;
  const contentBytes = new TextEncoder().encode(content).length;
  if (contentBytes > 64 * 1024) {
    throw new HTTPException(400, { message: 'Paste exceeds 64KB limit' });
  }
  let finalExpiresAt: string | null = null;
  if (expiresAt) {
    const expiresDate = new Date(expiresAt);
    if (Number.isNaN(expiresDate.getTime()) || expiresDate.getTime() <= Date.now()) {
      throw new HTTPException(400, { message: 'expiresAt must be in the future' });
    }
    finalExpiresAt = expiresDate.toISOString();
  }

  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  await runInsert(mode, (db as any).insert(pastes).values({
    id,
    userId: session.userId,
    title: title ?? null,
    content,
    createdAt: now,
    updatedAt: now,
    expiresAt: finalExpiresAt
  }));

  const paste = await fetchOne<{
    id: string;
    title: string | null;
    content: string;
    createdAt: string;
    updatedAt: string;
    expiresAt: string | null;
  }>(mode, (db as any).select({
    id: pastes.id,
    title: pastes.title,
    content: pastes.content,
    createdAt: pastes.createdAt,
    updatedAt: pastes.updatedAt,
    expiresAt: pastes.expiresAt
  }).from(pastes).where(eq(pastes.id, id)));

  return c.json(paste, 201);
});

app.get('/pastes/:id', async (c) => {
  const session = requireAuth(c);
  const db = c.get('db');
  const mode = c.get('mode');
  const id = c.req.param('id');
  const paste = await fetchOne<{
    id: string;
    userId: string;
    title: string | null;
    content: string;
    createdAt: string;
    updatedAt: string;
    expiresAt: string | null;
  }>(
    mode,
    (db as any)
      .select({
        id: pastes.id,
        userId: pastes.userId,
        title: pastes.title,
        content: pastes.content,
        createdAt: pastes.createdAt,
        updatedAt: pastes.updatedAt,
        expiresAt: pastes.expiresAt
      })
      .from(pastes)
      .where(eq(pastes.id, id))
  );
  if (!paste || paste.userId !== session.userId) {
    throw new HTTPException(404, { message: 'Paste not found' });
  }
  const { userId: _userId, ...rest } = paste;
  return c.json(rest);
});

app.delete('/pastes/:id', async (c) => {
  const session = requireAuth(c);
  const db = c.get('db');
  const mode = c.get('mode');
  const id = c.req.param('id');
  const result = await runMutation(
    mode,
    (db as any).delete(pastes).where(and(eq(pastes.id, id), eq(pastes.userId, session.userId)))
  );
  if (mode === 'd1') {
    const rowsAffected = (result as { success: boolean; meta?: { changes?: number } }).meta?.changes ?? 0;
    if (rowsAffected === 0) {
      throw new HTTPException(404, { message: 'Paste not found' });
    }
  } else if ((result as { changes: number }).changes === 0) {
    throw new HTTPException(404, { message: 'Paste not found' });
  }
  return c.body(null, 204);
});

const serveFromAssets = async (c: Hono<AppEnv>['Context']) => {
  if (!c.env.ASSETS) {
    return c.notFound();
  }
  const url = new URL(c.req.url);
  const path = url.pathname === '/' ? '/index.html' : url.pathname;
  const asset = await c.env.ASSETS.fetch(new Request(`https://assets${path}`));
  if (asset.status === 404) {
    return c.notFound();
  }
  return new Response(asset.body, asset);
};

app.get('*', async (c, next) => {
  if (isNodeRuntime()) {
    return next();
  }
  return serveFromAssets(c);
});

if (isNodeRuntime()) {
  app.get('*', serveStatic({
    root: './dist/client',
    rewriteRequestPath: (path) => (path === '/' ? '/index.html' : path)
  }));
}

export default app;
