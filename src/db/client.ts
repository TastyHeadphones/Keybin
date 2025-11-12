import { drizzle as drizzleBetter } from 'drizzle-orm/better-sqlite3';
import { drizzle as drizzleD1 } from 'drizzle-orm/d1';
import { migrate as migrateBetter } from 'drizzle-orm/better-sqlite3/migrator';
import { migrate as migrateD1 } from 'drizzle-orm/d1/migrator';
import type { Config, RuntimeEnv } from '../env';
import { loadConfig } from '../env';

export type BetterClient = ReturnType<typeof drizzleBetter>;
export type D1Client = ReturnType<typeof drizzleD1>;
export type AppDatabase = BetterClient | D1Client;

type Cache = {
  better?: { raw: any; client: BetterClient };
  d1?: D1Client;
  migrated?: boolean;
  config?: Config;
};

const cache: Cache = {};

const migrationsFolder = 'drizzle';

let BetterSqlite: any;

const loadBetter = async () => {
  if (!BetterSqlite) {
    BetterSqlite = (await import('better-sqlite3')).default;
  }
  return BetterSqlite as typeof import('better-sqlite3').default;
};

const ensureConfig = (env: RuntimeEnv) => {
  if (!cache.config) {
    cache.config = loadConfig(env);
  }
  return cache.config;
};

const ensureBetter = async (config: Config) => {
  if (!cache.better) {
    const Better = await loadBetter();
    const db = new Better(config.sqlitePath);
    cache.better = { raw: db, client: drizzleBetter(db) };
  }
  return cache.better.client;
};

const ensureD1 = (env: RuntimeEnv) => {
  if (!env.DB) {
    throw new Error('Missing D1 binding');
  }
  if (!cache.d1) {
    cache.d1 = drizzleD1(env.DB);
  }
  return cache.d1;
};

let migrationPromise: Promise<void> | null = null;

const runMigrations = (env: RuntimeEnv) => {
  if (cache.migrated) return Promise.resolve();
  if (!migrationPromise) {
    migrationPromise = (async () => {
      const config = ensureConfig(env);
      if (env.DB) {
        const client = ensureD1(env);
        await migrateD1(client, { migrationsFolder });
      } else {
        const client = await ensureBetter(config);
        await migrateBetter(client, { migrationsFolder });
      }
      cache.migrated = true;
    })();
  }
  return migrationPromise;
};

export const getDatabase = async (
  env: RuntimeEnv
): Promise<{ db: AppDatabase; config: Config; mode: 'd1' | 'sqlite' }> => {
  const config = ensureConfig(env);
  await runMigrations(env);
  if (env.DB) {
    return { db: ensureD1(env), config, mode: 'd1' };
  }
  return { db: await ensureBetter(config), config, mode: 'sqlite' };
};
