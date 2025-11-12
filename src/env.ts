export type Config = {
  origin: string;
  rpId: string;
  rpName: string;
  sessionSecret: string;
  sqlitePath: string;
};

export type RuntimeEnv = Record<string, string | undefined> & {
  DB?: D1Database;
};

export const loadConfig = (env: RuntimeEnv): Config => {
  const getEnv = (key: string) => env[key] || (typeof process !== 'undefined' ? process.env[key] : undefined);
  const requireValue = (key: string) => {
    const value = getEnv(key);
    if (!value) {
      throw new Error(`Missing env ${key}`);
    }
    return value;
  };

  const sqlitePath = getEnv('SQLITE_PATH') || './.sqlite/keybin.db';

  return {
    origin: requireValue('ORIGIN'),
    rpId: requireValue('RP_ID'),
    rpName: requireValue('RP_NAME'),
    sessionSecret: requireValue('SESSION_SECRET'),
    sqlitePath
  };
};
