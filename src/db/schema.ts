import { integer, sqliteTable, text, uniqueIndex } from 'drizzle-orm/sqlite-core';
import { sql } from 'drizzle-orm';

export const users = sqliteTable('users', {
  id: text('id').primaryKey(),
  createdAt: text('created_at').notNull().default(sql`CURRENT_TIMESTAMP`)
});

export const credentials = sqliteTable(
  'credentials',
  {
    id: text('id').primaryKey(),
    userId: text('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    credentialId: text('credential_id').notNull(),
    publicKey: text('public_key').notNull(),
    signCount: integer('sign_count').notNull(),
    transports: text('transports'),
    createdAt: text('created_at').notNull().default(sql`CURRENT_TIMESTAMP`)
  },
  (table) => ({
    credentialIdx: uniqueIndex('credentials_credential_idx').on(table.credentialId)
  })
);

export const pastes = sqliteTable('pastes', {
  id: text('id').primaryKey(),
  userId: text('user_id')
    .notNull()
    .references(() => users.id, { onDelete: 'cascade' }),
  title: text('title'),
  content: text('content').notNull(),
  createdAt: text('created_at').notNull().default(sql`CURRENT_TIMESTAMP`),
  updatedAt: text('updated_at').notNull().default(sql`CURRENT_TIMESTAMP`),
  expiresAt: text('expires_at')
});

export const challenges = sqliteTable('challenges', {
  id: text('id').primaryKey(),
  type: text('type', { enum: ['registration', 'login'] }).notNull(),
  userId: text('user_id'),
  challenge: text('challenge').notNull(),
  createdAt: text('created_at').notNull().default(sql`CURRENT_TIMESTAMP`)
});

export type User = typeof users.$inferSelect;
export type Credential = typeof credentials.$inferSelect;
export type Paste = typeof pastes.$inferSelect;
export type Challenge = typeof challenges.$inferSelect;
