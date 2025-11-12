import { pgTable, serial, text, timestamp, boolean } from 'drizzle-orm/pg-core';

export const users = pgTable('users', {
  id: serial('id').primaryKey(),
  email: text('email').notNull().unique(),
  password: text('password'), // NULL for Google users
  firstName: text('first_name').notNull(),
  lastName: text('last_name').notNull(),
  imageUrl: text('image_url'),
  googleId: text('google_id').unique(),
  authProvider: text('auth_provider').default('email'), // 'email' or 'google'
  isEmailVerified: boolean('is_email_verified').default(false),
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow(),
});
