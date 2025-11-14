// import { pgTable, text, timestamp, boolean, integer, uuid } from 'drizzle-orm/pg-core';
import { pgTable, text, timestamp, boolean, integer, uuid, jsonb } from 'drizzle-orm/pg-core';
import { relations, sql } from 'drizzle-orm';
import { createInsertSchema } from 'drizzle-zod';
import { z } from 'zod';

// ==================== AUTHENTICATION TABLES ====================

export const users = pgTable('users', {
  id: uuid('id').primaryKey().defaultRandom(), // Changed to UUID
  email: text('email').notNull().unique(),
  password: text('password'),
  firstName: text('first_name').notNull(),
  lastName: text('last_name').notNull(),
  imageUrl: text('image_url'),
  googleId: text('google_id').unique(),
  authProvider: text('auth_provider').default('email'), // 'email' or 'google'
  isEmailVerified: boolean('is_email_verified').default(false),
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow(),
});

export const emailVerifications = pgTable('email_verifications', {
  id: uuid('id').primaryKey().defaultRandom(), // Changed to UUID
  email: text('email').notNull().unique(),
  otp: text('otp').notNull(),
  attempts: integer('attempts').default(0),
  expiresAt: timestamp('expires_at').notNull(),
  createdAt: timestamp('created_at').defaultNow(),
});

export type User = typeof users.$inferSelect;
export type InsertUser = typeof users.$inferInsert;

// ==================== NETWORKING EVENTS TABLE ====================

export const networkingEvents = pgTable('networking_events', {
  id: uuid('id').primaryKey().defaultRandom(), // Changed to UUID
  userId: uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }), // Changed to UUID
  name: text('name').notNull(),
  description: text('description'),
  location: text('location'),
  eventDate: timestamp('event_date'),
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow(),
});

export const networkingEventsRelations = relations(networkingEvents, ({ one, many }) => ({
  user: one(users, {
    fields: [networkingEvents.userId],
    references: [users.id],
  }),
  contacts: many(contacts),
}));

export const insertNetworkingEventSchema = createInsertSchema(networkingEvents).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
}).extend({
  eventDate: z.union([
    z.string().transform((val) => val ? new Date(val) : null),
    z.date(),
    z.null(),
  ]).optional(),
});

export type NetworkingEvent = typeof networkingEvents.$inferSelect;
export type InsertNetworkingEvent = z.infer<typeof insertNetworkingEventSchema>;

// ==================== CONTACTS TABLE ====================

export const contacts = pgTable('contacts', {
  id: uuid('id').primaryKey().defaultRandom(), // Changed to UUID
  userId: uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }), // Changed to UUID
  networkingEventId: uuid('networking_event_id').references(() => networkingEvents.id, { onDelete: 'set null' }), // Changed to UUID

  // Basic contact information
  name: text('name').notNull(),
  email: text('email'),
  phone: text('phone'),
  whatsappNumber: text('whatsapp_number'),
  company: text('company'),
  title: text('title'),
  website: text('website'),
  country: text('country'),
  address: text('address'),

  // Social media links
  socialMedia: jsonb('social_media').$type<{
    linkedin?: string | null;
    twitter?: string | null;
    instagram?: string | null;
    facebook?: string | null;
  }>(),

  // Card images and media
  cardImageUrl: text('card_image_url'),
  displayPictureUrl: text('display_picture_url'),
  mediaUrls: text('media_urls').array().default([]),

  // Voice notes and metadata
  voiceNoteUrl: text('voice_note_url'),
  tags: text('tags').array().default([]),
  notes: text('notes'),

  // Scan metadata
  scanConfidence: text('scan_confidence'),
  manuallyCreated: boolean('manually_created').default(false),

  // Timestamps
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow(),
});

export const contactsRelations = relations(contacts, ({ one, many }) => ({
  user: one(users, {
    fields: [contacts.userId],
    references: [users.id],
  }),
  networkingEvent: one(networkingEvents, {
    fields: [contacts.networkingEventId],
    references: [networkingEvents.id],
  }),
  voiceNotes: many(voiceNotes),
  todos: many(todos),
  reminders: many(reminders),
  events: many(events),
}));

export const insertContactSchema = createInsertSchema(contacts).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
}).extend({
  userId: z.string().uuid(),
  networkingEventId: z.string().uuid().optional().nullable(),
  socialMedia: z.object({
    linkedin: z.string().nullable().optional(),
    twitter: z.string().nullable().optional(),
    instagram: z.string().nullable().optional(),
    facebook: z.string().nullable().optional(),
  }).optional(),
  tags: z.array(z.string()).optional(),
  mediaUrls: z.array(z.string()).optional(),
  scanConfidence: z.enum(['high', 'medium', 'low']).optional().nullable(),
});

export type Contact = typeof contacts.$inferSelect;
export type InsertContact = z.infer<typeof insertContactSchema>;

// ==================== VOICE NOTES TABLE ====================

export const voiceNotes = pgTable('voice_notes', {
  id: uuid('id').primaryKey().defaultRandom(), // Changed to UUID
  userId: uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }), // Changed to UUID
  contactId: uuid('contact_id').references(() => contacts.id, { onDelete: 'cascade' }), // Changed to UUID
  audioUrl: text('audio_url').notNull(),
  transcription: text('transcription').notNull(),
  extractedContext: text('extracted_context'),
  duration: integer('duration'),
  createdAt: timestamp('created_at').defaultNow(),
});

export const voiceNotesRelations = relations(voiceNotes, ({ one }) => ({
  user: one(users, {
    fields: [voiceNotes.userId],
    references: [users.id],
  }),
  contact: one(contacts, {
    fields: [voiceNotes.contactId],
    references: [contacts.id],
  }),
}));

export const insertVoiceNoteSchema = createInsertSchema(voiceNotes).omit({
  id: true,
  createdAt: true,
}).extend({
  userId: z.string().uuid(),
  contactId: z.string().uuid().optional().nullable(),
  duration: z.number().optional().nullable(),
});

export type VoiceNote = typeof voiceNotes.$inferSelect;
export type InsertVoiceNote = z.infer<typeof insertVoiceNoteSchema>;

// ==================== TODOS TABLE ====================

export const todos = pgTable('todos', {
  id: uuid('id').primaryKey().defaultRandom(), // Changed to UUID
  userId: uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }), // Changed to UUID
  contactId: uuid('contact_id').references(() => contacts.id, { onDelete: 'cascade' }), // Changed to UUID
  title: text('title').notNull(),
  description: text('description'),
  completed: boolean('completed').default(false).notNull(),
  dueDate: timestamp('due_date'),
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow(),
});

export const todosRelations = relations(todos, ({ one }) => ({
  user: one(users, {
    fields: [todos.userId],
    references: [users.id],
  }),
  contact: one(contacts, {
    fields: [todos.contactId],
    references: [contacts.id],
  }),
}));

export const insertTodoSchema = createInsertSchema(todos).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
}).extend({
  userId: z.string().uuid(),
  contactId: z.string().uuid().optional().nullable(),
  dueDate: z.union([
    z.string().transform((v) => new Date(v)),
    z.date(),
    z.null(),
  ]).optional(),
});

export type Todo = typeof todos.$inferSelect;
export type InsertTodo = z.infer<typeof insertTodoSchema>;

// ==================== REMINDERS TABLE ====================

export const reminders = pgTable('reminders', {
  id: uuid('id').primaryKey().defaultRandom(), // Changed to UUID
  userId: uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }), // Changed to UUID
  contactId: uuid('contact_id').references(() => contacts.id, { onDelete: 'cascade' }), // Changed to UUID
  title: text('title').notNull(),
  description: text('description'),
  reminderDate: timestamp('reminder_date').notNull(),
  completed: boolean('completed').default(false).notNull(),
  createdAt: timestamp('created_at').defaultNow(),
});

export const remindersRelations = relations(reminders, ({ one }) => ({
  user: one(users, {
    fields: [reminders.userId],
    references: [users.id],
  }),
  contact: one(contacts, {
    fields: [reminders.contactId],
    references: [contacts.id],
  }),
}));

export const insertReminderSchema = createInsertSchema(reminders).omit({
  id: true,
  createdAt: true,
}).extend({
  userId: z.string().uuid(),
  contactId: z.string().uuid().optional().nullable(),
  reminderDate: z.union([
    z.string().transform((v) => new Date(v)),
    z.date(),
  ]),
});

export type Reminder = typeof reminders.$inferSelect;
export type InsertReminder = z.infer<typeof insertReminderSchema>;

// ==================== EVENTS TABLE ====================

export const events = pgTable('events', {
  id: uuid('id').primaryKey().defaultRandom(), // Changed to UUID
  userId: uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }), // Changed to UUID
  contactId: uuid('contact_id').references(() => contacts.id, { onDelete: 'cascade' }), // Changed to UUID
  title: text('title').notNull(),
  description: text('description'),
  eventDate: timestamp('event_date').notNull(),
  location: text('location'),
  attendees: text('attendees').array().default([]),
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow(),
});

export const eventsRelations = relations(events, ({ one }) => ({
  user: one(users, {
    fields: [events.userId],
    references: [users.id],
  }),
  contact: one(contacts, {
    fields: [events.contactId],
    references: [contacts.id],
  }),
}));

export const insertEventSchema = createInsertSchema(events).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
}).extend({
  userId: z.string().uuid(),
  contactId: z.string().uuid().optional().nullable(),
  eventDate: z.union([
    z.string().transform((v) => new Date(v)),
    z.date(),
  ]),
  attendees: z.array(z.string().email()).optional(),
});

export type Event = typeof events.$inferSelect;
export type InsertEvent = z.infer<typeof insertEventSchema>;
