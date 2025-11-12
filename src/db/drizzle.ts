import { drizzle } from 'drizzle-orm/node-postgres';
import { pool } from './client.js';

export const db = drizzle(pool);
