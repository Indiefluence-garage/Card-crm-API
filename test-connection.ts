import { Pool } from 'pg';
import dotenv from 'dotenv';

dotenv.config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

async function testConnection() {
  try {
    const result = await pool.query('SELECT NOW()');
    console.log('✓ Connection successful!', result.rows[0]);
    process.exit(0);
  } catch (error) {
    console.error('✗ Connection failed:', error);
    process.exit(1);
  }
}

testConnection();
