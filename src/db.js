const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS bookings (
      id SERIAL PRIMARY KEY,
      date TEXT NOT NULL,
      time TEXT NOT NULL,
      duration_minutes INTEGER NOT NULL,
      service TEXT NOT NULL,
      customer_id TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW(),
      UNIQUE (date, time)
    )
  `);

  // Migration for tables created before the UNIQUE constraint existed.
  await pool.query(`
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'bookings_date_time_key'
      ) THEN
        ALTER TABLE bookings ADD CONSTRAINT bookings_date_time_key UNIQUE (date, time);
      END IF;
    END $$;
  `);
}

module.exports = { pool, initDatabase };
