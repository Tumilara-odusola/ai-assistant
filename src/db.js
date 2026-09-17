const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS businesses (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      whatsapp_phone_number_id TEXT UNIQUE,
      instagram_account_id TEXT UNIQUE,
      business_profile JSONB NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

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

  await pool.query(`
    CREATE TABLE IF NOT EXISTS orders (
      id SERIAL PRIMARY KEY,
      product_name TEXT NOT NULL,
      quantity INTEGER NOT NULL,
      price NUMERIC NOT NULL,
      customer_id TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  // business_id links each row back to the business it belongs to. Added
  // via ADD COLUMN IF NOT EXISTS so this is safe to rerun against tables
  // that already existed before multi-tenancy was introduced.
  await pool.query(`
    ALTER TABLE bookings
    ADD COLUMN IF NOT EXISTS business_id INTEGER REFERENCES businesses(id)
  `);

  await pool.query(`
    ALTER TABLE orders
    ADD COLUMN IF NOT EXISTS business_id INTEGER REFERENCES businesses(id)
  `);
}

// One-time migration: seeds the current businessProfile.json as the first
// row in `businesses`, and backfills business_id on any existing
// bookings/orders rows that don't have one yet. Safe to run more than
// once — uses ON CONFLICT on whatsapp_phone_number_id to avoid inserting
// a duplicate business row, and only backfills rows where business_id IS
// NULL. Not called automatically by initDatabase(); wire this up
// explicitly (e.g. a one-time route) when ready to run it.
async function migrateInitialBusiness() {
  const businessProfile = JSON.parse(
    fs.readFileSync(path.join(__dirname, 'businessProfile.json'), 'utf8')
  );

  const whatsappPhoneNumberId = process.env.META_WHATSAPP_PHONE_NUMBER_ID || null;

  // The Instagram Business Account ID this app is actually receiving
  // webhooks for (seen repeatedly in real [META WEBHOOK] logs and already
  // hardcoded in resolveInstagramMessageEdit) — there's no env var for
  // this today, so it's inlined here rather than invented from nothing.
  const instagramAccountId = '17841434513621888';

  if (!whatsappPhoneNumberId) {
    console.error(
      '[MIGRATE INITIAL BUSINESS] META_WHATSAPP_PHONE_NUMBER_ID is not set — skipping'
    );
    return null;
  }

  const insertResult = await pool.query(
    `INSERT INTO businesses (name, whatsapp_phone_number_id, instagram_account_id, business_profile)
     VALUES ($1, $2, $3, $4)
     ON CONFLICT (whatsapp_phone_number_id) DO NOTHING
     RETURNING id`,
    [
      businessProfile.businessName,
      whatsappPhoneNumberId,
      instagramAccountId,
      JSON.stringify(businessProfile)
    ]
  );

  let businessId;

  if (insertResult.rows.length > 0) {
    businessId = insertResult.rows[0].id;
    console.log(`[MIGRATE INITIAL BUSINESS] Inserted business id=${businessId}`);
  } else {
    const existing = await pool.query(
      'SELECT id FROM businesses WHERE whatsapp_phone_number_id = $1',
      [whatsappPhoneNumberId]
    );
    businessId = existing.rows[0]?.id;
    console.log(`[MIGRATE INITIAL BUSINESS] Business already existed, id=${businessId}`);
  }

  if (!businessId) {
    throw new Error('Failed to determine business id during migration');
  }

  const bookingsResult = await pool.query(
    'UPDATE bookings SET business_id = $1 WHERE business_id IS NULL',
    [businessId]
  );

  const ordersResult = await pool.query(
    'UPDATE orders SET business_id = $1 WHERE business_id IS NULL',
    [businessId]
  );

  console.log(
    `[MIGRATE INITIAL BUSINESS] Backfilled ${bookingsResult.rowCount} bookings, ${ordersResult.rowCount} orders`
  );

  return {
    businessId,
    bookingsBackfilled: bookingsResult.rowCount,
    ordersBackfilled: ordersResult.rowCount
  };
}

module.exports = { pool, initDatabase, migrateInitialBusiness };
