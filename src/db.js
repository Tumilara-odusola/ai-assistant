const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

// Loaded and validated once at module load time so a missing/malformed
// ENCRYPTION_KEY crashes the process immediately on boot (this throw is
// synchronous, during `require('./db')`, before Express or the DB pool
// ever get used) rather than failing silently the first time a token is
// read or written.
function loadEncryptionKey() {
  const keyBase64 = process.env.ENCRYPTION_KEY;

  if (!keyBase64) {
    throw new Error('ENCRYPTION_KEY environment variable is not set');
  }

  const key = Buffer.from(keyBase64, 'base64');

  if (key.length !== 32) {
    throw new Error(
      `ENCRYPTION_KEY must decode to exactly 32 bytes (got ${key.length}) — ` +
      'expected a base64-encoded 32-byte key, e.g. from ' +
      `node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"`
    );
  }

  return key;
}

const ENCRYPTION_KEY = loadEncryptionKey();

function encryptToken(plaintext) {
  if (plaintext === null || plaintext === undefined) {
    return null;
  }

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return Buffer.concat([iv, authTag, encrypted]).toString('base64');
}

function decryptToken(ciphertext) {
  if (ciphertext === null || ciphertext === undefined) {
    return null;
  }

  const combined = Buffer.from(ciphertext, 'base64');
  const iv = combined.subarray(0, 12);
  const authTag = combined.subarray(12, 28);
  const encrypted = combined.subarray(28);

  const decipher = crypto.createDecipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
  decipher.setAuthTag(authTag);

  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
}

// Every function that SELECTs a business row runs it through this before
// returning, so decryption happens in exactly one place and can't be
// forgotten by a future lookup function.
function decryptBusinessRow(row) {
  if (!row) {
    return row;
  }

  return {
    ...row,
    whatsapp_token: decryptToken(row.whatsapp_token),
    instagram_token: decryptToken(row.instagram_token)
  };
}

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS businesses (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      whatsapp_phone_number_id TEXT UNIQUE,
      instagram_account_id TEXT UNIQUE,
      business_profile JSONB NOT NULL,
      created_at TIMESTAMP DEFAULT NOW(),
      dashboard_token TEXT UNIQUE,
      whatsapp_token TEXT,
      instagram_token TEXT,
      twilio_phone_number TEXT UNIQUE,
      recovery_email TEXT
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
      business_id INTEGER REFERENCES businesses(id),
      UNIQUE (business_id, date, time)
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS orders (
      id SERIAL PRIMARY KEY,
      product_name TEXT NOT NULL,
      quantity INTEGER NOT NULL,
      price NUMERIC NOT NULL,
      customer_id TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW(),
      payment_status TEXT DEFAULT 'pending',
      payment_reference TEXT UNIQUE
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

  // Payment tracking columns for the Paystack integration. Added via
  // ADD COLUMN IF NOT EXISTS so this is safe to rerun against the
  // existing orders table.
  await pool.query(`
    ALTER TABLE orders
    ADD COLUMN IF NOT EXISTS payment_status TEXT DEFAULT 'pending'
  `);

  await pool.query(`
    ALTER TABLE orders
    ADD COLUMN IF NOT EXISTS payment_reference TEXT UNIQUE
  `);

  // Migration: replace the old (date, time)-only uniqueness with
  // (business_id, date, time) so two different businesses can hold the
  // same date/time slot without colliding. Safe to rerun — drops the old
  // constraint only if present, adds the new one only if missing.
  await pool.query(`
    DO $$
    BEGIN
      IF EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'bookings_date_time_key'
      ) THEN
        ALTER TABLE bookings DROP CONSTRAINT bookings_date_time_key;
      END IF;

      IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'bookings_business_id_date_time_key'
      ) THEN
        ALTER TABLE bookings
        ADD CONSTRAINT bookings_business_id_date_time_key UNIQUE (business_id, date, time);
      END IF;
    END $$;
  `);

  // dashboard_token is the bearer credential for /my-dashboard/:token. Added
  // via ADD COLUMN IF NOT EXISTS so this is safe to rerun against the
  // existing businesses table.
  await pool.query(`
    ALTER TABLE businesses
    ADD COLUMN IF NOT EXISTS dashboard_token TEXT UNIQUE
  `);

  await backfillDashboardTokens();

  // Per-business sending credentials. Added via ADD COLUMN IF NOT EXISTS so
  // this is safe to rerun against the existing businesses table. Nullable —
  // business_id=1 falls back to process.env values when these are unset,
  // but every other business must supply its own.
  await pool.query(`
    ALTER TABLE businesses
    ADD COLUMN IF NOT EXISTS whatsapp_token TEXT
  `);

  await pool.query(`
    ALTER TABLE businesses
    ADD COLUMN IF NOT EXISTS instagram_token TEXT
  `);

  // The Twilio phone number (E.164, e.g. "+15551234567") that routes voice
  // calls to this business — a real phone number, not an opaque
  // platform-assigned ID like whatsapp_phone_number_id, and a distinct
  // value even for a business that "shares" a number across channels
  // conceptually, since Twilio and Meta assign these independently.
  await pool.query(`
    ALTER TABLE businesses
    ADD COLUMN IF NOT EXISTS twilio_phone_number TEXT UNIQUE
  `);

  // Plaintext, unlike whatsapp_token/instagram_token — this needs a direct
  // SQL WHERE match for the dashboard-link recovery flow, and it isn't a
  // credential the way those tokens are.
  await pool.query(`
    ALTER TABLE businesses
    ADD COLUMN IF NOT EXISTS recovery_email TEXT
  `);
}

// Generates a dashboard_token for any business row that doesn't have one
// yet (e.g. rows created before this column existed). Each row needs its
// own unique token, so this updates one row at a time rather than a single
// bulk UPDATE. Safe to rerun — only touches rows where the token is NULL.
async function backfillDashboardTokens() {
  const { rows } = await pool.query(
    'SELECT id FROM businesses WHERE dashboard_token IS NULL'
  );

  for (const row of rows) {
    const token = crypto.randomBytes(24).toString('hex');

    await pool.query(
      'UPDATE businesses SET dashboard_token = $1 WHERE id = $2',
      [token, row.id]
    );
  }

  if (rows.length > 0) {
    console.log(
      `[BACKFILL DASHBOARD TOKENS] Generated tokens for ${rows.length} business(es)`
    );
  }
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

async function getBusinessByWhatsAppPhoneId(phoneNumberId) {
  const { rows } = await pool.query(
    'SELECT * FROM businesses WHERE whatsapp_phone_number_id = $1',
    [phoneNumberId]
  );

  return decryptBusinessRow(rows[0]) || null;
}

async function getBusinessByInstagramAccountId(accountId) {
  const { rows } = await pool.query(
    'SELECT * FROM businesses WHERE instagram_account_id = $1',
    [accountId]
  );

  return decryptBusinessRow(rows[0]) || null;
}

async function getBusinessByTwilioPhoneNumber(phoneNumber) {
  const { rows } = await pool.query(
    'SELECT * FROM businesses WHERE twilio_phone_number = $1',
    [phoneNumber]
  );

  return decryptBusinessRow(rows[0]) || null;
}

async function createBusiness({
  name,
  whatsappPhoneNumberId,
  instagramAccountId,
  businessProfile,
  whatsappToken,
  instagramToken,
  recoveryEmail
}) {
  const dashboardToken = crypto.randomBytes(24).toString('hex');

  const { rows } = await pool.query(
    `INSERT INTO businesses (name, whatsapp_phone_number_id, instagram_account_id, business_profile, dashboard_token, whatsapp_token, instagram_token, recovery_email)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
     RETURNING *`,
    [
      name,
      whatsappPhoneNumberId || null,
      instagramAccountId || null,
      JSON.stringify(businessProfile),
      dashboardToken,
      encryptToken(whatsappToken || null),
      encryptToken(instagramToken || null),
      recoveryEmail || null
    ]
  );

  return decryptBusinessRow(rows[0]);
}

async function updateBusiness(id, { name, businessProfile }) {
  const { rows } = await pool.query(
    `UPDATE businesses SET name = $1, business_profile = $2 WHERE id = $3 RETURNING *`,
    [name, JSON.stringify(businessProfile), id]
  );

  return decryptBusinessRow(rows[0]) || null;
}

async function getBusinessByDashboardToken(token) {
  const { rows } = await pool.query(
    'SELECT * FROM businesses WHERE dashboard_token = $1',
    [token]
  );

  return decryptBusinessRow(rows[0]) || null;
}

async function getBusinessById(id) {
  const { rows } = await pool.query(
    'SELECT * FROM businesses WHERE id = $1',
    [id]
  );

  return decryptBusinessRow(rows[0]) || null;
}

async function getBusinessByName(name) {
  const { rows } = await pool.query(
    'SELECT * FROM businesses WHERE LOWER(name) = LOWER($1) LIMIT 1',
    [name]
  );

  return decryptBusinessRow(rows[0]) || null;
}

module.exports = {
  pool,
  initDatabase,
  migrateInitialBusiness,
  getBusinessByWhatsAppPhoneId,
  getBusinessByInstagramAccountId,
  getBusinessByDashboardToken,
  getBusinessById,
  getBusinessByTwilioPhoneNumber,
  getBusinessByName,
  createBusiness,
  updateBusiness
};
