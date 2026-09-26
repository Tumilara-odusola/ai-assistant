// Registered before anything else can run: a single unhandled error
// anywhere in this process (any channel, any business, mid-payment or
// not) would otherwise crash the whole app silently or in an inconsistent
// state. Fail fast and loud instead, and let Railway restart cleanly.
process.on('uncaughtException', (err) => {
  console.error('[FATAL UNCAUGHT] Uncaught exception:', err);
  process.exit(1);
});

process.on('unhandledRejection', (reason) => {
  console.error('[FATAL UNCAUGHT] Unhandled promise rejection:', reason);
  process.exit(1);
});

require('dotenv').config({ override: true });

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const {
  generateReply,
  computeTypingDelayMs
} = require('./replyEngine');
const { computeAvailableSlots, confirmBooking } = require('./booking');
const { confirmOrder } = require('./orders');
const { verifyPaystackSignature } = require('./paystack');
const { sendRecoveryEmail } = require('./email');
const {
  pool,
  initDatabase,
  getBusinessByWhatsAppPhoneId,
  getBusinessByInstagramAccountId,
  getBusinessByDashboardToken,
  getBusinessById,
  getBusinessByName,
  getBusinessByEmail,
  getBusinessByFacebookPageId,
  getAllBusinesses,
  createBusiness,
  updateBusiness,
  createEscalation,
  getUnresolvedEscalations,
  resolveEscalation,
  createAdminSession,
  getAdminSessionByToken,
  deleteAdminSession,
  cleanupExpiredAdminSessions,
  createBusinessSession,
  getBusinessSessionByToken,
  deleteBusinessSession,
  cleanupExpiredBusinessSessions
} = require('./db');
const { setupVoiceWebSocket } = require('./voice');

const app = express();

// ---------------------------------------------------------------------
// PAYSTACK WEBHOOK
// Registered before the global express.json() below on purpose: this
// route needs the raw request body (as a Buffer) to verify Paystack's
// HMAC signature. Express walks middleware/routes in registration order,
// so putting this route first means it consumes the raw body and responds
// before the later express.json() layer ever sees this request — for
// every other path, execution falls through to express.json() as normal.
// ---------------------------------------------------------------------

app.post(
  '/webhook/paystack',
  express.raw({ type: 'application/json' }),
  async (req, res) => {
    const signature = req.headers['x-paystack-signature'];
    const rawBody = req.body;

    if (!verifyPaystackSignature(rawBody, signature)) {
      console.error('[PAYSTACK WEBHOOK] Invalid signature, rejecting');
      return res.sendStatus(401);
    }

    // Ack immediately once the request is verified — Paystack expects a
    // fast 200 and retries on anything else. Everything past this point
    // is best-effort and only ever logged, never reflected in the response.
    res.sendStatus(200);

    let event;

    try {
      event = JSON.parse(rawBody.toString('utf8'));
    } catch (err) {
      console.error('[PAYSTACK WEBHOOK] Failed to parse JSON body', err);
      return;
    }

    console.log('[PAYSTACK WEBHOOK]', JSON.stringify(event, null, 2));

    if (event.event !== 'charge.success') {
      console.log(`[PAYSTACK WEBHOOK] Ignoring event type: ${event.event}`);
      return;
    }

    const reference = event.data?.reference;

    if (!reference) {
      console.error('[PAYSTACK WEBHOOK] charge.success event missing data.reference');
      return;
    }

    try {
      const result = await pool.query(
        `UPDATE orders SET payment_status = 'paid' WHERE payment_reference = $1`,
        [reference]
      );

      if (result.rowCount === 0) {
        console.error(
          `[PAYSTACK WEBHOOK] No matching order found for reference=${reference}`
        );
      } else {
        console.log(
          `[PAYSTACK WEBHOOK] Order marked as paid for reference=${reference}`
        );
      }
    } catch (err) {
      console.error('[PAYSTACK WEBHOOK] Failed to update order payment status', err);
    }
  }
);

// ---------------------------------------------------------------------
// META WEBHOOK VERIFICATION
// Meta's handshake for subscribing the webhook URL — no body involved,
// just query params, so it doesn't need raw-body handling. Kept here
// alongside the POST receiver for readability.
// ---------------------------------------------------------------------

app.get('/webhook/meta', (req, res) => {
  const verifyToken = process.env.META_VERIFY_TOKEN;

  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];

  if (mode === 'subscribe' && token === verifyToken) {
    console.log('Meta webhook verified.');
    return res.status(200).send(challenge);
  }

  console.error('Meta webhook verification failed.');
  return res.sendStatus(403);
});

// ---------------------------------------------------------------------
// META WEBHOOK RECEIVER
// Registered before the global express.json() below on purpose, same as
// /webhook/paystack: this route needs the raw request body (as a Buffer)
// to verify Meta's HMAC signature (X-Hub-Signature-256) before trusting
// anything in it. Without this, anyone who knew a connected business's
// phone_number_id / instagram_account_id / facebook_page_id could POST
// fake payloads and trigger fake bookings, fake orders, or spoofed sends.
// ---------------------------------------------------------------------

function verifyMetaSignature(rawBody, signatureHeader) {
  const appSecret = process.env.META_APP_SECRET;
  if (!appSecret || !signatureHeader) return false;

  const prefix = 'sha256=';
  if (!signatureHeader.startsWith(prefix)) return false;
  const providedSignature = signatureHeader.slice(prefix.length);

  const expectedSignature = crypto
    .createHmac('sha256', appSecret)
    .update(rawBody)
    .digest('hex');

  const expectedBuffer = Buffer.from(expectedSignature, 'utf8');
  const providedBuffer = Buffer.from(providedSignature, 'utf8');

  if (expectedBuffer.length !== providedBuffer.length) return false;
  return crypto.timingSafeEqual(expectedBuffer, providedBuffer);
}

app.post(
  '/webhook/meta',
  express.raw({ type: 'application/json' }),
  (req, res) => {
    const signature = req.headers['x-hub-signature-256'];
    const rawBody = req.body;

    if (!verifyMetaSignature(rawBody, signature)) {
      console.error('[META WEBHOOK] Invalid signature, rejecting');
      return res.sendStatus(401);
    }

    // Reply to Meta immediately once the request is verified — same
    // fast-ack-then-process pattern as Paystack.
    res.sendStatus(200);

    let body;

    try {
      body = JSON.parse(rawBody.toString('utf8'));
    } catch (err) {
      console.error('[META WEBHOOK] Failed to parse JSON body', err);
      return;
    }

    console.log('[META WEBHOOK]', JSON.stringify(body, null, 2));

    // Process the message after acknowledging Meta.
    processMetaWebhook(body).catch((err) => {
      console.error('Error processing Meta webhook:', err);
    });
  }
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '..', 'public')));

// Fallback business used only where there's no real webhook payload to look
// up a business from — the /test-message endpoint and the (unimplemented)
// TikTok path. Real WhatsApp/Instagram traffic is routed per-message to the
// matching row in the `businesses` table instead of this module-level value.
const businessProfile = JSON.parse(
  fs.readFileSync(
    path.join(__dirname, 'businessProfile.json'),
    'utf8'
  )
);

const FALLBACK_BUSINESS_ID = 1;

function formatDateYYYYMMDD(date) {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

// Shared PWA <head> tags + service worker registration, included on the
// pages a user would plausibly install (landing, dashboards, settings).
// Static manifest/icons only — see service-worker.js for what it does and
// doesn't cache.
const PWA_HEAD_TAGS = `
<link rel="manifest" href="/manifest.json">
<meta name="theme-color" content="#1A2E2B">
<link rel="apple-touch-icon" href="/icons/apple-touch-icon.png">`;

const PWA_REGISTRATION_SCRIPT = `
<script>
  if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
      navigator.serviceWorker.register('/service-worker.js').catch((err) => {
        console.error('Service worker registration failed:', err);
      });
    });
  }
</script>`;

const BOOKING_CONFIRMED_REGEX =
  /\n?\[BOOKING_CONFIRMED:\s*date=([^,]+),\s*time=([^,]+),\s*service=([^\]]+)\]\s*$/;

const BOOKING_SAVE_FAILURE_MESSAGE =
  "Sorry, something went wrong confirming that — can you try again in a moment?";

const SLOT_ALREADY_BOOKED_MESSAGE =
  "sorry, that slot just got taken, want to pick another time?";

function messageForBookingError(err) {
  return err.code === 'SLOT_ALREADY_BOOKED'
    ? SLOT_ALREADY_BOOKED_MESSAGE
    : BOOKING_SAVE_FAILURE_MESSAGE;
}

function extractBookingConfirmation(replyText) {
  const match = replyText.match(BOOKING_CONFIRMED_REGEX);

  if (!match) {
    return { cleanReply: replyText, booking: null };
  }

  const [, date, time, service] = match;

  return {
    cleanReply: replyText.slice(0, match.index).trimEnd(),
    booking: {
      date: date.trim(),
      time: time.trim(),
      service: service.trim()
    }
  };
}

const ORDER_CONFIRMED_REGEX =
  /\n?\[ORDER_CONFIRMED:\s*product=([^,]+),\s*quantity=([^\]]+)\]\s*$/;

const ORDER_SAVE_FAILURE_MESSAGE =
  "Sorry, something went wrong placing that order — can you try again in a moment?";

function paymentLinkMessage(authorizationUrl) {
  return `Almost there! Complete your payment here: ${authorizationUrl}`;
}

// Explicit, non-AI-generated booking success text — used only when a
// booking marker and an order marker both appear in the same reply, so
// combining outcomes doesn't depend on the AI's own (possibly blended,
// possibly wrong-about-the-other-thing) phrasing.
function bookingSuccessMessage(booking) {
  return `Your ${booking.service} is booked for ${booking.date} at ${booking.time}.`;
}

// Attempts whichever of confirmBooking/confirmOrder apply, then builds the
// final customer-facing reply from both outcomes together — never letting
// one operation's result silently overwrite the other's.
async function resolveBookingAndOrderReply({ cleanReply, booking, order, businessProfile, businessId, key }) {
  let bookingOutcome = null;
  let orderOutcome = null;

  if (booking) {
    try {
      await confirmBooking(
        businessProfile,
        businessId,
        booking.date,
        booking.time,
        booking.service,
        key
      );

      console.log(
        `[BOOKING CONFIRMED] ${key}: ${booking.service} on ${booking.date} at ${booking.time}`
      );

      bookingOutcome = { success: true };
    } catch (err) {
      console.error('[BOOKING CONFIRMATION ERROR]', err);
      bookingOutcome = { success: false, message: messageForBookingError(err) };
    }
  }

  if (order) {
    try {
      const { authorizationUrl } = await confirmOrder(
        businessProfile,
        businessId,
        order.product,
        order.quantity,
        key
      );

      console.log(
        `[ORDER CONFIRMED] ${key}: ${order.quantity}x ${order.product}, payment link generated`
      );

      orderOutcome = { success: true, message: paymentLinkMessage(authorizationUrl) };
    } catch (err) {
      console.error('[ORDER CONFIRMATION ERROR]', err);
      orderOutcome = { success: false, message: ORDER_SAVE_FAILURE_MESSAGE };
    }
  }

  // Neither marker present — nothing to reconcile.
  if (!bookingOutcome && !orderOutcome) {
    return cleanReply;
  }

  // Only a booking marker — unchanged from prior behavior: success keeps
  // the AI's own phrasing, failure always shows the specific message.
  if (bookingOutcome && !orderOutcome) {
    return bookingOutcome.success ? cleanReply : bookingOutcome.message;
  }

  // Only an order marker — success needs the real payment link (which
  // can't come from the AI's own text), failure shows the specific message.
  if (orderOutcome && !bookingOutcome) {
    return orderOutcome.message;
  }

  // Both markers present. Build fully explicit text for both sides rather
  // than leaning on cleanReply (which may blend or misstate one side) —
  // this is the combination that was previously vulnerable to one outcome
  // silently overwriting the other.
  const bookingMessage = bookingOutcome.success
    ? bookingSuccessMessage(booking)
    : bookingOutcome.message;

  return `${bookingMessage} ${orderOutcome.message}`;
}

function extractOrderConfirmation(replyText) {
  const match = replyText.match(ORDER_CONFIRMED_REGEX);

  if (!match) {
    return { cleanReply: replyText, order: null };
  }

  const [, product, quantity] = match;

  return {
    cleanReply: replyText.slice(0, match.index).trimEnd(),
    order: {
      product: product.trim(),
      quantity: parseInt(quantity.trim(), 10)
    }
  };
}

const conversations = {};

const MAX_HISTORY_MESSAGES = 20; // 10 exchanges (1 user + 1 assistant message each)
const CONVERSATION_TTL_MS = 24 * 60 * 60 * 1000; // drop conversations idle longer than this
const CONVERSATION_CLEANUP_INTERVAL_MS = 60 * 60 * 1000; // how often to sweep for stale ones

function getHistory(key) {
  if (!conversations[key]) {
    conversations[key] = { messages: [], lastActivity: Date.now() };
  }

  return conversations[key].messages;
}

// Callers should use this instead of pushing onto the array returned by
// getHistory() directly — it's the one place that enforces the history cap
// and keeps lastActivity current for the inactivity cleanup below.
function appendToHistory(key, message) {
  if (!conversations[key]) {
    conversations[key] = { messages: [], lastActivity: Date.now() };
  }

  const conversation = conversations[key];

  conversation.messages.push(message);

  if (conversation.messages.length > MAX_HISTORY_MESSAGES) {
    conversation.messages.splice(0, conversation.messages.length - MAX_HISTORY_MESSAGES);
  }

  conversation.lastActivity = Date.now();
}

function cleanupStaleConversations() {
  const now = Date.now();
  let removedCount = 0;

  for (const key of Object.keys(conversations)) {
    if (now - conversations[key].lastActivity > CONVERSATION_TTL_MS) {
      delete conversations[key];
      removedCount++;
    }
  }

  if (removedCount > 0) {
    console.log(`[CONVERSATION CLEANUP] Removed ${removedCount} inactive conversation(s)`);
  }
}

setInterval(cleanupStaleConversations, CONVERSATION_CLEANUP_INTERVAL_MS);

const ADMIN_SESSION_CLEANUP_INTERVAL_MS = 60 * 60 * 1000; // how often to sweep for expired sessions

setInterval(() => {
  cleanupExpiredAdminSessions().catch((err) => {
    console.error('[ADMIN SESSION CLEANUP ERROR]', err);
  });
}, ADMIN_SESSION_CLEANUP_INTERVAL_MS);

setInterval(() => {
  cleanupExpiredBusinessSessions().catch((err) => {
    console.error('[BUSINESS SESSION CLEANUP ERROR]', err);
  });
}, ADMIN_SESSION_CLEANUP_INTERVAL_MS);

async function processMetaWebhook(body) {
  const entries = body.entry || [];

  // ---------------------------------------------------------------
  // WHATSAPP
  // WhatsApp payload:
  // entry[].changes[].value.messages[]
  // ---------------------------------------------------------------
  if (body.object === 'whatsapp_business_account') {
    for (const entry of entries) {
      const changes = entry.changes || [];

      for (const change of changes) {
        const value = change.value || {};
        const messages = value.messages || [];

        if (messages.length === 0) {
          continue;
        }

        const phoneNumberId = value.metadata?.phone_number_id;
        const business = phoneNumberId
          ? await getBusinessByWhatsAppPhoneId(phoneNumberId)
          : null;

        if (!business) {
          console.error(
            `[WHATSAPP] No business found for phone_number_id=${phoneNumberId}, skipping`
          );
          continue;
        }

        for (const message of messages) {
          // Ignore sent, delivered, read, and failed status events.
          if (message.type !== 'text') {
            console.log(
              `[WHATSAPP EVENT IGNORED] type=${message.type}`
            );
            continue;
          }

          const senderId = message.from;
          const text = message.text?.body;

          if (!senderId || typeof text !== 'string') {
            console.log(
              '[WHATSAPP MESSAGE IGNORED] Missing sender or text'
            );
            continue;
          }

          console.log(
            `[INCOMING whatsapp] ${senderId}: ${text}`
          );

          await handleIncomingMessage(
            'whatsapp',
            senderId,
            text,
            business.business_profile,
            business.id
          );
        }
      }
    }

    return;
  }

  // ---------------------------------------------------------------
  // FACEBOOK MESSENGER
  // Messenger payload: entry[].messaging[], routed by the Facebook
  // Page ID (entry.id) rather than a phone number or Instagram account.
  // ---------------------------------------------------------------
  if (body.object === 'page') {
    for (const entry of entries) {
      const messaging = entry.messaging || [];

      if (messaging.length === 0) {
        continue;
      }

      const pageId = entry.id;
      const business = pageId
        ? await getBusinessByFacebookPageId(pageId)
        : null;

      if (!business) {
        console.error(
          `[MESSENGER] No business found for page id=${pageId}, skipping`
        );
        continue;
      }

      for (const event of messaging) {
        const senderId = event.sender?.id;
        const text = event.message?.text;

        if (!senderId || typeof text !== 'string') {
          continue;
        }

        console.log(
          `[INCOMING messenger] ${senderId}: ${text}`
        );

        await handleIncomingMessage(
          'messenger',
          senderId,
          text,
          business.business_profile,
          business.id
        );
      }
    }

    return;
  }

  // ---------------------------------------------------------------
  // INSTAGRAM
  // Instagram can arrive in two shapes depending on how the app is
  // integrated:
  //   1. entry[].changes[].value.sender.id / value.message.text
  //      (Instagram Graph API "messages" field)
  //   2. entry[].messaging[].sender.id / message.text
  //      (legacy Messenger-platform style)
  // ---------------------------------------------------------------

  for (const entry of entries) {
    const changes = entry.changes || [];
    const messaging = entry.messaging || [];

    if (changes.length === 0 && messaging.length === 0) {
      continue;
    }

    const accountId = entry.id;
    const business = accountId
      ? await getBusinessByInstagramAccountId(accountId)
      : null;

    if (!business) {
      console.error(
        `[INSTAGRAM] No business found for account id=${accountId}, skipping`
      );
      continue;
    }

    for (const change of changes) {
      const value = change.value || {};
      const senderId = value.sender?.id;
      const text = value.message?.text;

      if (!senderId || typeof text !== 'string') {
        continue;
      }

      console.log(
        `[INCOMING instagram] ${senderId}: ${text}`
      );

      await handleIncomingMessage(
        'instagram',
        senderId,
        text,
        business.business_profile,
        business.id
      );
    }

    for (const event of messaging) {
      const senderId = event.sender?.id;
      const text = event.message?.text;

      if (senderId && typeof text === 'string') {
        console.log(
          `[INCOMING instagram] ${senderId}: ${text}`
        );

        await handleIncomingMessage(
          'instagram',
          senderId,
          text,
          business.business_profile,
          business.id
        );

        continue;
      }

      const mid = event.message_edit?.mid;

      if (mid) {
        const resolved = await resolveInstagramMessageEdit(mid, accountId);

        if (resolved) {
          console.log(
            `[INCOMING instagram] ${resolved.senderId}: ${resolved.text}`
          );

          await handleIncomingMessage(
            'instagram',
            resolved.senderId,
            resolved.text,
            business.business_profile,
            business.id
          );
        }
      }
    }
  }
}

// ---------------------------------------------------------------------
// INSTAGRAM MESSAGE_EDIT RESOLUTION
// A message_edit event only carries a `mid`, not sender/text, and the
// mid does not resolve as its own graph node. Instead, fetch the most
// recent conversation's latest message to recover sender/text.
// ---------------------------------------------------------------------

async function resolveInstagramMessageEdit(mid, accountId) {
  const token = process.env.META_INSTAGRAM_TOKEN;

  if (!token) {
    console.error(
      '[INSTAGRAM MESSAGE_EDIT] Missing META_INSTAGRAM_TOKEN, cannot resolve mid'
    );
    return null;
  }

  const url =
    `https://graph.instagram.com/v21.0/${accountId}/conversations` +
    '?fields=messages{message,from,id,created_time}&limit=1';

  let response;

  try {
    response = await fetch(url, {
      headers: {
        Authorization: `Bearer ${token}`
      }
    });
  } catch (err) {
    console.error(
      `[INSTAGRAM MESSAGE_EDIT LOOKUP ERROR] mid=${mid}`,
      err
    );
    return null;
  }

  const responseText = await response.text();

  let data;

  try {
    data = JSON.parse(responseText);
  } catch {
    data = {
      raw: responseText
    };
  }

  console.log(
    `[INSTAGRAM MESSAGE_EDIT LOOKUP] ${response.status}:`,
    JSON.stringify(data, null, 2)
  );

  if (!response.ok) {
    console.error(
      `[INSTAGRAM MESSAGE_EDIT LOOKUP FAILED] mid=${mid}`
    );
    return null;
  }

  const latestMessage = data.data?.[0]?.messages?.data?.[0];

  const senderId = latestMessage?.from?.id;
  const text = latestMessage?.message;

  if (!senderId || typeof text !== 'string') {
    console.error(
      `[INSTAGRAM MESSAGE_EDIT LOOKUP] Unexpected response shape for mid=${mid}, ` +
      'cannot extract sender id / message text. Check the logged raw response above ' +
      'and adjust the extraction to match.'
    );
    return null;
  }

  return { senderId, text };
}

// ---------------------------------------------------------------------
// TIKTOK WEBHOOK
// ---------------------------------------------------------------------

app.post('/webhook/tiktok', (req, res) => {
  res.sendStatus(200);

  processTikTokWebhook(req.body).catch((err) => {
    console.error('Error processing TikTok webhook:', err);
  });
});

async function processTikTokWebhook(body) {
  const senderId = body.sender_id;
  const text = body.message?.text;

  if (!senderId || typeof text !== 'string') {
    return;
  }

  console.log(
    `[INCOMING tiktok] ${senderId}: ${text}`
  );

  // TikTok has no per-tenant lookup wired up yet — uses the fallback
  // business, same as /test-message.
  await handleIncomingMessage(
    'tiktok',
    senderId,
    text,
    businessProfile,
    FALLBACK_BUSINESS_ID
  );
}

// ---------------------------------------------------------------------
// SHARED MESSAGE HANDLING
// ---------------------------------------------------------------------

async function handleIncomingMessage(platform, senderId, text, businessProfile, businessId) {
  const key = `${platform}:${senderId}`;
  const history = getHistory(key);

  console.log(
    `[GENERATING REPLY] ${platform}:${senderId} -> ${text}`
  );

  const today = new Date();
  const tomorrow = new Date(today);
  tomorrow.setDate(tomorrow.getDate() + 1);
  const todayDate = formatDateYYYYMMDD(today);
  const tomorrowDate = formatDateYYYYMMDD(tomorrow);

  const [todaySlots, tomorrowSlots] = await Promise.all([
    computeAvailableSlots(businessProfile, businessId, todayDate),
    computeAvailableSlots(businessProfile, businessId, tomorrowDate)
  ]);

  const availableSlots = {
    todayDate,
    tomorrowDate,
    today: todaySlots,
    tomorrow: tomorrowSlots
  };

  const result = await generateReply(
    businessProfile,
    history,
    text,
    availableSlots
  );

  const needsHumanReview = result.needsHumanReview;

  console.log(`[GENERATED REPLY] ${result.reply}`);

  const { cleanReply: replyAfterBooking, booking } = extractBookingConfirmation(result.reply);
  const { cleanReply, order } = extractOrderConfirmation(replyAfterBooking);

  const reply = await resolveBookingAndOrderReply({
    cleanReply,
    booking,
    order,
    businessProfile,
    businessId,
    key
  });

  appendToHistory(key, {
    role: 'user',
    content: text
  });

  appendToHistory(key, {
    role: 'assistant',
    content: reply
  });

  if (needsHumanReview) {
    console.log(
      `[NEEDS HUMAN REVIEW] ${key}: "${text}"`
    );

    try {
      await createEscalation({
        businessId,
        platform,
        senderId,
        messageText: text
      });
    } catch (err) {
      console.error('[ESCALATION INSERT ERROR]', err);
    }
  }

  const delay = computeTypingDelayMs(reply);

  console.log(
    `[WAITING ${delay}ms BEFORE SENDING]`
  );

  setTimeout(async () => {
    try {
      await sendMessage(
        platform,
        senderId,
        reply,
        businessId
      );
    } catch (err) {
      console.error(
        '[OUTBOUND SEND ERROR]',
        err
      );
    }
  }, delay);
}

// ---------------------------------------------------------------------
// SEND MESSAGE
// ---------------------------------------------------------------------

// Looks up business_id's own WhatsApp credentials. business_id=1 (this
// deployment's original business) falls back to process.env when its own
// columns are unset, so the original setup keeps working unchanged. Every
// other business must supply its own — no silent fallback to the shared
// env credentials, since that would send on their behalf from our account.
async function resolveWhatsAppCredentials(businessId) {
  const business = await getBusinessById(businessId);

  let phoneNumberId = business?.whatsapp_phone_number_id;
  let token = business?.whatsapp_token;

  if (businessId === FALLBACK_BUSINESS_ID) {
    phoneNumberId = phoneNumberId || process.env.META_WHATSAPP_PHONE_NUMBER_ID;
    token = token || process.env.META_WHATSAPP_TEST_TOKEN;
  }

  if (!phoneNumberId || !token) {
    throw new Error(`Missing WhatsApp credentials for business ${businessId}`);
  }

  return { phoneNumberId, token };
}

async function resolveInstagramToken(businessId) {
  const business = await getBusinessById(businessId);

  let token = business?.instagram_token;

  if (businessId === FALLBACK_BUSINESS_ID) {
    token = token || process.env.META_INSTAGRAM_TOKEN || process.env.META_WHATSAPP_TEST_TOKEN;
  }

  if (!token) {
    throw new Error(`Missing Instagram token for business ${businessId}`);
  }

  return token;
}

async function resolveMessengerToken(businessId) {
  const business = await getBusinessById(businessId);

  let token = business?.facebook_page_token;

  if (businessId === FALLBACK_BUSINESS_ID) {
    token = token || process.env.META_MESSENGER_TOKEN;
  }

  if (!token) {
    throw new Error(`Missing Messenger token for business ${businessId}`);
  }

  return token;
}

async function sendMessage(platform, recipientId, text, businessId) {
  console.log(
    `[SEND ATTEMPT] platform=${platform}, to=${recipientId}, business=${businessId}`
  );

  if (platform === 'whatsapp') {
    const { phoneNumberId, token } = await resolveWhatsAppCredentials(businessId);

    return sendWhatsAppMessage(
      recipientId,
      text,
      phoneNumberId,
      token
    );
  }

  if (platform === 'instagram') {
    const token = await resolveInstagramToken(businessId);

    return sendInstagramMessage(
      recipientId,
      text,
      token
    );
  }

  if (platform === 'messenger') {
    const token = await resolveMessengerToken(businessId);

    return sendMessengerMessage(
      recipientId,
      text,
      token
    );
  }

  if (platform === 'tiktok') {
    console.log(
      '[TIKTOK] Sending is not implemented yet.'
    );
    return;
  }

  console.log(
    `[SEND SKIPPED] Unknown platform: ${platform}`
  );
}

// ---------------------------------------------------------------------
// WHATSAPP CLOUD API SEND
// ---------------------------------------------------------------------

async function sendWhatsAppMessage(recipientId, text, phoneNumberId, token) {
  if (!phoneNumberId || !token) {
    throw new Error(
      'Missing WhatsApp phoneNumberId or token'
    );
  }

  const url =
    `https://graph.facebook.com/v20.0/${phoneNumberId}/messages`;

  const payload = {
    messaging_product: 'whatsapp',
    recipient_type: 'individual',
    to: recipientId,
    type: 'text',
    text: {
      preview_url: false,
      body: text
    }
  };

  console.log(
    '[WHATSAPP REQUEST]',
    JSON.stringify(
      {
        url,
        recipient: recipientId,
        body: text
      },
      null,
      2
    )
  );

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(payload)
  });

  const responseText = await response.text();

  let data;

  try {
    data = JSON.parse(responseText);
  } catch {
    data = {
      raw: responseText
    };
  }

  console.log(
    `[WHATSAPP API] ${response.status}:`,
    JSON.stringify(data, null, 2)
  );

  if (!response.ok) {
    throw new Error(
      `WhatsApp send failed with HTTP ${response.status}: ` +
      JSON.stringify(data)
    );
  }

  console.log(
    'WhatsApp message sent successfully:',
    data.messages?.[0]?.id || 'no message ID returned'
  );

  return data;
}

// ---------------------------------------------------------------------
// INSTAGRAM GRAPH API SEND
// ---------------------------------------------------------------------

async function sendInstagramMessage(recipientId, text, token) {
  if (!token) {
    throw new Error('Missing Instagram token');
  }

  const url = 'https://graph.instagram.com/v21.0/me/messages';

  const payload = {
    recipient: {
      id: recipientId
    },
    message: {
      text
    }
  };

  console.log(
    '[INSTAGRAM REQUEST]',
    JSON.stringify(
      {
        url,
        recipient: recipientId,
        body: text
      },
      null,
      2
    )
  );

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(payload)
  });

  const responseText = await response.text();

  let data;

  try {
    data = JSON.parse(responseText);
  } catch {
    data = {
      raw: responseText
    };
  }

  console.log(
    `[INSTAGRAM API] ${response.status}:`,
    JSON.stringify(data, null, 2)
  );

  if (!response.ok) {
    throw new Error(
      `Instagram send failed with HTTP ${response.status}: ` +
      JSON.stringify(data)
    );
  }

  console.log(
    'Instagram message sent successfully:',
    data.message_id || 'no message ID returned'
  );

  return data;
}

// ---------------------------------------------------------------------
// FACEBOOK MESSENGER SEND
// Same Send API payload shape as Instagram, but a different host
// (graph.facebook.com, not graph.instagram.com) and a Page Access Token
// rather than an Instagram-scoped one — the actual "not just a copy-paste"
// difference between these two channels.
// ---------------------------------------------------------------------

async function sendMessengerMessage(recipientId, text, token) {
  if (!token) {
    throw new Error('Missing Messenger token');
  }

  const url = 'https://graph.facebook.com/v20.0/me/messages';

  const payload = {
    recipient: {
      id: recipientId
    },
    message: {
      text
    }
  };

  console.log(
    '[MESSENGER REQUEST]',
    JSON.stringify(
      {
        url,
        recipient: recipientId,
        body: text
      },
      null,
      2
    )
  );

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(payload)
  });

  const responseText = await response.text();

  let data;

  try {
    data = JSON.parse(responseText);
  } catch {
    data = {
      raw: responseText
    };
  }

  console.log(
    `[MESSENGER API] ${response.status}:`,
    JSON.stringify(data, null, 2)
  );

  if (!response.ok) {
    throw new Error(
      `Messenger send failed with HTTP ${response.status}: ` +
      JSON.stringify(data)
    );
  }

  console.log(
    'Messenger message sent successfully:',
    data.message_id || 'no message ID returned'
  );

  return data;
}

// ---------------------------------------------------------------------
// LOCAL TEST ENDPOINT
// ---------------------------------------------------------------------

app.post('/test-message', async (req, res) => {
  const message = req.body?.message;

  if (!message || typeof message !== 'string') {
    return res.status(400).json({
      error: 'Send JSON like: { "message": "hello" }'
    });
  }

  try {
    const key = 'test:local-user';
    const history = getHistory(key);

    const today = new Date();
    const tomorrow = new Date(today);
    tomorrow.setDate(tomorrow.getDate() + 1);
    const todayDate = formatDateYYYYMMDD(today);
    const tomorrowDate = formatDateYYYYMMDD(tomorrow);

    const [todaySlots, tomorrowSlots] = await Promise.all([
      computeAvailableSlots(businessProfile, FALLBACK_BUSINESS_ID, todayDate),
      computeAvailableSlots(businessProfile, FALLBACK_BUSINESS_ID, tomorrowDate)
    ]);

    const availableSlots = {
      todayDate,
      tomorrowDate,
      today: todaySlots,
      tomorrow: tomorrowSlots
    };

    const result = await generateReply(
      businessProfile,
      history,
      message,
      availableSlots
    );

    const { cleanReply: replyAfterBooking, booking } = extractBookingConfirmation(result.reply);
    const { cleanReply, order } = extractOrderConfirmation(replyAfterBooking);

    result.reply = await resolveBookingAndOrderReply({
      cleanReply,
      booking,
      order,
      businessProfile,
      businessId: FALLBACK_BUSINESS_ID,
      key
    });

    appendToHistory(key, {
      role: 'user',
      content: message
    });

    appendToHistory(key, {
      role: 'assistant',
      content: result.reply
    });

    return res.json({
      reply: result.reply,
      needsHumanReview: result.needsHumanReview
    });
  } catch (err) {
    console.error(
      'Local test error:',
      err
    );

    return res.status(500).json({
      error: err.message
    });
  }
});

// ---------------------------------------------------------------------
// LANDING PAGE
// ---------------------------------------------------------------------

app.get('/', (req, res) => {
  res.type('html').send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Autumn Assistant</title>
${PWA_HEAD_TAGS}
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Lora:wght@600;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #F7F3EC;
    --text: #1A2E2B;
    --muted: #4A5D57;
    --accent: #D4A257;
    --alert: #8B3A3A;
  }
  * {
    box-sizing: border-box;
  }
  body {
    font-family: 'Inter', -apple-system, sans-serif;
    background: var(--bg);
    color: var(--text);
    margin: 0;
    padding: 60px 20px 80px;
  }
  .page {
    max-width: 720px;
    margin: 0 auto;
  }
  .wordmark {
    font-family: 'Lora', Georgia, serif;
    font-size: clamp(28px, 7vw, 40px);
    font-weight: 700;
    margin: 0 0 20px;
    text-align: center;
  }
  .tagline {
    font-size: clamp(16px, 3vw, 20px);
    color: var(--muted);
    text-align: center;
    line-height: 1.5;
    max-width: 560px;
    margin: 0 auto 48px;
  }
  .cta-wrap {
    text-align: center;
    margin-bottom: 64px;
  }
  .cta-button {
    display: inline-block;
    background: var(--text);
    color: var(--bg);
    text-decoration: none;
    padding: 14px 32px;
    border-radius: 4px;
    font-weight: 600;
    font-size: 16px;
  }
  .section-label {
    font-size: 12px;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: var(--muted);
    margin: 0 0 24px;
    text-align: center;
    border-top: 2px solid var(--text);
    padding-top: 24px;
  }
  .steps {
    margin-bottom: 56px;
  }
  .step {
    display: flex;
    gap: 20px;
    align-items: flex-start;
    padding: 20px 0;
    border-bottom: 1px solid rgba(26, 46, 43, 0.14);
  }
  .step:last-child {
    border-bottom: none;
  }
  .step-number {
    font-family: 'Lora', Georgia, serif;
    font-size: 28px;
    font-weight: 700;
    color: var(--accent);
    flex-shrink: 0;
    width: 40px;
  }
  .step-title {
    font-weight: 600;
    font-size: 16px;
    margin: 0 0 4px;
  }
  .step-description {
    color: var(--muted);
    font-size: 14px;
    margin: 0;
    line-height: 1.5;
  }
  .cta-wrap-bottom {
    text-align: center;
    margin-bottom: 48px;
  }
  footer {
    text-align: center;
    padding-top: 24px;
    border-top: 1px solid rgba(26, 46, 43, 0.14);
  }
  footer p {
    color: var(--muted);
    font-size: 12px;
    margin: 0;
  }
  footer a {
    color: var(--accent);
  }
  @media (min-width: 700px) {
    body {
      padding: 80px 20px 100px;
    }
  }
</style>
</head>
<body>
<div class="page">
  <h1 class="wordmark">Autumn Assistant</h1>
  <p class="tagline">The AI that doesn't just reply — it books appointments and completes sales over WhatsApp, Instagram, and Messenger, automatically.</p>

  <div class="cta-wrap">
    <a href="/onboard" class="cta-button">Get Started</a>
  </div>

  <p class="section-label">How It Works</p>
  <div class="steps">
    <div class="step">
      <div class="step-number">1</div>
      <div>
        <p class="step-title">Customer messages you</p>
        <p class="step-description">On WhatsApp, Instagram, or Messenger — like any normal DM.</p>
      </div>
    </div>
    <div class="step">
      <div class="step-number">2</div>
      <div>
        <p class="step-title">The AI handles it</p>
        <p class="step-description">Answers questions, checks real availability, and actually completes the booking or sale.</p>
      </div>
    </div>
    <div class="step">
      <div class="step-number">3</div>
      <div>
        <p class="step-title">You see it all on your dashboard</p>
        <p class="step-description">Bookings, orders, and anything that needs your attention, in one place.</p>
      </div>
    </div>
  </div>

  <div class="cta-wrap-bottom">
    <a href="/onboard" class="cta-button">Get Started</a>
  </div>

  <footer>
    <p>Contact: <a href="mailto:autumnhqapp@gmail.com">autumnhqapp@gmail.com</a></p>
  </footer>
</div>
${PWA_REGISTRATION_SCRIPT}
</body>
</html>`);
});

// ---------------------------------------------------------------------
// HEALTH CHECK
// ---------------------------------------------------------------------

app.get('/health', (req, res) => {
  res.json({
    status: 'online',
    service: 'AI assistant'
  });
});

// ---------------------------------------------------------------------
// BOOKINGS DASHBOARD
// ---------------------------------------------------------------------

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function timingSafePasswordEqual(a, b) {
  const hashA = crypto.createHash('sha256').update(a).digest();
  const hashB = crypto.createHash('sha256').update(b).digest();
  return crypto.timingSafeEqual(hashA, hashB);
}

// Shared by requireDashboardAuth (Basic Auth, for the HTML pages) and
// POST /api/auth/login (JSON, for the mobile app) — one credential check,
// two different ways of presenting it to the caller.
function verifyDashboardCredentials(providedUser, providedPassword) {
  const expectedUser = process.env.DASHBOARD_USER;
  const expectedPassword = process.env.DASHBOARD_PASSWORD;

  if (!expectedUser || !expectedPassword) {
    console.error(
      '[DASHBOARD AUTH] DASHBOARD_USER or DASHBOARD_PASSWORD not set'
    );
    return false;
  }

  if (typeof providedUser !== 'string' || typeof providedPassword !== 'string') {
    return false;
  }

  return (
    providedUser === expectedUser &&
    timingSafePasswordEqual(providedPassword, expectedPassword)
  );
}

function requireDashboardAuth(req, res, next) {
  const sendAuthRequired = () => {
    res.set('WWW-Authenticate', 'Basic realm="Dashboard"');
    return res.sendStatus(401);
  };

  const authHeader = req.headers.authorization || '';
  const [scheme, encoded] = authHeader.split(' ');

  if (scheme !== 'Basic' || !encoded) {
    return sendAuthRequired();
  }

  const decoded = Buffer.from(encoded, 'base64').toString('utf8');
  const separatorIndex = decoded.indexOf(':');

  if (separatorIndex === -1) {
    return sendAuthRequired();
  }

  const providedUser = decoded.slice(0, separatorIndex);
  const providedPassword = decoded.slice(separatorIndex + 1);

  if (!verifyDashboardCredentials(providedUser, providedPassword)) {
    return sendAuthRequired();
  }

  next();
}

async function requireApiAuth(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const [scheme, token] = authHeader.split(' ');

  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ error: 'Missing or invalid Authorization header' });
  }

  const session = await getAdminSessionByToken(token);

  if (!session) {
    return res.status(401).json({ error: 'Invalid or expired session token' });
  }

  next();
}

// Same Bearer-token shape as requireApiAuth, but backed by business_sessions
// instead of admin_sessions — the resulting req.businessId is what scopes
// every /api/my-business/* route to "my own business only". Handlers must
// read req.businessId, never req.params.id, or this scoping is pointless.
async function requireBusinessAuth(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const [scheme, token] = authHeader.split(' ');

  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ error: 'Missing or invalid Authorization header' });
  }

  const session = await getBusinessSessionByToken(token);

  if (!session) {
    return res.status(401).json({ error: 'Invalid or expired session token' });
  }

  req.businessId = session.business_id;
  next();
}

async function fetchDashboardData(businessId) {
  const [{ rows: businessRows }, { rows: bookings }, { rows: orders }] = await Promise.all([
    pool.query(
      'SELECT name, business_profile, dashboard_token FROM businesses WHERE id = $1',
      [businessId]
    ),
    pool.query(
      'SELECT * FROM bookings WHERE business_id = $1 ORDER BY date, time',
      [businessId]
    ),
    pool.query(
      'SELECT * FROM orders WHERE business_id = $1 ORDER BY created_at DESC',
      [businessId]
    )
  ]);

  const business = businessRows[0] || null;

  return {
    businessName: business?.name || `Business #${businessId} (not found)`,
    businessProfile: business?.business_profile || null,
    dashboardToken: business?.dashboard_token || null,
    bookings,
    orders
  };
}

function getServicePrice(businessProfile, serviceName) {
  const service = businessProfile?.services?.find((s) => s.name === serviceName);
  return service ? Number(service.price) : 0;
}

function formatMoney(amount, currencyCode) {
  try {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: currencyCode || 'NGN',
      currencyDisplay: 'narrowSymbol'
    }).format(amount);
  } catch {
    return `${amount}`;
  }
}

function computeTodaySummary(businessProfile, bookings, orders, todayDate) {
  const todaysBookings = bookings.filter((b) => b.date === todayDate);

  const bookingRevenue = todaysBookings.reduce(
    (sum, b) => sum + getServicePrice(businessProfile, b.service),
    0
  );

  const todaysOrders = orders.filter(
    (o) => formatDateYYYYMMDD(new Date(o.created_at)) === todayDate
  );

  const orderRevenue = todaysOrders.reduce(
    (sum, o) => sum + Number(o.price) * o.quantity,
    0
  );

  return {
    bookingsCount: todaysBookings.length,
    revenue: bookingRevenue + orderRevenue
  };
}

function buildActivityRows(businessProfile, bookings, orders) {
  const bookingRows = bookings.map((b) => ({
    type: 'booking',
    timestamp: new Date(`${b.date}T${b.time}:00`),
    title: b.service,
    customer: b.customer_id,
    amount: getServicePrice(businessProfile, b.service),
    status: null,
    dateLabel: `${b.date} · ${b.time}`
  }));

  const orderRows = orders.map((o) => ({
    type: 'order',
    timestamp: new Date(o.created_at),
    title: `${o.quantity}× ${o.product_name}`,
    customer: o.customer_id,
    amount: Number(o.price) * o.quantity,
    status: o.payment_status,
    dateLabel: new Date(o.created_at).toLocaleString()
  }));

  return [...bookingRows, ...orderRows].sort((a, b) => b.timestamp - a.timestamp);
}

async function renderBookingsOrdersPage(businessId, { requestOrigin, isAdminView } = {}) {
  const { businessName, businessProfile, dashboardToken, bookings, orders } =
    await fetchDashboardData(businessId);

  const currency = businessProfile?.currency || 'NGN';
  const todayDate = formatDateYYYYMMDD(new Date());
  const summary = computeTodaySummary(businessProfile, bookings, orders, todayDate);
  const activity = buildActivityRows(businessProfile, bookings, orders);
  const escalations = await getUnresolvedEscalations(businessId);

  const dashboardUrl = requestOrigin && dashboardToken
    ? `${requestOrigin}/my-dashboard/${dashboardToken}`
    : null;

  function resolveEscalationUrl(escalationId) {
    return isAdminView
      ? `/dashboard/resolve-escalation/${escalationId}?businessId=${businessId}`
      : `/my-dashboard/${dashboardToken}/resolve-escalation/${escalationId}`;
  }

  const escalationsHtml = escalations.length > 0 ? `
  <section class="escalations-section">
    <p class="section-label alert-label">⚠ Needs Human Attention</p>
    ${escalations.map((esc) => `
    <div class="escalation-row">
      <div class="escalation-main">
        <div class="escalation-meta">${escapeHtml(esc.platform)}:${escapeHtml(esc.sender_id)} · ${escapeHtml(new Date(esc.created_at).toLocaleString())}</div>
        <div class="escalation-message">"${escapeHtml(esc.message_text)}"</div>
      </div>
      <form method="POST" action="${escapeHtml(resolveEscalationUrl(esc.id))}">
        <button type="submit" class="resolve-button">Mark Resolved</button>
      </form>
    </div>`).join('')}
  </section>` : '';

  const activityHtml = activity.map((row) => `
    <div class="row">
      <div class="row-main">
        <div class="row-date">${escapeHtml(row.dateLabel)}</div>
        <div class="row-title">${escapeHtml(row.title)}</div>
        <div class="row-customer">${escapeHtml(row.customer)}</div>
      </div>
      <div class="row-side">
        <div class="row-amount">${formatMoney(row.amount, currency)}</div>
        ${row.status ? `<div class="status status-${escapeHtml(row.status)}">${escapeHtml(row.status)}</div>` : ''}
      </div>
    </div>`).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(businessName)} Dashboard</title>
${PWA_HEAD_TAGS}
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Lora:wght@600;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #F7F3EC;
    --text: #1A2E2B;
    --muted: #4A5D57;
    --accent: #D4A257;
    --alert: #8B3A3A;
  }
  * {
    box-sizing: border-box;
  }
  body {
    font-family: 'Inter', -apple-system, sans-serif;
    background: var(--bg);
    color: var(--text);
    margin: 0;
    padding: 32px 20px 80px;
  }
  .page {
    max-width: 640px;
    margin: 0 auto;
  }
  .eyebrow {
    font-size: 12px;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: var(--muted);
    margin: 0 0 6px;
  }
  h1 {
    font-family: 'Lora', Georgia, serif;
    font-size: clamp(22px, 5vw, 28px);
    font-weight: 700;
    margin: 0 0 28px;
  }
  .hero {
    display: flex;
    gap: 32px;
    flex-wrap: wrap;
    padding-bottom: 24px;
    margin-bottom: 24px;
    border-bottom: 2px solid var(--text);
  }
  .stat-label {
    font-size: 12px;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: var(--muted);
    margin: 0 0 4px;
  }
  .stat-value {
    font-family: 'Lora', Georgia, serif;
    font-size: clamp(28px, 8vw, 36px);
    font-weight: 700;
    line-height: 1.1;
  }
  .stat-value.revenue {
    color: var(--accent);
  }
  .section-label {
    font-size: 12px;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: var(--muted);
    margin: 0 0 8px;
  }
  .admin-nav-link {
    margin: 0 0 16px;
    font-size: 13px;
  }
  .admin-nav-link a {
    color: var(--muted);
    text-decoration: none;
  }
  .admin-nav-link a:hover {
    color: var(--accent);
  }
  .admin-link-section {
    margin-bottom: 24px;
  }
  .link-box {
    border: 1px solid rgba(26, 46, 43, 0.25);
    border-radius: 4px;
    padding: 12px;
    font-size: 13px;
    word-break: break-all;
  }
  .link-box a {
    color: var(--accent);
  }
  .row {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 16px;
    padding: 16px 0;
    border-bottom: 1px solid rgba(26, 46, 43, 0.14);
  }
  .row:first-of-type {
    padding-top: 0;
  }
  .row-date {
    font-size: 12px;
    color: var(--muted);
    margin-bottom: 2px;
  }
  .row-title {
    font-size: 16px;
    font-weight: 600;
  }
  .row-customer {
    font-size: 13px;
    color: var(--muted);
    margin-top: 2px;
  }
  .row-side {
    text-align: right;
    flex-shrink: 0;
  }
  .row-amount {
    font-family: 'Lora', Georgia, serif;
    font-size: 17px;
    font-weight: 700;
    color: var(--accent);
  }
  .status {
    display: inline-block;
    margin-top: 6px;
    padding: 2px 8px;
    border-radius: 3px;
    font-size: 10px;
    font-weight: 600;
    letter-spacing: 0.06em;
    text-transform: uppercase;
  }
  .status-paid {
    color: var(--accent);
    border: 1px solid var(--accent);
  }
  .status-pending {
    color: var(--alert);
    border: 1px solid var(--alert);
  }
  .empty {
    color: var(--muted);
    padding: 24px 0;
    font-size: 14px;
  }
  .escalations-section {
    margin-bottom: 32px;
  }
  .alert-label {
    color: var(--alert);
  }
  .escalation-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 16px;
    background: rgba(139, 58, 58, 0.08);
    border: 1px solid var(--alert);
    border-radius: 4px;
    padding: 12px 16px;
    margin-bottom: 10px;
  }
  .escalation-meta {
    font-size: 12px;
    color: var(--muted);
    margin-bottom: 4px;
  }
  .escalation-message {
    font-size: 14px;
    color: var(--text);
  }
  .resolve-button {
    background: none;
    border: 1px solid var(--alert);
    color: var(--alert);
    border-radius: 3px;
    padding: 8px 14px;
    font-family: 'Inter', sans-serif;
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
    white-space: nowrap;
    flex-shrink: 0;
  }
  @media (min-width: 700px) {
    body {
      padding: 56px 20px 100px;
    }
  }
</style>
</head>
<body>
<div class="page">
  ${isAdminView ? '<p class="admin-nav-link"><a href="/dashboard/businesses">← All Businesses</a></p>' : ''}
  <p class="eyebrow">Today</p>
  <h1>${escapeHtml(businessName)}</h1>

  ${escalationsHtml}

  ${dashboardUrl ? `<div class="admin-link-section">
    <p class="section-label">Business Dashboard Link</p>
    <div class="link-box"><a href="${escapeHtml(dashboardUrl)}">${escapeHtml(dashboardUrl)}</a></div>
  </div>` : ''}

  <div class="hero">
    <div>
      <p class="stat-label">Bookings Today</p>
      <p class="stat-value">${summary.bookingsCount}</p>
    </div>
    <div>
      <p class="stat-label">Revenue Today</p>
      <p class="stat-value revenue">${formatMoney(summary.revenue, currency)}</p>
    </div>
  </div>

  <p class="section-label">Activity</p>
  ${activity.length === 0 ? '<p class="empty">Nothing booked or ordered yet.</p>' : activityHtml}
</div>
${PWA_REGISTRATION_SCRIPT}
</body>
</html>`;
}

function renderBusinessesListPage(businesses) {
  function channelBadge(label, isConnected) {
    return `<span class="badge ${isConnected ? 'yes' : 'no'}">${escapeHtml(label)}: ${isConnected ? 'Yes' : 'No'}</span>`;
  }

  const rowsHtml = businesses.map((b) => {
    const signupDate = new Date(b.created_at).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    });

    return `
    <div class="row">
      <div class="row-main">
        <div class="row-title">${escapeHtml(b.name)}</div>
        <div class="row-date">Signed up ${escapeHtml(signupDate)}</div>
        <div class="badges">
          ${channelBadge('WhatsApp', Boolean(b.whatsapp_phone_number_id))}
          ${channelBadge('Instagram', Boolean(b.instagram_account_id))}
          ${channelBadge('Messenger', Boolean(b.facebook_page_id))}
          ${channelBadge('Voice', Boolean(b.twilio_phone_number))}
        </div>
      </div>
      <div class="row-side">
        <a class="view-link" href="/dashboard?businessId=${b.id}">View Dashboard →</a>
      </div>
    </div>`;
  }).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>All Businesses</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Lora:wght@600;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #F7F3EC;
    --text: #1A2E2B;
    --muted: #4A5D57;
    --accent: #D4A257;
    --alert: #8B3A3A;
  }
  * {
    box-sizing: border-box;
  }
  body {
    font-family: 'Inter', -apple-system, sans-serif;
    background: var(--bg);
    color: var(--text);
    margin: 0;
    padding: 32px 20px 80px;
  }
  .page {
    max-width: 720px;
    margin: 0 auto;
  }
  .eyebrow {
    font-size: 12px;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: var(--muted);
    margin: 0 0 6px;
  }
  h1 {
    font-family: 'Lora', Georgia, serif;
    font-size: clamp(22px, 5vw, 28px);
    font-weight: 700;
    margin: 0 0 28px;
    padding-bottom: 24px;
    border-bottom: 2px solid var(--text);
  }
  .row {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 16px;
    padding: 20px 0;
    border-bottom: 1px solid rgba(26, 46, 43, 0.14);
  }
  .row:first-of-type {
    padding-top: 0;
  }
  .row-title {
    font-family: 'Lora', Georgia, serif;
    font-size: 18px;
    font-weight: 700;
  }
  .row-date {
    font-size: 12px;
    color: var(--muted);
    margin: 2px 0 10px;
  }
  .badges {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
  }
  .badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 3px;
    font-size: 10px;
    font-weight: 600;
    letter-spacing: 0.04em;
  }
  .badge.yes {
    color: var(--accent);
    border: 1px solid var(--accent);
  }
  .badge.no {
    color: var(--muted);
    border: 1px solid rgba(26, 46, 43, 0.25);
  }
  .row-side {
    flex-shrink: 0;
  }
  .view-link {
    color: var(--accent);
    font-size: 13px;
    font-weight: 600;
    text-decoration: none;
    white-space: nowrap;
  }
  .view-link:hover {
    text-decoration: underline;
  }
  .empty {
    color: var(--muted);
    padding: 24px 0;
    font-size: 14px;
  }
  @media (min-width: 700px) {
    body {
      padding: 56px 20px 100px;
    }
  }
</style>
</head>
<body>
<div class="page">
  <p class="eyebrow">Admin</p>
  <h1>All Businesses</h1>
  ${businesses.length === 0 ? '<p class="empty">No businesses yet.</p>' : rowsHtml}
</div>
</body>
</html>`;
}

app.get('/dashboard', requireDashboardAuth, async (req, res) => {
  const parsedBusinessId = parseInt(req.query.businessId, 10);
  const businessId = Number.isInteger(parsedBusinessId) ? parsedBusinessId : 1;

  const requestOrigin = `${req.protocol}://${req.get('host')}`;

  res.type('html').send(await renderBookingsOrdersPage(businessId, { requestOrigin, isAdminView: true }));
});

app.get('/dashboard/businesses', requireDashboardAuth, async (req, res) => {
  const businesses = await getAllBusinesses();
  res.type('html').send(renderBusinessesListPage(businesses));
});

app.post('/dashboard/resolve-escalation/:id', requireDashboardAuth, async (req, res) => {
  const parsedBusinessId = parseInt(req.query.businessId, 10);
  const businessId = Number.isInteger(parsedBusinessId) ? parsedBusinessId : 1;
  const escalationId = parseInt(req.params.id, 10);

  await resolveEscalation(escalationId, businessId);

  res.redirect(`/dashboard?businessId=${businessId}`);
});

function renderNotFoundPage(title, message) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Lora:wght@600;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #F7F3EC;
    --text: #1A2E2B;
    --muted: #4A5D57;
  }
  body {
    font-family: 'Inter', -apple-system, sans-serif;
    background: var(--bg);
    color: var(--text);
    margin: 0;
    padding: 80px 20px;
    text-align: center;
  }
  h1 {
    font-family: 'Lora', Georgia, serif;
    font-size: 24px;
    font-weight: 700;
    margin: 0 0 12px;
  }
  p {
    color: var(--muted);
    font-size: 14px;
  }
</style>
</head>
<body>
<h1>${escapeHtml(title)}</h1>
<p>${escapeHtml(message)}</p>
</body>
</html>`;
}

app.get('/my-dashboard/:token', async (req, res) => {
  const business = await getBusinessByDashboardToken(req.params.token);

  if (!business) {
    return res.status(404).type('html').send(
      renderNotFoundPage('Dashboard not found', "This link isn't valid. Double-check the URL you were given.")
    );
  }

  res.type('html').send(await renderBookingsOrdersPage(business.id));
});

app.post('/my-dashboard/:token/resolve-escalation/:id', async (req, res) => {
  const business = await getBusinessByDashboardToken(req.params.token);

  if (!business) {
    return res.status(404).type('html').send(
      renderNotFoundPage('Dashboard not found', "This link isn't valid. Double-check the URL you were given.")
    );
  }

  const escalationId = parseInt(req.params.id, 10);

  await resolveEscalation(escalationId, business.id);

  res.redirect(`/my-dashboard/${req.params.token}`);
});

// ---------------------------------------------------------------------
// SELF-SERVICE BUSINESS SETTINGS
// ---------------------------------------------------------------------

function channelStatusHtml(label, isConnected, notConnectedGuidance) {
  return `
    <div class="channel-entry">
      <div class="channel-row">
        <span class="channel-label">${escapeHtml(label)}</span>
        <span class="channel-status ${isConnected ? 'connected' : 'disconnected'}">${isConnected ? 'Connected' : 'Not connected'}</span>
      </div>
      ${!isConnected && notConnectedGuidance ? `<p class="channel-guidance">${escapeHtml(notConnectedGuidance)}</p>` : ''}
    </div>`;
}

function renderSettingsForm({ token, business, values, errors, saved }) {
  const v = values || {};
  const errs = errors || [];

  const serviceNames = toArray(v.serviceName).length ? toArray(v.serviceName) : [''];
  const servicePrices = toArray(v.servicePrice);
  const serviceDurations = toArray(v.serviceDuration);
  const productNames = toArray(v.productName).length ? toArray(v.productName) : [''];
  const productPrices = toArray(v.productPrice);

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Settings — ${escapeHtml(business.name)}</title>
${PWA_HEAD_TAGS}
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Lora:wght@600;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #F7F3EC;
    --text: #1A2E2B;
    --muted: #4A5D57;
    --accent: #D4A257;
    --alert: #8B3A3A;
  }
  * {
    box-sizing: border-box;
  }
  body {
    font-family: 'Inter', -apple-system, sans-serif;
    background: var(--bg);
    color: var(--text);
    margin: 0;
    padding: 40px 20px 80px;
  }
  form {
    max-width: 640px;
    margin: 0 auto;
  }
  h1 {
    font-family: 'Lora', Georgia, serif;
    font-size: clamp(22px, 5vw, 28px);
    font-weight: 700;
    margin: 0 0 28px;
  }
  h2 {
    font-family: 'Lora', Georgia, serif;
    font-size: 18px;
    font-weight: 700;
    margin: 36px 0 16px;
    border-top: 2px solid var(--text);
    padding-top: 24px;
  }
  label {
    display: block;
    font-size: 12px;
    font-weight: 600;
    letter-spacing: 0.05em;
    text-transform: uppercase;
    color: var(--muted);
    margin: 18px 0 6px;
  }
  input[type="text"],
  input[type="number"] {
    width: 100%;
    padding: 8px 0;
    font-family: 'Inter', sans-serif;
    font-size: 15px;
    color: var(--text);
    background: transparent;
    border: none;
    border-bottom: 1px solid rgba(26, 46, 43, 0.25);
    border-radius: 0;
  }
  input[type="text"]:focus,
  input[type="number"]:focus {
    outline: none;
    border-bottom-color: var(--accent);
  }
  .day-row {
    display: flex;
    align-items: center;
    gap: 12px;
    margin: 10px 0;
  }
  .day-row label {
    width: 100px;
    margin: 0;
    flex-shrink: 0;
  }
  .row {
    display: flex;
    gap: 12px;
    align-items: center;
    margin-bottom: 10px;
  }
  .row input {
    flex: 1;
  }
  .remove-row {
    background: none;
    border: 1px solid rgba(26, 46, 43, 0.25);
    border-radius: 3px;
    padding: 8px 10px;
    font-size: 12px;
    color: var(--muted);
    cursor: pointer;
    white-space: nowrap;
  }
  .add-row {
    background: none;
    border: none;
    color: var(--accent);
    font-weight: 600;
    font-size: 13px;
    cursor: pointer;
    padding: 4px 0;
  }
  .errors {
    background: rgba(139, 58, 58, 0.08);
    border: 1px solid var(--alert);
    color: var(--alert);
    padding: 14px 16px;
    border-radius: 4px;
    margin-bottom: 24px;
    font-size: 13px;
  }
  .errors ul {
    margin: 4px 0 0;
    padding-left: 18px;
  }
  .saved-banner {
    background: rgba(212, 162, 87, 0.12);
    border: 1px solid var(--accent);
    color: var(--text);
    padding: 12px 16px;
    border-radius: 4px;
    margin-bottom: 24px;
    font-size: 13px;
  }
  .channel-entry {
    padding: 10px 0;
    border-bottom: 1px solid rgba(26, 46, 43, 0.14);
  }
  .channel-row {
    display: flex;
    justify-content: space-between;
    font-size: 14px;
  }
  .channel-status {
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }
  .channel-status.connected {
    color: var(--accent);
  }
  .channel-status.disconnected {
    color: var(--muted);
  }
  .channel-guidance {
    color: var(--muted);
    font-size: 12px;
    margin: 6px 0 0;
    line-height: 1.5;
  }
  button[type="submit"] {
    width: 100%;
    margin-top: 36px;
    padding: 14px;
    background: var(--text);
    color: var(--bg);
    border: none;
    border-radius: 4px;
    font-family: 'Inter', sans-serif;
    font-weight: 600;
    font-size: 15px;
    cursor: pointer;
  }
</style>
</head>
<body>
<form method="POST" action="/my-dashboard/${escapeHtml(token)}/settings">
<h1>${escapeHtml(business.name)} — Settings</h1>

${saved ? '<div class="saved-banner">Saved!</div>' : ''}
${errs.length > 0 ? `<div class="errors"><strong>Please fix the following:</strong><ul>${errs.map((e) => `<li>${escapeHtml(e)}</li>`).join('')}</ul></div>` : ''}

<h2>Connected Channels</h2>
${channelStatusHtml(
  'WhatsApp',
  Boolean(business.whatsapp_phone_number_id),
  "You'll need a WhatsApp Business number set up through Meta's Developer platform — contact us for help getting this configured."
)}
${channelStatusHtml(
  'Instagram',
  Boolean(business.instagram_account_id),
  "You'll need to connect Instagram through Meta's Developer platform, which requires business verification — contact us for help getting this configured."
)}
${channelStatusHtml(
  'Messenger',
  Boolean(business.facebook_page_id),
  "You'll need a Facebook Page connected through Meta's Developer platform — contact us for help getting this configured."
)}
${channelStatusHtml(
  'Voice',
  Boolean(business.twilio_phone_number),
  'This feature is still being rolled out.'
)}

<label for="businessName">Business name</label>
<input type="text" id="businessName" name="businessName" value="${escapeHtml(v.businessName || '')}">

<h2>Business hours</h2>
${Object.keys(DAY_FIELD_NAMES).map((day) => `
  <div class="day-row">
    <label for="${DAY_FIELD_NAMES[day]}">${DAY_LABELS[day]}</label>
    <input type="text" id="${DAY_FIELD_NAMES[day]}" name="${DAY_FIELD_NAMES[day]}" placeholder="9:00-19:00 or closed" value="${escapeHtml(v[DAY_FIELD_NAMES[day]] || '')}">
  </div>`).join('')}

<h2>Services</h2>
<div id="services-container">
${renderOfferingRows('service', serviceNames, servicePrices, serviceDurations)}
</div>
<button type="button" class="add-row" onclick="addRow('service-row-template','services-container')">+ Add another service</button>

<h2>Products</h2>
<div id="products-container">
${renderOfferingRows('product', productNames, productPrices, null)}
</div>
<button type="button" class="add-row" onclick="addRow('product-row-template','products-container')">+ Add another product</button>

<button type="submit">Save Changes</button>
</form>

<template id="service-row-template">
  <div class="row">
    <input type="text" name="serviceName[]" placeholder="Name">
    <input type="number" name="servicePrice[]" placeholder="Price" min="0" step="0.01">
    <input type="number" name="serviceDuration[]" placeholder="Duration (min)" min="1" step="1">
    <button type="button" class="remove-row" onclick="this.parentElement.remove()">Remove</button>
  </div>
</template>

<template id="product-row-template">
  <div class="row">
    <input type="text" name="productName[]" placeholder="Name">
    <input type="number" name="productPrice[]" placeholder="Price" min="0" step="0.01">
    <button type="button" class="remove-row" onclick="this.parentElement.remove()">Remove</button>
  </div>
</template>

<script>
  function addRow(templateId, containerId) {
    var template = document.getElementById(templateId);
    var container = document.getElementById(containerId);
    container.appendChild(template.content.cloneNode(true));
  }
</script>
${PWA_REGISTRATION_SCRIPT}
</body>
</html>`;
}

function businessProfileToFormValues(businessProfile) {
  const values = { businessName: businessProfile.businessName };

  for (const day of Object.keys(DAY_FIELD_NAMES)) {
    values[DAY_FIELD_NAMES[day]] = businessProfile.hours?.[day] || '';
  }

  const services = businessProfile.services || [];
  values.serviceName = services.map((s) => s.name);
  values.servicePrice = services.map((s) => s.price);
  values.serviceDuration = services.map((s) => s.durationMinutes);

  const products = businessProfile.products || [];
  values.productName = products.map((p) => p.name);
  values.productPrice = products.map((p) => p.price);

  return values;
}

app.get('/my-dashboard/:token/settings', async (req, res) => {
  const business = await getBusinessByDashboardToken(req.params.token);

  if (!business) {
    return res.status(404).type('html').send(
      renderNotFoundPage('Dashboard not found', "This link isn't valid. Double-check the URL you were given.")
    );
  }

  res.type('html').send(renderSettingsForm({
    token: req.params.token,
    business,
    values: businessProfileToFormValues(business.business_profile),
    errors: [],
    saved: req.query.saved === 'true'
  }));
});

app.post('/my-dashboard/:token/settings', async (req, res) => {
  const business = await getBusinessByDashboardToken(req.params.token);

  if (!business) {
    return res.status(404).type('html').send(
      renderNotFoundPage('Dashboard not found', "This link isn't valid. Double-check the URL you were given.")
    );
  }

  const body = req.body || {};
  const businessName = (body.businessName || '').trim();

  const hours = {};

  for (const day of Object.keys(DAY_FIELD_NAMES)) {
    const raw = (body[DAY_FIELD_NAMES[day]] || '').trim();
    hours[day] = raw || 'closed';
  }

  const { rows: services, errors: serviceErrors } = parseOfferingRows(
    toArray(body.serviceName),
    toArray(body.servicePrice),
    toArray(body.serviceDuration)
  );

  const { rows: products, errors: productErrors } = parseOfferingRows(
    toArray(body.productName),
    toArray(body.productPrice),
    null
  );

  const updatedProfile = {
    ...business.business_profile,
    businessName,
    hours,
    services,
    products
  };

  const errors = [
    ...serviceErrors,
    ...productErrors,
    ...validateNewBusinessPayload({ name: businessName, businessProfile: updatedProfile })
  ];

  if (errors.length > 0) {
    return res.status(400).type('html').send(renderSettingsForm({
      token: req.params.token,
      business,
      values: body,
      errors,
      saved: false
    }));
  }

  try {
    await updateBusiness(business.id, { name: businessName, businessProfile: updatedProfile });

    return res.redirect(`/my-dashboard/${req.params.token}/settings?saved=true`);
  } catch (err) {
    console.error('[UPDATE BUSINESS ERROR]', err);

    return res.status(500).type('html').send(renderSettingsForm({
      token: req.params.token,
      business,
      values: body,
      errors: ['Something went wrong saving your changes — please try again.'],
      saved: false
    }));
  }
});

// ---------------------------------------------------------------------
// BUSINESS ONBOARDING (ADMIN)
// ---------------------------------------------------------------------

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MIN_PASSWORD_LENGTH = 8;
const BCRYPT_COST_FACTOR = 10;

// A precomputed bcrypt hash of an arbitrary, unguessable-but-irrelevant
// string — never checked against a real password. Used only so
// POST /api/business-auth/login can run a bcrypt.compare() on every
// request, including ones where the email doesn't match any business.
// Without this, a request for a nonexistent email would return in
// microseconds (no compare needed) while a wrong-password request takes
// bcrypt's ~100ms, letting an attacker enumerate valid business emails
// purely by measuring response time.
const DUMMY_PASSWORD_HASH = '$2b$10$1gyOeYto/gDXi..FlxR6d.9U4KIRvbmDzglbRBRUSpRJmFu30nqIi';

// Shared by /onboard and POST /api/business-auth/signup — both create a
// business-owner login credential, so both need the same email/password
// rules. confirmPassword is optional: /onboard's form collects it to catch
// typos, but a JSON API caller has no reason to send a password twice.
function validateEmailAndPassword({ email, password, confirmPassword }) {
  const errors = [];

  if (!email || !EMAIL_REGEX.test(email)) {
    errors.push('A valid email is required');
  }

  if (!password || password.length < MIN_PASSWORD_LENGTH) {
    errors.push(`Password must be at least ${MIN_PASSWORD_LENGTH} characters`);
  }

  if (confirmPassword !== undefined && password !== confirmPassword) {
    errors.push('Passwords do not match');
  }

  return errors;
}

function validateNewBusinessPayload(body) {
  const errors = [];

  if (!body || typeof body !== 'object') {
    return ['Request body must be a JSON object'];
  }

  if (!body.name || typeof body.name !== 'string') {
    errors.push('name is required and must be a string');
  }

  const businessProfile = body.businessProfile;

  if (!businessProfile || typeof businessProfile !== 'object') {
    errors.push('businessProfile is required and must be an object');
    return errors;
  }

  if (!businessProfile.businessName || typeof businessProfile.businessName !== 'string') {
    errors.push('businessProfile.businessName is required and must be a string');
  }

  if (!businessProfile.hours || typeof businessProfile.hours !== 'object') {
    errors.push('businessProfile.hours is required and must be an object');
  }

  const hasServices = Array.isArray(businessProfile.services) && businessProfile.services.length > 0;
  const hasProducts = Array.isArray(businessProfile.products) && businessProfile.products.length > 0;

  if (!hasServices && !hasProducts) {
    errors.push('businessProfile must include a non-empty services array or products array');
  }

  return errors;
}

app.post('/admin/businesses', requireDashboardAuth, async (req, res) => {
  const errors = validateNewBusinessPayload(req.body);

  if (errors.length > 0) {
    return res.status(400).json({ errors });
  }

  const {
    name,
    whatsappPhoneNumberId,
    instagramAccountId,
    businessProfile,
    whatsappToken,
    instagramToken,
    recoveryEmail,
    facebookPageId,
    facebookPageToken
  } = req.body;

  try {
    const business = await createBusiness({
      name,
      whatsappPhoneNumberId,
      instagramAccountId,
      businessProfile,
      whatsappToken,
      instagramToken,
      recoveryEmail,
      facebookPageId,
      facebookPageToken
    });

    return res.status(201).json(business);
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({
        error: 'A business with that WhatsApp phone number ID or Instagram account ID already exists'
      });
    }

    console.error('[CREATE BUSINESS ERROR]', err);
    return res.status(500).json({ error: 'Failed to create business' });
  }
});

// ---------------------------------------------------------------------
// PUBLIC ONBOARDING
// ---------------------------------------------------------------------

const DAY_FIELD_NAMES = {
  mon: 'hoursMon',
  tue: 'hoursTue',
  wed: 'hoursWed',
  thu: 'hoursThu',
  fri: 'hoursFri',
  sat: 'hoursSat',
  sun: 'hoursSun'
};

const DAY_LABELS = {
  mon: 'Monday',
  tue: 'Tuesday',
  wed: 'Wednesday',
  thu: 'Thursday',
  fri: 'Friday',
  sat: 'Saturday',
  sun: 'Sunday'
};

const DEFAULT_VOICE = {
  tone: 'friendly and professional, like a helpful staff member texting back',
  useEmoji: true,
  maxReplyLength: 'short - 1-2 sentences unless the customer asks something detailed',
  avoidPhrases: [
    "I'd be happy to assist you",
    'I understand your concern',
    "Let me know if there's anything else!",
    'Thank you for reaching out',
    'As an AI'
  ],
  sampleReplies: []
};

const DEFAULT_ESCALATE_TERMS = ['refund', 'complaint', 'angry', 'lawsuit', 'manager'];

function toArray(value) {
  return [].concat(value === undefined || value === null ? [] : value);
}

// Parses repeatable row inputs (services or products) from raw form strings
// into structured rows, skipping blank rows and collecting per-row errors.
// `durations` is null for products, which have no duration field.
function parseOfferingRows(names, prices, durations) {
  const rows = [];
  const errors = [];

  for (let i = 0; i < names.length; i++) {
    const name = (names[i] || '').trim();

    if (!name) {
      continue;
    }

    const price = Number(prices[i]);

    if (!Number.isFinite(price) || price <= 0) {
      errors.push(`"${name}": price must be a positive number`);
      continue;
    }

    const row = { name, price };

    if (durations) {
      const duration = Number(durations[i]);

      if (!Number.isFinite(duration) || duration <= 0) {
        errors.push(`"${name}": duration must be a positive number of minutes`);
        continue;
      }

      row.durationMinutes = duration;
    }

    rows.push(row);
  }

  return { rows, errors };
}

function renderOfferingRows(prefix, names, prices, durations) {
  return names.map((name, i) => `
    <div class="row">
      <input type="text" name="${prefix}Name[]" placeholder="Name" value="${escapeHtml(name)}">
      <input type="number" name="${prefix}Price[]" placeholder="Price" min="0" step="0.01" value="${escapeHtml(prices[i] ?? '')}">
      ${durations ? `<input type="number" name="${prefix}Duration[]" placeholder="Duration (min)" min="1" step="1" value="${escapeHtml(durations[i] ?? '')}">` : ''}
      <button type="button" class="remove-row" onclick="this.parentElement.remove()">Remove</button>
    </div>`).join('');
}

function renderOnboardForm({ values, errors }) {
  const v = values || {};
  const errs = errors || [];

  const serviceNames = toArray(v.serviceName).length ? toArray(v.serviceName) : [''];
  const servicePrices = toArray(v.servicePrice);
  const serviceDurations = toArray(v.serviceDuration);
  const productNames = toArray(v.productName).length ? toArray(v.productName) : [''];
  const productPrices = toArray(v.productPrice);

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Onboard Your Business</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Lora:wght@600;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #F7F3EC;
    --text: #1A2E2B;
    --muted: #4A5D57;
    --accent: #D4A257;
    --alert: #8B3A3A;
  }
  * {
    box-sizing: border-box;
  }
  body {
    font-family: 'Inter', -apple-system, sans-serif;
    background: var(--bg);
    color: var(--text);
    margin: 0;
    padding: 40px 20px 80px;
  }
  form {
    max-width: 640px;
    margin: 0 auto;
  }
  h1 {
    font-family: 'Lora', Georgia, serif;
    font-size: clamp(22px, 5vw, 28px);
    font-weight: 700;
    margin: 0 0 8px;
  }
  p.intro {
    color: var(--muted);
    margin: 0 0 28px;
    font-size: 14px;
  }
  h2 {
    font-family: 'Lora', Georgia, serif;
    font-size: 18px;
    font-weight: 700;
    margin: 36px 0 16px;
    border-top: 2px solid var(--text);
    padding-top: 24px;
  }
  label {
    display: block;
    font-size: 12px;
    font-weight: 600;
    letter-spacing: 0.05em;
    text-transform: uppercase;
    color: var(--muted);
    margin: 18px 0 6px;
  }
  input[type="text"],
  input[type="number"],
  input[type="password"] {
    width: 100%;
    padding: 8px 0;
    font-family: 'Inter', sans-serif;
    font-size: 15px;
    color: var(--text);
    background: transparent;
    border: none;
    border-bottom: 1px solid rgba(26, 46, 43, 0.25);
    border-radius: 0;
  }
  input[type="text"]:focus,
  input[type="number"]:focus,
  input[type="password"]:focus {
    outline: none;
    border-bottom-color: var(--accent);
  }
  .hint {
    color: var(--muted);
    font-size: 12px;
    margin: 6px 0 0;
  }
  .day-row {
    display: flex;
    align-items: center;
    gap: 12px;
    margin: 10px 0;
  }
  .day-row label {
    width: 100px;
    margin: 0;
    flex-shrink: 0;
  }
  .row {
    display: flex;
    gap: 12px;
    align-items: center;
    margin-bottom: 10px;
  }
  .row input {
    flex: 1;
  }
  .remove-row {
    background: none;
    border: 1px solid rgba(26, 46, 43, 0.25);
    border-radius: 3px;
    padding: 8px 10px;
    font-size: 12px;
    color: var(--muted);
    cursor: pointer;
    white-space: nowrap;
  }
  .add-row {
    background: none;
    border: none;
    color: var(--accent);
    font-weight: 600;
    font-size: 13px;
    cursor: pointer;
    padding: 4px 0;
  }
  .errors {
    background: rgba(139, 58, 58, 0.08);
    border: 1px solid var(--alert);
    color: var(--alert);
    padding: 14px 16px;
    border-radius: 4px;
    margin-bottom: 24px;
    font-size: 13px;
  }
  .errors ul {
    margin: 4px 0 0;
    padding-left: 18px;
  }
  button[type="submit"] {
    width: 100%;
    margin-top: 36px;
    padding: 14px;
    background: var(--text);
    color: var(--bg);
    border: none;
    border-radius: 4px;
    font-family: 'Inter', sans-serif;
    font-weight: 600;
    font-size: 15px;
    cursor: pointer;
  }
</style>
</head>
<body>
<form method="POST" action="/onboard">
<h1>Onboard Your Business</h1>
<p class="intro">Set up your business to start taking bookings or orders over WhatsApp and Instagram.</p>

${errs.length > 0 ? `<div class="errors"><strong>Please fix the following:</strong><ul>${errs.map((e) => `<li>${escapeHtml(e)}</li>`).join('')}</ul></div>` : ''}

<label for="businessName">Business name</label>
<input type="text" id="businessName" name="businessName" value="${escapeHtml(v.businessName || '')}">

<label for="email">Email</label>
<input type="text" id="email" name="email" value="${escapeHtml(v.email || '')}">
<p class="hint">Used to log in to your dashboard.</p>

<label for="password">Password</label>
<input type="password" id="password" name="password" value="">
<p class="hint">At least 8 characters.</p>

<label for="confirmPassword">Confirm password</label>
<input type="password" id="confirmPassword" name="confirmPassword" value="">

<label for="recoveryEmail">Recovery email (optional)</label>
<input type="text" id="recoveryEmail" name="recoveryEmail" value="${escapeHtml(v.recoveryEmail || '')}">
<p class="hint">If you ever lose your dashboard link, we can help you find it again using your business name and this email. Recommended, but optional.</p>

<label for="whatsappPhoneNumberId">WhatsApp phone number ID (optional)</label>
<input type="text" id="whatsappPhoneNumberId" name="whatsappPhoneNumberId" value="${escapeHtml(v.whatsappPhoneNumberId || '')}">
<p class="hint">Found in your Meta Developer dashboard under WhatsApp → API Setup.</p>

<label for="whatsappToken">WhatsApp access token (optional)</label>
<input type="password" id="whatsappToken" name="whatsappToken" value="${escapeHtml(v.whatsappToken || '')}">
<p class="hint">Your WhatsApp Business API access token from Meta — used to send replies on your behalf. Kept confidential, never shown again after this.</p>

<label for="instagramAccountId">Instagram account ID (optional)</label>
<input type="text" id="instagramAccountId" name="instagramAccountId" value="${escapeHtml(v.instagramAccountId || '')}">
<p class="hint">Found in your Meta Developer dashboard under Instagram → Business Account.</p>

<label for="instagramToken">Instagram access token (optional)</label>
<input type="password" id="instagramToken" name="instagramToken" value="${escapeHtml(v.instagramToken || '')}">
<p class="hint">Your Instagram access token from Meta — used to send replies on your behalf. Kept confidential, never shown again after this.</p>

<label for="facebookPageId">Facebook Page ID (optional)</label>
<input type="text" id="facebookPageId" name="facebookPageId" value="${escapeHtml(v.facebookPageId || '')}">
<p class="hint">Found in your Meta Developer dashboard under Messenger → Settings, or your Page's About section.</p>

<label for="facebookPageToken">Facebook Page access token (optional)</label>
<input type="password" id="facebookPageToken" name="facebookPageToken" value="${escapeHtml(v.facebookPageToken || '')}">
<p class="hint">Your Page Access Token from Meta — used to send Messenger replies on your behalf. Kept confidential, never shown again after this.</p>

<h2>Business hours</h2>
${Object.keys(DAY_FIELD_NAMES).map((day) => `
  <div class="day-row">
    <label for="${DAY_FIELD_NAMES[day]}">${DAY_LABELS[day]}</label>
    <input type="text" id="${DAY_FIELD_NAMES[day]}" name="${DAY_FIELD_NAMES[day]}" placeholder="9:00-19:00 or closed" value="${escapeHtml(v[DAY_FIELD_NAMES[day]] || '')}">
  </div>`).join('')}

<h2>Services</h2>
<div id="services-container">
${renderOfferingRows('service', serviceNames, servicePrices, serviceDurations)}
</div>
<button type="button" class="add-row" onclick="addRow('service-row-template','services-container')">+ Add another service</button>

<h2>Products</h2>
<div id="products-container">
${renderOfferingRows('product', productNames, productPrices, null)}
</div>
<button type="button" class="add-row" onclick="addRow('product-row-template','products-container')">+ Add another product</button>

<button type="submit">Create Business</button>
</form>

<template id="service-row-template">
  <div class="row">
    <input type="text" name="serviceName[]" placeholder="Name">
    <input type="number" name="servicePrice[]" placeholder="Price" min="0" step="0.01">
    <input type="number" name="serviceDuration[]" placeholder="Duration (min)" min="1" step="1">
    <button type="button" class="remove-row" onclick="this.parentElement.remove()">Remove</button>
  </div>
</template>

<template id="product-row-template">
  <div class="row">
    <input type="text" name="productName[]" placeholder="Name">
    <input type="number" name="productPrice[]" placeholder="Price" min="0" step="0.01">
    <button type="button" class="remove-row" onclick="this.parentElement.remove()">Remove</button>
  </div>
</template>

<script>
  function addRow(templateId, containerId) {
    var template = document.getElementById(templateId);
    var container = document.getElementById(containerId);
    container.appendChild(template.content.cloneNode(true));
  }
</script>
</body>
</html>`;
}

function renderOnboardSuccess(business, dashboardUrl) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Business Created</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Lora:wght@600;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #F7F3EC;
    --text: #1A2E2B;
    --muted: #4A5D57;
    --accent: #D4A257;
  }
  * {
    box-sizing: border-box;
  }
  body {
    font-family: 'Inter', -apple-system, sans-serif;
    background: var(--bg);
    color: var(--text);
    margin: 0;
    padding: 60px 20px;
    display: flex;
    justify-content: center;
  }
  .card {
    max-width: 480px;
    text-align: center;
  }
  h1 {
    font-family: 'Lora', Georgia, serif;
    font-size: clamp(20px, 5vw, 24px);
    font-weight: 700;
    margin: 0 0 12px;
  }
  p {
    color: var(--muted);
    font-size: 14px;
    line-height: 1.5;
  }
  .id-badge {
    display: inline-block;
    font-family: 'Lora', Georgia, serif;
    color: var(--accent);
    border: 1px solid var(--accent);
    padding: 8px 20px;
    border-radius: 4px;
    font-size: 20px;
    font-weight: 700;
    margin: 16px 0;
  }
  .link-box {
    border: 1px solid rgba(26, 46, 43, 0.25);
    border-radius: 4px;
    padding: 14px;
    font-size: 13px;
    word-break: break-all;
    margin: 16px 0;
  }
  .link-box a {
    color: var(--accent);
  }
</style>
</head>
<body>
<div class="card">
  <h1>🎉 ${escapeHtml(business.name)} is set up!</h1>
  <p>Your business ID is:</p>
  <div class="id-badge">#${business.id}</div>
  <p>Once your WhatsApp/Instagram IDs are correctly connected, messages will route to this business automatically.</p>
  <p><strong>Bookmark this link</strong> — it's your personal dashboard for viewing bookings and orders, no login required:</p>
  <div class="link-box"><a href="${escapeHtml(dashboardUrl)}">${escapeHtml(dashboardUrl)}</a></div>
</div>
</body>
</html>`;
}

app.get('/onboard', (req, res) => {
  res.type('html').send(renderOnboardForm({ values: {}, errors: [] }));
});

app.post('/onboard', async (req, res) => {
  const body = req.body || {};

  const businessName = (body.businessName || '').trim();
  const email = (body.email || '').trim();
  const password = body.password || '';
  const confirmPassword = body.confirmPassword || '';
  const whatsappPhoneNumberId = (body.whatsappPhoneNumberId || '').trim();
  const instagramAccountId = (body.instagramAccountId || '').trim();
  const whatsappToken = (body.whatsappToken || '').trim();
  const instagramToken = (body.instagramToken || '').trim();
  const recoveryEmail = (body.recoveryEmail || '').trim();
  const facebookPageId = (body.facebookPageId || '').trim();
  const facebookPageToken = (body.facebookPageToken || '').trim();

  const hours = {};

  for (const day of Object.keys(DAY_FIELD_NAMES)) {
    const raw = (body[DAY_FIELD_NAMES[day]] || '').trim();
    hours[day] = raw || 'closed';
  }

  const { rows: services, errors: serviceErrors } = parseOfferingRows(
    toArray(body.serviceName),
    toArray(body.servicePrice),
    toArray(body.serviceDuration)
  );

  const { rows: products, errors: productErrors } = parseOfferingRows(
    toArray(body.productName),
    toArray(body.productPrice),
    null
  );

  const businessProfile = {
    businessName,
    currency: 'NGN',
    voice: DEFAULT_VOICE,
    hours,
    services,
    products,
    escalateIfCustomerMentions: DEFAULT_ESCALATE_TERMS
  };

  const errors = [
    ...serviceErrors,
    ...productErrors,
    ...validateNewBusinessPayload({ name: businessName, businessProfile }),
    ...validateEmailAndPassword({ email, password, confirmPassword })
  ];

  if (errors.length > 0) {
    return res.status(400).type('html').send(renderOnboardForm({ values: body, errors }));
  }

  try {
    const passwordHash = await bcrypt.hash(password, BCRYPT_COST_FACTOR);

    const business = await createBusiness({
      name: businessName,
      email,
      passwordHash,
      whatsappPhoneNumberId: whatsappPhoneNumberId || null,
      instagramAccountId: instagramAccountId || null,
      businessProfile,
      whatsappToken: whatsappToken || null,
      instagramToken: instagramToken || null,
      recoveryEmail: recoveryEmail || null,
      facebookPageId: facebookPageId || null,
      facebookPageToken: facebookPageToken || null
    });

    const dashboardUrl = `${req.protocol}://${req.get('host')}/my-dashboard/${business.dashboard_token}`;

    return res.type('html').send(renderOnboardSuccess(business, dashboardUrl));
  } catch (err) {
    if (err.code === '23505') {
      const message = err.constraint === 'businesses_email_key'
        ? 'A business with that email already exists'
        : 'A business with that WhatsApp phone number ID or Instagram account ID already exists';

      return res.status(409).type('html').send(
        renderOnboardForm({ values: body, errors: [message] })
      );
    }

    console.error('[ONBOARD ERROR]', err);
    return res.status(500).type('html').send(
      renderOnboardForm({
        values: body,
        errors: ['Something went wrong creating your business — please try again.']
      })
    );
  }
});

// ---------------------------------------------------------------------
// DASHBOARD LINK RECOVERY
// ---------------------------------------------------------------------

function renderRecoverForm({ values, result }) {
  const v = values || {};

  let resultHtml = '';

  if (result?.type === 'sent') {
    resultHtml = `<div class="result success">
      <p>If that business name and email match an account, we've sent the dashboard link to that email address.</p>
    </div>`;
  } else if (result?.type === 'no_recovery_email') {
    resultHtml = `<div class="result alert">
      <p>We found a business with that name, but no recovery email was ever set up for it. There's no automatic way to recover this link — please contact us directly for help.</p>
    </div>`;
  }

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Recover Dashboard Link</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Lora:wght@600;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #F7F3EC;
    --text: #1A2E2B;
    --muted: #4A5D57;
    --accent: #D4A257;
    --alert: #8B3A3A;
  }
  * {
    box-sizing: border-box;
  }
  body {
    font-family: 'Inter', -apple-system, sans-serif;
    background: var(--bg);
    color: var(--text);
    margin: 0;
    padding: 40px 20px 80px;
  }
  .page {
    max-width: 480px;
    margin: 0 auto;
  }
  h1 {
    font-family: 'Lora', Georgia, serif;
    font-size: clamp(20px, 5vw, 24px);
    font-weight: 700;
    margin: 0 0 12px;
  }
  p.intro {
    color: var(--muted);
    font-size: 14px;
    margin: 0 0 20px;
  }
  label {
    display: block;
    font-size: 12px;
    font-weight: 600;
    letter-spacing: 0.05em;
    text-transform: uppercase;
    color: var(--muted);
    margin: 18px 0 6px;
  }
  input[type="text"] {
    width: 100%;
    padding: 8px 0;
    font-family: 'Inter', sans-serif;
    font-size: 15px;
    color: var(--text);
    background: transparent;
    border: none;
    border-bottom: 1px solid rgba(26, 46, 43, 0.25);
  }
  input[type="text"]:focus {
    outline: none;
    border-bottom-color: var(--accent);
  }
  button[type="submit"] {
    width: 100%;
    margin-top: 32px;
    padding: 14px;
    background: var(--text);
    color: var(--bg);
    border: none;
    border-radius: 4px;
    font-family: 'Inter', sans-serif;
    font-weight: 600;
    font-size: 15px;
    cursor: pointer;
  }
  .result {
    margin-top: 28px;
    padding: 14px 16px;
    border-radius: 4px;
    font-size: 13px;
  }
  .result.success {
    background: rgba(212, 162, 87, 0.12);
    border: 1px solid var(--accent);
  }
  .result.alert {
    background: rgba(139, 58, 58, 0.08);
    border: 1px solid var(--alert);
    color: var(--alert);
  }
</style>
</head>
<body>
<div class="page">
  <h1>Recover Your Dashboard Link</h1>
  <p class="intro">Enter your business name and recovery email — if they match an account, we'll email you the dashboard link.</p>

  <form method="POST" action="/recover-dashboard-link">
    <label for="businessName">Business name</label>
    <input type="text" id="businessName" name="businessName" value="${escapeHtml(v.businessName || '')}">

    <label for="recoveryEmail">Recovery email</label>
    <input type="text" id="recoveryEmail" name="recoveryEmail" value="${escapeHtml(v.recoveryEmail || '')}">

    <button type="submit">Find My Dashboard</button>
  </form>

  ${resultHtml}
</div>
</body>
</html>`;
}

app.get('/recover-dashboard-link', (req, res) => {
  res.type('html').send(renderRecoverForm({ values: {}, result: null }));
});

app.post('/recover-dashboard-link', async (req, res) => {
  const body = req.body || {};
  const businessName = (body.businessName || '').trim();
  const recoveryEmail = (body.recoveryEmail || '').trim();

  const business = businessName ? await getBusinessByName(businessName) : null;

  let result;

  if (business && !business.recovery_email) {
    // A genuinely different, legitimate case — the business exists but was
    // never set up with a recovery email, so there's nothing to send to.
    // Worth surfacing plainly rather than folding into the generic
    // response below, which would silently fail a real business owner.
    result = { type: 'no_recovery_email' };
  } else {
    const isMatch = Boolean(
      business &&
      business.recovery_email &&
      business.recovery_email.trim().toLowerCase() === recoveryEmail.toLowerCase()
    );

    if (isMatch) {
      const dashboardUrl = `${req.protocol}://${req.get('host')}/my-dashboard/${business.dashboard_token}`;

      try {
        await sendRecoveryEmail(recoveryEmail, business.name, dashboardUrl);
      } catch (err) {
        // Never let a send failure change the response below — that would
        // leak whether businessName+recoveryEmail matched via an error
        // appearing only on real matches. Logged so we notice; currently
        // expected to fail for any recipient other than the Resend
        // account's own email, until a custom sending domain is verified.
        console.error('[RECOVERY EMAIL ERROR]', err);
      }
    }

    // Identical response whether this was a real match or not — a wrong
    // guess and a real match must look the same from the outside, or the
    // response itself becomes a way to enumerate valid name+email pairs.
    result = { type: 'sent' };
  }

  res.type('html').send(renderRecoverForm({ values: body, result }));
});

// ---------------------------------------------------------------------
// JSON REST API (foundation for a future React Native / Expo app)
// Runs alongside the HTML pages above — same data, same auth model
// (the single global admin identity), just JSON instead of rendered
// HTML. See requireApiAuth / verifyDashboardCredentials above.
//
// CORS is scoped to /api only — these routes are called by non-browser
// clients (the mobile app) and, going forward, browser-based ones (the
// Expo web build, or any other web client), authenticated by a bearer
// token rather than a browser session/cookie, so allowing any origin
// doesn't expose anything a valid token wouldn't already grant. The
// dashboard HTML routes stay un-CORS'd — those rely on Basic Auth, which
// browsers handle very differently, and were never meant to be called
// cross-origin.
// ---------------------------------------------------------------------

app.use('/api', cors());

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body || {};

  if (!verifyDashboardCredentials(username, password)) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  const { token, expiresAt } = await createAdminSession();
  res.status(200).json({ token, expiresAt });
});

app.post('/api/auth/logout', requireApiAuth, async (req, res) => {
  const [, token] = req.headers.authorization.split(' ');
  await deleteAdminSession(token);
  res.sendStatus(204);
});

// Shared by the admin GET /api/businesses/:id/dashboard and the
// business-scoped GET /api/my-business/dashboard — same data, only the
// source of businessId differs between the two routes. Returns null if
// the business doesn't exist.
async function buildDashboardJson(businessId) {
  const { businessName, businessProfile, bookings, orders } =
    await fetchDashboardData(businessId);

  if (!businessProfile) {
    return null;
  }

  const currency = businessProfile?.currency || 'NGN';
  const todayDate = formatDateYYYYMMDD(new Date());
  const summary = computeTodaySummary(businessProfile, bookings, orders, todayDate);
  const activity = buildActivityRows(businessProfile, bookings, orders);
  const escalations = await getUnresolvedEscalations(businessId);

  return {
    businessId,
    businessName,
    today: {
      bookingsCount: summary.bookingsCount,
      revenue: summary.revenue,
      currency
    },
    activity: activity.map((row) => ({
      type: row.type,
      title: row.title,
      customer: row.customer,
      amount: row.amount,
      status: row.status,
      timestamp: row.timestamp
    })),
    escalations: escalations.map((esc) => ({
      id: esc.id,
      platform: esc.platform,
      senderId: esc.sender_id,
      messageText: esc.message_text,
      createdAt: esc.created_at
    }))
  };
}

app.get('/api/businesses/:id/dashboard', requireApiAuth, async (req, res) => {
  const businessId = parseInt(req.params.id, 10);

  if (!Number.isInteger(businessId)) {
    return res.status(400).json({ error: 'businessId must be an integer' });
  }

  const dashboard = await buildDashboardJson(businessId);

  if (!dashboard) {
    return res.status(404).json({ error: 'Business not found' });
  }

  res.status(200).json(dashboard);
});

function businessToSettingsJson(business) {
  const profile = business.business_profile || {};

  return {
    id: business.id,
    name: business.name,
    businessName: profile.businessName || business.name,
    hours: profile.hours || {},
    services: profile.services || [],
    products: profile.products || [],
    currency: profile.currency || 'NGN',
    channels: {
      whatsapp: Boolean(business.whatsapp_phone_number_id),
      instagram: Boolean(business.instagram_account_id),
      messenger: Boolean(business.facebook_page_id),
      voice: Boolean(business.twilio_phone_number)
    }
  };
}

app.get('/api/businesses/:id/settings', requireApiAuth, async (req, res) => {
  const businessId = parseInt(req.params.id, 10);

  if (!Number.isInteger(businessId)) {
    return res.status(400).json({ error: 'businessId must be an integer' });
  }

  const business = await getBusinessById(businessId);

  if (!business) {
    return res.status(404).json({ error: 'Business not found' });
  }

  res.status(200).json(businessToSettingsJson(business));
});

// Validates a JSON-shaped offering row array (services or products) using
// the same rules parseOfferingRows enforces for the HTML form — just
// operating on real JSON types instead of parallel form-string arrays.
function validateOfferingRowsJson(rows, label, { requireDuration }) {
  const errors = [];
  const normalizedRows = [];

  if (!Array.isArray(rows)) {
    return { rows: [], errors: [`${label} must be an array`] };
  }

  for (const row of rows) {
    const name = typeof row?.name === 'string' ? row.name.trim() : '';

    if (!name) {
      errors.push(`${label}: each row needs a non-empty name`);
      continue;
    }

    const price = Number(row.price);

    if (!Number.isFinite(price) || price <= 0) {
      errors.push(`"${name}": price must be a positive number`);
      continue;
    }

    const normalizedRow = { name, price };

    if (requireDuration) {
      const duration = Number(row.durationMinutes);

      if (!Number.isFinite(duration) || duration <= 0) {
        errors.push(`"${name}": durationMinutes must be a positive number`);
        continue;
      }

      normalizedRow.durationMinutes = duration;
    }

    // Optional free text — buildSystemPrompt interpolates products[].description
    // directly into the LLM's system prompt (replyEngine.js), so it has to
    // survive a round-trip through this endpoint, not just get dropped.
    if (typeof row.description === 'string' && row.description.trim()) {
      normalizedRow.description = row.description.trim();
    }

    normalizedRows.push(normalizedRow);
  }

  return { rows: normalizedRows, errors };
}

// Shared by the admin PUT /api/businesses/:id/settings and the
// business-scoped PUT /api/my-business/settings — identical validation and
// update logic; only how `business` was looked up differs between callers.
// Returns { errors } on validation failure, { settings } on success. Lets
// the update itself (a real DB write) throw, so each route's own
// try/catch decides how to log and respond to a failure.
async function applySettingsUpdate(business, body) {
  const businessName = typeof body.businessName === 'string' ? body.businessName.trim() : '';
  const hours = body.hours && typeof body.hours === 'object' ? body.hours : {};

  const { rows: services, errors: serviceErrors } =
    validateOfferingRowsJson(body.services ?? [], 'services', { requireDuration: true });
  const { rows: products, errors: productErrors } =
    validateOfferingRowsJson(body.products ?? [], 'products', { requireDuration: false });

  const updatedProfile = {
    ...business.business_profile,
    businessName,
    hours,
    services,
    products
  };

  const errors = [
    ...serviceErrors,
    ...productErrors,
    ...validateNewBusinessPayload({ name: businessName, businessProfile: updatedProfile })
  ];

  if (errors.length > 0) {
    return { errors };
  }

  await updateBusiness(business.id, { name: businessName, businessProfile: updatedProfile });
  const updatedBusiness = await getBusinessById(business.id);
  return { settings: businessToSettingsJson(updatedBusiness) };
}

app.put('/api/businesses/:id/settings', requireApiAuth, async (req, res) => {
  const businessId = parseInt(req.params.id, 10);

  if (!Number.isInteger(businessId)) {
    return res.status(400).json({ error: 'businessId must be an integer' });
  }

  const business = await getBusinessById(businessId);

  if (!business) {
    return res.status(404).json({ error: 'Business not found' });
  }

  try {
    const result = await applySettingsUpdate(business, req.body || {});

    if (result.errors) {
      return res.status(400).json({ errors: result.errors });
    }

    res.status(200).json(result.settings);
  } catch (err) {
    console.error('[API UPDATE SETTINGS ERROR]', err);
    res.status(500).json({ error: 'Failed to save settings' });
  }
});

// ---------------------------------------------------------------------
// BUSINESS OWNER AUTH (email + password) — additive alongside the
// existing dashboard_token / my-dashboard link flow, which keeps working
// unchanged. This is a second, parallel login path for the JSON API
// (mobile app, etc.), not a replacement of the token-based one.
// ---------------------------------------------------------------------

app.post('/api/business-auth/signup', async (req, res) => {
  const body = req.body || {};
  const name = typeof body.name === 'string' ? body.name.trim() : '';
  const email = typeof body.email === 'string' ? body.email.trim() : '';
  const password = typeof body.password === 'string' ? body.password : '';
  const profileInput = body.businessProfile || {};

  const hours = profileInput.hours && typeof profileInput.hours === 'object' ? profileInput.hours : {};

  const { rows: services, errors: serviceErrors } =
    validateOfferingRowsJson(profileInput.services ?? [], 'services', { requireDuration: true });
  const { rows: products, errors: productErrors } =
    validateOfferingRowsJson(profileInput.products ?? [], 'products', { requireDuration: false });

  const businessProfile = {
    businessName: typeof profileInput.businessName === 'string' ? profileInput.businessName.trim() : name,
    currency: 'NGN',
    voice: DEFAULT_VOICE,
    hours,
    services,
    products,
    escalateIfCustomerMentions: DEFAULT_ESCALATE_TERMS
  };

  const errors = [
    ...serviceErrors,
    ...productErrors,
    ...validateNewBusinessPayload({ name, businessProfile }),
    ...validateEmailAndPassword({ email, password })
  ];

  if (errors.length > 0) {
    return res.status(400).json({ errors });
  }

  try {
    const passwordHash = await bcrypt.hash(password, BCRYPT_COST_FACTOR);
    const business = await createBusiness({ name, email, passwordHash, businessProfile });
    const { token, expiresAt } = await createBusinessSession(business.id);

    res.status(201).json({ token, expiresAt, businessId: business.id });
  } catch (err) {
    if (err.code === '23505') {
      const message = err.constraint === 'businesses_email_key'
        ? 'A business with that email already exists'
        : 'A business with that WhatsApp phone number ID or Instagram account ID already exists';

      return res.status(409).json({ error: message });
    }

    console.error('[BUSINESS SIGNUP ERROR]', err);
    res.status(500).json({ error: 'Failed to create business' });
  }
});

app.post('/api/business-auth/login', async (req, res) => {
  const { email, password } = req.body || {};

  if (!email || !password) {
    return res.status(400).json({ error: 'email and password are required' });
  }

  const business = await getBusinessByEmail(email);

  // Always run bcrypt.compare, even when no business/password_hash was
  // found — comparing against DUMMY_PASSWORD_HASH keeps this request's
  // timing indistinguishable from a real wrong-password attempt, so a
  // nonexistent email can't be detected by response time. See
  // DUMMY_PASSWORD_HASH's own comment for why this matters.
  const passwordMatches = await bcrypt.compare(password, business?.password_hash || DUMMY_PASSWORD_HASH);

  if (!business || !business.password_hash || !passwordMatches) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  const { token, expiresAt } = await createBusinessSession(business.id);
  res.status(200).json({ token, expiresAt, businessId: business.id });
});

app.post('/api/business-auth/logout', requireBusinessAuth, async (req, res) => {
  const [, token] = req.headers.authorization.split(' ');
  await deleteBusinessSession(token);
  res.sendStatus(204);
});

// ---------------------------------------------------------------------
// "MY BUSINESS" API — scoped to the caller's own business via
// requireBusinessAuth's req.businessId, never a URL param. Same data/
// validation as the admin /api/businesses/:id/* routes above, just
// reachable without knowing (or being able to guess) a business ID.
// ---------------------------------------------------------------------

app.get('/api/my-business/dashboard', requireBusinessAuth, async (req, res) => {
  const dashboard = await buildDashboardJson(req.businessId);

  if (!dashboard) {
    return res.status(404).json({ error: 'Business not found' });
  }

  res.status(200).json(dashboard);
});

app.get('/api/my-business/settings', requireBusinessAuth, async (req, res) => {
  const business = await getBusinessById(req.businessId);

  if (!business) {
    return res.status(404).json({ error: 'Business not found' });
  }

  res.status(200).json(businessToSettingsJson(business));
});

app.put('/api/my-business/settings', requireBusinessAuth, async (req, res) => {
  const business = await getBusinessById(req.businessId);

  if (!business) {
    return res.status(404).json({ error: 'Business not found' });
  }

  try {
    const result = await applySettingsUpdate(business, req.body || {});

    if (result.errors) {
      return res.status(400).json({ errors: result.errors });
    }

    res.status(200).json(result.settings);
  } catch (err) {
    console.error('[MY BUSINESS UPDATE SETTINGS ERROR]', err);
    res.status(500).json({ error: 'Failed to save settings' });
  }
});

// ---------------------------------------------------------------------
// START SERVER
// ---------------------------------------------------------------------

const PORT = process.env.PORT || 3000;

async function start() {
  await initDatabase();

  const server = app.listen(PORT, () => {
    console.log(
      `AI assistant server running on http://localhost:${PORT}`
    );

    console.log(
      `Try it: curl -X POST http://localhost:${PORT}/test-message ` +
      `-H "Content-Type: application/json" ` +
      `-d '{"message":"hey do you have anything free tomorrow?"}'`
    );
  });

  setupVoiceWebSocket(server);
}

start().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});