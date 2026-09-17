require('dotenv').config({ override: true });

const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const {
  generateReply,
  computeTypingDelayMs
} = require('./replyEngine');
const { computeAvailableSlots, confirmBooking } = require('./booking');
const { confirmOrder } = require('./orders');
const {
  pool,
  initDatabase,
  getBusinessByWhatsAppPhoneId,
  getBusinessByInstagramAccountId
} = require('./db');

const app = express();
app.use(express.json());

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

function getHistory(key) {
  if (!conversations[key]) {
    conversations[key] = [];
  }

  return conversations[key];
}

// ---------------------------------------------------------------------
// META WEBHOOK VERIFICATION
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
// ---------------------------------------------------------------------

app.post('/webhook/meta', (req, res) => {
  // Reply to Meta immediately.
  res.sendStatus(200);

  console.log(
    '[META WEBHOOK]',
    JSON.stringify(req.body, null, 2)
  );

  // Process the message after acknowledging Meta.
  processMetaWebhook(req.body).catch((err) => {
    console.error('Error processing Meta webhook:', err);
  });
});

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

  let reply = cleanReply;

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
    } catch (err) {
      console.error('[BOOKING CONFIRMATION ERROR]', err);
      reply = messageForBookingError(err);
    }
  }

  if (order) {
    try {
      await confirmOrder(
        businessProfile,
        businessId,
        order.product,
        order.quantity,
        key
      );

      console.log(
        `[ORDER CONFIRMED] ${key}: ${order.quantity}x ${order.product}`
      );
    } catch (err) {
      console.error('[ORDER CONFIRMATION ERROR]', err);
      reply = ORDER_SAVE_FAILURE_MESSAGE;
    }
  }

  history.push({
    role: 'user',
    content: text
  });

  history.push({
    role: 'assistant',
    content: reply
  });

  if (needsHumanReview) {
    console.log(
      `[NEEDS HUMAN REVIEW] ${key}: "${text}"`
    );
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
        reply
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

async function sendMessage(platform, recipientId, text) {
  console.log(
    `[SEND ATTEMPT] platform=${platform}, to=${recipientId}`
  );

  if (platform === 'whatsapp') {
    return sendWhatsAppMessage(
      recipientId,
      text
    );
  }

  if (platform === 'instagram') {
    return sendInstagramMessage(
      recipientId,
      text
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

async function sendWhatsAppMessage(recipientId, text) {
  const phoneNumberId =
    process.env.META_WHATSAPP_PHONE_NUMBER_ID;

  const token =
    process.env.META_WHATSAPP_TEST_TOKEN;

  if (!phoneNumberId || !token) {
    throw new Error(
      'Missing META_WHATSAPP_PHONE_NUMBER_ID or META_WHATSAPP_TEST_TOKEN in .env'
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

async function sendInstagramMessage(recipientId, text) {
  const token =
    process.env.META_INSTAGRAM_TOKEN ||
    process.env.META_WHATSAPP_TEST_TOKEN;

  if (!token) {
    throw new Error(
      'Missing META_INSTAGRAM_TOKEN (or fallback META_WHATSAPP_TEST_TOKEN) in .env'
    );
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

    result.reply = cleanReply;

    if (booking) {
      try {
        await confirmBooking(
          businessProfile,
          FALLBACK_BUSINESS_ID,
          booking.date,
          booking.time,
          booking.service,
          key
        );

        console.log(
          `[BOOKING CONFIRMED] ${key}: ${booking.service} on ${booking.date} at ${booking.time}`
        );
      } catch (err) {
        console.error('[BOOKING CONFIRMATION ERROR]', err);
        result.reply = messageForBookingError(err);
      }
    }

    if (order) {
      try {
        await confirmOrder(
          businessProfile,
          FALLBACK_BUSINESS_ID,
          order.product,
          order.quantity,
          key
        );

        console.log(
          `[ORDER CONFIRMED] ${key}: ${order.quantity}x ${order.product}`
        );
      } catch (err) {
        console.error('[ORDER CONFIRMATION ERROR]', err);
        result.reply = ORDER_SAVE_FAILURE_MESSAGE;
      }
    }

    history.push({
      role: 'user',
      content: message
    });

    history.push({
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
<title>Autumn Assistant</title>
</head>
<body>
<h1>Autumn Assistant</h1>
<p>AI-powered customer messaging for businesses on WhatsApp and Instagram.</p>
<p>Contact: <a href="mailto:autumnhqapp@gmail.com">autumnhqapp@gmail.com</a></p>
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

function requireDashboardAuth(req, res, next) {
  const expectedUser = process.env.DASHBOARD_USER;
  const expectedPassword = process.env.DASHBOARD_PASSWORD;

  const sendAuthRequired = () => {
    res.set('WWW-Authenticate', 'Basic realm="Dashboard"');
    return res.sendStatus(401);
  };

  if (!expectedUser || !expectedPassword) {
    console.error(
      '[DASHBOARD AUTH] DASHBOARD_USER or DASHBOARD_PASSWORD not set'
    );
    return sendAuthRequired();
  }

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

  if (
    providedUser !== expectedUser ||
    !timingSafePasswordEqual(providedPassword, expectedPassword)
  ) {
    return sendAuthRequired();
  }

  next();
}

app.get('/dashboard', requireDashboardAuth, async (req, res) => {
  const [{ rows: bookings }, { rows: orders }] = await Promise.all([
    pool.query('SELECT * FROM bookings ORDER BY date, time'),
    pool.query('SELECT * FROM orders ORDER BY created_at DESC')
  ]);

  const bookingRows = bookings.map((booking) => `
    <tr>
      <td>${escapeHtml(booking.date)}</td>
      <td>${escapeHtml(booking.time)}</td>
      <td>${escapeHtml(booking.service)}</td>
      <td>${escapeHtml(booking.customer_id)}</td>
      <td>${escapeHtml(new Date(booking.created_at).toLocaleString())}</td>
    </tr>`).join('');

  const orderRows = orders.map((order) => `
    <tr>
      <td>${escapeHtml(order.product_name)}</td>
      <td>${escapeHtml(order.quantity)}</td>
      <td>${escapeHtml(order.price)}</td>
      <td>${escapeHtml(order.customer_id)}</td>
      <td>${escapeHtml(new Date(order.created_at).toLocaleString())}</td>
    </tr>`).join('');

  res.type('html').send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Bookings Dashboard</title>
<style>
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: #f7f7f8;
    color: #1a1a1a;
    margin: 0;
    padding: 40px;
  }
  h1 {
    font-size: 20px;
    margin: 0 0 20px;
  }
  section {
    margin-bottom: 40px;
  }
  table {
    border-collapse: collapse;
    width: 100%;
    max-width: 800px;
    background: #fff;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
  }
  th, td {
    text-align: left;
    padding: 10px 14px;
    border-bottom: 1px solid #eee;
    font-size: 14px;
  }
  th {
    background: #fafafa;
    font-weight: 600;
    color: #555;
  }
  tr:last-child td {
    border-bottom: none;
  }
  .empty {
    color: #888;
  }
</style>
</head>
<body>
<section>
<h1>Bookings</h1>
${bookings.length === 0 ? '<p class="empty">No bookings yet.</p>' : `<table>
  <thead>
    <tr><th>Date</th><th>Time</th><th>Service</th><th>Customer</th><th>Booked At</th></tr>
  </thead>
  <tbody>${bookingRows}
  </tbody>
</table>`}
</section>
<section>
<h1>Orders</h1>
${orders.length === 0 ? '<p class="empty">No orders yet.</p>' : `<table>
  <thead>
    <tr><th>Product</th><th>Quantity</th><th>Price</th><th>Customer</th><th>Ordered At</th></tr>
  </thead>
  <tbody>${orderRows}
  </tbody>
</table>`}
</section>
</body>
</html>`);
});

// ---------------------------------------------------------------------
// START SERVER
// ---------------------------------------------------------------------

const PORT = process.env.PORT || 3000;

async function start() {
  await initDatabase();

  app.listen(PORT, () => {
    console.log(
      `AI assistant server running on http://localhost:${PORT}`
    );

    console.log(
      `Try it: curl -X POST http://localhost:${PORT}/test-message ` +
      `-H "Content-Type: application/json" ` +
      `-d '{"message":"hey do you have anything free tomorrow?"}'`
    );
  });
}

start().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});