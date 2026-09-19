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
const { verifyPaystackSignature } = require('./paystack');
const {
  pool,
  initDatabase,
  getBusinessByWhatsAppPhoneId,
  getBusinessByInstagramAccountId,
  getBusinessByDashboardToken,
  createBusiness
} = require('./db');

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

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

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

function paymentLinkMessage(authorizationUrl) {
  return `Almost there! Complete your payment here: ${authorizationUrl}`;
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

      reply = paymentLinkMessage(authorizationUrl);
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
        const { authorizationUrl } = await confirmOrder(
          businessProfile,
          FALLBACK_BUSINESS_ID,
          order.product,
          order.quantity,
          key
        );

        console.log(
          `[ORDER CONFIRMED] ${key}: ${order.quantity}x ${order.product}, payment link generated`
        );

        result.reply = paymentLinkMessage(authorizationUrl);
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

async function renderBookingsOrdersPage(businessId) {
  const [{ rows: businessRows }, { rows: bookings }, { rows: orders }] = await Promise.all([
    pool.query('SELECT name FROM businesses WHERE id = $1', [businessId]),
    pool.query(
      'SELECT * FROM bookings WHERE business_id = $1 ORDER BY date, time',
      [businessId]
    ),
    pool.query(
      'SELECT * FROM orders WHERE business_id = $1 ORDER BY created_at DESC',
      [businessId]
    )
  ]);

  const businessName = businessRows[0]?.name || `Business #${businessId} (not found)`;

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

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>${escapeHtml(businessName)} Dashboard</title>
<style>
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: #f7f7f8;
    color: #1a1a1a;
    margin: 0;
    padding: 40px;
  }
  h1 {
    font-size: 22px;
    margin: 0 0 24px;
  }
  h2 {
    font-size: 18px;
    margin: 0 0 16px;
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
<h1>${escapeHtml(businessName)}</h1>
<section>
<h2>Bookings</h2>
${bookings.length === 0 ? '<p class="empty">No bookings yet.</p>' : `<table>
  <thead>
    <tr><th>Date</th><th>Time</th><th>Service</th><th>Customer</th><th>Booked At</th></tr>
  </thead>
  <tbody>${bookingRows}
  </tbody>
</table>`}
</section>
<section>
<h2>Orders</h2>
${orders.length === 0 ? '<p class="empty">No orders yet.</p>' : `<table>
  <thead>
    <tr><th>Product</th><th>Quantity</th><th>Price</th><th>Customer</th><th>Ordered At</th></tr>
  </thead>
  <tbody>${orderRows}
  </tbody>
</table>`}
</section>
</body>
</html>`;
}

app.get('/dashboard', requireDashboardAuth, async (req, res) => {
  const parsedBusinessId = parseInt(req.query.businessId, 10);
  const businessId = Number.isInteger(parsedBusinessId) ? parsedBusinessId : 1;

  res.type('html').send(await renderBookingsOrdersPage(businessId));
});

app.get('/my-dashboard/:token', async (req, res) => {
  const business = await getBusinessByDashboardToken(req.params.token);

  if (!business) {
    return res.status(404).type('html').send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Dashboard Not Found</title>
<style>
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: #f7f7f8;
    color: #1a1a1a;
    margin: 0;
    padding: 60px 20px;
    text-align: center;
  }
</style>
</head>
<body>
<h1>Dashboard not found</h1>
<p>This link isn't valid. Double-check the URL you were given.</p>
</body>
</html>`);
  }

  res.type('html').send(await renderBookingsOrdersPage(business.id));
});

// ---------------------------------------------------------------------
// BUSINESS ONBOARDING (ADMIN)
// ---------------------------------------------------------------------

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

  const { name, whatsappPhoneNumberId, instagramAccountId, businessProfile } = req.body;

  try {
    const business = await createBusiness({
      name,
      whatsappPhoneNumberId,
      instagramAccountId,
      businessProfile
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
<title>Onboard Your Business</title>
<style>
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: #f7f7f8;
    color: #1a1a1a;
    margin: 0;
    padding: 40px 20px;
  }
  form {
    max-width: 640px;
    margin: 0 auto;
    background: #fff;
    padding: 32px;
    border-radius: 8px;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
  }
  h1 {
    font-size: 22px;
    margin: 0 0 8px;
  }
  p.intro {
    color: #555;
    margin: 0 0 28px;
    font-size: 14px;
  }
  h2 {
    font-size: 16px;
    margin: 32px 0 12px;
    border-top: 1px solid #eee;
    padding-top: 24px;
  }
  label {
    display: block;
    font-size: 13px;
    font-weight: 600;
    margin: 16px 0 4px;
  }
  input[type="text"],
  input[type="number"] {
    width: 100%;
    padding: 8px 10px;
    font-size: 14px;
    border: 1px solid #ddd;
    border-radius: 4px;
    box-sizing: border-box;
  }
  .hint {
    color: #888;
    font-size: 12px;
    margin: 4px 0 0;
  }
  .day-row {
    display: flex;
    align-items: center;
    gap: 12px;
    margin: 8px 0;
  }
  .day-row label {
    width: 100px;
    margin: 0;
    flex-shrink: 0;
  }
  .row {
    display: flex;
    gap: 8px;
    align-items: center;
    margin-bottom: 8px;
  }
  .row input {
    flex: 1;
  }
  .remove-row {
    background: none;
    border: 1px solid #ddd;
    border-radius: 4px;
    padding: 8px 10px;
    font-size: 12px;
    color: #888;
    cursor: pointer;
    white-space: nowrap;
  }
  .add-row {
    background: none;
    border: none;
    color: #2563eb;
    font-size: 13px;
    cursor: pointer;
    padding: 4px 0;
  }
  .errors {
    background: #fef2f2;
    border: 1px solid #fecaca;
    color: #991b1b;
    padding: 12px 16px;
    border-radius: 4px;
    margin-bottom: 20px;
    font-size: 13px;
  }
  .errors ul {
    margin: 4px 0 0;
    padding-left: 18px;
  }
  button[type="submit"] {
    width: 100%;
    margin-top: 32px;
    padding: 12px;
    background: #1a1a1a;
    color: #fff;
    border: none;
    border-radius: 4px;
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

<label for="whatsappPhoneNumberId">WhatsApp phone number ID (optional)</label>
<input type="text" id="whatsappPhoneNumberId" name="whatsappPhoneNumberId" value="${escapeHtml(v.whatsappPhoneNumberId || '')}">
<p class="hint">Found in your Meta Developer dashboard under WhatsApp → API Setup.</p>

<label for="instagramAccountId">Instagram account ID (optional)</label>
<input type="text" id="instagramAccountId" name="instagramAccountId" value="${escapeHtml(v.instagramAccountId || '')}">
<p class="hint">Found in your Meta Developer dashboard under Instagram → Business Account.</p>

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
<title>Business Created</title>
<style>
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: #f7f7f8;
    color: #1a1a1a;
    margin: 0;
    padding: 40px 20px;
    display: flex;
    justify-content: center;
  }
  .card {
    max-width: 480px;
    background: #fff;
    padding: 32px;
    border-radius: 8px;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
    text-align: center;
  }
  h1 {
    font-size: 20px;
    margin: 0 0 12px;
  }
  p {
    color: #555;
    font-size: 14px;
    line-height: 1.5;
  }
  .id-badge {
    display: inline-block;
    background: #f0fdf4;
    color: #166534;
    border: 1px solid #bbf7d0;
    padding: 8px 16px;
    border-radius: 4px;
    font-size: 18px;
    font-weight: 600;
    margin: 12px 0;
  }
  .link-box {
    background: #f7f7f8;
    border: 1px solid #ddd;
    border-radius: 4px;
    padding: 12px;
    font-size: 13px;
    word-break: break-all;
    margin: 16px 0;
  }
  .link-box a {
    color: #2563eb;
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
  const whatsappPhoneNumberId = (body.whatsappPhoneNumberId || '').trim();
  const instagramAccountId = (body.instagramAccountId || '').trim();

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
    ...validateNewBusinessPayload({ name: businessName, businessProfile })
  ];

  if (errors.length > 0) {
    return res.status(400).type('html').send(renderOnboardForm({ values: body, errors }));
  }

  try {
    const business = await createBusiness({
      name: businessName,
      whatsappPhoneNumberId: whatsappPhoneNumberId || null,
      instagramAccountId: instagramAccountId || null,
      businessProfile
    });

    const dashboardUrl = `${req.protocol}://${req.get('host')}/my-dashboard/${business.dashboard_token}`;

    return res.type('html').send(renderOnboardSuccess(business, dashboardUrl));
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).type('html').send(
        renderOnboardForm({
          values: body,
          errors: ['A business with that WhatsApp phone number ID or Instagram account ID already exists']
        })
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