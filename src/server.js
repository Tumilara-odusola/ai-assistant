require('dotenv').config({ override: true });

const express = require('express');
const fs = require('fs');
const path = require('path');
const {
  generateReply,
  computeTypingDelayMs
} = require('./replyEngine');
const { computeAvailableSlots, confirmBooking } = require('./booking');
const { initDatabase } = require('./db');

const app = express();
app.use(express.json());

const businessProfile = JSON.parse(
  fs.readFileSync(
    path.join(__dirname, 'businessProfile.json'),
    'utf8'
  )
);

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
            text
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
        text
      );
    }

    const messaging = entry.messaging || [];

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
          text
        );

        continue;
      }

      const mid = event.message_edit?.mid;

      if (mid) {
        const resolved = await resolveInstagramMessageEdit(mid);

        if (resolved) {
          console.log(
            `[INCOMING instagram] ${resolved.senderId}: ${resolved.text}`
          );

          await handleIncomingMessage(
            'instagram',
            resolved.senderId,
            resolved.text
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

async function resolveInstagramMessageEdit(mid) {
  const token = process.env.META_INSTAGRAM_TOKEN;

  if (!token) {
    console.error(
      '[INSTAGRAM MESSAGE_EDIT] Missing META_INSTAGRAM_TOKEN, cannot resolve mid'
    );
    return null;
  }

  const url =
    'https://graph.instagram.com/v21.0/17841434513621888/conversations' +
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

  await handleIncomingMessage(
    'tiktok',
    senderId,
    text
  );
}

// ---------------------------------------------------------------------
// SHARED MESSAGE HANDLING
// ---------------------------------------------------------------------

async function handleIncomingMessage(platform, senderId, text) {
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
    computeAvailableSlots(businessProfile, todayDate),
    computeAvailableSlots(businessProfile, tomorrowDate)
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

  const { cleanReply, booking } = extractBookingConfirmation(result.reply);

  let reply = cleanReply;

  if (booking) {
    try {
      await confirmBooking(
        businessProfile,
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
      reply = BOOKING_SAVE_FAILURE_MESSAGE;
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
      computeAvailableSlots(businessProfile, todayDate),
      computeAvailableSlots(businessProfile, tomorrowDate)
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

    const { cleanReply, booking } = extractBookingConfirmation(result.reply);

    result.reply = cleanReply;

    if (booking) {
      try {
        await confirmBooking(
          businessProfile,
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
        result.reply = BOOKING_SAVE_FAILURE_MESSAGE;
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