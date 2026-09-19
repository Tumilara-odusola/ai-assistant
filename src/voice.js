const { WebSocketServer } = require('ws');
const { generateReply } = require('./replyEngine');
const { computeAvailableSlots } = require('./booking');
const { getBusinessByTwilioPhoneNumber } = require('./db');

// Duplicated from server.js rather than imported: server.js requires this
// module near the top of the file (before its own exports are set up), so
// importing back from server.js here would create a circular require that
// resolves to undefined. This is a plain 4-line date formatter, low risk
// to keep in sync manually.
function formatDateYYYYMMDD(date) {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

// Matches a trailing [BOOKING_CONFIRMED: ...] or [ORDER_CONFIRMED: ...]
// marker. Unlike server.js's extractBookingConfirmation/
// extractOrderConfirmation, this doesn't need to parse out the individual
// fields — voice doesn't act on these yet, it only needs to detect and
// remove them so they're never spoken aloud by Twilio's TTS.
const TRAILING_MARKER_REGEX = /\n?\[(BOOKING_CONFIRMED|ORDER_CONFIRMED):[^\]]*\]\s*$/;

function stripMarkers(replyText) {
  let text = replyText;
  const attemptedTypes = [];

  let match = text.match(TRAILING_MARKER_REGEX);

  while (match) {
    attemptedTypes.push(match[1]);
    text = text.slice(0, match.index).trimEnd();
    match = text.match(TRAILING_MARKER_REGEX);
  }

  return { text, attemptedTypes };
}

function greetingText(businessProfile) {
  return `Hey! Thanks for calling ${businessProfile.businessName}. How can I help you today?`;
}

function sendText(ws, token, last) {
  if (ws.readyState !== ws.OPEN) {
    console.error('[VOICE WS] Cannot send, connection is not open');
    return;
  }

  ws.send(JSON.stringify({ type: 'text', token, last }));
}

// Per-call state, keyed by the WebSocket connection itself — call sessions
// are ephemeral, so there's no phone-number-style key to reuse here the way
// the text channels use `platform:senderId`. Entries are removed on close.
const connections = new Map();

async function handleSetup(ws, message) {
  const toNumber = message.to;

  const business = toNumber
    ? await getBusinessByTwilioPhoneNumber(toNumber)
    : null;

  if (!business) {
    console.error(
      `[VOICE WS] No business found for twilio number=${toNumber}, ending call`
    );
    sendText(ws, "Sorry, this number isn't set up yet. Goodbye.", true);
    ws.close();
    return;
  }

  connections.set(ws, {
    businessProfile: business.business_profile,
    businessId: business.id,
    history: []
  });

  console.log(
    `[VOICE WS] Call connected for business id=${business.id} (${business.business_profile.businessName})`
  );

  sendText(ws, greetingText(business.business_profile), true);
}

async function handlePrompt(ws, message) {
  const state = connections.get(ws);

  if (!state) {
    console.error('[VOICE WS] Received prompt before setup completed, ignoring');
    return;
  }

  const voicePrompt = message.voicePrompt;

  if (typeof voicePrompt !== 'string' || !voicePrompt.trim()) {
    console.log('[VOICE WS] Prompt message missing voicePrompt, ignoring');
    return;
  }

  console.log(`[VOICE INCOMING] business=${state.businessId}: ${voicePrompt}`);

  const today = new Date();
  const tomorrow = new Date(today);
  tomorrow.setDate(tomorrow.getDate() + 1);
  const todayDate = formatDateYYYYMMDD(today);
  const tomorrowDate = formatDateYYYYMMDD(tomorrow);

  const [todaySlots, tomorrowSlots] = await Promise.all([
    computeAvailableSlots(state.businessProfile, state.businessId, todayDate),
    computeAvailableSlots(state.businessProfile, state.businessId, tomorrowDate)
  ]);

  const availableSlots = {
    todayDate,
    tomorrowDate,
    today: todaySlots,
    tomorrow: tomorrowSlots
  };

  const result = await generateReply(
    state.businessProfile,
    state.history,
    voicePrompt,
    availableSlots
  );

  const { text: cleanReply, attemptedTypes } = stripMarkers(result.reply);

  if (attemptedTypes.length > 0) {
    console.log(
      `[VOICE WS] Marker(s) detected but deferred (voice doesn't act on ` +
      `bookings/orders yet): ${attemptedTypes.join(', ')}`
    );
  }

  state.history.push({ role: 'user', content: voicePrompt });
  state.history.push({ role: 'assistant', content: cleanReply });

  console.log(`[VOICE OUTGOING] business=${state.businessId}: ${cleanReply}`);

  sendText(ws, cleanReply, true);
}

async function handleVoiceMessage(ws, data) {
  const text = data.toString();

  let message;

  try {
    message = JSON.parse(text);
  } catch {
    console.log('[VOICE WS MESSAGE] (non-JSON, ignoring)', text);
    return;
  }

  console.log('[VOICE WS MESSAGE]', JSON.stringify(message, null, 2));

  if (message.type === 'setup') {
    await handleSetup(ws, message);
    return;
  }

  if (message.type === 'prompt') {
    await handlePrompt(ws, message);
    return;
  }

  // interrupt, dtmf, or anything else — already logged above, nothing to
  // act on yet.
}

// Attaches a WebSocket server to the existing HTTP server on /voice-relay,
// for Twilio's Conversation Relay protocol. Sharing the HTTP server (rather
// than listening on a separate port) is done via the `server` option below —
// ws hooks into that server's 'upgrade' event and filters by path itself.
function setupVoiceWebSocket(server) {
  const wss = new WebSocketServer({ server, path: '/voice-relay' });

  wss.on('connection', (ws) => {
    console.log('[VOICE WS] Connection opened');

    ws.on('message', (data) => {
      handleVoiceMessage(ws, data).catch((err) => {
        console.error('[VOICE WS] Error handling message', err);
      });
    });

    ws.on('close', (code, reason) => {
      console.log(
        `[VOICE WS] Connection closed: code=${code} reason=${reason}`
      );
      connections.delete(ws);
    });

    // Required, not optional: an unhandled 'error' event on an EventEmitter
    // (which a ws connection is) throws and crashes the process. Without
    // this listener, any connection hiccup would take the whole app down.
    ws.on('error', (err) => {
      console.error('[VOICE WS ERROR]', err);
    });
  });

  wss.on('error', (err) => {
    console.error('[VOICE WS SERVER ERROR]', err);
  });

  console.log('[VOICE WS] WebSocket relay listening on /voice-relay');

  return wss;
}

module.exports = { setupVoiceWebSocket };
