// Plain fetch() against Expo's push API — no expo-server-sdk needed, same
// "call the platform's REST API directly" pattern this app already uses
// for WhatsApp/Instagram/Messenger sends (see sendWhatsAppMessage etc. in
// server.js). Docs: https://docs.expo.dev/push-notifications/sending-notifications/
const EXPO_PUSH_API_URL = 'https://exp.host/--/api/v2/push/send';

// Returns { ok: true } on a normal send, or { ok: false, deviceNotRegistered: true }
// when Expo reports the token is dead — callers should stop sending to that
// token (see clearPushToken in db.js) rather than retrying it forever.
async function sendPushNotification(pushToken, { title, body, data }) {
  const response = await fetch(EXPO_PUSH_API_URL, {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'Accept-Encoding': 'gzip, deflate',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ to: pushToken, title, body, data })
  });

  const responseText = await response.text();

  let result;

  try {
    result = JSON.parse(responseText);
  } catch {
    result = { raw: responseText };
  }

  console.log(`[EXPO PUSH API] ${response.status}:`, JSON.stringify(result, null, 2));

  if (!response.ok) {
    throw new Error(`Expo push send failed with HTTP ${response.status}: ${JSON.stringify(result)}`);
  }

  const ticket = result.data;
  const deviceNotRegistered = ticket?.status === 'error' && ticket?.details?.error === 'DeviceNotRegistered';

  if (ticket?.status === 'error' && !deviceNotRegistered) {
    throw new Error(`Expo push ticket error: ${ticket.message || JSON.stringify(ticket)}`);
  }

  return { ok: ticket?.status === 'ok', deviceNotRegistered };
}

module.exports = { sendPushNotification };
