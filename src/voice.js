const { WebSocketServer } = require('ws');

// Attaches a WebSocket server to the existing HTTP server on /voice-relay,
// for Twilio's Conversation Relay protocol. Sharing the HTTP server (rather
// than listening on a separate port) is done via the `server` option below —
// ws hooks into that server's 'upgrade' event and filters by path itself.
function setupVoiceWebSocket(server) {
  const wss = new WebSocketServer({ server, path: '/voice-relay' });

  wss.on('connection', (ws) => {
    console.log('[VOICE WS] Connection opened');

    ws.on('message', (data) => {
      const text = data.toString();

      let parsed;

      try {
        parsed = JSON.parse(text);
      } catch {
        parsed = null;
      }

      console.log(
        '[VOICE WS MESSAGE]',
        parsed ? JSON.stringify(parsed, null, 2) : text
      );
    });

    ws.on('close', (code, reason) => {
      console.log(
        `[VOICE WS] Connection closed: code=${code} reason=${reason}`
      );
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
