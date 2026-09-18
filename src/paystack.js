async function initializePayment(email, amount, currency, reference, metadata) {
  const secretKey = process.env.PAYSTACK_SECRET_KEY;

  if (!secretKey) {
    throw new Error('Missing PAYSTACK_SECRET_KEY in .env');
  }

  // Paystack's supported currencies (NGN, GHS, ZAR, USD, KES) all subdivide
  // into 100 minor units, so this multiplier holds regardless of currency.
  const amountMinorUnits = Math.round(amount * 100);

  const payload = {
    email,
    amount: amountMinorUnits,
    currency,
    reference,
    metadata
  };

  console.log(
    '[PAYSTACK INITIALIZE REQUEST]',
    JSON.stringify(payload, null, 2)
  );

  const response = await fetch('https://api.paystack.co/transaction/initialize', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${secretKey}`,
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
    `[PAYSTACK INITIALIZE] ${response.status}:`,
    JSON.stringify(data, null, 2)
  );

  if (!response.ok || !data.status) {
    throw new Error(
      `Paystack initialize failed with HTTP ${response.status}: ` +
      JSON.stringify(data)
    );
  }

  return {
    authorizationUrl: data.data.authorization_url,
    reference: data.data.reference
  };
}

module.exports = { initializePayment };
