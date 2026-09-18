const { pool } = require('./db');
const { initializePayment } = require('./paystack');

async function confirmOrder(businessProfile, businessId, productName, quantity, customerId) {
  const product = businessProfile.products.find((p) => p.name === productName);

  if (!product) {
    throw new Error(`Unknown product: ${productName}`);
  }

  const totalAmount = product.price * quantity;
  const currency = businessProfile.currency || 'NGN';
  const reference = `order_${Date.now()}`;

  // WhatsApp/Instagram customers are identified by phone number or IGSID,
  // not email, but Paystack requires one. Synthesizing a placeholder until
  // there's a real way to collect the customer's actual email.
  const placeholderEmail = `${customerId.replace(/[^a-zA-Z0-9]/g, '_')}@customer.placeholder`;

  const { authorizationUrl } = await initializePayment(
    placeholderEmail,
    totalAmount,
    currency,
    reference,
    { businessId, productName, quantity, customerId }
  );

  await pool.query(
    `INSERT INTO orders (product_name, quantity, price, customer_id, business_id, payment_status, payment_reference)
     VALUES ($1, $2, $3, $4, $5, $6, $7)`,
    [productName, quantity, product.price, customerId, businessId, 'pending', reference]
  );

  return { authorizationUrl, reference };
}

module.exports = { confirmOrder };
