const { pool } = require('./db');

async function confirmOrder(businessProfile, productName, quantity, customerId) {
  const product = businessProfile.products.find((p) => p.name === productName);

  if (!product) {
    throw new Error(`Unknown product: ${productName}`);
  }

  await pool.query(
    `INSERT INTO orders (product_name, quantity, price, customer_id)
     VALUES ($1, $2, $3, $4)`,
    [productName, quantity, product.price, customerId]
  );

  return {
    productName,
    quantity,
    price: product.price,
    customerId
  };
}

module.exports = { confirmOrder };
