require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const { DatabaseSync } = require("node:sqlite");
const Stripe = require("stripe");

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
const app = express();
const db = new DatabaseSync("store.db");
const BASE_URL = process.env.BASE_URL || "http://localhost:3000";

if (!process.env.ADMIN_PASSWORD) {
  console.warn("WARNING: ADMIN_PASSWORD is not set. Admin pages will stay locked.");
}
if (!process.env.STRIPE_WEBHOOK_SECRET) {
  console.warn("WARNING: STRIPE_WEBHOOK_SECRET is not set. The webhook will be rejected.");
}

app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));

function inTransaction(work) {
  db.exec("BEGIN");
  try {
    const result = work();
    db.exec("COMMIT");
    return result;
  } catch (err) {
    db.exec("ROLLBACK");
    throw err;
  }
}

db.exec(`
  CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    price REAL NOT NULL
  );
  CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    customer_name TEXT NOT NULL,
    customer_email TEXT NOT NULL,
    total REAL NOT NULL,
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS order_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id INTEGER NOT NULL,
    product_name TEXT NOT NULL,
    price REAL NOT NULL
  );
`);

try {
  db.exec("ALTER TABLE orders ADD COLUMN stripe_session_id TEXT");
} catch (e) {
  // Column already exists, nothing to do
}

// Each Stripe payment can be saved only once
db.exec(
  "CREATE UNIQUE INDEX IF NOT EXISTS idx_orders_session ON orders(stripe_session_id)"
);

const count = db.prepare("SELECT COUNT(*) AS n FROM products").get().n;
if (count === 0) {
  const insert = db.prepare("INSERT INTO products (name, price) VALUES (?, ?)");
  insert.run("Product 1", 10);
  insert.run("Product 2", 15);
  insert.run("Product 3", 20);
}

// Saves a paid Stripe session as an order. Safe to call twice for the same payment.
function saveOrderFromSession(session) {
  const existing = db
    .prepare("SELECT id, total FROM orders WHERE stripe_session_id = ?")
    .get(session.id);
  if (existing) return { orderId: Number(existing.id), total: existing.total };

  const getProduct = db.prepare("SELECT * FROM products WHERE id = ?");
  const ids = String(session.metadata.productIds).split(",").map(Number);
  const items = ids.map((id) => getProduct.get(id)).filter(Boolean);
  const total = items.reduce((sum, p) => sum + p.price, 0);

  const orderId = inTransaction(() => {
    const result = db
      .prepare(
        "INSERT INTO orders (customer_name, customer_email, total, created_at, stripe_session_id) VALUES (?, ?, ?, ?, ?)"
      )
      .run(
        session.metadata.name,
        session.customer_email || (session.customer_details && session.customer_details.email) || "unknown",
        total,
        new Date().toISOString(),
        session.id
      );
    const newId = Number(result.lastInsertRowid);
    const insertItem = db.prepare(
      "INSERT INTO order_items (order_id, product_name, price) VALUES (?, ?, ?)"
    );
    for (const p of items) insertItem.run(newId, p.name, p.price);
    return newId;
  });

  return { orderId: orderId, total: total };
}

// Stripe calls this by itself when a payment succeeds.
// It must come BEFORE express.json(), because it needs the raw body to check Stripe's signature.
app.post("/webhook", express.raw({ type: "application/json" }), (req, res) => {
  let event;
  try {
    event = stripe.webhooks.constructEvent(
      req.body,
      req.headers["stripe-signature"],
      process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (err) {
    console.error("Webhook signature check failed:", err.message);
    return res.status(400).send("Invalid signature");
  }

  if (event.type === "checkout.session.completed") {
    const session = event.data.object;
    if (session.payment_status === "paid") {
      try {
        const saved = saveOrderFromSession(session);
        console.log("Webhook saved order #" + saved.orderId);
      } catch (err) {
        console.error("Webhook could not save order:", err.message);
        return res.status(500).send("Could not save order");
      }
    }
  }
  res.json({ received: true });
});

const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  skipSuccessfulRequests: true,
  message: "Too many failed attempts. Try again in 15 minutes."
});
const checkoutLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: { error: "Too many requests. Please try again later." }
});

function requireAdmin(req, res, next) {
  const expected = process.env.ADMIN_PASSWORD;
  const header = req.headers.authorization || "";
  const [type, encoded] = header.split(" ");
  if (expected && type === "Basic" && encoded) {
    const decoded = Buffer.from(encoded, "base64").toString();
    const password = decoded.split(":").slice(1).join(":");
    const a = crypto.createHash("sha256").update(password).digest();
    const b = crypto.createHash("sha256").update(expected).digest();
    if (crypto.timingSafeEqual(a, b)) return next();
  }
  res.set("WWW-Authenticate", 'Basic realm="Admin"');
  res.status(401).send("Password required");
}
app.use(["/admin.html", "/orders.html"], adminLimiter, requireAdmin);

app.use(express.json({ limit: "10kb" }));
app.use(express.static("public"));

app.get("/products", (req, res) => {
  res.json(db.prepare("SELECT * FROM products").all());
});

app.post("/products", adminLimiter, requireAdmin, (req, res) => {
  const { name, price } = req.body;
  const cleanName = typeof name === "string" ? name.trim() : "";
  if (
    cleanName.length === 0 ||
    cleanName.length > 100 ||
    typeof price !== "number" ||
    !Number.isFinite(price) ||
    price <= 0 ||
    price > 100000
  ) {
    return res.status(400).json({ error: "Please send a name (up to 100 letters) and a price above 0." });
  }
  const result = db
    .prepare("INSERT INTO products (name, price) VALUES (?, ?)")
    .run(cleanName, price);
  res.json({ id: Number(result.lastInsertRowid), name: cleanName, price });
});

app.post("/checkout", checkoutLimiter, async (req, res) => {
  const { name, email, productIds } = req.body;

  const cleanName = typeof name === "string" ? name.trim() : "";
  const cleanEmail = typeof email === "string" ? email.trim() : "";
  const emailLooksOk = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail);

  if (
    cleanName.length === 0 ||
    cleanName.length > 100 ||
    !emailLooksOk ||
    cleanEmail.length > 200 ||
    !Array.isArray(productIds) ||
    productIds.length === 0 ||
    productIds.length > 20 ||
    !productIds.every((id) => Number.isInteger(id))
  ) {
    return res.status(400).json({ error: "Please check your name, email and cart." });
  }

  const getProduct = db.prepare("SELECT * FROM products WHERE id = ?");
  const items = [];
  for (const id of productIds) {
    const product = getProduct.get(id);
    if (!product) return res.status(400).json({ error: "Unknown product." });
    items.push(product);
  }

  try {
    const session = await stripe.checkout.sessions.create({
      mode: "payment",
      customer_email: cleanEmail,
      line_items: items.map((p) => ({
        price_data: {
          currency: "usd",
          product_data: { name: p.name },
          unit_amount: Math.round(p.price * 100)
        },
        quantity: 1
      })),
      metadata: { name: cleanName, productIds: productIds.join(",") },
      success_url: BASE_URL + "/success.html?session_id={CHECKOUT_SESSION_ID}",
      cancel_url: BASE_URL + "/"
    });
    res.json({ url: session.url });
  } catch (err) {
    console.error("Stripe error:", err.message);
    res.status(500).json({ error: "Could not start the payment. Please try again." });
  }
});

// The success page asks this. It uses the same save function as the webhook.
app.get("/confirm", checkoutLimiter, async (req, res) => {
  try {
    const sessionId = String(req.query.session_id || "");
    if (!sessionId.startsWith("cs_")) {
      return res.status(400).json({ error: "Could not confirm the payment." });
    }
    const session = await stripe.checkout.sessions.retrieve(sessionId);
    if (session.payment_status !== "paid") {
      return res.status(400).json({ error: "Payment was not completed." });
    }
    res.json(saveOrderFromSession(session));
  } catch (err) {
    console.error("Confirm error:", err.message);
    res.status(400).json({ error: "Could not confirm the payment." });
  }
});

app.get("/orders", adminLimiter, requireAdmin, (req, res) => {
  const orders = db.prepare("SELECT * FROM orders ORDER BY id DESC").all();
  const getItems = db.prepare("SELECT product_name, price FROM order_items WHERE order_id = ?");
  res.json(orders.map((o) => ({ ...o, items: getItems.all(o.id) })));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Store running on port " + PORT));