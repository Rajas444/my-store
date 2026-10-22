require("dotenv").config();
const express = require("express");
const { DatabaseSync } = require("node:sqlite");
const Stripe = require("stripe");

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
const app = express();
const db = new DatabaseSync("store.db");
const BASE_URL = process.env.BASE_URL || "http://localhost:3000";

// Saves several things together, or none of them if something fails
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

// Remember which Stripe payment each order belongs to
try {
  db.exec("ALTER TABLE orders ADD COLUMN stripe_session_id TEXT");
} catch (e) {
  // Column already exists, nothing to do
}

const count = db.prepare("SELECT COUNT(*) AS n FROM products").get().n;
if (count === 0) {
  const insert = db.prepare("INSERT INTO products (name, price) VALUES (?, ?)");
  insert.run("Product 1", 10);
  insert.run("Product 2", 15);
  insert.run("Product 3", 20);
}

// Password check for admin pages
function requireAdmin(req, res, next) {
  const header = req.headers.authorization || "";
  const [type, encoded] = header.split(" ");
  if (type === "Basic" && encoded) {
    const decoded = Buffer.from(encoded, "base64").toString();
    const password = decoded.split(":").slice(1).join(":");
    if (password === process.env.ADMIN_PASSWORD) return next();
  }
  res.set("WWW-Authenticate", 'Basic realm="Admin"');
  res.status(401).send("Password required");
}
app.use(["/admin.html", "/orders.html"], requireAdmin);

app.use(express.json());
app.use(express.static("public"));

// Get all products
app.get("/products", (req, res) => {
  res.json(db.prepare("SELECT * FROM products").all());
});

// Add a new product
app.post("/products", requireAdmin, (req, res) => {
  const { name, price } = req.body;
  if (!name || typeof price !== "number" || price < 0) {
    return res.status(400).json({ error: "Please send a name and a valid price." });
  }
  const result = db
    .prepare("INSERT INTO products (name, price) VALUES (?, ?)")
    .run(name, price);
  res.json({ id: Number(result.lastInsertRowid), name, price });
});

// Start a payment: send the customer to Stripe's secure payment page
app.post("/checkout", async (req, res) => {
  const { name, email, productIds } = req.body;
  if (!name || !email || !Array.isArray(productIds) || productIds.length === 0) {
    return res.status(400).json({ error: "Please send your name, email and cart." });
  }

  // Prices come from our database, never from the browser
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
      customer_email: email,
      line_items: items.map((p) => ({
        price_data: {
          currency: "usd",
          product_data: { name: p.name },
          unit_amount: Math.round(p.price * 100) // Stripe uses cents
        },
        quantity: 1
      })),
      metadata: { name: name, productIds: productIds.join(",") },
      success_url: BASE_URL + "/success.html?session_id={CHECKOUT_SESSION_ID}",
      cancel_url: BASE_URL + "/"
    });
    res.json({ url: session.url });
  } catch (err) {
    console.error("Stripe error:", err.message);
    res.status(500).json({ error: "Could not start the payment. Check the black window for details." });
  }
});

// After paying: check with Stripe that the payment is real, then save the order
app.get("/confirm", async (req, res) => {
  try {
    const session = await stripe.checkout.sessions.retrieve(req.query.session_id);
    if (session.payment_status !== "paid") {
      return res.status(400).json({ error: "Payment was not completed." });
    }

    // If this payment was already saved (page refreshed), don't save it twice
    const existing = db
      .prepare("SELECT id, total FROM orders WHERE stripe_session_id = ?")
      .get(session.id);
    if (existing) return res.json({ orderId: Number(existing.id), total: existing.total });

    const getProduct = db.prepare("SELECT * FROM products WHERE id = ?");
    const ids = session.metadata.productIds.split(",").map(Number);
    const items = ids.map((id) => getProduct.get(id)).filter(Boolean);
    const total = items.reduce((sum, p) => sum + p.price, 0);

    const orderId = inTransaction(() => {
      const result = db
        .prepare(
          "INSERT INTO orders (customer_name, customer_email, total, created_at, stripe_session_id) VALUES (?, ?, ?, ?, ?)"
        )
        .run(session.metadata.name, session.customer_email, total, new Date().toISOString(), session.id);
      const newId = Number(result.lastInsertRowid);
      const insertItem = db.prepare(
        "INSERT INTO order_items (order_id, product_name, price) VALUES (?, ?, ?)"
      );
      for (const p of items) insertItem.run(newId, p.name, p.price);
      return newId;
    });

    res.json({ orderId: orderId, total: total });
  } catch (err) {
    console.error("Confirm error:", err.message);
    res.status(400).json({ error: "Could not confirm the payment." });
  }
});

// See all orders (for you, the owner)
app.get("/orders", requireAdmin, (req, res) => {
  const orders = db.prepare("SELECT * FROM orders ORDER BY id DESC").all();
  const getItems = db.prepare("SELECT product_name, price FROM order_items WHERE order_id = ?");
  const result = orders.map((o) => ({ ...o, items: getItems.all(o.id) }));
  res.json(result);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Store running on port " + PORT));