require("dotenv").config();

const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const cookieSession = require("cookie-session");

const app = express();

app.set("trust proxy", 1);

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    service: "espaco-playstation"
  });
});

const PORT = Number(process.env.PORT || 3000);

const dbPath =
  process.env.DATABASE_FILE || "./espaco-playstation.sqlite";

const dbDirectory = path.dirname(dbPath);

if (!fs.existsSync(dbDirectory)) {
  fs.mkdirSync(dbDirectory, { recursive: true });
}

const db = new Database(dbPath);

const dbDirectory = path.dirname(dbPath);

if (!fs.existsSync(dbDirectory)) {
  fs.mkdirSync(dbDirectory, { recursive: true });
}

const db = new Database(dbPath);

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(
  fs.readFileSync(path.join(__dirname, "schema.sql"), "utf8")
);

app.use(
  helmet({
    contentSecurityPolicy: false
  })
);

app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({ extended: false }));

app.use(
  cookieSession({
    name: "espaco_session",
    keys: [
      process.env.SESSION_SECRET ||
        "ALTERE_ESTE_SEGREDO_NO_RAILWAY"
    ],
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 7 * 24 * 60 * 60 * 1000
  })
);

app.use(
  "/api/auth",
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 40
  })
);

function clean(value) {
  return String(value || "").trim();
}

function currentUser(req) {
  if (!req.session.userId) {
    return null;
  }

  return db
    .prepare(
      `
      SELECT id, name, cpf, email, phone
      FROM users
      WHERE id = ?
      `
    )
    .get(req.session.userId);
}

function requireLogin(req, res, next) {
  const user = currentUser(req);

  if (!user) {
    return res.status(401).json({
      error: "Inicie sessão para continuar."
    });
  }

  req.user = user;
  next();
}

function createOrderNumber() {
  return (
    "EPS-" +
    new Date().getFullYear() +
    "-" +
    crypto.randomBytes(4).toString("hex").toUpperCase()
  );
}

function validShipping(data) {
  const fields = [
    "name",
    "cpf",
    "phone",
    "cep",
    "state",
    "city",
    "street",
    "number"
  ];

  return fields.every((field) => clean(data[field]).length > 0);
}

const cover =
  "https://images.unsplash.com/photo-1605901309584-818e25960a8f?auto=format&fit=crop&w=1400&q=88";

const productExists = db
  .prepare("SELECT id FROM products LIMIT 1")
  .get();

if (!productExists) {
  db.prepare(
    `
    INSERT INTO products
    (
      name,
      slug,
      description,
      platform,
      price_cents,
      stock,
      active,
      cover_url,
      gallery_json,
      release_note
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `
  ).run(
    "GTA 6 — Edição Física",
    "gta-6-edicao-fisica",
    "Pré-venda da versão física em CD. A entrega depende do lançamento oficial e da distribuição autorizada.",
    "PlayStation 5",
    29990,
    null,
    1,
    cover,
    JSON.stringify([cover]),
    "A previsão de envio depende da confirmação oficial do lançamento e da distribuição."
  );
}

/* Produtos */

app.get("/api/products", (req, res) => {
  const products = db
    .prepare(
      `
      SELECT *
      FROM products
      WHERE active = 1
      ORDER BY id DESC
      `
    )
    .all()
    .map((product) => ({
      ...product,
      gallery: JSON.parse(product.gallery_json || "[]")
    }));

  res.json(products);
});

app.get("/api/products/:slug", (req, res) => {
  const product = db
    .prepare(
      `
      SELECT *
      FROM products
      WHERE slug = ?
      AND active = 1
      `
    )
    .get(req.params.slug);

  if (!product) {
    return res.status(404).json({
      error: "Produto não encontrado."
    });
  }

  product.gallery = JSON.parse(product.gallery_json || "[]");

  res.json(product);
});

/* Conta do cliente */

app.get("/api/auth/me", (req, res) => {
  res.json({
    user: currentUser(req)
  });
});

app.post("/api/auth/register", (req, res) => {
  const name = clean(req.body.name);
  const cpf = clean(req.body.cpf);
  const email = clean(req.body.email).toLowerCase();
  const phone = clean(req.body.phone);
  const password = String(req.body.password || "");

  if (
    name.length < 3 ||
    cpf.length < 11 ||
    !email.includes("@") ||
    phone.length < 8 ||
    password.length < 8
  ) {
    return res.status(400).json({
      error:
        "Preencha os dados corretamente. A senha deve ter pelo menos 8 caracteres."
    });
  }

  try {
    const passwordHash = bcrypt.hashSync(password, 12);

    const result = db
      .prepare(
        `
        INSERT INTO users
        (
          name,
          cpf,
          email,
          phone,
          password_hash
        )
        VALUES (?, ?, ?, ?, ?)
        `
      )
      .run(name, cpf, email, phone, passwordHash);

    req.session.userId = result.lastInsertRowid;

    res.status(201).json({
      user: currentUser(req)
    });
  } catch {
    res.status(409).json({
      error: "CPF ou e-mail já cadastrado."
    });
  }
});

app.post("/api/auth/login", (req, res) => {
  const email = clean(req.body.email).toLowerCase();
  const password = String(req.body.password || "");

  const user = db
    .prepare("SELECT * FROM users WHERE email = ?")
    .get(email);

  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({
      error: "E-mail ou senha inválidos."
    });
  }

  req.session.userId = user.id;

  res.json({
    user: currentUser(req)
  });
});

app.post("/api/auth/logout", (req, res) => {
  req.session = null;

  res.json({
    ok: true
  });
});

/* Pedidos */

app.post("/api/orders", requireLogin, (req, res) => {
  const product = db
    .prepare(
      `
      SELECT *
      FROM products
      WHERE id = ?
      AND active = 1
      `
    )
    .get(Number(req.body.productId));

  const quantity = Number(req.body.quantity || 1);
  const shipping = req.body.shipping || {};

  if (
    !product ||
    !Number.isInteger(quantity) ||
    quantity < 1 ||
    quantity > 10
  ) {
    return res.status(400).json({
      error: "Produto ou quantidade inválida."
    });
  }

  if (
    product.stock !== null &&
    quantity > product.stock
  ) {
    return res.status(409).json({
      error: "Quantidade indisponível."
    });
  }

  if (!validShipping(shipping)) {
    return res.status(400).json({
      error: "Preencha todos os dados de entrega."
    });
  }

  const number = createOrderNumber();
  const totalCents = product.price_cents * quantity;

  const createOrder = db.transaction(() => {
    const order = db
      .prepare(
        `
        INSERT INTO orders
        (
          public_number,
          user_id,
          total_cents,
          shipping_json
        )
        VALUES (?, ?, ?, ?)
        `
      )
      .run(
        number,
        req.user.id,
        totalCents,
        JSON.stringify(shipping)
      );

    db.prepare(
      `
      INSERT INTO order_items
      (
        order_id,
        product_id,
        product_name,
        quantity,
        unit_price_cents
      )
      VALUES (?, ?, ?, ?, ?)
      `
    ).run(
      order.lastInsertRowid,
      product.id,
      product.name,
      quantity,
      product.price_cents
    );

    db.prepare(
      `
      INSERT INTO payments
      (
        order_id,
        provider,
        amount_cents
      )
      VALUES (?, ?, ?)
      `
    ).run(
      order.lastInsertRowid,
      process.env.PIX_PROVIDER || "disabled",
      totalCents
    );

    db.prepare(
      "INSERT INTO shipments (order_id) VALUES (?)"
    ).run(order.lastInsertRowid);
  });

  createOrder();

  res.status(201).json({
    number,
    totalCents,
    paymentStatus: "pending"
  });
});

app.get("/api/orders", requireLogin, (req, res) => {
  const orders = db
    .prepare(
      `
      SELECT
        public_number,
        total_cents,
        order_status,
        payment_status,
        tracking_code,
        created_at,
        updated_at
      FROM orders
      WHERE user_id = ?
      ORDER BY id DESC
      `
    )
    .all(req.user.id);

  res.json(orders);
});

app.get(
  "/api/orders/:number",
  requireLogin,
  (req, res) => {
    const order = db
      .prepare(
        `
        SELECT *
        FROM orders
        WHERE public_number = ?
        AND user_id = ?
        `
      )
      .get(req.params.number, req.user.id);

    if (!order) {
      return res.status(404).json({
        error: "Pedido não encontrado."
      });
    }

    order.shipping = JSON.parse(order.shipping_json);

    order.items = db
      .prepare(
        `
        SELECT *
        FROM order_items
        WHERE order_id = ?
        `
      )
      .all(order.id);

    order.payment = db
      .prepare(
        `
        SELECT
          status,
          qr_code_url,
          qr_code_text,
          amount_cents,
          expires_at
        FROM payments
        WHERE order_id = ?
        `
      )
      .get(order.id);

    res.json(order);
  }
);

/* Integração GladePay */

async function gladePayRequest(endpoint, options = {}) {
  if (
    process.env.PIX_PROVIDER !== "gladepay" ||
    !process.env.PIX_API_KEY
  ) {
    throw new Error(
      "PIX ainda não configurado no servidor."
    );
  }

  const response = await fetch(
    (process.env.PIX_API_BASE_URL || "") + endpoint,
    {
      ...options,
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": process.env.PIX_API_KEY,
        ...(options.headers || {})
      }
    }
  );

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(
      data.message || `Erro do gateway: HTTP ${response.status}`
    );
  }

  return data;
}

app.post(
  "/api/orders/:number/pix",
  requireLogin,
  async (req, res) => {
    const order = db
      .prepare(
        `
        SELECT
          orders.*,
          payments.id AS payment_id
        FROM orders
        JOIN payments
          ON payments.order_id = orders.id
        WHERE orders.public_number = ?
        AND orders.user_id = ?
        `
      )
      .get(req.params.number, req.user.id);

    if (!order) {
      return res.status(404).json({
        error: "Pedido não encontrado."
      });
    }

    try {
      const charge = await gladePayRequest(
        "/pix/create",
        {
          method: "POST",
          body: JSON.stringify({
            amount: order.total_cents / 100,
            clientReference: order.public_number,
            callbackUrl:
              process.env.PUBLIC_URL +
              "/api/webhooks/pix"
          })
        }
      );

      db.prepare(
        `
        UPDATE payments
        SET
          provider_charge_id = ?,
          qr_code_url = ?,
          qr_code_text = ?,
          status = 'pending',
          updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        `
      ).run(
        charge.id,
        charge.qrCodeUrl || null,
        charge.qrCodeText || null,
        order.payment_id
      );

      res.json({
        status: "pending",
        amount: order.total_cents / 100,
        qrCodeUrl: charge.qrCodeUrl || null,
        qrCodeText: charge.qrCodeText || null
      });
    } catch (error) {
      res.status(503).json({
        error: error.message
      });
    }
  }
);

app.post("/api/webhooks/pix", async (req, res) => {
  const event = req.body || {};

  if (
    !event.id ||
    !event.clientReference ||
    event.type !== "DEPOSIT"
  ) {
    return res.status(400).json({
      error: "Evento inválido."
    });
  }

  const alreadyReceived = db
    .prepare(
      "SELECT id FROM payment_events WHERE event_id = ?"
    )
    .get(String(event.id));

  if (alreadyReceived) {
    return res.json({
      received: true
    });
  }

  const order = db
    .prepare(
      `
      SELECT
        orders.*,
        payments.id AS payment_id,
        payments.provider_charge_id
      FROM orders
      JOIN payments
        ON payments.order_id = orders.id
      WHERE orders.public_number = ?
      `
    )
    .get(event.clientReference);

  if (!order) {
    return res.status(404).json({
      error: "Pedido não encontrado."
    });
  }

  try {
    const transaction = await gladePayRequest(
      "/transaction/" +
        encodeURIComponent(
          order.provider_charge_id || event.id
        )
    );

    const confirmed =
      transaction.status === "COMPLETED" &&
      Math.round(Number(transaction.amount) * 100) ===
        order.total_cents;

    if (confirmed) {
      db.prepare(
        `
        UPDATE payments
        SET
          status = 'approved',
          updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        `
      ).run(order.payment_id);

      db.prepare(
        `
        UPDATE orders
        SET
          payment_status = 'approved',
          order_status = 'paid',
          updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        `
      ).run(order.id);
    }

    db.prepare(
      `
      INSERT INTO payment_events
      (
        payment_id,
        event_id,
        event_type,
        payload
      )
      VALUES (?, ?, ?, ?)
      `
    ).run(
      order.payment_id,
      String(event.id),
      event.status || "unknown",
      JSON.stringify(event)
    );

    res.json({
      received: true
    });
  } catch {
    res.status(502).json({
      error: "Não foi possível validar o pagamento."
    });
  }
});

/* Arquivos do site */

app.use(express.static(__dirname));

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.listen(PORT, () => {
  console.log(
    "Espaço PlayStation ativo na porta " + PORT
  );
});