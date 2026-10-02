require("dotenv").config();

const express = require("express");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const cookieSession = require("cookie-session");

const app = express();
const PORT = process.env.PORT || 3000;

const db = new Database(
  process.env.DATABASE_FILE || "./espaco-playstation.sqlite"
);

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  cpf TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE NOT NULL,
  phone TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  slug TEXT UNIQUE NOT NULL,
  description TEXT NOT NULL,
  platform TEXT NOT NULL,
  price_cents INTEGER NOT NULL,
  stock INTEGER,
  active INTEGER DEFAULT 1,
  cover_url TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  public_number TEXT UNIQUE NOT NULL,
  user_id INTEGER NOT NULL,
  total_cents INTEGER NOT NULL,
  order_status TEXT DEFAULT 'awaiting_payment',
  payment_status TEXT DEFAULT 'pending',
  shipping_json TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS order_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id INTEGER NOT NULL,
  product_id INTEGER NOT NULL,
  quantity INTEGER NOT NULL,
  unit_price_cents INTEGER NOT NULL,
  FOREIGN KEY (order_id) REFERENCES orders(id),
  FOREIGN KEY (product_id) REFERENCES products(id)
);

CREATE TABLE IF NOT EXISTS payments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id INTEGER UNIQUE NOT NULL,
  provider TEXT NOT NULL,
  provider_charge_id TEXT,
  qr_code_url TEXT,
  qr_code_text TEXT,
  amount_cents INTEGER NOT NULL,
  status TEXT DEFAULT 'pending',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (order_id) REFERENCES orders(id)
);

CREATE TABLE IF NOT EXISTS payment_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT UNIQUE NOT NULL,
  event_json TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
`);

const existingProduct = db
  .prepare("SELECT id FROM products LIMIT 1")
  .get();

if (!existingProduct) {
  db.prepare(`
    INSERT INTO products
    (name, slug, description, platform, price_cents, stock, active, cover_url)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    "GTA 6 — Edição Física",
    "gta-6-edicao-fisica",
    "Pré-venda da edição física em CD. A data de lançamento e a entrega dependem da confirmação oficial e da distribuição autorizada.",
    "PlayStation 5",
    29990,
    null,
    1,
    "https://images.unsplash.com/photo-1605901309584-818e25960a8f?auto=format&fit=crop&w=1200&q=85"
  );
}

app.use(
  helmet({
    contentSecurityPolicy: false
  })
);

app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({ extended: false }));

app.use(
  cookieSession({
    name: "espaco_playstation_session",
    keys: [
      process.env.SESSION_SECRET ||
        "altere-esta-chave-no-railway-imediatamente"
    ],
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 1000 * 60 * 60 * 24 * 7
  })
);

app.use(
  "/api/auth",
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 30
  })
);

function currentUser(req) {
  if (!req.session.userId) return null;

  return db
    .prepare(
      "SELECT id, name, cpf, email, phone FROM users WHERE id = ?"
    )
    .get(req.session.userId);
}

function requireAuth(req, res, next) {
  const user = currentUser(req);

  if (!user) {
    return res.status(401).json({
      error: "É necessário iniciar sessão."
    });
  }

  req.user = user;
  next();
}

function generateOrderNumber() {
  return (
    "EPS-" +
    new Date().getFullYear() +
    "-" +
    crypto.randomBytes(4).toString("hex").toUpperCase()
  );
}

function clean(value) {
  return String(value || "").trim();
}

app.get("/api/products", (req, res) => {
  const products = db
    .prepare("SELECT * FROM products WHERE active = 1 ORDER BY id DESC")
    .all();

  res.json(products);
});

app.get("/api/products/:slug", (req, res) => {
  const product = db
    .prepare(
      "SELECT * FROM products WHERE slug = ? AND active = 1"
    )
    .get(req.params.slug);

  if (!product) {
    return res.status(404).json({
      error: "Produto não encontrado."
    });
  }

  res.json(product);
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
        "Preencha todos os dados corretamente. A senha deve ter pelo menos 8 caracteres."
    });
  }

  try {
    const passwordHash = bcrypt.hashSync(password, 12);

    const result = db
      .prepare(`
        INSERT INTO users
        (name, cpf, email, phone, password_hash)
        VALUES (?, ?, ?, ?, ?)
      `)
      .run(name, cpf, email, phone, passwordHash);

    req.session.userId = result.lastInsertRowid;

    res.status(201).json({
      message: "Conta criada com sucesso.",
      user: currentUser(req)
    });
  } catch (error) {
    res.status(409).json({
      error: "Este CPF ou e-mail já está cadastrado."
    });
  }
});

app.post("/api/auth/login", (req, res) => {
  const email = clean(req.body.email).toLowerCase();
  const password = String(req.body.password || "");

  const account = db
    .prepare("SELECT * FROM users WHERE email = ?")
    .get(email);

  if (
    !account ||
    !bcrypt.compareSync(password, account.password_hash)
  ) {
    return res.status(401).json({
      error: "E-mail ou senha inválidos."
    });
  }

  req.session.userId = account.id;

  res.json({
    message: "Login realizado.",
    user: currentUser(req)
  });
});

app.post("/api/auth/logout", (req, res) => {
  req.session = null;
  res.json({ message: "Sessão encerrada." });
});

app.get("/api/auth/me", (req, res) => {
  res.json({
    user: currentUser(req)
  });
});

app.post("/api/orders", requireAuth, (req, res) => {
  const productId = Number(req.body.productId);
  const quantity = Number(req.body.quantity || 1);
  const shipping = req.body.shipping || {};

  const product = db
    .prepare(
      "SELECT * FROM products WHERE id = ? AND active = 1"
    )
    .get(productId);

  if (!product) {
    return res.status(404).json({
      error: "Produto não encontrado."
    });
  }

  if (!Number.isInteger(quantity) || quantity < 1 || quantity > 10) {
    return res.status(400).json({
      error: "Quantidade inválida."
    });
  }

  if (product.stock !== null && quantity > product.stock) {
    return res.status(409).json({
      error: "Quantidade indisponível em stock."
    });
  }

  const requiredShipping = [
    "name",
    "cpf",
    "phone",
    "cep",
    "state",
    "city",
    "street",
    "number"
  ];

  for (const field of requiredShipping) {
    if (!clean(shipping[field])) {
      return res.status(400).json({
        error: `O campo ${field} é obrigatório.`
      });
    }
  }

  const totalCents = product.price_cents * quantity;
  const orderNumber = generateOrderNumber();

  const createOrder = db.transaction(() => {
    const order = db
      .prepare(`
        INSERT INTO orders
        (public_number, user_id, total_cents, shipping_json)
        VALUES (?, ?, ?, ?)
      `)
      .run(
        orderNumber,
        req.user.id,
        totalCents,
        JSON.stringify(shipping)
      );

    db.prepare(`
      INSERT INTO order_items
      (order_id, product_id, quantity, unit_price_cents)
      VALUES (?, ?, ?, ?)
    `).run(
      order.lastInsertRowid,
      product.id,
      quantity,
      product.price_cents
    );

    db.prepare(`
      INSERT INTO payments
      (order_id, provider, amount_cents)
      VALUES (?, ?, ?)
    `).run(
      order.lastInsertRowid,
      process.env.PIX_PROVIDER || "disabled",
      totalCents
    );

    return order.lastInsertRowid;
  });

  const orderId = createOrder();

  res.status(201).json({
    message:
      "Pedido criado. O PIX será gerado depois que o gateway estiver configurado.",
    orderNumber,
    orderId,
    totalCents
  });
});

app.get("/api/orders", requireAuth, (req, res) => {
  const orders = db
    .prepare(`
      SELECT *
      FROM orders
      WHERE user_id = ?
      ORDER BY id DESC
    `)
    .all(req.user.id);

  res.json(orders);
});

app.get("/api/orders/:number", requireAuth, (req, res) => {
  const order = db
    .prepare(`
      SELECT *
      FROM orders
      WHERE public_number = ?
      AND user_id = ?
    `)
    .get(req.params.number, req.user.id);

  if (!order) {
    return res.status(404).json({
      error: "Pedido não encontrado."
    });
  }

  const items = db
    .prepare("SELECT * FROM order_items WHERE order_id = ?")
    .all(order.id);

  const payment = db
    .prepare(`
      SELECT
        id,
        status,
        qr_code_url,
        qr_code_text,
        amount_cents,
        provider_charge_id
      FROM payments
      WHERE order_id = ?
    `)
    .get(order.id);

  res.json({
    order,
    items,
    payment
  });
});

async function gladePayRequest(endpoint, options = {}) {
  const baseUrl =
    process.env.PIX_API_BASE_URL ||
    "https://web-production-73dbd.up.railway.app/api/v1";

  const response = await fetch(baseUrl + endpoint, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      "X-API-Key": process.env.PIX_API_KEY,
      ...(options.headers || {})
    }
  });

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
  requireAuth,
  async (req, res) => {
    const order = db
      .prepare(`
        SELECT
          o.*,
          p.id AS payment_id,
          p.provider_charge_id
        FROM orders o
        JOIN payments p ON p.order_id = o.id
        WHERE o.public_number = ?
        AND o.user_id = ?
      `)
      .get(req.params.number, req.user.id);

    if (!order) {
      return res.status(404).json({
        error: "Pedido não encontrado."
      });
    }

    if (
      process.env.PIX_PROVIDER !== "gladepay" ||
      !process.env.PIX_API_KEY
    ) {
      return res.status(503).json({
        error:
          "PIX ainda não está configurado. Adicione as variáveis no Railway."
      });
    }

    try {
      const charge = await gladePayRequest("/pix/create", {
        method: "POST",
        body: JSON.stringify({
          amount: order.total_cents / 100,
          clientReference: order.public_number,
          callbackUrl:
            process.env.PUBLIC_URL + "/api/webhooks/pix"
        })
      });

      db.prepare(`
        UPDATE payments
        SET
          provider_charge_id = ?,
          qr_code_url = ?,
          qr_code_text = ?,
          status = 'pending',
          updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `).run(
        charge.id,
        charge.qrCodeUrl || null,
        charge.qrCodeText || null,
        order.payment_id
      );

      res.json({
        status: "pending",
        transactionId: charge.id,
        qrCodeUrl: charge.qrCodeUrl,
        qrCodeText: charge.qrCodeText,
        expiresIn: charge.expiresIn
      });
    } catch (error) {
      res.status(502).json({
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
      error: "Evento PIX inválido."
    });
  }

  try {
    const order = db
      .prepare(`
        SELECT
          o.*,
          p.id AS payment_id,
          p.provider_charge_id
        FROM orders o
        JOIN payments p ON p.order_id = o.id
        WHERE o.public_number = ?
      `)
      .get(event.clientReference);

    if (!order) {
      return res.status(404).json({
        error: "Pedido não encontrado."
      });
    }

    const duplicate = db
      .prepare(
        "SELECT id FROM payment_events WHERE event_id = ?"
      )
      .get(String(event.id));

    if (duplicate) {
      return res.json({ received: true });
    }

    const transactionId =
      order.provider_charge_id || String(event.id);

    const verified = await gladePayRequest(
      "/transaction/" + encodeURIComponent(transactionId)
    );

    const correctStatus = verified.status === "COMPLETED";
    const correctAmount =
      Math.round(Number(verified.amount) * 100) ===
      order.total_cents;

    if (correctStatus && correctAmount) {
      db.prepare(`
        UPDATE payments
        SET status = 'approved',
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `).run(order.payment_id);

      db.prepare(`
        UPDATE orders
        SET payment_status = 'approved',
            order_status = 'paid',
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `).run(order.id);
    }

    db.prepare(`
      INSERT INTO payment_events
      (event_id, event_json)
      VALUES (?, ?)
    `).run(String(event.id), JSON.stringify(event));

    res.json({ received: true });
  } catch (error) {
    res.status(502).json({
      error: "Não foi possível validar o pagamento."
    });
  }
});

const page = `
<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Espaço PlayStation</title>
<style>
* {
  box-sizing: border-box;
}

body {
  margin: 0;
  background: #080b14;
  color: #f5f7ff;
  font-family: Arial, sans-serif;
}

header {
  padding: 20px 6%;
  display: flex;
  justify-content: space-between;
  align-items: center;
  background: #11172a;
  border-bottom: 1px solid #293252;
}

.logo {
  font-weight: bold;
  font-size: 20px;
}

main {
  max-width: 1100px;
  margin: auto;
  padding: 45px 6%;
}

.hero {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 35px;
  align-items: center;
}

.hero img {
  width: 100%;
  max-height: 520px;
  object-fit: cover;
  border-radius: 22px;
}

h1 {
  font-size: clamp(38px, 6vw, 76px);
  margin: 15px 0;
}

h2 {
  color: #9b8cff;
}

.price {
  font-size: 30px;
  color: #9bf7d2;
  font-weight: bold;
}

button {
  padding: 16px 23px;
  border: none;
  border-radius: 10px;
  background: #7865ff;
  color: white;
  font-size: 16px;
  font-weight: bold;
  cursor: pointer;
}

button:hover {
  background: #614ce8;
}

.card {
  margin-top: 55px;
  padding: 26px;
  border-radius: 16px;
  background: #131a2d;
  border: 1px solid #2b365a;
}

input {
  display: block;
  width: 100%;
  margin: 10px 0;
  padding: 14px;
  border: 1px solid #3a466c;
  border-radius: 8px;
  background: #0c1120;
  color: white;
}

.notice {
  color: #cbd2e8;
  line-height: 1.6;
}

@media (max-width: 700px) {
  .hero {
    grid-template-columns: 1fr;
  }

  main {
    padding: 28px 5%;
  }

  header {
    font-size: 13px;
  }
}
</style>
</head>

<body>
<header>
  <div class="logo">🎮 Espaço PlayStation</div>
  <div>Pré-venda GTA 6</div>
</header>

<main>
  <div id="app">A carregar...</div>
</main>

<script>
let product = null;

async function loadProduct() {
  const response = await fetch("/api/products");
  const products = await response.json();
  product = products[0];

  document.getElementById("app").innerHTML = \`
    <div class="hero">
      <div>
        <small>PRÉ-VENDA • EDIÇÃO FÍSICA</small>
        <h1>\${product.name}</h1>
        <p class="notice">\${product.description}</p>
        <p class="price">
          R$ \${(product.price_cents / 100)
            .toFixed(2)
            .replace(".", ",")}
        </p>
        <button onclick="showCheckout()">
          Comprar agora
        </button>
      </div>

      <img src="\${product.cover_url}" alt="Produto GTA 6">
    </div>

    <section class="card">
      <h2>Informações da pré-venda</h2>
      <p class="notice">
        O lançamento oficial, a disponibilidade e a entrega dependem
        da confirmação da distribuidora. O pagamento só será marcado
        como aprovado após confirmação real do gateway PIX.
      </p>
    </section>

    <section id="checkout" class="card" style="display:none">
      <h2>Checkout</h2>

      <input id="name" placeholder="Nome completo">
      <input id="cpf" placeholder="CPF">
      <input id="email" placeholder="E-mail">
      <input id="phone" placeholder="Telefone">
      <input id="cep" placeholder="CEP">
      <input id="state" placeholder="Estado">
      <input id="city" placeholder="Cidade">
      <input id="street" placeholder="Endereço">
      <input id="number" placeholder="Número">
      <input id="complement" placeholder="Complemento">
      <input id="password" type="password" placeholder="Senha com pelo menos 8 caracteres">

      <button onclick="createAccountAndOrder()">
        Criar conta e pedido
      </button>

      <p id="message" class="notice"></p>
    </section>
  \`;
}

function showCheckout() {
  document.getElementById("checkout").style.display = "block";
  document.getElementById("checkout").scrollIntoView({
    behavior: "smooth"
  });
}

async function createAccountAndOrder() {
  const message = document.getElementById("message");

  const account = {
    name: document.getElementById("name").value,
    cpf: document.getElementById("cpf").value,
    email: document.getElementById("email").value,
    phone: document.getElementById("phone").value,
    password: document.getElementById("password").value
  };

  const registerResponse = await fetch("/api/auth/register", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(account)
  });

  const registerData = await registerResponse.json();

  if (!registerResponse.ok) {
    message.textContent = registerData.error;
    return;
  }

  const shipping = {
    name: account.name,
    cpf: account.cpf,
    phone: account.phone,
    cep: document.getElementById("cep").value,
    state: document.getElementById("state").value,
    city: document.getElementById("city").value,
    street: document.getElementById("street").value,
    number: document.getElementById("number").value,
    complement: document.getElementById("complement").value
  };

  const orderResponse = await fetch("/api/orders", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      productId: product.id,
      quantity: 1,
      shipping
    })
  });

  const orderData = await orderResponse.json();

  if (!orderResponse.ok) {
    message.textContent = orderData.error;
    return;
  }

  message.textContent =
    "Pedido criado: " +
    orderData.orderNumber +
    ". O PIX será disponibilizado quando o gateway estiver configurado.";
}

loadProduct();
</script>
</body>
</html>
`;

app.get("*", (req, res) => {
  res.type("html").send(page);
});

app.listen(PORT, () => {
  console.log("Espaço PlayStation ativo na porta " + PORT);
});
