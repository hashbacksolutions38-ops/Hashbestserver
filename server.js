/*
 * Hashvest API
 *
 * Deploy this file to Render or Railway with:
 *   node server.js
 *
 * Required production variables:
 *   DATABASE_URL              Railway PostgreSQL connection string
 *   SESSION_SECRET            long random value used to sign/derive sessions
 *
 * Optional payment variables:
 *   HASHBACK_BASE_URL
 *   HASHBACK_API_KEY
 *   HASHBACK_ACCOUNT_ID
 *   HASHBACK_SECURITY_CREDENTIAL
 *   HASHBACK_STK_PATH
 *   HASHBACK_STATUS_PATH
 *   HASHBACK_PAYOUT_PATH
 *   HASHBACK_WEBHOOK_SECRET
 *   HASHBACK_CALLBACK_URL
 *   CORS_ORIGIN
 *   ADMIN_EMAIL
 *   ADMIN_PASSWORD
 *
 * The payment adapter intentionally returns the provider's HTTP status and
 * response body. A payment failure must be diagnosable by the operator.
 */

const http = require("node:http");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { URL } = require("node:url");
const { promisify } = require("node:util");
let Pool;
try {
  ({ Pool } = require("pg"));
} catch {
  // pg is owned by the existing database workspace package in this monorepo.
  // The fallback keeps `node server.js` usable before the root workspace is
  // reinstalled and is also harmless in a normal production install.
  ({ Pool } = require(path.join(__dirname, "lib/db/node_modules/pg")));
}

const scrypt = promisify(crypto.scrypt);
const PORT = Number(process.env.PORT || 8080);
const PUBLIC_DIR = path.join(__dirname, "public");
const SESSION_SECRET = process.env.SESSION_SECRET || "development-only-session-secret";
const DATABASE_URL = process.env.DATABASE_URL || process.env.RAILWAY_DATABASE_URL;
const CORS_ORIGIN = process.env.CORS_ORIGIN || "*";

const pool = DATABASE_URL
  ? new Pool({
      connectionString: DATABASE_URL,
      max: Number(process.env.DB_POOL_MAX || 10),
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 10_000,
      ssl: process.env.DATABASE_SSL === "false" ? false : { rejectUnauthorized: false },
    })
  : null;

const DEFAULT_SETTINGS = {
  trade_enabled: true,
  buy_enabled: true,
  sell_enabled: true,
  deposits_enabled: true,
  withdrawals_enabled: true,
  instant_withdrawal: false,
  registration_enabled: true,
  trade_duration: 60,
  prestart_wait: 5,
  min_stake: 10,
  max_stake: 50_000,
  payout_multiplier: 1.8,
  autosell_multiplier: 1.5,
  min_deposit: 50,
  min_withdrawal: 100,
  withdrawal_cooldown_minutes: 5,
  deposit_currency: "kes",
  usd_rate: 0,
  support_email: process.env.SUPPORT_EMAIL || "support@hashvest.co.ke",
  platform_name: "Hashvest",
};

const schemaSql = `
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL UNIQUE,
  phone TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  full_name TEXT NOT NULL DEFAULT '',
  country TEXT NOT NULL DEFAULT 'KE',
  date_of_birth DATE,
  avatar_url TEXT NOT NULL DEFAULT '',
  role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  balance NUMERIC(14,2) NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS sessions (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS sessions_token_hash_idx ON sessions(token_hash);
CREATE TABLE IF NOT EXISTS wallet_ledger (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  amount NUMERIC(14,2) NOT NULL,
  balance_after NUMERIC(14,2) NOT NULL,
  kind TEXT NOT NULL,
  reference TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS wallet_ledger_user_idx ON wallet_ledger(user_id, created_at DESC);
CREATE TABLE IF NOT EXISTS trades (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  direction TEXT NOT NULL CHECK (direction IN ('buy', 'sell')),
  stake NUMERIC(14,2) NOT NULL,
  entry_rate NUMERIC(18,8) NOT NULL,
  exit_rate NUMERIC(18,8),
  payout NUMERIC(14,2) NOT NULL DEFAULT 0,
  result TEXT NOT NULL DEFAULT 'open' CHECK (result IN ('open', 'win', 'loss', 'cancelled')),
  reason TEXT NOT NULL DEFAULT '',
  duration_seconds INTEGER NOT NULL,
  placed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  resolved_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS trades_user_idx ON trades(user_id, placed_at DESC);
CREATE TABLE IF NOT EXISTS payment_transactions (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('deposit', 'withdrawal')),
  gateway TEXT NOT NULL,
  amount NUMERIC(14,2) NOT NULL,
  phone TEXT NOT NULL DEFAULT '',
  provider_reference TEXT,
  provider_payload JSONB,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'completed', 'failed', 'cancelled')),
  failure_code TEXT NOT NULL DEFAULT '',
  failure_message TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS payment_transactions_user_idx ON payment_transactions(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS payment_transactions_provider_idx ON payment_transactions(provider_reference);
CREATE TABLE IF NOT EXISTS app_settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
`;

let databaseReady = false;
let databaseError = null;

function json(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "Content-Length": Buffer.byteLength(payload),
  });
  res.end(payload);
}

function text(res, status, body, contentType = "text/plain; charset=utf-8") {
  res.writeHead(status, { "Content-Type": contentType });
  res.end(body);
}

function setCors(res) {
  res.setHeader("Access-Control-Allow-Origin", CORS_ORIGIN);
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Admin-Key");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PATCH, OPTIONS");
  res.setHeader("Access-Control-Expose-Headers", "X-Request-Id");
}

function requestId() {
  return crypto.randomUUID();
}

function uid() {
  return crypto.randomUUID();
}

function hashToken(value) {
  return crypto.createHmac("sha256", SESSION_SECRET).update(value).digest("hex");
}

function normalizePhone(input) {
  const digits = String(input || "").replace(/\D/g, "");
  if (/^0\d{9}$/.test(digits)) return `254${digits.slice(1)}`;
  if (/^7\d{8}$/.test(digits) || /^1\d{8}$/.test(digits)) return `254${digits}`;
  if (/^254\d{9}$/.test(digits)) return digits;
  return null;
}

function safeNumber(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function roundMoney(value) {
  return Math.round((safeNumber(value) + Number.EPSILON) * 100) / 100;
}

function publicUser(row) {
  if (!row) return null;
  return {
    id: row.id,
    username: row.username,
    email: row.email,
    phone: row.phone,
    fullName: row.full_name,
    country: row.country,
    dateOfBirth: row.date_of_birth,
    avatarUrl: row.avatar_url,
    role: row.role,
    isActive: row.is_active,
    balance: safeNumber(row.balance),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function errorBody(error, requestIdValue) {
  return {
    error: error?.message || "Unexpected server error",
    code: error?.code || "INTERNAL_ERROR",
    requestId: requestIdValue,
    ...(error?.details ? { details: error.details } : {}),
  };
}

async function readBody(req) {
  const chunks = [];
  let length = 0;
  for await (const chunk of req) {
    length += chunk.length;
    if (length > 2_000_000) {
      const error = new Error("Request body is too large");
      error.code = "PAYLOAD_TOO_LARGE";
      throw error;
    }
    chunks.push(chunk);
  }
  if (chunks.length === 0) return {};
  const raw = Buffer.concat(chunks).toString("utf8");
  req.rawBody = Buffer.from(raw);
  const contentType = String(req.headers["content-type"] || "");
  if (contentType.includes("application/json")) {
    try {
      return JSON.parse(raw);
    } catch {
      const error = new Error("Request body must be valid JSON");
      error.code = "INVALID_JSON";
      throw error;
    }
  }
  return Object.fromEntries(new URLSearchParams(raw));
}

function queryPath(urlPath) {
  return urlPath.replace(/\/+$/, "") || "/";
}

async function dbQuery(textQuery, values = []) {
  if (!pool) {
    const error = new Error("DATABASE_URL is not configured. Connect the Railway PostgreSQL database first.");
    error.code = "DATABASE_NOT_CONFIGURED";
    throw error;
  }
  return pool.query(textQuery, values);
}

async function withTransaction(callback) {
  if (!pool) {
    const error = new Error("DATABASE_URL is not configured. Connect the Railway PostgreSQL database first.");
    error.code = "DATABASE_NOT_CONFIGURED";
    throw error;
  }
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const result = await callback(client);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

async function passwordHash(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const derived = await scrypt(String(password), salt, 64);
  return `scrypt:${salt}:${derived.toString("hex")}`;
}

async function verifyPassword(password, encoded) {
  const [, salt, expectedHex] = String(encoded || "").split(":");
  if (!salt || !expectedHex) return false;
  const actual = await scrypt(String(password), salt, 64);
  const expected = Buffer.from(expectedHex, "hex");
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}

async function createSession(userId) {
  const rawToken = crypto.randomBytes(32).toString("base64url");
  await dbQuery(
    "INSERT INTO sessions (id, user_id, token_hash, expires_at) VALUES ($1, $2, $3, NOW() + INTERVAL '30 days')",
    [uid(), userId, hashToken(rawToken)],
  );
  return rawToken;
}

function bearerToken(req) {
  const value = String(req.headers.authorization || "");
  return value.startsWith("Bearer ") ? value.slice(7).trim() : "";
}

async function currentUser(req) {
  const token = bearerToken(req);
  if (!token) return null;
  const result = await dbQuery(
    `SELECT u.* FROM users u
     JOIN sessions s ON s.user_id = u.id
     WHERE s.token_hash = $1 AND s.expires_at > NOW() AND u.is_active = TRUE
     LIMIT 1`,
    [hashToken(token)],
  );
  return result.rows[0] || null;
}

async function requireUser(req) {
  const user = await currentUser(req);
  if (!user) {
    const error = new Error("Authentication required");
    error.code = "AUTH_REQUIRED";
    throw error;
  }
  return user;
}

async function requireAdmin(req) {
  const user = await requireUser(req);
  if (user.role !== "admin") {
    const error = new Error("Administrator access required");
    error.code = "ADMIN_REQUIRED";
    throw error;
  }
  return user;
}

async function getSettings() {
  const values = { ...DEFAULT_SETTINGS };
  const result = await dbQuery("SELECT key, value FROM app_settings");
  for (const row of result.rows) {
    if (!(row.key in values)) continue;
    const defaultValue = values[row.key];
    values[row.key] =
      typeof defaultValue === "number"
        ? safeNumber(row.value, defaultValue)
        : typeof defaultValue === "boolean"
          ? row.value === "true"
          : row.value;
  }
  return values;
}

async function ensureAdminFromEnvironment() {
  if (!pool || !process.env.ADMIN_EMAIL || !process.env.ADMIN_PASSWORD) return;
  const email = process.env.ADMIN_EMAIL.trim().toLowerCase();
  const existing = await dbQuery("SELECT id FROM users WHERE email = $1 LIMIT 1", [email]);
  const password = await passwordHash(process.env.ADMIN_PASSWORD);
  if (existing.rowCount === 0) {
    await dbQuery(
      `INSERT INTO users (id, username, email, phone, password_hash, full_name, role)
       VALUES ($1, $2, $3, $4, $5, $6, 'admin')`,
      [uid(), "admin", email, "254700000000", password, "Platform Administrator"],
    );
  } else {
    await dbQuery("UPDATE users SET role = 'admin', password_hash = $1, updated_at = NOW() WHERE email = $2", [password, email]);
  }
}

async function initDatabase() {
  if (!pool) {
    databaseError = "DATABASE_URL is not configured";
    return;
  }
  try {
    await dbQuery(schemaSql);
    for (const [key, value] of Object.entries(DEFAULT_SETTINGS)) {
      await dbQuery(
        `INSERT INTO app_settings (key, value) VALUES ($1, $2)
         ON CONFLICT (key) DO NOTHING`,
        [key, String(value)],
      );
    }
    await dbQuery(
      "UPDATE app_settings SET value = 'Hashvest', updated_at = NOW() WHERE key = 'platform_name' AND value = 'ShikaPesa Trade Gurus'",
    );
    await dbQuery(
      "UPDATE app_settings SET value = $1, updated_at = NOW() WHERE key = 'support_email' AND value = 'support@shikapesa.com'",
      [process.env.SUPPORT_EMAIL || "support@hashvest.co.ke"],
    );
    await ensureAdminFromEnvironment();
    databaseReady = true;
  } catch (error) {
    databaseError = error.message;
    console.error("[database:init]", error);
  }
}

function providerError(message, details, code = "HASHBACK_PROVIDER_ERROR") {
  const error = new Error(message);
  error.code = code;
  error.details = details;
  return error;
}

async function hashbackRequest({ path: providerPath, method = "POST", payload = {}, includeAccountId = false }) {
  const baseUrl = process.env.HASHBACK_BASE_URL || "https://api.hashback.co.ke";
  const apiKey = process.env.HASHBACK_API_KEY;
  const accountId = process.env.HASHBACK_ACCOUNT_ID;
  if (!apiKey || (includeAccountId && !accountId)) {
    const missing = [];
    if (!apiKey) missing.push("HASHBACK_API_KEY");
    if (includeAccountId && !accountId) missing.push("HASHBACK_ACCOUNT_ID");
    throw providerError(
      "HashBack is not configured. Add the required HashBack environment variables.",
      { missing },
      "HASHBACK_NOT_CONFIGURED",
    );
  }
  const target = new URL(providerPath, baseUrl).toString();
  const requestPayload = {
    api_key: apiKey,
    ...(includeAccountId ? { account_id: accountId } : {}),
    ...payload,
  };
  let response;
  try {
    response = await fetch(target, {
      method,
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: method === "GET" ? undefined : JSON.stringify(requestPayload),
    });
  } catch (cause) {
    throw providerError("Could not connect to HashBack.", { cause: cause.message, url: target }, "HASHBACK_NETWORK_ERROR");
  }
  const raw = await response.text();
  let body = raw;
  try {
    body = raw ? JSON.parse(raw) : null;
  } catch {
    // Keep the provider's raw non-JSON response visible.
  }
  if (!response.ok) {
    throw providerError(`HashBack returned HTTP ${response.status}.`, {
      providerStatus: response.status,
      providerBody: body,
      url: target,
    });
  }
  return { status: response.status, body, headers: Object.fromEntries(response.headers.entries()) };
}

function hashbackReference(body, fallback = "") {
  const candidates = [
    body?.reference,
    body?.transaction_id,
    body?.transactionId,
    body?.checkout_request_id,
    body?.CheckoutRequestID,
    body?.checkout_id,
    body?.MerchantRequestID,
    body?.TransactionID,
    body?.data?.reference,
    body?.data?.transaction_id,
    body?.data?.transactionId,
    body?.data?.checkout_request_id,
    body?.transaction?.id,
  ];
  return String(candidates.find(value => value !== undefined && value !== null && String(value).trim()) || fallback);
}

function hashbackStatus(body) {
  const candidates = [
    body?.status,
    body?.payment_status,
    body?.transaction_status,
    body?.result,
    body?.data?.status,
    body?.transaction?.status,
    body?.ResponseDescription,
    body?.ResultDescription,
  ].filter(value => value !== undefined && value !== null).map(value => String(value).toLowerCase());
  if (candidates.some(value => ["success", "successful", "completed", "complete", "paid", "confirmed"].some(token => value.includes(token)))) return "completed";
  if (candidates.some(value => ["failed", "failure", "cancelled", "canceled", "rejected", "declined", "expired"].some(token => value.includes(token)))) return "failed";
  const code = body?.ResultCode ?? body?.response_code ?? body?.ResponseCode ?? body?.result_code;
  if (String(code) === "0" && hashbackReference(body)) return "completed";
  return "pending";
}

function hashbackAmount(body) {
  const candidates = [
    body?.amount,
    body?.TransactionAmount,
    body?.transaction_amount,
    body?.data?.amount,
    body?.transaction?.amount,
  ];
  const value = candidates.find(item => item !== undefined && item !== null && item !== "");
  return value === undefined ? null : roundMoney(value);
}

async function recordLedger(client, { userId, amount, kind, reference, description }) {
  const updated = await client.query(
    "UPDATE users SET balance = balance + $1, updated_at = NOW() WHERE id = $2 RETURNING balance",
    [roundMoney(amount), userId],
  );
  if (updated.rowCount === 0) throw new Error("User account was not found");
  const balanceAfter = safeNumber(updated.rows[0].balance);
  await client.query(
    `INSERT INTO wallet_ledger (id, user_id, amount, balance_after, kind, reference, description)
     VALUES ($1, $2, $3, $4, $5, $6, $7)`,
    [uid(), userId, roundMoney(amount), balanceAfter, kind, reference, description],
  );
  return balanceAfter;
}

async function completePaymentByReference(providerReference, providerPayload = {}) {
  return withTransaction(async (client) => {
    const paymentResult = await client.query(
      "SELECT * FROM payment_transactions WHERE provider_reference = $1 FOR UPDATE",
      [providerReference],
    );
    if (paymentResult.rowCount === 0) {
      const error = new Error(`No payment transaction matches provider reference ${providerReference}`);
      error.code = "PAYMENT_REFERENCE_NOT_FOUND";
      throw error;
    }
    const payment = paymentResult.rows[0];
    if (payment.status === "completed") {
      const user = await client.query("SELECT balance FROM users WHERE id = $1", [payment.user_id]);
      return { alreadyCompleted: true, balance: safeNumber(user.rows[0]?.balance) };
    }
    const receivedAmount = hashbackAmount(providerPayload);
    if (receivedAmount !== null && receivedAmount !== roundMoney(payment.amount)) {
      const error = new Error("HashBack payment amount does not match the requested deposit");
      error.code = "PAYMENT_AMOUNT_MISMATCH";
      error.details = { expected: roundMoney(payment.amount), received: receivedAmount };
      throw error;
    }
    await client.query(
      `UPDATE payment_transactions
       SET status = 'completed', provider_payload = $1, updated_at = NOW()
       WHERE id = $2`,
      [providerPayload, payment.id],
    );
    const balance = await recordLedger(client, {
      userId: payment.user_id,
      amount: payment.amount,
      kind: "deposit",
      reference: `deposit:${payment.id}`,
      description: `Deposit via ${payment.gateway}`,
    });
    return { balance, paymentId: payment.id };
  });
}

async function completePaymentByCandidates(candidates, providerPayload = {}) {
  const references = [...new Set(candidates.map(value => String(value || "").trim()).filter(Boolean))];
  if (!references.length) {
    const error = new Error("HashBack payment reference missing");
    error.code = "INVALID_WEBHOOK";
    throw error;
  }
  return withTransaction(async (client) => {
    const paymentResult = await client.query(
      `SELECT * FROM payment_transactions
       WHERE kind = 'deposit' AND (provider_reference = ANY($1::text[]) OR id::text = ANY($1::text[]))
       ORDER BY created_at DESC LIMIT 1 FOR UPDATE`,
      [references],
    );
    if (paymentResult.rowCount === 0) {
      const error = new Error("No deposit matches the HashBack webhook reference");
      error.code = "PAYMENT_REFERENCE_NOT_FOUND";
      throw error;
    }
    const payment = paymentResult.rows[0];
    if (payment.status === "completed") {
      const user = await client.query("SELECT balance FROM users WHERE id = $1", [payment.user_id]);
      return { alreadyCompleted: true, balance: safeNumber(user.rows[0]?.balance), paymentId: payment.id };
    }
    const receivedAmount = hashbackAmount(providerPayload);
    if (receivedAmount !== null && receivedAmount !== roundMoney(payment.amount)) {
      const error = new Error("HashBack payment amount does not match the requested deposit");
      error.code = "PAYMENT_AMOUNT_MISMATCH";
      error.details = { expected: roundMoney(payment.amount), received: receivedAmount };
      throw error;
    }
    await client.query(
      `UPDATE payment_transactions
       SET status = 'completed', provider_payload = $1, updated_at = NOW()
       WHERE id = $2`,
      [providerPayload, payment.id],
    );
    const balance = await recordLedger(client, {
      userId: payment.user_id,
      amount: payment.amount,
      kind: "deposit",
      reference: `deposit:${payment.id}`,
      description: "Deposit via HashBack",
    });
    return { balance, paymentId: payment.id };
  });
}

async function pollHashbackDeposit(paymentId, userId) {
  const result = await dbQuery(
    "SELECT * FROM payment_transactions WHERE id = $1 AND user_id = $2 AND kind = 'deposit' LIMIT 1",
    [paymentId, userId],
  );
  const payment = result.rows[0];
  if (!payment) return { status: "not_found", balance: 0 };
  if (payment.status !== "pending") {
    const user = await dbQuery("SELECT balance FROM users WHERE id = $1", [userId]);
    return { status: payment.status, reference: payment.provider_reference, balance: safeNumber(user.rows[0]?.balance) };
  }
  try {
    const response = await hashbackRequest({
      path: process.env.HASHBACK_STATUS_PATH || "/transactionstatus",
      includeAccountId: true,
      payload: {
        transaction_id: payment.provider_reference,
        reference: payment.provider_reference,
      },
    });
    const status = hashbackStatus(response.body);
    if (status === "completed") {
      const completed = await completePaymentByReference(payment.provider_reference, response.body);
      return { status: "completed", reference: payment.provider_reference, balance: completed.balance, provider: response.body };
    }
    if (status === "failed") {
      await dbQuery(
        `UPDATE payment_transactions
         SET status = 'failed', failure_code = 'HASHBACK_PAYMENT_FAILED',
             failure_message = $1, provider_payload = $2, updated_at = NOW()
         WHERE id = $3 AND status = 'pending'`,
        [String(response.body?.message || response.body?.ResultDescription || "HashBack reported a failed payment"), response.body, payment.id],
      );
    }
    const user = await dbQuery("SELECT balance FROM users WHERE id = $1", [userId]);
    return { status, reference: payment.provider_reference, balance: safeNumber(user.rows[0]?.balance), provider: response.body };
  } catch (error) {
    // A temporary HashBack status failure must not turn a still-pending deposit
    // into a failed deposit. The browser can safely retry the status request.
    const user = await dbQuery("SELECT balance FROM users WHERE id = $1", [userId]);
    return {
      status: "pending",
      reference: payment.provider_reference,
      balance: safeNumber(user.rows[0]?.balance),
      provider_error: error.message,
    };
  }
}

async function withdrawalAvailability(userId, cooldownMinutes) {
  const cooldownSeconds = Math.max(0, safeNumber(cooldownMinutes, 5) * 60);
  const result = await dbQuery(
    `SELECT created_at FROM payment_transactions
     WHERE user_id = $1 AND kind = 'withdrawal'
     ORDER BY created_at DESC LIMIT 1`,
    [userId],
  );
  if (result.rowCount === 0 || cooldownSeconds === 0) {
    return { canWithdraw: true, remainingSeconds: 0, availableAt: null, cooldownSeconds };
  }
  const availableAtMs = new Date(result.rows[0].created_at).getTime() + cooldownSeconds * 1000;
  const remainingSeconds = Math.max(0, Math.ceil((availableAtMs - Date.now()) / 1000));
  return {
    canWithdraw: remainingSeconds === 0,
    remainingSeconds,
    availableAt: remainingSeconds ? new Date(availableAtMs).toISOString() : null,
    cooldownSeconds,
  };
}

async function handleAuthRegister(body) {
  const settings = await getSettings();
  if (!settings.registration_enabled) {
    throw Object.assign(new Error("New account registration is temporarily disabled"), { code: "REGISTRATION_DISABLED" });
  }
  const username = String(body.username || "").trim();
  const email = String(body.email || "").trim().toLowerCase();
  const phone = normalizePhone(body.phone);
  const password = String(body.password || "");
  const confirmPassword = String(body.confirm_password || body.confirmPassword || password);
  if (!/^[a-zA-Z0-9_.-]{3,40}$/.test(username)) throw Object.assign(new Error("Username must be 3-40 letters, numbers, dots, dashes, or underscores"), { code: "VALIDATION_ERROR" });
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) throw Object.assign(new Error("A valid email is required"), { code: "VALIDATION_ERROR" });
  if (!phone) throw Object.assign(new Error("Phone must be a Kenyan number such as 0712345678 or 254712345678"), { code: "VALIDATION_ERROR" });
  if (password.length < 8) throw Object.assign(new Error("Password must be at least 8 characters"), { code: "VALIDATION_ERROR" });
  if (password !== confirmPassword) throw Object.assign(new Error("Passwords do not match"), { code: "VALIDATION_ERROR" });
  const passwordEncoded = await passwordHash(password);
  const user = await withTransaction(async (client) => {
    const result = await client.query(
      `INSERT INTO users (id, username, email, phone, password_hash, full_name, country, date_of_birth)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING *`,
      [
        uid(),
        username,
        email,
        phone,
        passwordEncoded,
        String(body.full_name || body.fullName || "").trim(),
        String(body.country || "KE").trim().slice(0, 2).toUpperCase(),
        body.date_of_birth || body.dateOfBirth || null,
      ],
    );
    return result.rows[0];
  });
  return { user, token: await createSession(user.id) };
}

async function handleAuthLogin(body) {
  const identifier = String(body.email || body.phone || body.identifier || "").trim().toLowerCase();
  const result = await dbQuery(
    "SELECT * FROM users WHERE LOWER(email) = $1 OR phone = $1 OR username = $1 LIMIT 1",
    [identifier],
  );
  const user = result.rows[0];
  if (!user || !(await verifyPassword(body.password, user.password_hash))) {
    throw Object.assign(new Error("Invalid email, phone, username, or password"), { code: "INVALID_CREDENTIALS" });
  }
  if (!user.is_active) throw Object.assign(new Error("This account is disabled"), { code: "ACCOUNT_DISABLED" });
  return { user, token: await createSession(user.id) };
}

async function handleTrade(user, body) {
  const settings = await getSettings();
  const action = String(body.action || "place");
  if (action === "place" && !settings.trade_enabled) throw Object.assign(new Error("Trading is temporarily disabled by the administrator"), { code: "TRADING_DISABLED" });
  if (action === "balance") return { balance: safeNumber(user.balance) };
  if (action === "place") {
    const direction = body.type === "sell" || body.direction === "sell" ? "sell" : "buy";
    if (direction === "buy" && !settings.buy_enabled) throw Object.assign(new Error("Buy trades are temporarily disabled"), { code: "BUY_DISABLED" });
    if (direction === "sell" && !settings.sell_enabled) throw Object.assign(new Error("Sell trades are temporarily disabled"), { code: "SELL_DISABLED" });
    const stake = roundMoney(body.stake);
    const entryRate = safeNumber(body.entry_rate ?? body.entryRate);
    if (stake < settings.min_stake || stake > settings.max_stake) throw Object.assign(new Error(`Stake must be between KES ${settings.min_stake} and KES ${settings.max_stake}`), { code: "STAKE_OUT_OF_RANGE" });
    if (!Number.isFinite(entryRate)) throw Object.assign(new Error("A valid entry rate is required"), { code: "VALIDATION_ERROR" });
    return withTransaction(async (client) => {
      const locked = await client.query("SELECT * FROM users WHERE id = $1 FOR UPDATE", [user.id]);
      const current = locked.rows[0];
      if (safeNumber(current.balance) < stake) throw Object.assign(new Error("Insufficient balance. Please deposit first."), { code: "INSUFFICIENT_BALANCE" });
      const tradeId = uid();
      await client.query(
        `INSERT INTO trades (id, user_id, direction, stake, entry_rate, duration_seconds)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [tradeId, user.id, direction, stake, entryRate, settings.trade_duration],
      );
      const balance = await recordLedger(client, {
        userId: user.id,
        amount: -stake,
        kind: "trade_stake",
        reference: `trade-stake:${tradeId}`,
        description: `${direction.toUpperCase()} trade stake`,
      });
      return { trade_id: tradeId, balance, prestart_wait: settings.prestart_wait, duration: settings.trade_duration };
    });
  }
  if (action === "cancel") {
    const tradeId = String(body.trade_id || "");
    return withTransaction(async (client) => {
      const result = await client.query("SELECT * FROM trades WHERE id = $1 AND user_id = $2 FOR UPDATE", [tradeId, user.id]);
      const trade = result.rows[0];
      if (!trade || trade.result !== "open") throw Object.assign(new Error("Trade is no longer open"), { code: "TRADE_NOT_OPEN" });
      const ageSeconds = (Date.now() - new Date(trade.placed_at).getTime()) / 1000;
      if (ageSeconds > settings.prestart_wait) throw Object.assign(new Error("The cancellation window has closed"), { code: "CANCEL_WINDOW_CLOSED" });
      await client.query("UPDATE trades SET result = 'cancelled', reason = 'user_cancelled', resolved_at = NOW() WHERE id = $1", [tradeId]);
      const balance = await recordLedger(client, {
        userId: user.id,
        amount: safeNumber(trade.stake),
        kind: "trade_cancel",
        reference: `trade-cancel:${tradeId}`,
        description: "Trade stake returned after cancellation",
      });
      return { balance, result: "cancelled", payout: safeNumber(trade.stake) };
    });
  }
  if (action === "resolve") {
    const tradeId = String(body.trade_id || "");
    const exitRate = safeNumber(body.exit_rate ?? body.exitRate);
    return withTransaction(async (client) => {
      const result = await client.query("SELECT * FROM trades WHERE id = $1 AND user_id = $2 FOR UPDATE", [tradeId, user.id]);
      const trade = result.rows[0];
      if (!trade || trade.result !== "open") throw Object.assign(new Error("Trade is no longer open"), { code: "TRADE_NOT_OPEN" });
      const ageSeconds = (Date.now() - new Date(trade.placed_at).getTime()) / 1000;
      if (ageSeconds < settings.prestart_wait) throw Object.assign(new Error("Trade has not started yet"), { code: "TRADE_NOT_STARTED" });
      const isExpired = Boolean(body.expired) || ageSeconds >= safeNumber(trade.duration_seconds, settings.trade_duration);
      const isWin = !isExpired && (trade.direction === "buy" ? exitRate > safeNumber(trade.entry_rate) : exitRate < safeNumber(trade.entry_rate));
      const payout = isWin ? roundMoney(safeNumber(trade.stake) * settings.payout_multiplier) : 0;
      const tradeResult = isWin ? "win" : "loss";
      const reason = isExpired ? "expired" : String(body.reason || "manual");
      await client.query(
        "UPDATE trades SET exit_rate = $1, payout = $2, result = $3, reason = $4, resolved_at = NOW() WHERE id = $5",
        [exitRate, payout, tradeResult, reason, tradeId],
      );
      const balance = payout > 0
        ? await recordLedger(client, { userId: user.id, amount: payout, kind: "trade_payout", reference: `trade-payout:${tradeId}`, description: `Winning ${trade.direction.toUpperCase()} trade payout` })
        : safeNumber((await client.query("SELECT balance FROM users WHERE id = $1", [user.id])).rows[0]?.balance);
      return { balance, result: tradeResult, payout, reason };
    });
  }
  throw Object.assign(new Error(`Unknown trade action: ${action}`), { code: "UNKNOWN_ACTION" });
}

async function startDeposit(user, body, forcedGateway) {
  const settings = await getSettings();
  if (!settings.deposits_enabled) throw Object.assign(new Error("Deposits are temporarily disabled by the administrator"), { code: "DEPOSITS_DISABLED" });
  const amount = roundMoney(body.amount);
  const phone = normalizePhone(body.phone || user.phone);
  const gateway = forcedGateway || body.gateway || "hashback";
  if (amount < settings.min_deposit) throw Object.assign(new Error(`Minimum deposit is KES ${settings.min_deposit}`), { code: "DEPOSIT_TOO_SMALL" });
  if (!phone) throw Object.assign(new Error("A valid Kenyan phone number is required"), { code: "VALIDATION_ERROR" });
  const paymentId = uid();
  await dbQuery(
    `INSERT INTO payment_transactions (id, user_id, kind, gateway, amount, phone)
     VALUES ($1, $2, 'deposit', $3, $4, $5)`,
    [paymentId, user.id, gateway, amount, phone],
  );
  try {
    const response = await hashbackRequest({
      path: process.env.HASHBACK_STK_PATH || "/initiatestk",
      includeAccountId: true,
      payload: {
        amount,
        msisdn: phone,
        phone,
        reference: paymentId,
        callback_url: process.env.HASHBACK_CALLBACK_URL || undefined,
      },
    });
    if (response.body?.success === false) {
      throw providerError(
        String(response.body?.message || response.body?.error || "HashBack rejected the STK Push request"),
        { providerBody: response.body },
        "HASHBACK_STK_REJECTED",
      );
    }
    const providerReference = hashbackReference(response.body, paymentId);
    await dbQuery(
      "UPDATE payment_transactions SET provider_reference = $1, provider_payload = $2, updated_at = NOW() WHERE id = $3",
      [providerReference, response.body, paymentId],
    );
    return { success: true, transaction_id: paymentId, reference: providerReference, status: "pending", provider: response.body };
  } catch (error) {
    await dbQuery(
      "UPDATE payment_transactions SET status = 'failed', failure_code = $1, failure_message = $2, provider_payload = $3, updated_at = NOW() WHERE id = $4",
      [error.code || "PROVIDER_ERROR", error.message, error.details || null, paymentId],
    );
    throw error;
  }
}

async function startWithdrawal(user, body) {
  const settings = await getSettings();
  if (!settings.withdrawals_enabled) throw Object.assign(new Error("Withdrawals are temporarily disabled by the administrator"), { code: "WITHDRAWALS_DISABLED" });
  const amount = roundMoney(body.amount);
  if (amount < settings.min_withdrawal) throw Object.assign(new Error(`Minimum withdrawal is KES ${settings.min_withdrawal}`), { code: "WITHDRAWAL_TOO_SMALL" });
  const paymentId = uid();
  const request = await withTransaction(async (client) => {
    const locked = await client.query("SELECT * FROM users WHERE id = $1 FOR UPDATE", [user.id]);
    const lastWithdrawal = await client.query(
      `SELECT created_at FROM payment_transactions
       WHERE user_id = $1 AND kind = 'withdrawal'
       ORDER BY created_at DESC LIMIT 1`,
      [user.id],
    );
    const cooldownSeconds = Math.max(0, safeNumber(settings.withdrawal_cooldown_minutes, 5) * 60);
    if (lastWithdrawal.rowCount > 0 && cooldownSeconds > 0) {
      const availableAtMs = new Date(lastWithdrawal.rows[0].created_at).getTime() + cooldownSeconds * 1000;
      const remainingSeconds = Math.max(0, Math.ceil((availableAtMs - Date.now()) / 1000));
      if (remainingSeconds > 0) {
        const error = new Error(`Please wait ${Math.ceil(remainingSeconds / 60)} minute(s) before requesting another withdrawal`);
        error.code = "WITHDRAWAL_COOLDOWN";
        error.details = { remainingSeconds, availableAt: new Date(availableAtMs).toISOString() };
        throw error;
      }
    }
    if (safeNumber(locked.rows[0]?.balance) < amount) throw Object.assign(new Error("Amount exceeds your balance"), { code: "INSUFFICIENT_BALANCE" });
    await client.query(
      `INSERT INTO payment_transactions (id, user_id, kind, gateway, amount, phone)
       VALUES ($1, $2, 'withdrawal', 'hashback', $3, $4)`,
      [paymentId, user.id, amount, locked.rows[0].phone],
    );
    const balance = await recordLedger(client, {
      userId: user.id,
      amount: -amount,
      kind: "withdrawal_hold",
      reference: `withdrawal-hold:${paymentId}`,
      description: "HashBack withdrawal request hold",
    });
    return {
      success: true,
      transaction_id: paymentId,
      balance,
      status: "pending",
      cooldown_until: new Date(Date.now() + cooldownSeconds * 1000).toISOString(),
    };
  });
  if (!settings.instant_withdrawal) return request;
  return dispatchWithdrawal(paymentId);
}

async function dispatchWithdrawal(paymentId) {
  const paymentResult = await dbQuery(
    `SELECT p.*, u.phone AS user_phone FROM payment_transactions p
     JOIN users u ON u.id = p.user_id
     WHERE p.id = $1 LIMIT 1`,
    [paymentId],
  );
  const payment = paymentResult.rows[0];
  if (!payment) throw Object.assign(new Error("Withdrawal request was not found"), { code: "WITHDRAWAL_NOT_FOUND" });
  if (payment.status !== "pending") {
    return { success: true, transaction_id: payment.id, status: payment.status, balance: safeNumber((await dbQuery("SELECT balance FROM users WHERE id = $1", [payment.user_id])).rows[0]?.balance) };
  }
  try {
    if (!process.env.HASHBACK_SECURITY_CREDENTIAL) {
      throw providerError(
        "HashBack withdrawal is not configured. Add HASHBACK_SECURITY_CREDENTIAL.",
        { missing: ["HASHBACK_SECURITY_CREDENTIAL"] },
        "HASHBACK_NOT_CONFIGURED",
      );
    }
    const response = await hashbackRequest({
      path: process.env.HASHBACK_PAYOUT_PATH || "/V2/processwithdrawal",
      payload: {
        amount: safeNumber(payment.amount),
        msisdn: payment.phone || payment.user_phone,
        SecurityCredential: process.env.HASHBACK_SECURITY_CREDENTIAL,
      },
    });
    if (response.body?.success === false) {
      throw providerError(
        String(response.body?.message || response.body?.error || "HashBack rejected the withdrawal"),
        { providerBody: response.body },
        "HASHBACK_WITHDRAWAL_REJECTED",
      );
    }
    const providerReference = hashbackReference(response.body, payment.id);
    await dbQuery(
      `UPDATE payment_transactions
       SET status = 'completed', provider_reference = $1, provider_payload = $2, updated_at = NOW()
       WHERE id = $3 AND status = 'pending'`,
      [providerReference, response.body, payment.id],
    );
    const balance = safeNumber((await dbQuery("SELECT balance FROM users WHERE id = $1", [payment.user_id])).rows[0]?.balance);
    return { success: true, transaction_id: payment.id, reference: providerReference, status: "completed", balance, provider: response.body };
  } catch (error) {
    await refundWithdrawal(payment.id, error.code || "WITHDRAWAL_PROVIDER_ERROR", error.message, error.details);
    throw error;
  }
}

async function refundWithdrawal(paymentId, failureCode, failureMessage, providerPayload = null) {
  return withTransaction(async (client) => {
    const result = await client.query("SELECT * FROM payment_transactions WHERE id = $1 FOR UPDATE", [paymentId]);
    const payment = result.rows[0];
    if (!payment || payment.status !== "pending") return null;
    await client.query(
      `UPDATE payment_transactions
       SET status = 'failed', failure_code = $1, failure_message = $2, provider_payload = $3, updated_at = NOW()
       WHERE id = $4`,
      [failureCode, failureMessage, providerPayload, paymentId],
    );
    return recordLedger(client, {
      userId: payment.user_id,
      amount: safeNumber(payment.amount),
      kind: "withdrawal_refund",
      reference: `withdrawal-refund:${paymentId}`,
      description: "Withdrawal request returned after provider failure",
    });
  });
}

async function rejectWithdrawal(paymentId, reason = "Rejected by administrator") {
  return withTransaction(async (client) => {
    const result = await client.query("SELECT * FROM payment_transactions WHERE id = $1 FOR UPDATE", [paymentId]);
    const payment = result.rows[0];
    if (!payment) throw Object.assign(new Error("Withdrawal request was not found"), { code: "WITHDRAWAL_NOT_FOUND" });
    if (payment.status !== "pending") throw Object.assign(new Error(`Withdrawal is already ${payment.status}`), { code: "WITHDRAWAL_NOT_PENDING" });
    await client.query(
      `UPDATE payment_transactions SET status = 'cancelled', failure_code = 'ADMIN_REJECTED',
       failure_message = $1, updated_at = NOW() WHERE id = $2`,
      [reason, paymentId],
    );
    const balance = await recordLedger(client, {
      userId: payment.user_id,
      amount: safeNumber(payment.amount),
      kind: "withdrawal_refund",
      reference: `withdrawal-reject:${paymentId}`,
      description: reason,
    });
    return { success: true, transaction_id: paymentId, status: "cancelled", balance };
  });
}

async function routeRequest(req, res, urlPath, body) {
  const method = req.method || "GET";
  const pathName = queryPath(urlPath);

  if (pathName === "/favicon.ico" || pathName === "/api/favicon.ico") {
    res.writeHead(204);
    return res.end();
  }

  if (method === "GET" && (pathName === "/healthz" || pathName === "/health")) {
    return json(res, 200, {
      status: databaseReady ? "ok" : "degraded",
      service: "hashvest-api",
      database: databaseReady ? "connected" : "unavailable",
      databaseError,
      timestamp: new Date().toISOString(),
    });
  }

  if (pathName === "/api" || pathName === "/api/") return serveStatic(res, "/index.html");
  if (!pathName.startsWith("/api/")) return serveStatic(res, pathName);
  if (method === "OPTIONS") return json(res, 204, {});

  const apiPath = pathName.slice(4).replace(/\.php$/, "");
  if (apiPath.endsWith(".html")) return serveStatic(res, apiPath);

  if (apiPath === "/healthz" || apiPath === "/health") {
    return json(res, 200, {
      status: databaseReady ? "ok" : "degraded",
      service: "hashvest-api",
      database: databaseReady ? "connected" : "unavailable",
      databaseError,
      timestamp: new Date().toISOString(),
    });
  }

  if (apiPath === "/auth/register" && method === "POST") {
    const result = await handleAuthRegister(body);
    return json(res, 201, { success: true, token: result.token, user: publicUser(result.user) });
  }
  if (apiPath === "/auth/login" && method === "POST") {
    const result = await handleAuthLogin(body);
    return json(res, 200, { success: true, token: result.token, user: publicUser(result.user) });
  }
  if (apiPath === "/auth/logout" && method === "POST") {
    const token = bearerToken(req);
    if (token) await dbQuery("DELETE FROM sessions WHERE token_hash = $1", [hashToken(token)]);
    return json(res, 200, { success: true });
  }
  if (apiPath === "/auth/me" && method === "GET") {
    const user = await requireUser(req);
    return json(res, 200, { user: publicUser(user) });
  }
  if (apiPath === "/settings" && method === "GET") {
    const settings = await getSettings();
    return json(res, 200, {
      trade: {
        enabled: settings.trade_enabled,
        buy_enabled: settings.buy_enabled,
        sell_enabled: settings.sell_enabled,
        duration: settings.trade_duration,
        min_stake: settings.min_stake,
        max_stake: settings.max_stake,
        prestart_wait: settings.prestart_wait,
        autosell_multiplier: settings.autosell_multiplier,
        max_multiplier: settings.payout_multiplier,
      },
      payments: settings,
    });
  }

  // HashBack can call this endpoint when a payment completes. It does not
  // require a browser session. Signature verification is mandatory when a
  // webhook secret is configured.
  if (apiPath === "/payments/hashback/webhook" && method === "POST") {
    const secret = process.env.HASHBACK_WEBHOOK_SECRET;
    const signature = String(req.headers["x-hashpay-signature"] || req.headers["x-hashback-signature"] || "");
    if (!secret) return json(res, 503, { error: "HashBack webhook secret is not configured", code: "HASHBACK_WEBHOOK_NOT_CONFIGURED" });
    const expected = `sha256=${crypto.createHmac("sha256", secret).update(req.rawBody || Buffer.from(JSON.stringify(body))).digest("hex")}`;
    const expectedBuffer = Buffer.from(expected);
    const signatureBuffer = Buffer.from(signature);
    if (expectedBuffer.length !== signatureBuffer.length || !crypto.timingSafeEqual(expectedBuffer, signatureBuffer)) {
      return json(res, 401, { error: "Invalid HashBack webhook signature", code: "INVALID_WEBHOOK_SECRET" });
    }
    const candidates = [
      body.reference,
      body.transaction_id,
      body.transactionId,
      body.checkout_request_id,
      body.CheckoutRequestID,
      body.TransactionReference,
      body.TransactionID,
      body.data?.reference,
      body.data?.transaction_id,
      body.data?.transactionId,
    ];
    const status = hashbackStatus(body);
    if (status === "completed" || String(body.event || "").toLowerCase().includes("success")) {
      return json(res, 200, { success: true, ...(await completePaymentByCandidates(candidates, body)) });
    }
    if (status === "failed") {
      await dbQuery(
        `UPDATE payment_transactions
         SET status = 'failed', failure_code = 'HASHBACK_PAYMENT_FAILED',
             failure_message = $1, provider_payload = $2, updated_at = NOW()
         WHERE provider_reference = ANY($3::text[]) AND status = 'pending'`,
        [String(body.message || body.ResponseDescription || body.ResultDescription || "HashBack reported a failed payment"), body, candidates.map(value => String(value || "")).filter(Boolean)],
      );
    }
    return json(res, 200, { success: true, status });
  }

  const user = await requireUser(req);
  if (apiPath === "/profile" && method === "GET") return json(res, 200, { user: publicUser(user) });
  if (apiPath === "/profile" && method === "PATCH") {
    const fields = {
      username: String(body.username ?? user.username).trim(),
      email: String(body.email ?? user.email).trim().toLowerCase(),
      phone: normalizePhone(body.phone ?? user.phone) || user.phone,
      full_name: String(body.full_name ?? body.fullName ?? user.full_name).trim(),
      country: String(body.country ?? user.country).trim().slice(0, 2).toUpperCase(),
      date_of_birth: body.date_of_birth ?? body.dateOfBirth ?? user.date_of_birth,
      avatar_url: String(body.avatar_url ?? body.avatarUrl ?? user.avatar_url).trim(),
    };
    const updated = await dbQuery(
      `UPDATE users SET username = $1, email = $2, phone = $3, full_name = $4, country = $5,
       date_of_birth = $6, avatar_url = $7, updated_at = NOW()
       WHERE id = $8 RETURNING *`,
      [fields.username, fields.email, fields.phone, fields.full_name, fields.country, fields.date_of_birth || null, fields.avatar_url, user.id],
    );
    return json(res, 200, { success: true, user: publicUser(updated.rows[0]) });
  }
  if (apiPath === "/transactions" && method === "GET") {
    const result = await dbQuery(
      `SELECT id, kind, amount, gateway, status, provider_reference, failure_code, failure_message, created_at, updated_at
       FROM payment_transactions WHERE user_id = $1
       UNION ALL
       SELECT id, 'trade' AS kind, payout - stake AS amount, direction AS gateway, result AS status, id::text AS provider_reference, '' AS failure_code, reason AS failure_message, placed_at AS created_at, COALESCE(resolved_at, placed_at) AS updated_at
       FROM trades WHERE user_id = $1
       ORDER BY created_at DESC LIMIT 100`,
      [user.id],
    );
    return json(res, 200, { transactions: result.rows.map((row) => ({ ...row, amount: safeNumber(row.amount) })) });
  }
  if (apiPath === "/trade" && method === "POST") return json(res, 200, await handleTrade(user, body));
  if (apiPath === "/deposit" && method === "POST") return json(res, 202, await startDeposit(user, body));
  if (apiPath === "/withdraw" && method === "POST") return json(res, 202, await startWithdrawal(user, body));
  if (apiPath === "/deposit/status" && method === "GET") {
    const reference = new URL(req.url, `http://${req.headers.host || "localhost"}`).searchParams.get("ref") || "";
    const result = await dbQuery("SELECT id FROM payment_transactions WHERE provider_reference = $1 AND user_id = $2 LIMIT 1", [reference, user.id]);
    if (result.rowCount === 0) return json(res, 404, { status: "not_found", error: "Payment reference not found" });
    return json(res, 200, await pollHashbackDeposit(result.rows[0].id, user.id));
  }
  if (apiPath === "/withdraw/status" && method === "GET") {
    const settings = await getSettings();
    return json(res, 200, {
      enabled: settings.withdrawals_enabled,
      minimum: settings.min_withdrawal,
      ...(await withdrawalAvailability(user.id, settings.withdrawal_cooldown_minutes)),
    });
  }
  if (apiPath.startsWith("/admin/")) {
    await requireAdmin(req);
    if (apiPath === "/admin/dashboard" && method === "GET") {
      const [users, payments, trades, withdrawals] = await Promise.all([
        dbQuery("SELECT COUNT(*)::int AS count, COALESCE(SUM(balance), 0) AS balance FROM users WHERE role = 'user'"),
        dbQuery("SELECT COUNT(*)::int AS count, COALESCE(SUM(amount) FILTER (WHERE status = 'completed'), 0) AS completed FROM payment_transactions WHERE kind = 'deposit'"),
        dbQuery("SELECT COUNT(*)::int AS count, COUNT(*) FILTER (WHERE result = 'win')::int AS wins FROM trades"),
        dbQuery("SELECT COUNT(*)::int AS count, COALESCE(SUM(amount) FILTER (WHERE status = 'pending'), 0) AS pending FROM payment_transactions WHERE kind = 'withdrawal'"),
      ]);
      return json(res, 200, {
        users: users.rows[0],
        deposits: payments.rows[0],
        trades: trades.rows[0],
        withdrawals: withdrawals.rows[0],
        settings: await getSettings(),
      });
    }
    if (apiPath === "/admin/settings" && method === "GET") return json(res, 200, { settings: await getSettings() });
    if (apiPath === "/admin/settings" && method === "PATCH") {
      const allowed = new Set(Object.keys(DEFAULT_SETTINGS));
      for (const [key, value] of Object.entries(body)) {
        if (!allowed.has(key)) continue;
        await dbQuery(
          `INSERT INTO app_settings (key, value) VALUES ($1, $2)
           ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
          [key, String(value)],
        );
      }
      return json(res, 200, { success: true, settings: await getSettings() });
    }
    if (apiPath === "/admin/users" && method === "GET") {
      const result = await dbQuery("SELECT id, username, email, phone, full_name, role, is_active, balance, created_at FROM users ORDER BY created_at DESC LIMIT 200");
      return json(res, 200, { users: result.rows.map((row) => ({ ...row, balance: safeNumber(row.balance) })) });
    }
    if (apiPath === "/admin/trades" && method === "GET") {
      const result = await dbQuery(
        `SELECT t.*, u.username, u.email FROM trades t JOIN users u ON u.id = t.user_id
         ORDER BY t.placed_at DESC LIMIT 200`,
      );
      return json(res, 200, { trades: result.rows });
    }
    if (apiPath === "/admin/withdrawals" && method === "GET") {
      const result = await dbQuery(
        `SELECT p.*, u.username, u.email, u.phone FROM payment_transactions p
         JOIN users u ON u.id = p.user_id WHERE p.kind = 'withdrawal'
         ORDER BY p.created_at DESC LIMIT 200`,
      );
      return json(res, 200, { withdrawals: result.rows });
    }
    const withdrawalAction = apiPath.match(/^\/admin\/withdrawals\/([^/]+)\/(approve|reject)$/);
    if (withdrawalAction && method === "POST") {
      const [, paymentId, action] = withdrawalAction;
      if (action === "reject") return json(res, 200, await rejectWithdrawal(paymentId, String(body.reason || "Rejected by administrator")));
      return json(res, 200, await dispatchWithdrawal(paymentId));
    }
    const balanceMatch = apiPath.match(/^\/admin\/users\/([^/]+)\/balance$/);
    if (balanceMatch && method === "POST") {
      const amount = roundMoney(body.amount);
      const reference = `admin-adjustment:${uid()}`;
      const result = await withTransaction(async (client) => {
        const balance = await recordLedger(client, {
          userId: balanceMatch[1],
          amount,
          kind: "admin_adjustment",
          reference,
          description: String(body.description || "Administrator balance adjustment"),
        });
        return { balance };
      });
      return json(res, 200, { success: true, ...result });
    }
  }
  return json(res, 404, { error: `Endpoint not found: ${method} ${pathName}`, code: "NOT_FOUND" });
}

function safeStaticPath(requestPath) {
  const decoded = decodeURIComponent(requestPath);
  const clean = decoded === "/" ? "/index.html" : decoded;
  const normalized = path.normalize(clean).replace(/^(\.\.(\/|\\|$))+/, "");
  return path.join(PUBLIC_DIR, normalized);
}

function serveStatic(res, requestPath) {
  const aliases = {
    "/login.php": "/login.html",
    "/register.php": "/register.html",
    "/profile.php": "/profile.html",
    "/transactions.php": "/transactions.html",
    "/admin/login.php": "/admin.html",
    "/trade_index.php": "/index.html",
  };
  if (aliases[requestPath]) {
    res.writeHead(302, { Location: aliases[requestPath] });
    return res.end();
  }
  const filePath = safeStaticPath(requestPath);
  if (!filePath.startsWith(PUBLIC_DIR)) return text(res, 403, "Forbidden");
  fs.stat(filePath, (error, stat) => {
    if (error || !stat.isFile()) return text(res, 404, "Not found");
    const ext = path.extname(filePath).toLowerCase();
    const types = { ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "application/javascript; charset=utf-8", ".json": "application/json; charset=utf-8", ".png": "image/png", ".jpg": "image/jpeg", ".svg": "image/svg+xml" };
    res.writeHead(200, { "Content-Type": types[ext] || "application/octet-stream", "Cache-Control": ext === ".html" ? "no-store" : "public, max-age=300" });
    fs.createReadStream(filePath).pipe(res);
  });
}

const server = http.createServer(async (req, res) => {
  const id = requestId();
  res.setHeader("X-Request-Id", id);
  setCors(res);
  if (req.method === "OPTIONS") return json(res, 204, {});
  try {
    const requestUrl = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);
    const body = ["POST", "PATCH", "PUT"].includes(req.method || "") ? await readBody(req) : {};
    await routeRequest(req, res, requestUrl.pathname, body);
  } catch (error) {
    const status =
      error.code === "AUTH_REQUIRED" ? 401 :
      error.code === "ADMIN_REQUIRED" ? 403 :
      error.code === "NOT_FOUND" ? 404 :
      error.code === "PAYLOAD_TOO_LARGE" || error.code === "INVALID_JSON" || error.code === "VALIDATION_ERROR" ? 400 :
      ["INSUFFICIENT_BALANCE", "STAKE_OUT_OF_RANGE", "DEPOSIT_TOO_SMALL", "WITHDRAWAL_TOO_SMALL", "WITHDRAWAL_COOLDOWN", "TRADE_NOT_OPEN", "TRADE_NOT_STARTED", "CANCEL_WINDOW_CLOSED", "UNKNOWN_ACTION", "BUY_DISABLED", "SELL_DISABLED", "TRADING_DISABLED", "DEPOSITS_DISABLED", "WITHDRAWALS_DISABLED", "REGISTRATION_DISABLED", "WITHDRAWAL_NOT_PENDING"].includes(error.code) ? 400 :
      error.code === "DATABASE_NOT_CONFIGURED" || error.code === "DATABASE_ERROR" ? 503 :
      error.code?.includes("NOT_CONFIGURED") || error.code?.startsWith("HASHBACK_") || error.code === "PAYMENT_PROVIDER_ERROR" ? 502 :
      500;
    console.error(`[${id}] ${req.method} ${req.url}`, error);
    json(res, status, errorBody(error, id));
  }
});

server.on("error", (error) => {
  console.error("[server]", error);
  process.exitCode = 1;
});

initDatabase().then(() => {
  server.listen(PORT, "0.0.0.0", () => {
    console.info(`Hashvest server listening on port ${PORT}`);
    if (!databaseReady) console.error(`[database] ${databaseError || "not ready"}`);
  });
});

process.on("SIGTERM", async () => {
  await pool?.end();
  server.close(() => process.exit(0));
});