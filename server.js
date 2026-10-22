'use strict';

/**
 * TopUp Store - email OTP sign-up backend
 *
 * Flow:
 *   1) POST /api/signup/start   { email }                      -> emails a 6-digit code
 *   2) POST /api/signup/verify  { email, code, password }      -> checks code, creates the account
 *
 * Security notes:
 *   - Codes are random (crypto.randomInt), stored only as an HMAC hash, expire in 10 minutes,
 *     are single use, and are locked after 5 wrong guesses.
 *   - Passwords are never stored by this server. They are sent once at verify time and handed
 *     straight to Firebase Auth, which hashes them.
 *   - Per-IP rate limits plus per-email send limits and cooldowns (stored in Firestore).
 *   - Same response whether or not an email already has an account (no account enumeration).
 *   - Strict CORS allowlist, helmet headers, small body limit, no secrets in logs.
 */

require('dotenv').config();

const crypto = require('crypto');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');
const admin = require('firebase-admin');

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
const env = process.env;

function requireEnv(name) {
  const value = env[name];
  if (!value || !String(value).trim()) {
    console.error('Missing required environment variable: ' + name);
    process.exit(1);
  }
  return String(value).trim();
}

const PORT = Number(env.PORT) || 3000;
const STORE_NAME = env.STORE_NAME || 'TopUp Store';
const OTP_SECRET = requireEnv('OTP_SECRET');
const ALLOWED_ORIGINS = requireEnv('ALLOWED_ORIGINS')
  .split(',')
  .map((s) => s.trim().replace(/\/+$/, ''))
  .filter(Boolean);
const SMTP_HOST = requireEnv('SMTP_HOST');
const SMTP_PORT = Number(env.SMTP_PORT) || 587;
const SMTP_USER = requireEnv('SMTP_USER');
const SMTP_PASS = requireEnv('SMTP_PASS');
const MAIL_FROM = requireEnv('MAIL_FROM');
const TURNSTILE_SECRET = (env.TURNSTILE_SECRET || '').trim();
const TRUST_PROXY = Number(env.TRUST_PROXY === undefined ? 1 : env.TRUST_PROXY);

if (OTP_SECRET.length < 32) {
  console.error('OTP_SECRET must be at least 32 characters long.');
  process.exit(1);
}

const OTP_TTL_MS = 10 * 60 * 1000; // code valid for 10 minutes
const MAX_ATTEMPTS = 5; // wrong guesses before the code is locked
const RESEND_COOLDOWN_MS = 60 * 1000; // wait between code emails
const SEND_WINDOW_MS = 60 * 60 * 1000; // window for the hourly send cap
const MAX_SENDS_PER_WINDOW = 5; // code emails per address per hour
const COLLECTION = 'signup_otps';

// ---------------------------------------------------------------------------
// Firebase Admin (Auth + Firestore)
// ---------------------------------------------------------------------------
function loadServiceAccount(raw) {
  const text = raw.trim().startsWith('{') ? raw : Buffer.from(raw, 'base64').toString('utf8');
  return JSON.parse(text);
}

admin.initializeApp({
  credential: admin.credential.cert(loadServiceAccount(requireEnv('FIREBASE_SERVICE_ACCOUNT'))),
});
const db = admin.firestore();
const fbAuth = admin.auth();

// ---------------------------------------------------------------------------
// Mail
// ---------------------------------------------------------------------------
const transporter = nodemailer.createTransport({
  host: SMTP_HOST,
  port: SMTP_PORT,
  secure: SMTP_PORT === 465,
  auth: { user: SMTP_USER, pass: SMTP_PASS },
  connectionTimeout: 10000,
  greetingTimeout: 10000,
  socketTimeout: 15000,
});

async function sendOtpEmail(to, code) {
  const minutes = OTP_TTL_MS / 60000;
  await transporter.sendMail({
    from: MAIL_FROM,
    to,
    subject: code + ' is your ' + STORE_NAME + ' verification code',
    text:
      'Your ' + STORE_NAME + ' verification code is ' + code + '.\n\n' +
      'It expires in ' + minutes + ' minutes. Never share this code with anyone.\n' +
      'If you did not request it, you can safely ignore this email.',
    html:
      '<div style="font-family:Arial,sans-serif;max-width:420px;margin:0 auto;padding:24px;background:#0a1a3a;color:#ffffff;border-radius:12px;">' +
      '<h2 style="margin:0 0 12px;color:#4db8ff;">' + STORE_NAME + '</h2>' +
      '<p style="margin:0 0 16px;">Use this code to finish creating your account:</p>' +
      '<div style="font-size:34px;letter-spacing:8px;font-weight:bold;text-align:center;background:#05050a;border:1px solid #1e6bff;border-radius:10px;padding:14px 0;">' +
      code + '</div>' +
      '<p style="margin:16px 0 0;font-size:13px;color:#b0c4de;">It expires in ' + minutes + ' minutes. Never share this code with anyone. ' +
      'If you did not request it, ignore this email.</p>' +
      '</div>',
  });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function normalizeEmail(value) {
  if (typeof value !== 'string') return null;
  const email = value.trim().toLowerCase();
  if (email.length < 5 || email.length > 254 || !EMAIL_RE.test(email)) return null;
  return email;
}

function validatePassword(password) {
  if (typeof password !== 'string') return 'Please enter a password.';
  if (password.length < 8) return 'Password must be at least 8 characters.';
  if (password.length > 128) return 'Password is too long (maximum 128 characters).';
  return null;
}

const docIdFor = (email) => crypto.createHash('sha256').update(email).digest('hex');

const hashCode = (email, code) =>
  crypto.createHmac('sha256', OTP_SECRET).update(email + ':' + code).digest('hex');

const generateCode = () => String(crypto.randomInt(0, 1000000)).padStart(6, '0');

function safeEqualHex(a, b) {
  const bufA = Buffer.from(String(a), 'hex');
  const bufB = Buffer.from(String(b), 'hex');
  if (bufA.length === 0 || bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

const fail = (res, status, error) => res.status(status).json({ ok: false, error });

const bodyOf = (req) => (req.body && typeof req.body === 'object' && !Array.isArray(req.body) ? req.body : {});

async function verifyTurnstile(token, ip) {
  if (!TURNSTILE_SECRET) return true; // captcha is optional
  if (typeof token !== 'string' || !token || token.length > 2048) return false;
  try {
    const form = new URLSearchParams({ secret: TURNSTILE_SECRET, response: token });
    if (ip) form.set('remoteip', ip);
    const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      body: form,
      signal: AbortSignal.timeout(5000),
    });
    const data = await response.json();
    return data && data.success === true;
  } catch (err) {
    return false;
  }
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', TRUST_PROXY);

app.use(helmet());
app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
});
app.use(
  cors({
    origin: (origin, callback) => callback(null, Boolean(origin) && ALLOWED_ORIGINS.includes(origin)),
    methods: ['POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type'],
    maxAge: 600,
  })
);
app.use(express.json({ limit: '10kb' }));

const limiterMessage = { ok: false, error: 'Too many requests. Please wait a few minutes and try again.' };
const limiterBase = { standardHeaders: 'draft-7', legacyHeaders: false, message: limiterMessage };

const globalLimiter = rateLimit({ ...limiterBase, windowMs: 15 * 60 * 1000, limit: 120 });
const startLimiter = rateLimit({ ...limiterBase, windowMs: 15 * 60 * 1000, limit: 8 });
const verifyLimiter = rateLimit({ ...limiterBase, windowMs: 15 * 60 * 1000, limit: 20 });

app.use(globalLimiter);

app.get('/health', (req, res) => res.json({ ok: true }));

// ---- Step 1: send the code -------------------------------------------------
app.post('/api/signup/start', startLimiter, async (req, res) => {
  const body = bodyOf(req);
  const email = normalizeEmail(body.email);
  if (!email) return fail(res, 400, 'Please enter a valid email address.');

  if (!(await verifyTurnstile(body.turnstileToken, req.ip))) {
    return fail(res, 400, 'Security check failed. Please refresh the page and try again.');
  }

  const genericOk = {
    ok: true,
    message:
      'If this email can be registered, a 6-digit code has been sent. It expires in 10 minutes. ' +
      'If you already have an account, please sign in instead.',
  };

  try {
    const ref = db.collection(COLLECTION).doc(docIdFor(email));
    const code = generateCode();
    const now = Date.now();

    // Per-email cooldown and hourly cap, enforced atomically.
    const decision = await db.runTransaction(async (t) => {
      const snap = await t.get(ref);
      const data = snap.exists ? snap.data() : {};
      let sendCount = data.sendCount || 0;
      let windowStart = data.windowStart || now;

      if (now - windowStart > SEND_WINDOW_MS) {
        sendCount = 0;
        windowStart = now;
      }
      if (data.lastSentAt && now - data.lastSentAt < RESEND_COOLDOWN_MS) return 'cooldown';
      if (sendCount >= MAX_SENDS_PER_WINDOW) return 'cap';

      t.set(ref, {
        codeHash: hashCode(email, code),
        expiresAt: now + OTP_TTL_MS,
        attempts: 0,
        lastSentAt: now,
        sendCount: sendCount + 1,
        windowStart,
      });
      return 'ok';
    });

    if (decision === 'cooldown') return fail(res, 429, 'Please wait a minute before asking for another code.');
    if (decision === 'cap') return fail(res, 429, 'Too many codes requested for this email. Please try again in an hour.');

    // Already registered? Respond exactly the same but send nothing.
    try {
      await fbAuth.getUserByEmail(email);
      return res.json(genericOk);
    } catch (err) {
      if (!err || err.code !== 'auth/user-not-found') throw err;
    }

    try {
      await sendOtpEmail(email, code);
    } catch (err) {
      console.error('Email send failed:', err && err.message);
      // Free the cooldown so the customer can retry right away.
      await ref.update({ lastSentAt: 0 }).catch(() => {});
      return fail(res, 502, 'We could not send the email right now. Please try again shortly.');
    }

    return res.json(genericOk);
  } catch (err) {
    console.error('signup/start error:', err && err.message);
    return fail(res, 500, 'Something went wrong. Please try again.');
  }
});

// ---- Step 2: check the code and create the account -------------------------
app.post('/api/signup/verify', verifyLimiter, async (req, res) => {
  const body = bodyOf(req);
  const email = normalizeEmail(body.email);
  const code = typeof body.code === 'string' ? body.code.trim() : '';
  const password = body.password;

  if (!email) return fail(res, 400, 'Please enter a valid email address.');
  if (!/^\d{6}$/.test(code)) return fail(res, 400, 'Please enter the 6-digit code.');
  const passwordError = validatePassword(password);
  if (passwordError) return fail(res, 400, passwordError);

  try {
    const ref = db.collection(COLLECTION).doc(docIdFor(email));

    // Check and consume the code atomically so guesses cannot race each other.
    const outcome = await db.runTransaction(async (t) => {
      const snap = await t.get(ref);
      if (!snap.exists) return 'invalid';
      const data = snap.data();

      if (Date.now() > data.expiresAt) return 'invalid';
      if ((data.attempts || 0) >= MAX_ATTEMPTS) return 'locked';

      if (!safeEqualHex(data.codeHash, hashCode(email, code))) {
        const attempts = (data.attempts || 0) + 1;
        t.update(ref, { attempts });
        return attempts >= MAX_ATTEMPTS ? 'locked' : 'invalid';
      }

      t.delete(ref); // single use
      return 'ok';
    });

    if (outcome === 'locked') {
      return fail(res, 429, 'Too many wrong attempts. Please request a new code.');
    }
    if (outcome !== 'ok') {
      return fail(res, 400, 'That code is incorrect or has expired.');
    }

    try {
      await fbAuth.createUser({ email, password, emailVerified: true });
    } catch (err) {
      if (err && err.code === 'auth/email-already-exists') {
        return fail(res, 409, 'This email already has an account. Please sign in.');
      }
      if (err && (err.code === 'auth/invalid-password' || err.code === 'auth/weak-password')) {
        return fail(res, 400, 'Please choose a stronger password.');
      }
      console.error('createUser failed:', err && (err.code || err.message));
      return fail(res, 500, 'Could not create the account. Please request a new code and try again.');
    }

    return res.json({ ok: true, message: 'Account created! You can sign in now.' });
  } catch (err) {
    console.error('signup/verify error:', err && err.message);
    return fail(res, 500, 'Something went wrong. Please try again.');
  }
});

// ---- Fallbacks -------------------------------------------------------------
app.use((req, res) => fail(res, 404, 'Not found.'));

app.use((err, req, res, next) => {
  if (err && err.type === 'entity.parse.failed') return fail(res, 400, 'Invalid request.');
  if (err && err.type === 'entity.too.large') return fail(res, 413, 'Request too large.');
  console.error('Unhandled error:', err && err.message);
  return fail(res, 500, 'Something went wrong. Please try again.');
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log('OTP backend listening on port ' + PORT);
    transporter.verify().then(
      () => console.log('Mail server connection OK'),
      (err) => console.warn('Mail server check failed:', err && err.message)
    );
  });
}

module.exports = { app };
