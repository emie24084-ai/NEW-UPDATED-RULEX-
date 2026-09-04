const express = require('express');
const bodyParser = require('body-parser');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const pino = require('pino');
const chalk = require('chalk');
const app = express();
const logger = pino({ level: process.env.LOG_LEVEL || 'info' });
const PORT = process.env.PORT || 26059;

const SERVER_START_TIME = Date.now();
const RECONNECT_MAX = 6;
const RECONNECT_DELAY_MS = 4000;
const SESSION_TIMEOUT_MS = 60 * 60 * 1000;
const MAX_PREKEY_FILES = parseInt(process.env.MAX_PREKEY_FILES || '20', 10);
const MAX_SENDER_KEY_FILES = parseInt(process.env.MAX_SENDER_KEY_FILES || '5', 10);
const MAX_SESSION_FILES = parseInt(process.env.MAX_SESSION_FILES || '10', 10);
const PRUNE_DEBOUNCE_MS = parseInt(process.env.PRUNE_DEBOUNCE_MS || '2000', 10);
const GLOBAL_PRUNE_INTERVAL_MS = parseInt(process.env.GLOBAL_PRUNE_INTERVAL_MS || (60 * 60 * 1000).toString(), 10);

const uploadsDir = path.join(process.cwd(), 'uploads');
const sessionsRoot = path.join(process.cwd(), 'uploaded_sessions');
const usersFilePath = path.join(process.cwd(), 'users.json');
const approvalFilePath = path.join(process.cwd(), 'approval.txt');
const pendingUsersPath = path.join(process.cwd(), 'pending_users.json');

if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
if (!fs.existsSync(sessionsRoot)) fs.mkdirSync(sessionsRoot, { recursive: true });
if (!fs.existsSync(approvalFilePath)) {
  fs.writeFileSync(approvalFilePath, '', 'utf8');
  console.log(chalk.yellow('[OK] approval.txt file created'));
}
if (!fs.existsSync(pendingUsersPath)) {
  fs.writeFileSync(pendingUsersPath, '[]', 'utf8');
  console.log(chalk.yellow('[OK] pending_users.json file created'));
}

// ============ ADMIN SETUP (NO APPROVAL KEY NEEDED) ============
function initializeUsers() {
  if (!fs.existsSync(usersFilePath)) {
    const users = {
      admin: {
        username: 'Danishkhan',
        password: hashPassword('Danishkhan786'),
        role: 'admin',
        createdAt: new Date().toISOString()
      }
    };
    fs.writeFileSync(usersFilePath, JSON.stringify(users, null, 2), 'utf8');
    console.log(chalk.green('[OK] Admin user created: Danishkhan / Danishkhan786'));
  } else {
    // Ensure admin exists even if file exists
    try {
      const users = JSON.parse(fs.readFileSync(usersFilePath, 'utf8'));
      const hasAdmin = Object.values(users).some(u => u.role === 'admin');
      if (!hasAdmin) {
        users['admin'] = {
          username: 'Danishkhan',
          password: hashPassword('Danishkhan786'),
          role: 'admin',
          createdAt: new Date().toISOString()
        };
        fs.writeFileSync(usersFilePath, JSON.stringify(users, null, 2), 'utf8');
        console.log(chalk.green('[OK] Admin user added: Danishkhan / Danishkhan786'));
      }
    } catch (e) {}
  }
}

function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

function loadUsers() {
  try {
    if (fs.existsSync(usersFilePath)) {
      return JSON.parse(fs.readFileSync(usersFilePath, 'utf8'));
    }
  } catch (e) {
    logger.error('Failed to load users', e?.message || e);
  }
  return {};
}

function saveUsers(users) {
  try {
    fs.writeFileSync(usersFilePath, JSON.stringify(users, null, 2), 'utf8');
  } catch (e) {
    logger.error('Failed to save users', e?.message || e);
  }
}

// ============ PENDING USERS SYSTEM ============
function loadPendingUsers() {
  try {
    if (fs.existsSync(pendingUsersPath)) {
      return JSON.parse(fs.readFileSync(pendingUsersPath, 'utf8'));
    }
  } catch (e) {
    logger.error('Failed to load pending users', e?.message || e);
  }
  return [];
}

function savePendingUsers(list) {
  try {
    fs.writeFileSync(pendingUsersPath, JSON.stringify(list, null, 2), 'utf8');
  } catch (e) {
    logger.error('Failed to save pending users', e?.message || e);
  }
}

function loadApprovedKeys() {
  try {
    if (fs.existsSync(approvalFilePath)) {
      const content = fs.readFileSync(approvalFilePath, 'utf8');
      return content.split('\n').map(line => line.trim()).filter(Boolean);
    }
  } catch (e) {
    logger.error('Failed to load approval keys', e?.message || e);
  }
  return [];
}

function saveApprovedKeys(keys) {
  try {
    fs.writeFileSync(approvalFilePath, keys.join('\n'), 'utf8');
  } catch (e) {
    logger.error('Failed to save approval keys', e?.message || e);
  }
}

function isKeyApproved(key) {
  const approvedKeys = loadApprovedKeys();
  return approvedKeys.includes(key);
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => cb(null, Date.now() + '' + Math.random().toString(36).slice(2, 8) + '' + file.originalname.replace(/\s+/g, ''))
});
const upload = multer({ storage, limits: { fileSize: 50 * 1024 * 1024 } });

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(process.cwd()));

const SESSIONS = Object.create(null);
const CREDS_HASH_TO_SESSION = Object.create(null);
const DIR_WATCHERS = Object.create(null);

function sha256File(filePath) {
  const buf = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function makeSessionId() {
  return 'sess_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 9);
}

function makeSessionDir(sessionId) {
  const dir = path.join(sessionsRoot, sessionId);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function sleep(ms) {
  const n = Number(ms);
  return new Promise(r => setTimeout(r, Number.isFinite(n) && n >= 0 ? n : 2000));
}

function safeDelayMs(value, fallback = 5000) {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0) return fallback;
  return Math.min(Math.floor(n), 24 * 60 * 60 * 1000);
}

function safeReconnectDelay(value, fallback = 4000) {
  return safeDelayMs(value, fallback);
}

// ============ ANTI-BAN: Random Jitter ============
function antiBanJitter(baseMs, jitterPercent = 30) {
  const base = safeDelayMs(baseMs, 5000);
  const jitter = Math.floor(base * (jitterPercent / 100));
  const randomOffset = Math.floor(Math.random() * jitter * 2) - jitter;
  return Math.max(1000, base + randomOffset);
}

// ============ ANTI-BAN: Rotate Browser Fingerprints ============
function pickRandomBrowser() {
  const browsers = [
    ['Chrome', '120.0.0.0', 'Windows'],
    ['Chrome', '121.0.0.0', 'Windows'],
    ['Chrome', '122.0.0.0', 'Windows'],
    ['Edge', '120.0.0.0', 'Windows'],
    ['Firefox', '121.0', 'Windows'],
    ['Safari', '17.0', 'macOS'],
    ['Chrome', '120.0.0.0', 'Linux'],
  ];
  return browsers[Math.floor(Math.random() * browsers.length)];
}

function appendSessionLog(sessionId, rawMsg) {
  const time = new Date().toISOString();
  const msg = String(rawMsg || '');
  const s = SESSIONS[sessionId];
  if (s) {
    s.logs = s.logs || [];
    s.logs.push({ time, msg });
    if (s.logs.length > 200) s.logs = s.logs.slice(-200);
  }
  const lower = msg.toLowerCase();
  let kind = 'other';
  if (/(\bsent\b|\bsuccessful\b|\bsuccess\b|\breconnect successful\b|\bstarted\b|\bopen\b|\bcreated\b|\bstarted loop\b)/.test(lower)) {
    kind = 'success';
  } else if (/(\berror\b|\bfailed\b|\bdeleted\b|\blogged out\b|\binvalid\b|\bunauthorized\b|\b401\b|\bdisconnect\b|\bclose\b|\bfailed to\b|\bexpired\b|\bremoved\b)/.test(lower)) {
    kind = 'error';
  } else {
    kind = 'other';
  }
  const timeStr = chalk.yellow(`[${time}]`);
  let symbol = 'i';
  let symbolColored = chalk.cyan(`[${symbol}]`);
  let messageColored = chalk.cyan(msg);
  if (kind === 'success') {
    symbol = '[OK]';
    symbolColored = chalk.greenBright(`[${symbol}]`);
    messageColored = chalk.green(msg);
  } else if (kind === 'error') {
    symbol = '[ERROR]';
    symbolColored = chalk.redBright(`[${symbol}]`);
    messageColored = chalk.red(msg);
  } else {
    symbol = 'i';
    symbolColored = chalk.cyan(`[${symbol}]`);
    messageColored = chalk.cyan(msg);
  }
  const sessionIdStr = sessionId ? chalk.magenta(`[${sessionId}]`) : '';
  const line = `${timeStr} ${symbolColored} ${messageColored} ${sessionIdStr}`;
  console.log(line);
  console.log(chalk.gray('-'.repeat(80)));
  logger.info({ sessionId, kind, time }, msg);
}

function persistSessionFiles(sessionId) {
  const s = SESSIONS[sessionId];
  if (!s) return;
  try {
    const sessionMeta = {
      sessionId: s.sessionId, username: s.username, contacts: s.contacts,
      messages: s.messages, prefixName: s.prefixName, delayMs: s.delayMs,
      target: s.target, groupId: s.groupId,
      sessionType: s.sessionType || 'message',
      mentionType: s.mentionType || 'none',
      mentionNumbers: Array.isArray(s.mentionNumbers) ? s.mentionNumbers : [],
      mediaFiles: (s.mediaFiles || []).map(p => path.basename(p)),
      createdAt: s.createdAt || new Date().toISOString(),
      startedAt: s.startedAt || Date.now(),
      credsHash: s.credsHash || null,
      stopped: s.stopped || false,
      awaitingCredentials: !!s.awaitingCredentials,
      lastAuthError: s.lastAuthError || null,
      autoReplyEnabled: !!s.autoReplyEnabled,
      autoReplyMessage: s.autoReplyMessage || ''
    };
    fs.writeFileSync(path.join(s.sessionDir, 'session.json'), JSON.stringify(sessionMeta, null, 2), 'utf8');
    fs.writeFileSync(path.join(s.sessionDir, 'messages.txt'), (s.messages || []).join('\n'), 'utf8');
  } catch (e) {
    appendSessionLog(sessionId, 'persistSessionFiles error: ' + (e?.message || e));
  }
}

function pruneAuthFiles(sessionDir, sessionId = null) {
  return 0;
}

function startSessionWatch(sessionId) {
  const s = SESSIONS[sessionId];
  if (!s) return;
  const sessionDir = s.sessionDir;
  if (!sessionDir || !fs.existsSync(sessionDir)) return;
  if (DIR_WATCHERS[sessionId]) return;
  const watchers = { dirWatcher: null, keysWatcher: null, debounceTimer: null };
  const schedulePrune = () => {
    if (watchers.debounceTimer) clearTimeout(watchers.debounceTimer);
    watchers.debounceTimer = setTimeout(() => {
      try {
        const removed = pruneAuthFiles(sessionDir, sessionId);
        if (removed && removed > 0) {
          logger.debug && logger.debug({ sessionId, removed }, 'Pruned auth files after fs event');
        }
      } catch (e) {}
      watchers.debounceTimer = null;
    }, PRUNE_DEBOUNCE_MS);
  };
  try {
    watchers.dirWatcher = fs.watch(sessionDir, (eventType, filename) => {
      if (!filename) return;
      if (String(filename).startsWith('media')) return;
      schedulePrune();
    });
  } catch (e) {}
  try {
    const keysDir = path.join(sessionDir, 'keys');
    if (!fs.existsSync(keysDir)) fs.mkdirSync(keysDir, { recursive: true });
    watchers.keysWatcher = fs.watch(keysDir, (eventType, filename) => {
      if (!filename) return;
      schedulePrune();
    });
  } catch (e) {}
  DIR_WATCHERS[sessionId] = watchers;
}

function stopSessionWatch(sessionId) {
  const w = DIR_WATCHERS[sessionId];
  if (!w) return;
  try { if (w.dirWatcher) w.dirWatcher.close(); } catch (e) {}
  try { if (w.keysWatcher) w.keysWatcher.close(); } catch (e) {}
  try { if (w.debounceTimer) clearTimeout(w.debounceTimer); } catch (e) {}
  delete DIR_WATCHERS[sessionId];
}

function completeSessionCleanup(sessionId) {
  const s = SESSIONS[sessionId];
  if (!s || !s.sessionDir) return;
  try {
    appendSessionLog(sessionId, '[CLEANUP] Complete cleanup: removing session folder');
    stopSessionWatch(sessionId);
    if (fs.existsSync(s.sessionDir)) {
      fs.rmSync(s.sessionDir, { recursive: true, force: true });
      appendSessionLog(sessionId, '[OK] Session folder completely removed');
    }
    if (s.credsHash && CREDS_HASH_TO_SESSION[s.credsHash]) {
      delete CREDS_HASH_TO_SESSION[s.credsHash];
    }
    delete SESSIONS[sessionId];
  } catch (e) {
    appendSessionLog(sessionId, '[ERROR] Cleanup error: ' + (e?.message || e));
  }
}

function cleanupSessionFiles(sessionId) {
  const s = SESSIONS[sessionId];
  if (!s || !s.sessionDir) return;
  const PROTECTED_FILES = ['session.json', 'messages.txt', 'creds.json'];
  let deletedCount = 0;
  try {
    appendSessionLog(sessionId, '[CLEANUP] Starting cleanup of session files...');
    const files = fs.readdirSync(s.sessionDir, { withFileTypes: true });
    for (const file of files) {
      if (file.isFile() && !PROTECTED_FILES.includes(file.name)) {
        try {
          fs.unlinkSync(path.join(s.sessionDir, file.name));
          deletedCount++;
        } catch (e) {}
      }
    }
    const keysDir = path.join(s.sessionDir, 'keys');
    if (fs.existsSync(keysDir)) {
      try {
        fs.rmSync(keysDir, { recursive: true, force: true });
        appendSessionLog(sessionId, '[OK] Deleted keys/ subdirectory');
      } catch (e) {}
    }
    const mediaDir = path.join(s.sessionDir, 'media');
    if (fs.existsSync(mediaDir)) {
      try {
        fs.rmSync(mediaDir, { recursive: true, force: true });
        appendSessionLog(sessionId, '[OK] Deleted media/ subdirectory');
      } catch (e) {}
    }
    appendSessionLog(sessionId, `[OK] Cleanup complete: ${deletedCount} files deleted, protected files preserved`);
  } catch (e) {
    appendSessionLog(sessionId, '[ERROR] Cleanup error: ' + (e?.message || e));
  }
}

function isLoggedOutUpdate(update) {
  const last = update?.lastDisconnect;
  if (!last) return false;
  const error = last.error;
  const statusCode = error?.output?.statusCode;
  const msg = (error && (error.message || String(error))) || String(error || '');
  if (!msg && !statusCode) return false;
  const lower = msg.toLowerCase();
  const actualLoggedOutPatterns = [
    'logged out', 'logged-out', 'device not found',
    'invalid mac', 'qr refs attempts ended', 'restart required'
  ];
  if (statusCode === 401) {
    appendSessionLog(null, `Detected auth failure with status code: ${statusCode}`);
    return true;
  }
  for (const pattern of actualLoggedOutPatterns) {
    if (lower.includes(pattern)) {
      appendSessionLog(null, `Detected logged out pattern: "${pattern}" in message: "${msg}"`);
      return true;
    }
  }
  return false;
}

async function checkIfLoggedIn(sock, sessionId, timeoutMs = 30000) {
  return new Promise((resolve, reject) => {
    let resolved = false;
    const timeout = setTimeout(() => {
      if (!resolved) {
        resolved = true;
        reject(new Error('Timeout: Failed to verify login status'));
      }
    }, timeoutMs);
    const connectionHandler = (update) => {
      if (resolved) return;
      const { connection, lastDisconnect } = update;
      if (connection === 'open') {
        if (!resolved) {
          resolved = true;
          clearTimeout(timeout);
          sock.ev.off('connection.update', connectionHandler);
          resolve(true);
        }
        return;
      }
      if (connection === 'close') {
        if (isLoggedOutUpdate(update)) {
          if (!resolved) {
            resolved = true;
            clearTimeout(timeout);
            sock.ev.off('connection.update', connectionHandler);
            const errorMsg = lastDisconnect?.error?.message || 'Credentials expired or logged out';
            reject(new Error(errorMsg));
          }
        }
      }
    };
    sock.ev.on('connection.update', connectionHandler);
  });
}

function extractWhatsAppPhoneFromCreds(filePath) {
  try {
    const json = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    const raw = json?.me?.id || json?.me?.jid || json?.me?.phoneNumber || '';
    const match = String(raw).match(/(\d{7,15})/);
    return match ? match[1] : null;
  } catch (e) {
    return null;
  }
}

function extractWhatsAppPhoneFromSession(s) {
  try {
    const raw = s?.phone || s?.phoneNumber || s?.sock?.user?.id || s?.sock?.user?.jid || '';
    const match = String(raw).match(/(\d{7,15})/);
    return match ? match[1] : null;
  } catch (e) {
    return null;
  }
}

function validateCredsJson(filePath) {
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    const json = JSON.parse(content);
    if (!json.noiseKey || !json.signedIdentityKey || !json.signedPreKey) {
      return false;
    }
    return true;
  } catch (e) {
    return false;
  }
}

function loadMediaFiles(sessionDir) {
  const mediaDir = path.join(sessionDir, 'media');
  if (!fs.existsSync(mediaDir)) return [];
  try {
    return fs.readdirSync(mediaDir)
      .filter(f => !f.startsWith('.'))
      .map(f => path.join(mediaDir, f))
      .filter(f => {
        try { return fs.statSync(f).isFile(); } catch (e) { return false; }
      })
      .sort();
  } catch (e) {
    return [];
  }
}

// ============ AUTO-REPLY HANDLER ============
function setupAutoReplyHandler(sock, sessionId) {
  sock.ev.on('messages.upsert', async (m) => {
    try {
      const s = SESSIONS[sessionId];
      if (!s || !s.autoReplyEnabled || !s.autoReplyMessage) return;
      if (s.stopped || s.deleting) return;

      const msgs = m.messages || [];
      for (const msg of msgs) {
        if (msg.key?.fromMe) continue;
        if (msg.key?.remoteJid === 'status@broadcast') continue;

        const remoteJid = msg.key?.remoteJid;
        if (!remoteJid) continue;

        const textContent =
          msg.message?.conversation ||
          msg.message?.extendedTextMessage?.text ||
          msg.message?.imageMessage?.caption ||
          msg.message?.videoMessage?.caption ||
          '';

        if (!textContent) continue;

        appendSessionLog(sessionId, `[AUTO-REPLY] Incoming from ${remoteJid}: ${textContent.substring(0, 50)}`);

        // Anti-ban: human-like typing delay
        const typingDelay = 1000 + Math.floor(Math.random() * 3000);
        await sleep(typingDelay);

        try {
          await sock.presenceSubscribe(remoteJid);
          await sock.sendPresenceUpdate('composing', remoteJid);
          await sleep(1500 + Math.floor(Math.random() * 2000));
          await sock.sendPresenceUpdate('paused', remoteJid);
        } catch (e) {}

        let replyText = s.autoReplyMessage;
        const variations = [replyText, replyText + ' 👍', replyText + ' ✨', '✅ ' + replyText];
        const finalReply = variations[Math.floor(Math.random() * variations.length)];

        try {
          await sock.sendMessage(remoteJid, { text: finalReply }, { quoted: msg });
          appendSessionLog(sessionId, `[AUTO-REPLY] Replied to ${remoteJid}`);
        } catch (e) {
          appendSessionLog(sessionId, '[AUTO-REPLY ERROR] ' + (e?.message || e));
        }
      }
    } catch (e) {
      appendSessionLog(sessionId, '[AUTO-REPLY HANDLER ERROR] ' + (e?.message || e));
    }
  });
}

async function restartSession(sessionId) {
  const s = SESSIONS[sessionId];
  if (!s) {
    appendSessionLog(sessionId, 'restartSession: no in-memory session found');
    return;
  }
  if (s.stopped) {
    appendSessionLog(sessionId, 'Session was manually stopped - will not restart');
    return;
  }
  if (s.restartLock) {
    appendSessionLog(sessionId, 'Restart already in progress, skipping duplicate restart.');
    return;
  }
  s.restartLock = true;
  const dir = s.sessionDir;
  if (!dir || !fs.existsSync(dir)) {
    appendSessionLog(sessionId, 'restartSession: session folder missing, cannot restart');
    s.restartLock = false;
    return;
  }
  appendSessionLog(sessionId, 'Restarting session from disk: ' + dir);
  try {
    const sessionJsonPath = path.join(dir, 'session.json');
    if (fs.existsSync(sessionJsonPath)) {
      const meta = JSON.parse(fs.readFileSync(sessionJsonPath, 'utf8'));
      s.contacts = meta.contacts || s.contacts;
      s.messages = meta.messages || s.messages;
      s.prefixName = meta.prefixName || s.prefixName || 'Bot';
      s.delayMs = safeDelayMs(meta.delayMs, safeDelayMs(s.delayMs, 5000));
      s.target = meta.target || s.target;
      s.groupId = meta.groupId || s.groupId;
      s.createdAt = meta.createdAt || s.createdAt;
      s.startedAt = meta.startedAt || s.startedAt || Date.now();
      s.credsHash = meta.credsHash || s.credsHash;
      s.awaitingCredentials = !!meta.awaitingCredentials;
      s.lastAuthError = meta.lastAuthError || null;
      s.username = meta.username || s.username;
      s.stopped = meta.stopped || false;
      s.sessionType = meta.sessionType || s.sessionType || 'message';
      s.mentionType = meta.mentionType || s.mentionType || 'none';
      s.mentionNumbers = Array.isArray(meta.mentionNumbers) ? meta.mentionNumbers : (s.mentionNumbers || []);
      s.mediaFiles = loadMediaFiles(dir);
      s.autoReplyEnabled = !!meta.autoReplyEnabled;
      s.autoReplyMessage = meta.autoReplyMessage || '';
      if (s.credsHash) CREDS_HASH_TO_SESSION[s.credsHash] = sessionId;
    }
  } catch (e) {
    appendSessionLog(sessionId, 'Failed to read session.json during restart: ' + (e?.message || e));
  }
  s.runningLoop = false;
  s.reconnectAttempts = 0;
  s.firstReconnectTime = null;
  try {
    s.sock = null;
    s.sock = await createOrGetSocket(dir, sessionId);
    appendSessionLog(sessionId, '[OK] Session restarted successfully');
    try {
      await startSendingLoop(sessionId);
      appendSessionLog(sessionId, 'Session restarted and sending loop started');
    } catch (e) {
      appendSessionLog(sessionId, 'restart startSendingLoop failed: ' + (e?.message || e));
    }
  } catch (e) {
    appendSessionLog(sessionId, 'Restart: socket creation failed: ' + (e?.message || e));
  } finally {
    s.restartLock = false;
  }
}

async function attemptReconnect(sessionId) {
  const s = SESSIONS[sessionId];
  if (!s || s.stopped || s.awaitingCredentials) return;
  if (s.reconnectLock || s.restartLock) {
    appendSessionLog(sessionId, 'Reconnect/restart already in progress, skipping duplicate call');
    return;
  }
  s.reconnectLock = true;
  s.reconnectAttempts = s.reconnectAttempts || 0;
  let delayMs = RECONNECT_DELAY_MS;
  try {
    while (SESSIONS[sessionId] && !s.stopped && !s.awaitingCredentials) {
      s.reconnectAttempts++;
      appendSessionLog(sessionId, `Reconnect attempt ${s.reconnectAttempts} (waiting ${delayMs}ms)`);
      await sleep(delayMs);
      if (!SESSIONS[sessionId] || s.stopped || s.awaitingCredentials) break;
      try {
        s.sock = null;
        const newSock = await createOrGetSocket(s.sessionDir, sessionId);
        if (newSock) {
          s.sock = newSock;
          s.reconnectAttempts = 0;
          s.firstReconnectTime = null;
          s.consecutiveSendErrors = 0;
          appendSessionLog(sessionId, '[OK] Reconnect successful - Socket recreated');
          return;
        }
      } catch (e) {
        const errorMsg = String(e?.message || e);
        appendSessionLog(sessionId, 'Reconnect try failed: ' + errorMsg);
        const lower = errorMsg.toLowerCase();
        if (
          lower.includes('logged out') ||
          lower.includes('invalid mac') ||
          lower.includes('device not found') ||
          lower.includes('qr refs attempts ended')
        ) {
          s.awaitingCredentials = true;
          s.lastAuthError = errorMsg;
          s.reconnectAttempts = 0;
          s.firstReconnectTime = null;
          persistSessionFiles(sessionId);
          appendSessionLog(sessionId, 'Authentication expired/logged out. Session preserved; waiting for new creds.json.');
          return;
        }
      }
      delayMs = Math.min(Math.max(RECONNECT_DELAY_MS, delayMs * 2), 60000);
    }
  } finally {
    s.reconnectLock = false;
  }
}

function restoreSessionsFromDisk() {
  const entries = fs.existsSync(sessionsRoot) ? fs.readdirSync(sessionsRoot, { withFileTypes: true }) : [];
  for (const e of entries) {
    if (!e.isDirectory()) continue;
    const sessionId = e.name;
    const dir = path.join(sessionsRoot, sessionId);
    const sessionJsonPath = path.join(dir, 'session.json');
    const credsPath = path.join(dir, 'creds.json');
    if (fs.existsSync(sessionJsonPath)) {
      try {
        if (!validateCredsJson(credsPath)) {
          appendSessionLog(sessionId, 'Invalid creds.json format detected. Session kept for replacement credentials.');
        }
        const meta = JSON.parse(fs.readFileSync(sessionJsonPath, 'utf8'));
        if (meta.stopped) {
          appendSessionLog(sessionId, 'Session was stopped - skipping restore');
          continue;
        }
        const sess = {
          sessionId: meta.sessionId || sessionId,
          sessionDir: dir,
          username: meta.username || 'unknown',
          credsHash: meta.credsHash || null,
          contacts: meta.contacts || [],
          messages: meta.messages || [],
          prefixName: meta.prefixName || 'Bot',
          delayMs: safeDelayMs(meta.delayMs, 5000),
          runningLoop: false,
          sock: null,
          target: meta.target || 'contacts',
          groupId: meta.groupId || null,
          sessionType: meta.sessionType || 'message',
          mentionType: meta.mentionType || 'none',
          mentionNumbers: Array.isArray(meta.mentionNumbers) ? meta.mentionNumbers : [],
          mediaFiles: loadMediaFiles(dir),
          logs: [],
          awaitingCredentials: !fs.existsSync(credsPath) || !validateCredsJson(credsPath),
          lastAuthError: meta.lastAuthError || null,
          createdAt: meta.createdAt || new Date().toISOString(),
          startedAt: meta.startedAt || Date.now(),
          autoReplyEnabled: !!meta.autoReplyEnabled,
          autoReplyMessage: meta.autoReplyMessage || '',
          reconnectAttempts: 0,
          reconnectLock: false,
          restartLock: false,
          firstReconnectTime: null,
          deleting: false,
          stopped: false
        };
        SESSIONS[sess.sessionId] = sess;
        if (fs.existsSync(credsPath)) {
          try {
            const hash = sha256File(credsPath);
            sess.credsHash = hash;
            CREDS_HASH_TO_SESSION[hash] = sess.sessionId;
          } catch (e) {}
        }
        appendSessionLog(sess.sessionId, `Restored session from disk (type=${sess.sessionType}, media=${sess.mediaFiles.length}), reconnecting...`);
        try { startSessionWatch(sess.sessionId); } catch (e) {}
        (async () => {
          if (SESSIONS[sess.sessionId].awaitingCredentials) {
            appendSessionLog(sess.sessionId, 'Session restored and waiting for valid creds.json; uptime preserved.');
            return;
          }
          try {
            SESSIONS[sess.sessionId].sock = await createOrGetSocket(sess.sessionDir, sess.sessionId);
            appendSessionLog(sess.sessionId, '[OK] Socket created successfully on restore');
          } catch (e) {
            appendSessionLog(sess.sessionId, 'Socket create failed on restore: ' + (e?.message || e));
            return;
          }
          try {
            await startSendingLoop(sess.sessionId);
          } catch (err) {
            appendSessionLog(sess.sessionId, 'startSendingLoop on restore failed: ' + (err?.message || err));
          }
        })();
      } catch (err) {
        logger.warn('Failed to restore session', sessionId, err?.message || err);
      }
    }
  }
}

async function createOrGetSocket(sessionDir, sessionId) {
  let baileys;
  try {
    baileys = await import('@whiskeysockets/baileys');
  } catch (e) {
    logger.error('Please npm install @whiskeysockets/baileys', e?.message || e);
    throw e;
  }
  const { makeWASocket, useMultiFileAuthState } = baileys;
  if (!fs.existsSync(sessionDir)) fs.mkdirSync(sessionDir, { recursive: true });
  let state, saveCreds;
  try {
    ({ state, saveCreds } = await useMultiFileAuthState(sessionDir));
  } catch (e) {
    appendSessionLog(sessionId, '[ERROR] Auth state load failed: ' + (e?.message || e));
    throw e;
  }

  const socketConfig = {
    logger: pino({ level: 'silent' }),
    auth: state,
    markOnlineOnConnect: false,
    syncFullHistory: false,
    keepAliveIntervalMs: 20000,
    connectTimeoutMs: 60000,
    generateHighQualityLinkPreview: false,
    browser: pickRandomBrowser(),
  };

  let sock = null;
  let lastError = null;
  for (let attempt = 1; attempt <= 8; attempt++) {
    try {
      if (attempt > 1) {
        try {
          ({ state, saveCreds } = await useMultiFileAuthState(sessionDir));
          socketConfig.auth = state;
          socketConfig.browser = pickRandomBrowser();
        } catch (e) {
          lastError = e;
          appendSessionLog(sessionId, `[WARN] Auth state reload failed (${attempt}/8): ${e?.message || e}`);
          await sleep(Math.min(5000 * attempt, 30000));
          continue;
        }
      }
      sock = makeWASocket(socketConfig);
      lastError = null;
      break;
    } catch (e) {
      lastError = e;
      const msg = String(e?.message || e);
      appendSessionLog(sessionId, `[WARN] Socket creation failed (${attempt}/8): ${msg}`);
      if (e?.stack) logger.debug({ sessionId, stack: e.stack }, 'Baileys socket creation stack');
      await sleep(Math.min(5000 * attempt, 30000));
    }
  }
  if (!sock) {
    throw lastError || new Error('Socket creation failed after retries');
  }

  if (sock?.ev?.on) {
    sock.ev.on('creds.update', async () => {
      try {
        if (typeof saveCreds === 'function') await saveCreds();
        try { pruneAuthFiles(sessionDir, sessionId); } catch (e) {}
      } catch (e) {
        appendSessionLog(sessionId, 'creds.update handler error: ' + (e?.message || e));
      }
    });
  }

  setupAutoReplyHandler(sock, sessionId);

  sock.ev.on('connection.update', async (update) => {
    const { connection, lastDisconnect } = update;
    if (connection === 'close') {
      const current = SESSIONS[sessionId];
      if (current && current.sock && current.sock !== sock) return;
      if (current) current.sock = null;
      const errorMsg = lastDisconnect?.error?.message || lastDisconnect?.error || 'unknown';
      appendSessionLog(sessionId, 'Socket closed: ' + errorMsg);
      if (isLoggedOutUpdate(update)) {
        const s = SESSIONS[sessionId];
        if (s && !s.stopped) {
          s.awaitingCredentials = true;
          s.lastAuthError = String(errorMsg);
          s.sock = null;
          s.runningLoop = false;
          s.reconnectAttempts = 0;
          s.firstReconnectTime = null;
          persistSessionFiles(sessionId);
          appendSessionLog(sessionId, 'Credentials expired/logged out. Session preserved; waiting for new creds.json.');
        }
        return;
      }
      const s = SESSIONS[sessionId];
      if (s && !s.stopped && !s.awaitingCredentials) {
        appendSessionLog(sessionId, '[WARN] Connection closed; starting reconnect...');
        attemptReconnect(sessionId).catch(err =>
          appendSessionLog(sessionId, 'attemptReconnect error: ' + (err?.message || err))
        );
      }
    }
    if (connection === 'open') {
      appendSessionLog(sessionId, '[OK] Socket open and connected to WhatsApp');
      const s = SESSIONS[sessionId];
      if (s) {
        s.reconnectAttempts = 0;
        s.firstReconnectTime = null;
        s.consecutiveSendErrors = 0;
      }
      try { startSessionWatch(sessionId); } catch (e) {}
    }
  });
  return sock;
}

async function waitForSocketOpen(sessionId, timeoutMs = 20000) {
  const s = SESSIONS[sessionId];
  if (!s || !s.sock) throw new Error('No session or socket');
  const sock = s.sock;
  if (sock?.authState?.creds?.registered || (sock.user && Object.keys(sock.user || {}).length)) return;
  return new Promise((resolve, reject) => {
    let done = false;
    const to = setTimeout(() => {
      if (!done) {
        done = true;
        reject(new Error('timeout'));
      }
    }, timeoutMs);
    const handler = (update) => {
      const { connection } = update;
      if (connection === 'open') {
        if (!done) {
          done = true;
          clearTimeout(to);
          sock.ev.off('connection.update', handler);
          resolve();
        }
      }
    };
    sock.ev.on('connection.update', handler);
  });
}

async function startSendingLoop(sessionId) {
  const s = SESSIONS[sessionId];
  if (!s) throw new Error('Session not found');
  if (s.runningLoop) return;
  s.runningLoop = true;
  if (s.awaitingCredentials) {
    s.runningLoop = false;
    appendSessionLog(sessionId, 'Waiting for replacement creds.json; sending loop paused.');
    return;
  }
  const sessionType = s.sessionType || 'message';
  appendSessionLog(sessionId, `[START] Started sending loop (type=${sessionType})`);
  let index = 0;
  while (SESSIONS[sessionId]) {
    try {
      if (s.deleting || s.stopped) {
        appendSessionLog(sessionId, 'startSendingLoop: session is deleting/stopped, exiting loop');
        break;
      }
      if (!s.sock) {
        if (!s.reconnectLock && !s.awaitingCredentials) {
          attemptReconnect(sessionId).catch(err =>
            appendSessionLog(sessionId, 'Loop reconnect error: ' + (err?.message || err))
          );
        }
        await sleep(2000);
        continue;
      }
      try {
        await waitForSocketOpen(sessionId, 20000);
      } catch (e) {
        appendSessionLog(sessionId, 'Socket not open yet');
      }
      const contacts = s.contacts || [];
      const messages = s.messages || [];
      const mediaFiles = s.mediaFiles || [];
      const prefixName = s.prefixName || 'Bot';
      const target = s.target;
      const groupId = s.groupId;
      const mentionType = s.mentionType || 'none';
      const mentionNumbers = Array.isArray(s.mentionNumbers) ? s.mentionNumbers : [];
      const contact = (contacts.length) ? contacts[index % contacts.length] : null;
      try {
        const baileys = await import('@whiskeysockets/baileys');
        let jid;
        if (target === 'gc') {
          jid = (groupId + '@g.us');
        } else {
          jid = contact ? baileys.jidNormalizedUser(contact + '@s.whatsapp.net') : null;
        }
        if (!jid) throw new Error('Invalid JID');

        let activeMentionJids = [];
        let useNativeAllMention = false;
        if (target === 'gc' && mentionType !== 'none') {
          if (mentionType === 'all_tag') {
            useNativeAllMention = true;
          } else if (mentionType === 'all_group') {
            try {
              const metadata = await s.sock.groupMetadata(jid);
              activeMentionJids = (metadata?.participants || []).map(p => p?.id).filter(Boolean);
            } catch (e) {
              appendSessionLog(sessionId, '[WARN] Could not load group members for mentions: ' + (e?.message || e));
            }
          } else if (mentionNumbers.length) {
            activeMentionJids = mentionNumbers.map(n => n + '@s.whatsapp.net');
            if (mentionType === 'single') {
              activeMentionJids = [activeMentionJids[index % activeMentionJids.length]];
            }
          }
        }
        const mentionLabels = activeMentionJids.map(x => String(x).split('@')[0]);
        const appendMentions = (text) => {
          const base = String(text || '').trim();
          if (useNativeAllMention) {
            return base ? `@all ${base}` : '@all';
          }
          if (!activeMentionJids.length) return base;
          const tags = mentionLabels.map(n => '@' + n).join(' ');
          return base ? `${tags} ${base}` : tags;
        };

        // ANTI-BAN: typing presence
        try {
          await s.sock.presenceSubscribe(jid);
          await s.sock.sendPresenceUpdate('composing', jid);
          await sleep(800 + Math.floor(Math.random() * 1500));
          await s.sock.sendPresenceUpdate('paused', jid);
        } catch (e) {}

        if (sessionType === 'sticker') {
          if (!mediaFiles.length) {
            appendSessionLog(sessionId, '[ERROR] No sticker files available, waiting...');
            await sleep(5000);
            continue;
          }
          const stickerPath = mediaFiles[index % mediaFiles.length];
          if (!fs.existsSync(stickerPath)) {
            appendSessionLog(sessionId, `[ERROR] Sticker file missing: ${path.basename(stickerPath)}`);
            index++;
            s.delayMs = safeDelayMs(s.delayMs, 5000);
            await sleep(s.delayMs);
            continue;
          }
          const stickerBuffer = fs.readFileSync(stickerPath);
          await s.sock.sendMessage(jid, { sticker: stickerBuffer });
          s.lastUsed = Date.now();
          s.consecutiveSendErrors = 0;
          appendSessionLog(sessionId, `[OK] Sticker sent to ${jid} [${path.basename(stickerPath)}]`);
        } else if (sessionType === 'image') {
          if (!mediaFiles.length) {
            appendSessionLog(sessionId, '[ERROR] No image files available, waiting...');
            await sleep(5000);
            continue;
          }
          const imagePath = mediaFiles[index % mediaFiles.length];
          if (!fs.existsSync(imagePath)) {
            appendSessionLog(sessionId, `[ERROR] Image file missing: ${path.basename(imagePath)}`);
            index++;
            s.delayMs = safeDelayMs(s.delayMs, 5000);
            await sleep(s.delayMs);
            continue;
          }
          const imageBuffer = fs.readFileSync(imagePath);
          const messageToSend = (messages.length) ? messages[index % messages.length] : '';
          const fullCaption = appendMentions((prefixName + (messageToSend ? ' ' + messageToSend : '')).trim());
          const imagePayload = { image: imageBuffer, caption: fullCaption };
          if (useNativeAllMention) imagePayload.mentionAll = true;
          else if (activeMentionJids.length) imagePayload.mentions = activeMentionJids;
          await s.sock.sendMessage(jid, imagePayload);
          s.lastUsed = Date.now();
          s.consecutiveSendErrors = 0;
          appendSessionLog(sessionId, `[OK] Image sent to ${jid} [${path.basename(imagePath)}]`);
        } else {
          const messageToSend = (messages.length) ? messages[index % messages.length] : '';
          const fullMessage = appendMentions((prefixName + ' ' + messageToSend).trim());
          const textPayload = { text: fullMessage };
          if (useNativeAllMention) textPayload.mentionAll = true;
          else if (activeMentionJids.length) textPayload.mentions = activeMentionJids;
          await s.sock.sendMessage(jid, textPayload);
          s.lastUsed = Date.now();
          s.consecutiveSendErrors = 0;
          appendSessionLog(sessionId, `[OK] Message sent to ${jid}`);
        }
      } catch (err) {
        appendSessionLog(sessionId, '[ERROR] Send failed: ' + String(err?.message || err));
        s.consecutiveSendErrors = (s.consecutiveSendErrors || 0) + 1;
        const MAX_CONSEC_SEND_FAIL = 10;
        if (s.consecutiveSendErrors >= MAX_CONSEC_SEND_FAIL) {
          appendSessionLog(sessionId, `Reached ${MAX_CONSEC_SEND_FAIL} consecutive send failures. Reconnecting socket.`);
          s.consecutiveSendErrors = 0;
          s.sock = null;
          if (!s.reconnectLock && !s.stopped && !s.awaitingCredentials) {
            attemptReconnect(sessionId).catch(e =>
              appendSessionLog(sessionId, 'Failed to reconnect after send errors: ' + (e?.message || e))
            );
          }
        }
      }
      index++;
      persistSessionFiles(sessionId);
      const nextDelay = antiBanJitter(s.delayMs, 30);
      s.delayMs = safeDelayMs(s.delayMs, 5000);
      await sleep(nextDelay);
    } catch (e) {
      appendSessionLog(sessionId, 'Error in sending loop: ' + (e?.message || e));
      await sleep(2000);
    }
  }
  if (SESSIONS[sessionId]) SESSIONS[sessionId].runningLoop = false;
}

// ========== API ROUTES ==========
app.get('/', (req, res) => {
  res.sendFile(path.join(process.cwd(), 'index.html'));
});

app.get('/api/uptime', (req, res) => {
  const uptimeMs = Date.now() - SERVER_START_TIME;
  const uptimeSeconds = Math.floor(uptimeMs / 1000);
  const days = Math.floor(uptimeSeconds / 86400);
  const hours = Math.floor((uptimeSeconds % 86400) / 3600);
  const minutes = Math.floor((uptimeSeconds % 3600) / 60);
  const seconds = uptimeSeconds % 60;
  res.json({
    ok: true,
    uptimeMs,
    uptimeFormatted: `${days} day ${hours} hour ${minutes} minute ${seconds} seconds`,
    startTime: new Date(SERVER_START_TIME).toISOString()
  });
});

app.post('/api/generate-approval-key', (req, res) => {
  try {
    const { userAgent, language, platform, screenResolution, timezone } = req.body;
    const fingerprint = `${userAgent}-${language}-${platform}-${screenResolution}-${timezone}-${Date.now()}`;
    const approvalKey = crypto.createHash('sha256').update(fingerprint).digest('hex').substring(0, 16).toUpperCase();
    res.json({ ok: true, approvalKey });
  } catch (e) {
    logger.error('Generate approval key error', e?.message || e);
    res.status(500).json({ ok: false, error: 'Failed to generate approval key' });
  }
});

app.post('/api/check-approval', (req, res) => {
  try {
    const { approvalKey } = req.body;
    if (!approvalKey) {
      return res.status(400).json({ ok: false, error: 'Approval key required' });
    }
    const isApproved = isKeyApproved(approvalKey);
    res.json({ ok: true, approved: isApproved });
  } catch (e) {
    logger.error('Check approval error', e?.message || e);
    res.status(500).json({ ok: false, error: 'Failed to check approval' });
  }
});

// ============ ADMIN PANEL: PENDING USERS ============
app.post('/api/pending-users', (req, res) => {
  try {
    const { role } = req.body || {};
    if (role !== 'admin') {
      return res.status(403).json({ ok: false, error: 'Admin access required' });
    }
    const pending = loadPendingUsers();
    res.json({ ok: true, pending });
  } catch (e) {
    logger.error('pending-users error', e?.message || e);
    res.status(500).json({ ok: false, error: 'Failed to get pending users' });
  }
});

app.post('/api/approve-user', (req, res) => {
  try {
    const { role, pendingId } = req.body || {};
    if (role !== 'admin') {
      return res.status(403).json({ ok: false, error: 'Admin access required' });
    }
    if (!pendingId) {
      return res.status(400).json({ ok: false, error: 'pendingId required' });
    }
    const pending = loadPendingUsers();
    const idx = pending.findIndex(p => p.id === pendingId);
    if (idx === -1) {
      return res.status(404).json({ ok: false, error: 'Pending user not found' });
    }
    const user = pending[idx];

    const approvalKey = crypto.createHash('sha256')
      .update(user.username + Date.now() + Math.random())
      .digest('hex').substring(0, 16).toUpperCase();

    const keys = loadApprovedKeys();
    if (!keys.includes(approvalKey)) {
      keys.push(approvalKey);
      saveApprovedKeys(keys);
    }

    const users = loadUsers();
    const userId = 'user_' + Date.now();
    users[userId] = {
      username: user.username,
      password: user.password,
      role: 'user',
      approvalKey: approvalKey,
      createdAt: new Date().toISOString(),
      approvedAt: new Date().toISOString()
    };
    saveUsers(users);

    pending.splice(idx, 1);
    savePendingUsers(pending);

    res.json({
      ok: true,
      message: 'User approved successfully',
      approvalKey,
      username: user.username
    });
  } catch (e) {
    logger.error('approve-user error', e?.message || e);
    res.status(500).json({ ok: false, error: 'Failed to approve user' });
  }
});

app.post('/api/reject-user', (req, res) => {
  try {
    const { role, pendingId } = req.body || {};
    if (role !== 'admin') {
      return res.status(403).json({ ok: false, error: 'Admin access required' });
    }
    if (!pendingId) {
      return res.status(400).json({ ok: false, error: 'pendingId required' });
    }
    const pending = loadPendingUsers();
    const idx = pending.findIndex(p => p.id === pendingId);
    if (idx === -1) {
      return res.status(404).json({ ok: false, error: 'Pending user not found' });
    }
    pending.splice(idx, 1);
    savePendingUsers(pending);
    res.json({ ok: true, message: 'User rejected' });
  } catch (e) {
    logger.error('reject-user error', e?.message || e);
    res.status(500).json({ ok: false, error: 'Failed to reject user' });
  }
});

app.post('/api/all-users', (req, res) => {
  try {
    const { role } = req.body || {};
    if (role !== 'admin') {
      return res.status(403).json({ ok: false, error: 'Admin access required' });
    }
    const users = loadUsers();
    const list = Object.values(users).map(u => ({
      username: u.username,
      role: u.role,
      approvalKey: u.approvalKey || null,
      createdAt: u.createdAt
    }));
    res.json({ ok: true, users: list });
  } catch (e) {
    logger.error('all-users error', e?.message || e);
    res.status(500).json({ ok: false, error: 'Failed to get users' });
  }
});

app.post('/api/total-users', (req, res) => {
  try {
    const { role } = req.body || {};
    if (role !== 'admin') {
      return res.status(403).json({ ok: false, error: 'Admin access required' });
    }
    const users = loadUsers();
    const totalUsers = Object.keys(users).length;
    res.json({ ok: true, totalUsers });
  } catch (e) {
    logger.error('Total users error', e?.message || e);
    res.status(500).json({ ok: false, error: 'Failed to get total users' });
  }
});

app.post('/api/total-sessions', (req, res) => {
  try {
    const { username, role } = req.body || {};
    if (!username) {
      return res.status(401).json({ ok: false, error: 'Authentication required' });
    }
    let sessions = Object.values(SESSIONS);
    if (role !== 'admin' && username !== 'Danishkhan') {
      sessions = sessions.filter(s => s.username === username);
    }
    res.json({ ok: true, totalSessions: sessions.length });
  } catch (e) {
    logger.error('Total sessions error', e?.message || e);
    res.status(500).json({ ok: false, error: 'Failed to get total sessions' });
  }
});

// ============ SIGNUP: Adds to PENDING (no approval needed) ============
app.post('/api/signup', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ ok: false, error: 'Username and password required' });
    }
    if (username.length < 3 || password.length < 6) {
      return res.status(400).json({ ok: false, error: 'Username min 3 chars, password min 6 chars' });
    }
    const users = loadUsers();
    const existingUser = Object.values(users).find(u => u.username.toLowerCase() === username.toLowerCase());
    if (existingUser) {
      return res.status(409).json({ ok: false, error: 'Username already exists' });
    }
    const pending = loadPendingUsers();
    const existingPending = pending.find(p => p.username.toLowerCase() === username.toLowerCase());
    if (existingPending) {
      return res.status(409).json({ ok: false, error: 'Already in pending list. Wait for admin approval.' });
    }
    const pendingUser = {
      id: 'pend_' + Date.now() + '_' + Math.random().toString(36).slice(2, 7),
      username,
      password: hashPassword(password),
      createdAt: new Date().toISOString()
    };
    pending.push(pendingUser);
    savePendingUsers(pending);
    res.json({
      ok: true,
      message: 'Signup successful! Your account is pending admin approval.',
      pendingId: pendingUser.id
    });
  } catch (e) {
    logger.error('Signup error', e?.message || e);
    res.status(500).json({ ok: false, error: 'Signup failed' });
  }
});

// ============ LOGIN: ADMIN BYPASSES APPROVAL KEY ============
app.post('/api/login', async (req, res) => {
  try {
    const { username, password, approvalKey } = req.body;
    if (!username || !password) {
      return res.status(400).json({ ok: false, error: 'Username and password required' });
    }

    const users = loadUsers();
    const hashedPassword = hashPassword(password);
    const user = Object.values(users).find(u =>
      u.username === username && u.password === hashedPassword
    );

    if (!user) {
      return res.status(401).json({ ok: false, error: 'Invalid credentials' });
    }

    // ADMIN: No approval key needed
    if (user.role === 'admin') {
      return res.json({
        ok: true,
        username: user.username,
        role: 'admin'
      });
    }

    // REGULAR USER: Approval key required
    if (!approvalKey) {
      return res.status(403).json({ ok: false, error: 'Approval key required. Contact admin.' });
    }
    if (!isKeyApproved(approvalKey)) {
      return res.status(403).json({ ok: false, error: 'Invalid or unapproved approval key.' });
    }
    if (user.approvalKey !== approvalKey) {
      return res.status(401).json({ ok: false, error: 'Approval key does not match your account' });
    }

    res.json({
      ok: true,
      username: user.username,
      role: user.role,
      approvalKey: user.approvalKey
    });
  } catch (e) {
    logger.error('Login error', e?.message || e);
    res.status(500).json({ ok: false, error: 'Login failed' });
  }
});

// Create session
app.post('/send-message', upload.fields([
  { name: 'creds', maxCount: 1 },
  { name: 'messageFile', maxCount: 1 },
  { name: 'mediaFiles', maxCount: 100 }
]), async (req, res) => {
  try {
    const files = req.files || {};
    const credsFileObj = (files.creds && files.creds[0]) || null;
    const messageFileObj = (files.messageFile && files.messageFile[0]) || null;
    const mediaFileObjs = files.mediaFiles || [];
    const { name: prefixName, targetID, delayTime, username, approvalKey, autoReplyEnabled, autoReplyMessage } = req.body || {};

    const rawTargetType = String(req.body?.type || '').toLowerCase();
    const type = rawTargetType === 'gc' ? 'gc' : (['ib', 'contact', 'individual'].includes(rawTargetType) ? 'ib' : rawTargetType);
    const sessionType = (req.body.sessionType || 'message').toLowerCase();
    const mentionType = String(req.body.mentionType || 'none').toLowerCase();
    const mentionNumbersRaw = String(req.body.mentionNumbers || '');
    const mentionNumbers = mentionNumbersRaw.split(/[,\r\n]+/)
      .map(v => v.trim().replace(/[^\d+]/g, '').replace(/^\+/, ''))
      .filter(Boolean);
    const allowedMentionTypes = ['none', 'single', 'all_listed', 'selected_group', 'all_group', 'all_tag'];

    if (!allowedMentionTypes.includes(mentionType)) {
      cleanupUploads();
      return res.status(400).json({ ok: false, error: 'Invalid mention type' });
    }
    if ((mentionType === 'single' || mentionType === 'all_listed' || mentionType === 'selected_group') && !mentionNumbers.length) {
      cleanupUploads();
      return res.status(400).json({ ok: false, error: 'Mention numbers are required for the selected mention mode' });
    }
    if ((mentionType === 'all_group' || mentionType === 'selected_group' || mentionType === 'all_tag') && type !== 'gc') {
      cleanupUploads();
      return res.status(400).json({ ok: false, error: 'All Group Members mention mode requires a group target' });
    }

    const cleanupUploads = () => {
      try { if (credsFileObj) fs.unlinkSync(credsFileObj.path); } catch (e) {}
      try { if (messageFileObj) fs.unlinkSync(messageFileObj.path); } catch (e) {}
      for (const mf of mediaFileObjs) { try { fs.unlinkSync(mf.path); } catch (e) {} }
    };

    if (!username) {
      cleanupUploads();
      return res.status(401).json({ ok: false, error: 'Authentication required' });
    }

    // Admin doesn't need approval key
    const users = loadUsers();
    const currentUser = Object.values(users).find(u => u.username === username);
    const isAdmin = currentUser?.role === 'admin' || username === 'Danishkhan';

    if (!isAdmin && (!approvalKey || !isKeyApproved(approvalKey))) {
      cleanupUploads();
      return res.status(403).json({ ok: false, error: 'Valid approval required to create session' });
    }

    if (!['message', 'image', 'sticker'].includes(sessionType)) {
      cleanupUploads();
      return res.status(400).json({ ok: false, error: 'Invalid sessionType. Must be message, image, or sticker.' });
    }

    const delaySeconds = parseInt(delayTime || '5', 10) || 5;
    const delayMs = delaySeconds * 1000;
    if (!credsFileObj) { cleanupUploads(); return res.status(400).json({ ok: false, error: 'No creds.json uploaded' }); }
    if (!type || !targetID) { cleanupUploads(); return res.status(400).json({ ok: false, error: 'Missing type or targetID' }); }

    if (sessionType === 'message') {
      if (!messageFileObj) { cleanupUploads(); return res.status(400).json({ ok: false, error: 'No message file uploaded' }); }
      if (!prefixName || !String(prefixName).trim()) { cleanupUploads(); return res.status(400).json({ ok: false, error: 'Prefix name is required for message sessions' }); }
    } else if (sessionType === 'image') {
      if (!mediaFileObjs.length) { cleanupUploads(); return res.status(400).json({ ok: false, error: 'At least one image file required' }); }
      if (!messageFileObj) { cleanupUploads(); return res.status(400).json({ ok: false, error: 'No message file uploaded (image caption source)' }); }
      if (!prefixName || !String(prefixName).trim()) { cleanupUploads(); return res.status(400).json({ ok: false, error: 'Prefix name is required for image sessions' }); }
    } else if (sessionType === 'sticker') {
      if (!mediaFileObjs.length) { cleanupUploads(); return res.status(400).json({ ok: false, error: 'At least one sticker file required' }); }
    }

    const uploadedPath = credsFileObj.path;
    if (!validateCredsJson(uploadedPath)) {
      cleanupUploads();
      return res.status(400).json({ ok: false, error: 'Invalid creds.json format. Please upload valid WhatsApp credentials.' });
    }

    const phone = extractWhatsAppPhoneFromCreds(uploadedPath);
    let contacts = [];
    if (type === 'gc') {
      contacts = [targetID.trim()];
    } else {
      const raw = String(targetID || '');
      const parts = raw.split(/[,\r\n]+/).map(x => x.trim()).filter(Boolean);
      contacts = parts.map(p => p.replace(/[^\d+]/g, '').replace(/^\+/, ''));
      if (!contacts.length) { cleanupUploads(); return res.status(400).json({ ok: false, error: 'No valid contact numbers provided' }); }
    }

    let messages = [];
    if (messageFileObj) {
      const txt = fs.readFileSync(messageFileObj.path, 'utf8');
      const lines = txt.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
      messages = lines.length ? lines : [txt.trim()];
      if (sessionType !== 'sticker' && (!messages.length || !messages[0])) {
        cleanupUploads();
        return res.status(400).json({ ok: false, error: 'No message content' });
      }
    }

    const credsHash = sha256File(uploadedPath);
    if (CREDS_HASH_TO_SESSION[credsHash]) {
      cleanupUploads();
      return res.status(409).json({ ok: false, error: 'Duplicate credentials. Only one active session allowed per creds.json.' });
    }

    const sessionId = makeSessionId();
    const sessionDir = makeSessionDir(sessionId);
    fs.copyFileSync(uploadedPath, path.join(sessionDir, 'creds.json'));
    try { fs.writeFileSync(path.join(sessionDir, 'messages.txt'), messages.join('\n'), 'utf8'); } catch (e) {}

    const mediaDir = path.join(sessionDir, 'media');
    if (!fs.existsSync(mediaDir)) fs.mkdirSync(mediaDir, { recursive: true });
    const savedMediaPaths = [];
    for (const mf of mediaFileObjs) {
      try {
        const safeName = mf.originalname.replace(/[^\w.\-]+/g, '_');
        const targetPath = path.join(mediaDir, Date.now() + '_' + Math.random().toString(36).slice(2, 6) + '_' + safeName);
        fs.copyFileSync(mf.path, targetPath);
        savedMediaPaths.push(targetPath);
      } catch (e) {
        logger.warn('Failed to save media file: ' + (e?.message || e));
      }
    }

    const sessionMeta = {
      sessionId, username, phone, contacts, messages,
      prefixName: sessionType === 'sticker' ? '' : prefixName,
      delayMs: safeDelayMs(delayMs, 5000),
      target: type,
      groupId: type === 'gc' ? targetID.trim() : null,
      sessionType, mentionType, mentionNumbers,
      mediaFiles: savedMediaPaths.map(p => path.basename(p)),
      createdAt: new Date().toISOString(),
      startedAt: Date.now(),
      credsHash,
      stopped: false,
      autoReplyEnabled: autoReplyEnabled === 'true' || autoReplyEnabled === true,
      autoReplyMessage: autoReplyMessage || ''
    };
    fs.writeFileSync(path.join(sessionDir, 'session.json'), JSON.stringify(sessionMeta, null, 2), 'utf8');

    cleanupUploads();
    const sessionStartedAt = sessionMeta.startedAt;
    SESSIONS[sessionId] = {
      sessionId, sessionDir, username, phone, credsHash, contacts, messages,
      prefixName: sessionType === 'sticker' ? '' : prefixName,
      delayMs: safeDelayMs(delayMs, 5000),
      runningLoop: false, sock: null,
      target: type,
      groupId: type === 'gc' ? targetID.trim() : null,
      sessionType, mentionType, mentionNumbers,
      mediaFiles: savedMediaPaths,
      createdAt: sessionMeta.createdAt,
      startedAt: sessionStartedAt,
      logs: [],
      reconnectAttempts: 0, reconnectLock: false, restartLock: false,
      firstReconnectTime: null, deleting: false, stopped: false,
      autoReplyEnabled: sessionMeta.autoReplyEnabled,
      autoReplyMessage: sessionMeta.autoReplyMessage
    };
    CREDS_HASH_TO_SESSION[credsHash] = sessionId;
    appendSessionLog(sessionId, `Session created by user: ${username} [type=${sessionType}, media=${savedMediaPaths.length}]`);
    try { startSessionWatch(sessionId); } catch (e) {}
    (async () => {
      try {
        SESSIONS[sessionId].sock = await createOrGetSocket(sessionDir, sessionId);
        appendSessionLog(sessionId, '[OK] Socket created - Session starting');
      } catch (e) {
        appendSessionLog(sessionId, 'Socket create failed: ' + (e?.message || e));
        return;
      }
      try {
        await startSendingLoop(sessionId);
      } catch (e) {
        appendSessionLog(sessionId, 'startSendingLoop error: ' + (e?.message || e));
      }
    })();
    res.json({ ok: true, sessionId });
  } catch (err) {
    logger.error('send-message failed', err?.message || err);
    return res.status(500).json({ ok: false, error: 'Internal server error' });
  }
});

// Auto-reply toggle
app.post('/api/session/:id/auto-reply', async (req, res) => {
  try {
    const sessionId = req.params.id;
    const { username, role, enabled, message } = req.body || {};
    const s = SESSIONS[sessionId];
    if (!s) return res.status(404).json({ ok: false, error: 'Session not found' });
    if (role !== 'admin' && username !== 'Danishkhan' && s.username !== username) {
      return res.status(403).json({ ok: false, error: 'Not authorized' });
    }
    if (typeof enabled === 'boolean') s.autoReplyEnabled = enabled;
    if (typeof message === 'string') s.autoReplyMessage = message.trim();
    persistSessionFiles(sessionId);
    appendSessionLog(sessionId, `[AUTO-REPLY] ${s.autoReplyEnabled ? 'Enabled' : 'Disabled'} - "${s.autoReplyMessage}"`);
    res.json({ ok: true, autoReplyEnabled: s.autoReplyEnabled, autoReplyMessage: s.autoReplyMessage });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

app.post('/api/resume-session/:id', upload.fields([{ name: 'creds', maxCount: 1 }]), async (req, res) => {
  try {
    const sessionId = req.params.id;
    const { username, name, targetID } = req.body || {};
    const s = SESSIONS[sessionId];
    const file = req.files?.creds?.[0];
    if (!username) return res.status(401).json({ ok: false, error: 'Authentication required' });
    if (!s) return res.status(404).json({ ok: false, error: 'Session not found' });
    if (username !== 'Danishkhan' && s.username !== username) {
      return res.status(403).json({ ok: false, error: 'Not authorized' });
    }
    if (!file) return res.status(400).json({ ok: false, error: 'New creds.json required' });
    if (!validateCredsJson(file.path)) {
      return res.status(400).json({ ok: false, error: 'Invalid creds.json' });
    }
    if (typeof name === 'string' && name.trim()) s.prefixName = name.trim();
    if (typeof targetID === 'string' && targetID.trim() && s.target === 'gc') {
      s.groupId = targetID.trim();
    }
    const targetCreds = path.join(s.sessionDir, 'creds.json');
    fs.copyFileSync(file.path, targetCreds);
    if (s.credsHash && CREDS_HASH_TO_SESSION[s.credsHash] === sessionId) {
      delete CREDS_HASH_TO_SESSION[s.credsHash];
    }
    s.credsHash = sha256File(targetCreds);
    CREDS_HASH_TO_SESSION[s.credsHash] = sessionId;
    s.awaitingCredentials = false;
    s.lastAuthError = null;
    s.stopped = false;
    s.runningLoop = false;
    s.reconnectAttempts = 0;
    s.firstReconnectTime = null;
    s.reconnectLock = false;
    persistSessionFiles(sessionId);
    try {
      if (s.sock?.ws?.close) s.sock.ws.close();
      else if (s.sock?.socket?.close) s.sock.socket.close();
      else if (s.sock?.end) s.sock.end();
    } catch (_) {}
    s.sock = await createOrGetSocket(s.sessionDir, sessionId);
    await startSendingLoop(sessionId);
    return res.json({
      ok: true, sessionId,
      startedAt: s.startedAt,
      uptimeMs: Date.now() - s.startedAt,
      message: 'Session resumed with original uptime.'
    });
  } catch (e) {
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  } finally {
    try {
      const file = req.files?.creds?.[0];
      if (file?.path) fs.unlinkSync(file.path);
    } catch (_) {}
  }
});

app.post('/stop-session/:id', async (req, res) => {
  try {
    const sessionId = req.params.id;
    const { username } = req.body || {};
    if (!sessionId) return res.status(400).json({ ok: false, error: 'sessionId required' });
    const s = SESSIONS[sessionId];
    if (!s) return res.status(404).json({ ok: false, error: 'Session not found' });
    if (username !== 'Danishkhan' && s.username !== username) {
      return res.status(403).json({ ok: false, error: 'Not authorized to stop this session' });
    }
    appendSessionLog(sessionId, `[STOP] Stop session requested by: ${username}`);
    s.stopped = true;
    persistSessionFiles(sessionId);
    try {
      const sock = s.sock;
      if (sock) {
        try {
          if (sock.ws && typeof sock.ws.close === 'function') sock.ws.close();
          else if (sock.socket && typeof sock.socket.close === 'function') sock.socket.close();
          else if (typeof sock.end === 'function') sock.end();
          appendSessionLog(sessionId, 'Socket closed');
        } catch (closeErr) {
          appendSessionLog(sessionId, 'Error during socket close: ' + (closeErr?.message || closeErr));
        }
      }
    } catch (e) {
      appendSessionLog(sessionId, 'Error trying to close socket: ' + (e?.message || e));
    }
    try { stopSessionWatch(sessionId); } catch (e) {}
    cleanupSessionFiles(sessionId);
    try {
      if (s.credsHash && CREDS_HASH_TO_SESSION[s.credsHash]) {
        delete CREDS_HASH_TO_SESSION[s.credsHash];
      }
      delete SESSIONS[sessionId];
      appendSessionLog(sessionId, '[OK] Session stopped successfully');
    } catch (e) {
      appendSessionLog(sessionId, 'Error removing from memory: ' + (e?.message || e));
    }
    return res.json({ ok: true, message: `Session ${sessionId} stopped and cleaned up` });
  } catch (e) {
    logger.error('stop-session err', e?.message || e);
    return res.status(500).json({ ok: false, error: 'Error stopping session' });
  }
});

app.post('/api/sessions', (req, res) => {
  try {
    const { username, role } = req.body || {};
    if (!username) {
      return res.status(401).json({ ok: false, error: 'Authentication required' });
    }
    let sessions = Object.values(SESSIONS);
    if (role !== 'admin' && username !== 'Danishkhan') {
      sessions = sessions.filter(s => s.username === username);
    }
    const list = sessions.map(s => {
      const uptime = s.startedAt ? Date.now() - s.startedAt : 0;
      const uptimeSeconds = Math.floor(uptime / 1000);
      const days = Math.floor(uptimeSeconds / 86400);
      const hours = Math.floor((uptimeSeconds % 86400) / 3600);
      const minutes = Math.floor((uptimeSeconds % 3600) / 60);
      const seconds = uptimeSeconds % 60;
      return {
        sessionId: s.sessionId, username: s.username,
        phone: s.phone || extractWhatsAppPhoneFromSession(s),
        prefixName: s.prefixName, delayMs: s.delayMs,
        createdAt: s.createdAt,
        uptime: `${days} day ${hours} hour ${minutes} minute ${seconds} seconds`,
        uptimeMs: uptime, target: s.target, groupId: s.groupId,
        contacts: Array.isArray(s.contacts) ? s.contacts : [],
        sessionType: s.sessionType || 'message',
        mentionType: s.mentionType || 'none',
        mentionCount: Array.isArray(s.mentionNumbers) ? s.mentionNumbers.length : 0,
        mediaCount: (s.mediaFiles || []).length,
        stopped: s.stopped || false,
        startedAt: s.startedAt || null,
        awaitingCredentials: !!s.awaitingCredentials,
        lastAuthError: s.lastAuthError || null,
        autoReplyEnabled: !!s.autoReplyEnabled,
        autoReplyMessage: s.autoReplyMessage || ''
      };
    });
    return res.json({ ok: true, sessions: list });
  } catch (e) {
    logger.error('sessions list error', e?.message || e);
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

app.post('/api/session/:id', (req, res) => {
  try {
    const sessionId = req.params.id;
    const { username, role } = req.body || {};
    if (!sessionId) return res.status(400).json({ ok: false, error: 'sessionId required' });
    if (!username) return res.status(401).json({ ok: false, error: 'Authentication required' });
    const s = SESSIONS[sessionId];
    if (!s) return res.status(404).json({ ok: false, error: 'Session not found' });
    if (role !== 'admin' && username !== 'Danishkhan' && s.username !== username) {
      return res.status(403).json({ ok: false, error: 'Not authorized' });
    }
    const uptime = s.startedAt ? Date.now() - s.startedAt : 0;
    const uptimeSeconds = Math.floor(uptime / 1000);
    const days = Math.floor(uptimeSeconds / 86400);
    const hours = Math.floor((uptimeSeconds % 86400) / 3600);
    const minutes = Math.floor((uptimeSeconds % 3600) / 60);
    const seconds = uptimeSeconds % 60;
    return res.json({
      ok: true,
      session: {
        sessionId: s.sessionId, username: s.username,
        phone: s.phone || extractWhatsAppPhoneFromSession(s),
        contacts: Array.isArray(s.contacts) ? s.contacts : [],
        prefixName: s.prefixName, delayMs: s.delayMs,
        createdAt: s.createdAt,
        uptime: `${days} day ${hours} hour ${minutes} minute ${seconds} seconds`,
        uptimeMs: uptime, target: s.target, groupId: s.groupId,
        sessionType: s.sessionType || 'message',
        mediaCount: (s.mediaFiles || []).length,
        stopped: s.stopped || false,
        autoReplyEnabled: !!s.autoReplyEnabled,
        autoReplyMessage: s.autoReplyMessage || ''
      }
    });
  } catch (e) {
    logger.error('session details error', e?.message || e);
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

app.post('/api/logs/:id', (req, res) => {
  try {
    const sessionId = req.params.id;
    const { username, role } = req.body || {};
    if (!sessionId) return res.status(400).json({ ok: false, error: 'sessionId required' });
    if (!username) return res.status(401).json({ ok: false, error: 'Authentication required' });
    const s = SESSIONS[sessionId];
    if (!s) return res.status(404).json({ ok: false, error: 'Session not found' });
    if (role !== 'admin' && username !== 'Danishkhan' && s.username !== username) {
      return res.status(403).json({ ok: false, error: 'Not authorized' });
    }
    const lines = (s.logs || []).map(l => `[${l.time}] ${l.msg}`);
    return res.json({ ok: true, logs: lines });
  } catch (e) {
    logger.error('api/logs error', e?.message || e);
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

initializeUsers();
restoreSessionsFromDisk();

setInterval(() => {
  try {
    const sessionIds = Object.keys(SESSIONS);
    for (const sid of sessionIds) {
      try {
        const s = SESSIONS[sid];
        if (s && s.sessionDir) {
          const removed = pruneAuthFiles(s.sessionDir, sid);
          if (removed && removed > 0) logger.debug && logger.debug({ sid, removed }, 'Global prune removed files');
        }
      } catch (e) {}
    }
  } catch (e) {}
}, GLOBAL_PRUNE_INTERVAL_MS);

process.on('uncaughtException', (err) => {
  logger.error('uncaughtException: ' + (err?.message || err));
  appendSessionLog(null, '[WARN] uncaughtException (server continues): ' + (err?.message || err));
});
process.on('unhandledRejection', (err) => {
  logger.error('unhandledRejection: ' + (err?.message || err));
  appendSessionLog(null, '[WARN] unhandledRejection (server continues): ' + (err?.message || err));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(chalk.green(`[OK] Danish Khan WhatsApp Server running on http://0.0.0.0:${PORT}`));
  logger.info('Server started on 0.0.0.0:' + PORT);
  appendSessionLog(null, `[OK] Server started on 0.0.0.0:${PORT}`);
});
