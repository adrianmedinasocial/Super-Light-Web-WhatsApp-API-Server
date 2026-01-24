// Memory optimization for production environments
if (process.env.NODE_ENV === 'production') {
    // Limit V8 heap if not already set
    if (!process.env.NODE_OPTIONS) {
        process.env.NODE_OPTIONS = '--max-old-space-size=1024';
    }
    // Optimize garbage collection
    if (global.gc) {
        setInterval(() => {
            global.gc();
        }, 60000); // Run GC every minute
    }
}

const {
    default: makeWASocket,
    useMultiFileAuthState,
    fetchLatestBaileysVersion,
    makeCacheableSignalKeyStore,
    isJidBroadcast,
    Browsers,
    DisconnectReason
} = require('@whiskeysockets/baileys');
const NodeCache = require('node-cache');
const pino = require('pino');
const { Boom } = require('@hapi/boom');
const express = require('express');
const bodyParser = require('body-parser');
const http = require('http');
const { WebSocketServer } = require('ws');
const path = require('path');
const fs = require('fs');
const axios = require('axios');
const { initializeApi, apiToken, getWebhookUrl } = require('./api_v1');
const { initializeLegacyApi } = require('./legacy_api');
const { randomUUID } = require('crypto');
const crypto = require('crypto'); // Add crypto for encryption
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();
const session = require('express-session');
const FileStore = require('session-file-store')(session);
const UserManager = require('./users');
const ActivityLogger = require('./activity-logger');
const AudioTranscriber = require('./audio-transcriber');

const sessions = new Map();
const retries = new Map();
const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

// 🔧 FIX: Global message store for retry requests (prevents "Bad MAC" errors)
// This stores sent messages so Baileys can re-encrypt them when WhatsApp requests a retry
const globalMessageStore = new Map();
const MESSAGE_STORE_TTL = 5 * 60 * 1000; // 5 minutes

// Cleanup old messages from store every 2 minutes
setInterval(() => {
    const now = Date.now();
    let cleaned = 0;
    for (const [key, value] of globalMessageStore.entries()) {
        if (now - value.timestamp > MESSAGE_STORE_TTL) {
            globalMessageStore.delete(key);
            cleaned++;
        }
    }
    if (cleaned > 0) {
        console.log(`[MESSAGE-STORE] Cleaned ${cleaned} expired messages from retry store`);
    }
}, 2 * 60 * 1000);

// 🔧 FIX: Global storage for cleanup intervals and processed messages per session
// This prevents memory leaks when sessions reconnect
const sessionCleanupIntervals = new Map();
const sessionProcessedMessages = new Map();

// 🔧 FIX: Message retry counter cache - CRITICAL for handling Bad MAC errors
// This cache stores retry counts for messages that fail to decrypt
// Without this, Baileys can't properly handle message retries from WhatsApp
const msgRetryCounterCache = new NodeCache({
    stdTTL: 600, // 10 minutes TTL
    checkperiod: 60, // Check for expired keys every 60 seconds
    useClones: false
});

// 🔧 FIX: Mutex system for saveCreds to prevent concurrent writes that corrupt Signal keys
// This fixes the intermittent "Bad MAC" errors caused by race conditions
const credsMutexes = new Map(); // Per-session mutex locks
const credsWriteQueues = new Map(); // Pending writes per session

// Simple mutex implementation for credential saving
function createCredsMutex(sessionId) {
    if (!credsMutexes.has(sessionId)) {
        credsMutexes.set(sessionId, {
            locked: false,
            queue: []
        });
    }
    return credsMutexes.get(sessionId);
}

async function withCredsMutex(sessionId, fn) {
    const mutex = createCredsMutex(sessionId);

    return new Promise((resolve, reject) => {
        const execute = async () => {
            mutex.locked = true;
            try {
                const result = await fn();
                resolve(result);
            } catch (err) {
                reject(err);
            } finally {
                mutex.locked = false;
                // Process next in queue
                if (mutex.queue.length > 0) {
                    const next = mutex.queue.shift();
                    next();
                }
            }
        };

        if (mutex.locked) {
            mutex.queue.push(execute);
        } else {
            execute();
        }
    });
}

// Debounced saveCreds wrapper to batch rapid credential updates
function createDebouncedSaveCreds(sessionId, originalSaveCreds, delay = 500) {
    let timeout = null;
    let pendingPromise = null;
    let pendingResolvers = [];

    return async () => {
        return new Promise((resolve, reject) => {
            pendingResolvers.push({ resolve, reject });

            if (timeout) {
                clearTimeout(timeout);
            }

            timeout = setTimeout(async () => {
                const resolvers = [...pendingResolvers];
                pendingResolvers = [];
                timeout = null;

                try {
                    await withCredsMutex(sessionId, async () => {
                        await originalSaveCreds();
                    });
                    resolvers.forEach(r => r.resolve());
                } catch (err) {
                    console.error(`[${sessionId}] Error saving credentials:`, err.message);
                    resolvers.forEach(r => r.reject(err));
                }
            }, delay);
        });
    };
}

// Track WebSocket connections with their associated users
const wsClients = new Map(); // Maps WebSocket client to user info

const logger = pino({ level: 'debug' });

// Persistent data directory (use DATA_DIR env for Railway volumes, fallback to local)
const DATA_DIR = process.env.DATA_DIR || __dirname;
const SESSIONS_DIR = process.env.SESSIONS_DIR || path.join(__dirname, 'auth_info_baileys');

const TOKENS_FILE = path.join(DATA_DIR, 'session_tokens.json');
const ENCRYPTED_TOKENS_FILE = path.join(DATA_DIR, 'session_tokens.enc');
let sessionTokens = new Map();

// Log data directories on startup
console.log(`📁 Data directory: ${DATA_DIR}`);
console.log(`📁 Sessions directory: ${SESSIONS_DIR}`);

// Encryption key - MUST be stored in .env file
// 🔧 FIX: Make encryption key MANDATORY in production to prevent session loss on restart
let ENCRYPTION_KEY;
if (!process.env.TOKEN_ENCRYPTION_KEY) {
    if (process.env.NODE_ENV === 'production') {
        console.error('❌ FATAL ERROR: TOKEN_ENCRYPTION_KEY not set!');
        console.error('   Without this key, all sessions will be lost on restart.');
        console.error('   Generate a key with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
        console.error('   Then add to environment: TOKEN_ENCRYPTION_KEY=<your_key>');
        process.exit(1);
    } else {
        // In development, generate a random key but warn loudly
        ENCRYPTION_KEY = crypto.randomBytes(32).toString('hex');
        console.warn('⚠️  WARNING: TOKEN_ENCRYPTION_KEY not set - using random key for development.');
        console.warn('   Sessions will be lost on restart!');
        console.warn(`   Add to .env: TOKEN_ENCRYPTION_KEY=${ENCRYPTION_KEY}`);
    }
} else {
    ENCRYPTION_KEY = process.env.TOKEN_ENCRYPTION_KEY;
}

// Initialize user management and activity logging
const userManager = new UserManager(ENCRYPTION_KEY);
const activityLogger = new ActivityLogger(ENCRYPTION_KEY);
const audioTranscriber = new AudioTranscriber();

// Encryption functions
function encrypt(text) {
    const algorithm = 'aes-256-cbc';
    const key = Buffer.from(ENCRYPTION_KEY.slice(0, 64), 'hex');
    const iv = crypto.randomBytes(16);

    const cipher = crypto.createCipheriv(algorithm, key, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    return iv.toString('hex') + ':' + encrypted;
}

function decrypt(text) {
    const algorithm = 'aes-256-cbc';
    const key = Buffer.from(ENCRYPTION_KEY.slice(0, 64), 'hex');

    const parts = text.split(':');
    const iv = Buffer.from(parts[0], 'hex');
    const encryptedText = parts[1];

    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
}

// Enhanced token management with encryption
function saveTokens() {
    try {
        const tokensToSave = Object.fromEntries(sessionTokens);
        const jsonString = JSON.stringify(tokensToSave, null, 2);
        const encrypted = encrypt(jsonString);

        fs.writeFileSync(ENCRYPTED_TOKENS_FILE, encrypted, 'utf-8');

        // Set file permissions (read/write for owner only)
        if (process.platform !== 'win32') {
            fs.chmodSync(ENCRYPTED_TOKENS_FILE, 0o600);
        }

        // Keep backward compatibility - save plain JSON but with warning
        if (fs.existsSync(TOKENS_FILE)) {
            fs.unlinkSync(TOKENS_FILE); // Remove old plain file
        }
    } catch (error) {
        console.error('Error saving encrypted tokens:', error);
    }
}

function loadTokens() {
    try {
        // Try to load encrypted file first
        if (fs.existsSync(ENCRYPTED_TOKENS_FILE)) {
            const encrypted = fs.readFileSync(ENCRYPTED_TOKENS_FILE, 'utf-8');
            const decrypted = decrypt(encrypted);
            const tokensFromFile = JSON.parse(decrypted);

            sessionTokens.clear();
            for (const [key, value] of Object.entries(tokensFromFile)) {
                sessionTokens.set(key, value);
            }
            return;
        }

        // Fallback: migrate from old plain JSON file
        if (fs.existsSync(TOKENS_FILE)) {
            console.log('📦 Migrating plain tokens to encrypted format...');
            const tokensFromFile = JSON.parse(fs.readFileSync(TOKENS_FILE, 'utf-8'));

            sessionTokens.clear();
            for (const [key, value] of Object.entries(tokensFromFile)) {
                sessionTokens.set(key, value);
            }

            // Save as encrypted and remove old file
            saveTokens();
            fs.unlinkSync(TOKENS_FILE);
            console.log('✅ Migration complete! Tokens are now encrypted.');
        }
    } catch (error) {
        console.error('Error loading tokens:', error);
        sessionTokens.clear();
    }
}

// Ensure media directory exists
const mediaDir = path.join(__dirname, 'media');
if (!fs.existsSync(mediaDir)) {
    fs.mkdirSync(mediaDir);
}

app.use(express.json());
// Trust proxy for Railway and other reverse proxy environments
// Railway uses a single reverse proxy, so we trust 1 hop
app.set('trust proxy', 1);

app.use(bodyParser.json());
app.use('/admin', express.static(path.join(__dirname, 'admin')));
app.use('/media', express.static(mediaDir)); // Serve uploaded media
app.use(express.urlencoded({ extended: true }));
app.use(
    helmet({
        contentSecurityPolicy: {
            directives: {
                ...helmet.contentSecurityPolicy.getDefaultDirectives(),
                "script-src": ["'self'", "'unsafe-inline'"]
            }
        }
    })
);
app.use(rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 100,
    message: { status: 'error', message: 'Too many requests, please try again later.' },
    // Railway uses a single reverse proxy
    trustProxy: false, // Let it use app.set('trust proxy') instead
    standardHeaders: true,
    legacyHeaders: false
}));

const ADMIN_PASSWORD = process.env.ADMIN_DASHBOARD_PASSWORD;

// Session limits configuration
const MAX_SESSIONS = parseInt(process.env.MAX_SESSIONS) || 10;
const SESSION_TIMEOUT_HOURS = parseInt(process.env.SESSION_TIMEOUT_HOURS) || 24;

// WebSocket connection handler
wss.on('connection', (ws, req) => {
    // Try to authenticate the WebSocket connection
    const url = new URL(req.url, `http://${req.headers.host}`);
    const wsToken = url.searchParams.get('token');

    let userInfo = null;

    if (wsToken && global.wsAuthTokens) {
        const tokenData = global.wsAuthTokens.get(wsToken);
        if (tokenData && tokenData.expires > Date.now()) {
            userInfo = {
                email: tokenData.email,
                role: tokenData.role
            };
            // Delete the token after use (one-time use)
            global.wsAuthTokens.delete(wsToken);
        }
    }

    // Store the user info for this WebSocket client
    wsClients.set(ws, userInfo);

    // Send initial session data based on user permissions
    if (userInfo) {
        ws.send(JSON.stringify({
            type: 'session-update',
            data: getSessionsDetails(userInfo.email, userInfo.role === 'admin')
        }));
    }

    ws.on('close', () => {
        // Clean up when client disconnects
        wsClients.delete(ws);
    });
});

// Use file-based session store for production
const sessionStore = new FileStore({
    path: './sessions',
    ttl: 86400, // 1 day
    retries: 3,
    secret: process.env.SESSION_SECRET || 'change_this_secret'
});

app.use(session({
    store: sessionStore,
    secret: process.env.SESSION_SECRET || 'change_this_secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: false, // Set secure: true if using HTTPS
        maxAge: 86400000 // 1 day
    }
}));

// Serve homepage
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Serve API documentation
app.get('/api-documentation', (req, res) => {
    res.sendFile(path.join(__dirname, 'api_documentation.html'));
});

// Redirect old URL to new one
app.get('/api_documentation.md', (req, res) => {
    res.redirect('/api-documentation');
});

// Admin login endpoint - supports both legacy password and new email/password
app.post('/admin/login', express.json(), async (req, res) => {
    const { email, password } = req.body;
    const ip = req.ip;
    const userAgent = req.headers['user-agent'];

    // Legacy support: if only password is provided, try admin password
    if (!email && password === ADMIN_PASSWORD) {
        req.session.adminAuthed = true;
        req.session.userEmail = 'admin@localhost';
        req.session.userRole = 'admin';
        await activityLogger.logLogin('admin@localhost', ip, userAgent, true);
        return res.json({ success: true, role: 'admin' });
    }

    // New email/password authentication
    if (email && password) {
        const user = await userManager.authenticateUser(email, password);
        if (user) {
            req.session.adminAuthed = true;
            req.session.userEmail = user.email;
            req.session.userRole = user.role;
            req.session.userId = user.id;
            await activityLogger.logLogin(user.email, ip, userAgent, true);
            return res.json({
                success: true,
                role: user.role,
                email: user.email
            });
        }
    }

    await activityLogger.logLogin(email || 'unknown', ip, userAgent, false);
    res.status(401).json({ success: false, message: 'Invalid credentials' });
});

// Middleware to protect admin dashboard
function requireAdminAuth(req, res, next) {
    if (req.session && req.session.adminAuthed) {
        return next();
    }
    res.status(401).sendFile(path.join(__dirname, 'admin', 'login.html'));
}

// Middleware to check if user is admin role
function requireAdminRole(req, res, next) {
    if (req.session && req.session.adminAuthed && req.session.userRole === 'admin') {
        return next();
    }
    res.status(403).json({ success: false, message: 'Admin access required' });
}

// Helper to get current user info
function getCurrentUser(req) {
    if (!req.session || !req.session.adminAuthed) return null;
    return {
        email: req.session.userEmail,
        role: req.session.userRole,
        id: req.session.userId
    };
}

// Serve login page only if not authenticated
app.get('/admin/login.html', (req, res) => {
    if (req.session && req.session.adminAuthed) {
        return res.redirect('/admin/dashboard.html');
    }
    res.sendFile(path.join(__dirname, 'admin', 'login.html'));
});

// Protect dashboard and /admin route
app.get('/admin/dashboard.html', requireAdminAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'admin', 'dashboard.html'));
});
app.get('/admin', requireAdminAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'admin', 'dashboard.html'));
});

// Protect user management page (admin only)
app.get('/admin/users.html', requireAdminAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'admin', 'users.html'));
});

// Protect activities page
app.get('/admin/activities.html', requireAdminAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'admin', 'activities.html'));
});

// Protect campaigns page
app.get('/admin/campaigns.html', requireAdminAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'admin', 'campaigns.html'));
});

// Admin logout endpoint
app.post('/admin/logout', requireAdminAuth, (req, res) => {
    req.session.destroy(() => {
        res.clearCookie('connect.sid');
        res.json({ success: true, redirect: '/admin/login.html' });
    });
});

// User management endpoints
app.get('/api/v1/users', requireAdminAuth, (req, res) => {
    const currentUser = getCurrentUser(req);
    if (currentUser.role === 'admin') {
        // Admin can see all users
        res.json(userManager.getAllUsers());
    } else {
        // Regular users can only see themselves
        res.json([userManager.getUser(currentUser.email)]);
    }
});

app.post('/api/v1/users', requireAdminRole, async (req, res) => {
    const { email, password, role = 'user' } = req.body;
    const currentUser = getCurrentUser(req);
    const ip = req.ip;
    const userAgent = req.headers['user-agent'];

    try {
        const newUser = await userManager.createUser({
            email,
            password,
            role,
            createdBy: currentUser.email
        });

        await activityLogger.logUserCreate(currentUser.email, email, role, ip, userAgent);
        res.status(201).json(newUser);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.put('/api/v1/users/:email', requireAdminRole, async (req, res) => {
    const { email } = req.params;
    const updates = req.body;
    const currentUser = getCurrentUser(req);
    const ip = req.ip;
    const userAgent = req.headers['user-agent'];

    try {
        const updatedUser = await userManager.updateUser(email, updates);
        await activityLogger.logUserUpdate(currentUser.email, email, updates, ip, userAgent);
        res.json(updatedUser);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.delete('/api/v1/users/:email', requireAdminRole, async (req, res) => {
    const { email } = req.params;
    const currentUser = getCurrentUser(req);
    const ip = req.ip;
    const userAgent = req.headers['user-agent'];

    try {
        await userManager.deleteUser(email);
        await activityLogger.logUserDelete(currentUser.email, email, ip, userAgent);
        res.json({ success: true });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Get current user info
app.get('/api/v1/me', (req, res) => {
    if (!req.session || !req.session.adminAuthed) {
        return res.status(401).json({ error: 'Authentication required' });
    }

    const currentUser = getCurrentUser(req);
    const user = userManager.getUser(currentUser.email);
    res.json(user);
});

// Generate WebSocket authentication token
app.get('/api/v1/ws-auth', requireAdminAuth, (req, res) => {
    const currentUser = getCurrentUser(req);
    // Create a temporary token for WebSocket authentication
    const wsToken = crypto.randomBytes(32).toString('hex');

    // Store the token temporarily (expires in 30 seconds)
    const tokenData = {
        email: currentUser.email,
        role: currentUser.role,
        expires: Date.now() + 30000 // 30 seconds
    };

    // Store in a temporary map (you might want to use Redis in production)
    if (!global.wsAuthTokens) {
        global.wsAuthTokens = new Map();
    }
    global.wsAuthTokens.set(wsToken, tokenData);

    // Clean up expired tokens
    setTimeout(() => {
        global.wsAuthTokens.delete(wsToken);
    }, 30000);

    res.json({ wsToken });
});

// Activity endpoints
app.get('/api/v1/activities', requireAdminAuth, async (req, res) => {
    const currentUser = getCurrentUser(req);
    const { limit = 100, startDate, endDate } = req.query;

    if (currentUser.role === 'admin') {
        // Admin can see all activities
        const activities = await activityLogger.getActivities({
            limit: parseInt(limit),
            startDate,
            endDate
        });
        res.json(activities);
    } else {
        // Regular users see only their activities
        const activities = await activityLogger.getUserActivities(currentUser.email, parseInt(limit));
        res.json(activities);
    }
});

app.get('/api/v1/activities/summary', requireAdminRole, async (req, res) => {
    const { days = 7 } = req.query;
    const summary = await activityLogger.getActivitySummary(null, parseInt(days));
    res.json(summary);
});

// Test endpoint to verify log injection
app.get('/admin/test-logs', requireAdminAuth, (req, res) => {
    let logData = [];
    try {
        if (fs.existsSync(SYSTEM_LOG_FILE)) {
            const lines = fs.readFileSync(SYSTEM_LOG_FILE, 'utf-8').split('\n').filter(Boolean);
            const entries = lines.map(line => {
                try { return JSON.parse(line); } catch { return null; }
            }).filter(Boolean);
            logData = entries;
        }
    } catch (error) {
        console.error('Test endpoint error:', error);
    }
    res.json({
        logFileExists: fs.existsSync(SYSTEM_LOG_FILE),
        logCount: logData.length,
        logs: logData
    });
});

// Update logs endpoint
app.post('/admin/update-logs', requireAdminAuth, express.json(), (req, res) => {
    const { logs } = req.body;

    if (!Array.isArray(logs)) {
        return res.status(400).json({ error: 'Invalid logs data' });
    }

    try {
        // Clear the in-memory log
        systemLog.length = 0;

        // Update in-memory log with new data
        logs.forEach(log => {
            if (log.details && log.details.event === 'messages-sent') {
                systemLog.push(log);
            }
        });

        // Rewrite the system.log file
        const logLines = logs.map(log => JSON.stringify(log)).join('\n');
        fs.writeFileSync(SYSTEM_LOG_FILE, logLines + '\n');

        log('System log updated', 'SYSTEM', { event: 'log-updated', count: logs.length });
        res.json({ success: true, message: 'Logs updated successfully' });
    } catch (error) {
        console.error('Error updating logs:', error);
        res.status(500).json({ error: 'Failed to update logs' });
    }
});

const v1ApiRouter = initializeApi(sessions, sessionTokens, createSession, getSessionsDetails, deleteSession, deleteAllSessions, log, userManager, activityLogger, globalMessageStore);
const legacyApiRouter = initializeLegacyApi(sessions, sessionTokens);
app.use('/api/v1', v1ApiRouter);
app.use('/api', legacyApiRouter); // Mount legacy routes at /api

// Set up campaign sender event listeners for WebSocket updates
if (v1ApiRouter.campaignSender) {
    v1ApiRouter.campaignSender.on('progress', (data) => {
        // Broadcast campaign progress to authenticated WebSocket clients
        wss.clients.forEach(client => {
            if (client.readyState === client.OPEN) {
                const userInfo = wsClients.get(client);
                if (userInfo) {
                    client.send(JSON.stringify({
                        type: 'campaign-progress',
                        ...data
                    }));
                }
            }
        });
    });

    v1ApiRouter.campaignSender.on('status', (data) => {
        // Broadcast campaign status updates
        wss.clients.forEach(client => {
            if (client.readyState === client.OPEN) {
                const userInfo = wsClients.get(client);
                if (userInfo) {
                    client.send(JSON.stringify({
                        type: 'campaign-status',
                        ...data
                    }));
                }
            }
        });
    });
}
// Prevent serving sensitive files
app.use((req, res, next) => {
    if (req.path.includes('session_tokens.json') || req.path.endsWith('.bak')) {
        return res.status(403).send('Forbidden');
    }
    next();
});

function broadcast(data) {
    wss.clients.forEach(client => {
        if (client.readyState === client.OPEN) {
            const userInfo = wsClients.get(client);

            // If it's a session update, filter based on user permissions
            if (data.type === 'session-update') {
                let filteredData = { ...data };

                if (userInfo && userInfo.email) {
                    // Send filtered sessions based on user permissions
                    filteredData.data = getSessionsDetails(userInfo.email, userInfo.role === 'admin');
                } else {
                    // Unauthenticated connections get no session data
                    filteredData.data = [];
                }

                client.send(JSON.stringify(filteredData));
            } else {
                // For other message types (logs), send as-is
                client.send(JSON.stringify(data));
            }
        }
    });
}

// System log history (in-memory)
const systemLog = [];
const MAX_LOG_ENTRIES = 1000;
const SYSTEM_LOG_FILE = path.join(__dirname, 'system.log');

// Load last N log entries from disk on startup
function loadSystemLogFromDisk() {
    if (!fs.existsSync(SYSTEM_LOG_FILE)) return;
    const lines = fs.readFileSync(SYSTEM_LOG_FILE, 'utf-8').split('\n').filter(Boolean);
    const lastLines = lines.slice(-MAX_LOG_ENTRIES);
    for (const line of lastLines) {
        try {
            const entry = JSON.parse(line);
            systemLog.push(entry);
        } catch { }
    }
}

function rotateSystemLogIfNeeded() {
    try {
        if (fs.existsSync(SYSTEM_LOG_FILE)) {
            const stats = fs.statSync(SYSTEM_LOG_FILE);
            if (stats.size > 5 * 1024 * 1024) { // 5MB
                if (fs.existsSync(SYSTEM_LOG_FILE + '.bak')) {
                    fs.unlinkSync(SYSTEM_LOG_FILE + '.bak');
                }
                fs.renameSync(SYSTEM_LOG_FILE, SYSTEM_LOG_FILE + '.bak');
            }
        }
    } catch (e) {
        console.error('Failed to rotate system.log:', e.message);
    }
}

function log(message, sessionId = 'SYSTEM', details = {}) {
    const logEntry = {
        type: 'log',
        sessionId,
        message,
        details,
        timestamp: new Date().toISOString()
    };
    // Only persist and show in dashboard if this is a sent message log (event: 'messages-sent')
    if (details && details.event === 'messages-sent') {
        systemLog.push(logEntry);
        if (systemLog.length > MAX_LOG_ENTRIES) {
            systemLog.shift(); // Remove oldest
        }
        try {
            rotateSystemLogIfNeeded();
            fs.appendFileSync(SYSTEM_LOG_FILE, JSON.stringify(logEntry) + '\n');
        } catch (e) {
            console.error('Failed to write to system.log:', e.message);
        }
    }
    console.log(`[${sessionId}] ${message}`);
    broadcast(logEntry);
}

// Export system log as JSON
app.get('/api/v1/logs/export', requireAdminAuth, (req, res) => {
    res.setHeader('Content-Disposition', 'attachment; filename="system-log.json"');
    res.setHeader('Content-Type', 'application/json');
    res.send(JSON.stringify(systemLog, null, 2));
});

// 🔧 FIX: Update postToWebhook with retry logic and exponential backoff
async function postToWebhook(data, retryCount = 0) {
    const MAX_RETRIES = 3;
    const BASE_DELAY = 2000; // 2 seconds base delay
    const sessionId = data.sessionId || 'SYSTEM';
    const webhookUrl = getWebhookUrl(sessionId);
    if (!webhookUrl) return;

    try {
        await axios.post(webhookUrl, data, {
            headers: { 'Content-Type': 'application/json' },
            timeout: 30000 // 30 second timeout
        });
        log(`Successfully posted to webhook: ${webhookUrl}`);
    } catch (error) {
        const isRetryable = error.code === 'ECONNRESET' ||
            error.code === 'ETIMEDOUT' ||
            error.code === 'ECONNABORTED' ||
            (error.response && error.response.status >= 500);

        if (isRetryable && retryCount < MAX_RETRIES) {
            const delay = BASE_DELAY * Math.pow(2, retryCount); // Exponential backoff: 2s, 4s, 8s
            log(`⚠️ Webhook failed (attempt ${retryCount + 1}/${MAX_RETRIES}), retrying in ${delay}ms: ${error.message}`);
            setTimeout(() => postToWebhook(data, retryCount + 1), delay);
        } else if (retryCount >= MAX_RETRIES) {
            log(`❌ Webhook failed after ${MAX_RETRIES} attempts: ${error.message}`);
            // Log the failed message data for potential manual recovery
            log(`   Failed message data: event=${data.event}, sessionId=${sessionId}, messageId=${data.messageId || 'N/A'}`);
        } else {
            log(`❌ Webhook failed (non-retryable): ${error.message}`);
        }
    }
}

function updateSessionState(sessionId, status, detail, qr, reason) {
    const oldSession = sessions.get(sessionId) || {};
    const newSession = {
        ...oldSession,
        sessionId: sessionId, // Explicitly ensure sessionId is preserved
        status,
        detail,
        qr,
        reason,
        retryCount: status === 'DISCONNECTED' ? (oldSession.retryCount || 0) + 1 : 0 // Track retry attempts
    };
    sessions.set(sessionId, newSession);

    broadcast({ type: 'session-update', data: getSessionsDetails() });

    postToWebhook({
        event: 'session-status',
        sessionId,
        status,
        detail,
        reason
    });
}

async function connectToWhatsApp(sessionId) {
    updateSessionState(sessionId, 'CONNECTING', 'Initializing session...', '', '');
    log('Starting session...', sessionId);

    // 🔧 FIX: Clear any existing cleanup interval for this session (prevents memory leaks on reconnect)
    if (sessionCleanupIntervals.has(sessionId)) {
        clearInterval(sessionCleanupIntervals.get(sessionId));
        log(`🧹 Cleared previous cleanup interval for session ${sessionId}`, sessionId);
    }

    // 🔧 FIX: Reuse or create processedMessages map for this session
    if (!sessionProcessedMessages.has(sessionId)) {
        sessionProcessedMessages.set(sessionId, new Map());
    }
    const processedMessages = sessionProcessedMessages.get(sessionId);

    const sessionDir = path.join(SESSIONS_DIR, sessionId);
    if (!fs.existsSync(sessionDir)) {
        fs.mkdirSync(sessionDir, { recursive: true });
    }

    const { state, saveCreds: originalSaveCreds } = await useMultiFileAuthState(sessionDir);

    // 🔧 FIX: Wrap saveCreds with debounce + mutex to prevent concurrent writes
    // This fixes intermittent "Bad MAC" errors caused by Signal key corruption
    const saveCreds = createDebouncedSaveCreds(sessionId, originalSaveCreds, 300);
    log(`🔐 Initialized debounced credential saver for session`, sessionId);

    const { version, isLatest } = await fetchLatestBaileysVersion();
    log(`Using WA version: ${version.join('.')}, isLatest: ${isLatest}`, sessionId);

    // 🔧 FIX: Use appropriate browser config based on session metadata
    // This helps with Android/iPhone compatibility
    const browserConfig = Browsers.appropriate('Desktop');
    log(`Using browser config: ${JSON.stringify(browserConfig)}`, sessionId);

    const sock = makeWASocket({
        version,
        auth: {
            creds: state.creds,
            keys: makeCacheableSignalKeyStore(state.keys, logger),
        },
        printQRInTerminal: false,
        logger,
        browser: browserConfig,  // 🔧 Changed from macOS to appropriate
        generateHighQualityLinkPreview: false, // Disable to save memory
        shouldIgnoreJid: (jid) => isJidBroadcast(jid),
        qrTimeout: 60000,  // 🔧 Increased from 30s to 60s for slower connections
        // Memory optimization settings
        markOnlineOnConnect: false,
        syncFullHistory: false,
        // 🔧 FIX: Message retry counter cache - CRITICAL for Bad MAC handling
        // This allows Baileys to track retry attempts and request message resends
        msgRetryCounterCache,
        // Reduce message retry count
        retryRequestDelayMs: 2000,
        maxMsgRetryCount: 5,  // 🔧 Increased from 3 to 5 for better reliability
        // Connection options for stability
        connectTimeoutMs: 60000,  // 🔧 Increased from 30s to 60s
        keepAliveIntervalMs: 25000,  // 🔧 Decreased slightly for better connection monitoring
        // Disable unnecessary features
        fireInitQueries: false,
        emitOwnEvents: false,
        // 🔧 Additional settings for better Android/iPhone compatibility
        defaultQueryTimeoutMs: 60000,
        // 🔧 FIX: Implement getMessage to support retry requests (prevents "Bad MAC" errors)
        getMessage: async (key) => {
            const msgKey = `${sessionId}_${key.remoteJid}_${key.id}`;
            const stored = globalMessageStore.get(msgKey);
            if (stored) {
                log(`📦 getMessage: Found message in store for retry: ${key.id}`, sessionId);
                return stored.message;
            }
            log(`⚠️ getMessage: Message not found in store: ${key.id}`, sessionId);
            return undefined;
        }
    });

    sock.ev.on('creds.update', saveCreds);

    // 🔧 FIX: Message deduplication cache - use global map per session
    const MESSAGE_CACHE_TTL = 5 * 60 * 1000; // 5 minutes (aligned with backend)

    // 🔧 FIX: Store cleanup interval in global map to prevent duplicates
    const cleanupInterval = setInterval(() => {
        const now = Date.now();
        let cleaned = 0;
        for (const [msgId, timestamp] of processedMessages.entries()) {
            if (now - timestamp > MESSAGE_CACHE_TTL) {
                processedMessages.delete(msgId);
                cleaned++;
            }
        }
        if (cleaned > 0) {
            log(`🧹 Cleaned ${cleaned} expired messages from cache`, sessionId);
        }
    }, 10 * 60 * 1000);

    // 🔧 FIX: Store cleanup interval in global map
    sessionCleanupIntervals.set(sessionId, cleanupInterval);

    // 🔧 FIX: Helper function to extract real phone number from message (handles LID)
    async function extractRealPhoneNumber(msg, sessionId) {
        let from = msg.key.remoteJid;
        const originalFrom = from; // Keep original for logging
        const isLID = from && from.includes('@lid');
        const isGroup = from && from.includes('@g.us');

        if (isLID) {
            log(`⚠️ LID detected: ${from}`, sessionId);

            // Option 1: Use Baileys' built-in LID mapping (most reliable)
            if (from.includes('@lid') && sock.signalRepository?.lidMapping) {
                try {
                    const pn = await sock.signalRepository.lidMapping.getPNForLID(from);
                    if (pn && pn.includes('@s.whatsapp.net')) {
                        from = pn;
                        log(`🔄 LID resolved via Baileys lidMapping: ${from}`, sessionId);
                    }
                } catch (e) {
                    log(`⚠️ Baileys lidMapping failed: ${e.message}`, sessionId);
                }
            }

            // 🔧 FIX: Changed else if to independent if statements so ALL options are tried
            // Option 2: Check for participant (in groups or as sender)
            if (from.includes('@lid') && msg.key.participant && msg.key.participant.includes('@s.whatsapp.net')) {
                from = msg.key.participant;
                log(`🔄 LID resolved via participant: ${from}`, sessionId);
            }

            // Option 3: Check message object for alternative fields (extendedTextMessage)
            if (from.includes('@lid') && msg.message?.extendedTextMessage?.contextInfo?.participant) {
                const participant = msg.message.extendedTextMessage.contextInfo.participant;
                if (participant.includes('@s.whatsapp.net')) {
                    from = participant;
                    log(`🔄 LID resolved via contextInfo.participant: ${from}`, sessionId);
                }
            }

            // Option 4: Check imageMessage contextInfo
            if (from.includes('@lid') && msg.message?.imageMessage?.contextInfo?.participant) {
                const participant = msg.message.imageMessage.contextInfo.participant;
                if (participant.includes('@s.whatsapp.net')) {
                    from = participant;
                    log(`🔄 LID resolved via imageMessage.contextInfo.participant: ${from}`, sessionId);
                }
            }

            // Option 5: Check audioMessage contextInfo
            if (from.includes('@lid') && msg.message?.audioMessage?.contextInfo?.participant) {
                const participant = msg.message.audioMessage.contextInfo.participant;
                if (participant.includes('@s.whatsapp.net')) {
                    from = participant;
                    log(`🔄 LID resolved via audioMessage.contextInfo.participant: ${from}`, sessionId);
                }
            }

            // Option 6: Check documentMessage contextInfo
            if (from.includes('@lid') && msg.message?.documentMessage?.contextInfo?.participant) {
                const participant = msg.message.documentMessage.contextInfo.participant;
                if (participant.includes('@s.whatsapp.net')) {
                    from = participant;
                    log(`🔄 LID resolved via documentMessage.contextInfo.participant: ${from}`, sessionId);
                }
            }

            // Still LID - log warning with more details
            if (from.includes('@lid')) {
                log(`❌ WARNING: Could not resolve LID ${originalFrom}. Message may not be delivered correctly to backend.`, sessionId);
                log(`   Message details: pushName=${msg.pushName}, hasParticipant=${!!msg.key.participant}, messageType=${Object.keys(msg.message || {})[0] || 'unknown'}`, sessionId);
            }
        }

        // For group messages, extract participant
        if (isGroup && msg.key.participant) {
            const groupId = from;
            from = msg.key.participant;
            log(`👥 Group message from ${from} in group ${groupId}`, sessionId);
            return { from, groupId, isGroup: true, isLID: from.includes('@lid') };
        }

        return { from, groupId: null, isGroup: false, isLID: from.includes('@lid') };
    }

    sock.ev.on('messages.upsert', async (m) => {
        const msg = m.messages[0];
        if (!msg.key.fromMe) {
            const messageId = msg.key.id;

            // 🔧 FIX: Check for duplicate messages
            if (processedMessages.has(messageId)) {
                log(`⚠️ Duplicate message detected and skipped: ${messageId}`, sessionId);
                return; // Skip processing duplicate
            }

            // Mark message as processed
            processedMessages.set(messageId, Date.now());

            // 🔧 FIX: Extract real phone number (handles LID and groups)
            const { from, groupId, isGroup, isLID } = await extractRealPhoneNumber(msg, sessionId);

            // Detect message type and check for audio
            const msgTypeInfo = audioTranscriber.detectMessageType(msg);
            log(`Received ${msgTypeInfo.type} message from ${from}${isGroup ? ` (group: ${groupId})` : ''}${isLID ? ' [LID-WARNING]' : ''}`, sessionId);

            // Base message data with resolved phone number
            const messageData = {
                event: 'new-message',
                sessionId,
                from: from,  // Now contains resolved phone number
                messageId: messageId,
                timestamp: msg.messageTimestamp,
                messageType: msgTypeInfo.type,
                isGroup: isGroup,
                groupId: groupId,
                isLID: isLID,  // Flag to warn backend about LID
                data: msg
            };

            // If message contains audio, download and transcribe
            if (msgTypeInfo.hasAudio) {
                try {
                    log(`🎤 Processing audio message...`, sessionId);
                    const audioResult = await audioTranscriber.processMessage(sock, msg, sessionId);

                    // Add audio data to webhook payload (including Base64)
                    messageData.audio = {
                        isVoiceNote: audioResult.isVoiceNote,
                        duration: audioResult.duration,
                        mimetype: audioResult.mimetype,
                        fileSizeKB: audioResult.fileSizeKB,
                        base64: audioResult.base64,
                        transcription: audioResult.transcription
                    };

                    if (audioResult.transcription && audioResult.transcription.success) {
                        messageData.transcribedText = audioResult.transcription.text;
                        log(`✅ Transcription: "${audioResult.transcription.text.substring(0, 50)}..."`, sessionId);
                    }

                    log(`📦 Audio included in webhook (${audioResult.fileSizeKB}KB)`, sessionId);
                } catch (error) {
                    log(`❌ Audio processing error: ${error.message}`, sessionId);
                    messageData.audio = {
                        error: error.message,
                        transcription: null,
                        base64: null
                    };
                }
            }
            // If message contains image, sticker, or document (non-audio media)
            else if (msgTypeInfo.hasMedia && !msgTypeInfo.hasAudio) {
                try {
                    log(`📷 Processing ${msgTypeInfo.type} message...`, sessionId);
                    const mediaResult = await audioTranscriber.processImage(sock, msg, sessionId);

                    // Add media data to webhook payload based on type
                    messageData.media = {
                        type: mediaResult.type,
                        mimetype: mediaResult.mimetype,
                        caption: mediaResult.caption,
                        fileSizeKB: mediaResult.fileSizeKB,
                        base64: mediaResult.base64
                    };

                    // Add type-specific fields
                    if (mediaResult.type === 'image') {
                        messageData.media.width = mediaResult.width;
                        messageData.media.height = mediaResult.height;
                    } else if (mediaResult.type === 'sticker') {
                        messageData.media.isAnimated = mediaResult.isAnimated;
                    } else if (mediaResult.type === 'document') {
                        messageData.media.filename = mediaResult.filename;
                    }

                    log(`📦 ${mediaResult.type} included in webhook (${mediaResult.fileSizeKB}KB)`, sessionId);
                } catch (error) {
                    log(`❌ Media processing error: ${error.message}`, sessionId);
                    messageData.media = {
                        type: msgTypeInfo.type,
                        error: error.message,
                        base64: null
                    };
                }
            }

            await postToWebhook(messageData);
        }
    });

    sock.ev.on('connection.update', (update) => {
        const { connection, lastDisconnect, qr, isNewLogin, isOnline, receivedPendingNotifications } = update;
        const statusCode = (lastDisconnect?.error instanceof Boom) ? lastDisconnect.error.output.statusCode : 0;

        // 🔧 Enhanced logging for debugging Android/iPhone issues
        log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`, sessionId);
        log(`Connection update:`, sessionId);
        log(`  connection: ${connection}`, sessionId);
        log(`  statusCode: ${statusCode}`, sessionId);
        log(`  isNewLogin: ${isNewLogin}`, sessionId);
        log(`  isOnline: ${isOnline}`, sessionId);
        log(`  receivedPendingNotifications: ${receivedPendingNotifications}`, sessionId);
        log(`  hasQR: ${qr ? 'YES' : 'NO'}`, sessionId);
        if (lastDisconnect?.error) {
            log(`  error: ${lastDisconnect.error.message}`, sessionId);
        }
        log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`, sessionId);

        // 🔧 FIX: Detect successful QR scan even if connection doesn't reach 'open' immediately
        // This handles Android devices that may disconnect/reconnect during pairing
        if (isNewLogin && sock.user) {
            const userName = sock.user?.name || sock.user?.verifiedName || sock.user?.notify || 'Unknown';
            const userPhone = sock.user?.id?.split(':')[0] || 'Unknown';

            log(`🎉 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`, sessionId);
            log(`🎉 QR SCAN SUCCESSFUL (isNewLogin detected)!`, sessionId);
            log(`🎉 User: ${userName}`, sessionId);
            log(`🎉 Phone: ${userPhone}`, sessionId);
            log(`🎉 Session ID: ${sessionId}`, sessionId);
            log(`🎉 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`, sessionId);

            updateSessionState(sessionId, 'CONNECTED', `Connected as ${userName}`, '', '');

            // 🔧 Notify booking-backend that session is connected
            const webhookData = {
                event: 'connection-success',
                sessionId,
                userName,
                userPhone,
                status: 'CONNECTED'
            };
            log(`📤 Sending webhook notification to backend (via isNewLogin):`, sessionId);
            log(`   ${JSON.stringify(webhookData, null, 2)}`, sessionId);
            postToWebhook(webhookData);
        }

        if (qr) {
            log('✅ QR code generated successfully', sessionId);
            log(`   QR length: ${qr.length} characters`, sessionId);
            updateSessionState(sessionId, 'GENERATING_QR', 'QR code available.', qr, '');
        }

        if (connection === 'close') {
            const reason = new Boom(lastDisconnect?.error)?.output?.payload?.error || 'Unknown';

            // Get current session state to check if we're in initial auth
            const currentSession = sessions.get(sessionId);
            const isInitialAuth = currentSession && currentSession.status === 'GENERATING_QR';
            const retryCount = currentSession?.retryCount || 0;

            // 🔧 FIX: Limit retries to prevent infinite loops (especially on Android)
            const MAX_RETRIES = 5;
            if (retryCount >= MAX_RETRIES) {
                log(`⛔ Max retry limit reached (${MAX_RETRIES} attempts). Stopping reconnection.`, sessionId);
                updateSessionState(sessionId, 'DISCONNECTED', `Connection failed after ${MAX_RETRIES} attempts. Please delete and recreate the session.`, '', reason);

                // 🔧 FIX: Cleanup message cache and intervals using global maps
                if (sessionCleanupIntervals.has(sessionId)) {
                    clearInterval(sessionCleanupIntervals.get(sessionId));
                    sessionCleanupIntervals.delete(sessionId);
                    log(`🧹 Cleared cleanup interval for session ${sessionId}`, sessionId);
                }
                if (sessionProcessedMessages.has(sessionId)) {
                    sessionProcessedMessages.get(sessionId).clear();
                    sessionProcessedMessages.delete(sessionId);
                    log(`🧹 Cleared message deduplication cache for session ${sessionId}`, sessionId);
                }

                // Clean up session data
                const sessionDir = path.join(SESSIONS_DIR, sessionId);
                if (fs.existsSync(sessionDir)) {
                    fs.rmSync(sessionDir, { recursive: true, force: true });
                    log(`Cleared session data for ${sessionId}`, sessionId);
                }
                return;
            }

            // 🔧 FIX: Improved reconnection logic for Android/iPhone compatibility
            // During initial authentication (QR scan), allow retry even on 401
            // 401 during QR scan is often temporary as WhatsApp validates the link
            let shouldReconnect;
            let retryDelay;

            if (isInitialAuth && statusCode === 401) {
                log(`⚠️  401 during initial auth (QR scan phase) - will retry (attempt ${retryCount + 1}/${MAX_RETRIES})`, sessionId);
                log(`   This is common during QR scan, especially on Android`, sessionId);
                shouldReconnect = true;
                retryDelay = 5000;  // 5s delay for initial auth retries
            } else if (statusCode === 401) {
                // 401 after initial auth - could be session expired
                log(`⚠️  401 after initial auth - possible session issue (attempt ${retryCount + 1}/${MAX_RETRIES})`, sessionId);
                shouldReconnect = retryCount < MAX_RETRIES;
                retryDelay = 8000;  // Longer delay for post-auth 401s
            } else if (statusCode === 403) {
                // 403 is FATAL - banned/blocked
                log(`🚫 403 Forbidden - account may be banned or blocked`, sessionId);
                shouldReconnect = false;
            } else if (statusCode === 428 || statusCode === 440) {
                // Connection/timeout issues - retry with longer delay
                log(`⏱️  Connection timeout (${statusCode}) - will retry with longer delay`, sessionId);
                shouldReconnect = true;
                retryDelay = 10000;  // 10s for timeout issues
            } else if (statusCode === 500 || statusCode === 503) {
                // Server errors - retry with backoff
                log(`🔧 WhatsApp server error (${statusCode}) - will retry`, sessionId);
                shouldReconnect = true;
                retryDelay = 15000;  // 15s for server errors
            } else {
                // Default behavior for other error codes
                shouldReconnect = statusCode !== 403;
                retryDelay = 5000;
            }

            log(`📊 Connection closed summary:`, sessionId);
            log(`   Reason: ${reason}`, sessionId);
            log(`   Status Code: ${statusCode}`, sessionId);
            log(`   Will Reconnect: ${shouldReconnect}`, sessionId);
            log(`   Retry Count: ${retryCount + 1}/${MAX_RETRIES}`, sessionId);

            updateSessionState(sessionId, 'DISCONNECTED', `Connection closed (${statusCode}): ${reason}`, '', reason);

            if (shouldReconnect) {
                log(`🔄 Retrying connection in ${retryDelay}ms... (attempt ${retryCount + 1}/${MAX_RETRIES})`, sessionId);
                setTimeout(() => connectToWhatsApp(sessionId), retryDelay);
            } else {
                log(`⛔ Not reconnecting for session ${sessionId} due to fatal error (${statusCode}). Please delete and recreate the session.`, sessionId);

                // 🔧 FIX: Cleanup message cache and intervals using global maps
                if (sessionCleanupIntervals.has(sessionId)) {
                    clearInterval(sessionCleanupIntervals.get(sessionId));
                    sessionCleanupIntervals.delete(sessionId);
                    log(`🧹 Cleared cleanup interval for session ${sessionId}`, sessionId);
                }
                if (sessionProcessedMessages.has(sessionId)) {
                    const msgCount = sessionProcessedMessages.get(sessionId).size;
                    sessionProcessedMessages.get(sessionId).clear();
                    sessionProcessedMessages.delete(sessionId);
                    log(`🧹 Cleared message deduplication cache (${msgCount} messages) for session ${sessionId}`, sessionId);
                }

                const sessionDir = path.join(SESSIONS_DIR, sessionId);
                if (fs.existsSync(sessionDir)) {
                    fs.rmSync(sessionDir, { recursive: true, force: true });
                    log(`🗑️  Cleared session data for ${sessionId}`, sessionId);
                }
            }
        } else if (connection === 'open') {
            // 🔧 FIX: Get user info properly and send webhook notification
            const userName = sock.user?.name || sock.user?.verifiedName || sock.user?.notify || 'Unknown';
            const userPhone = sock.user?.id?.split(':')[0] || 'Unknown';

            log(`🎉 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`, sessionId);
            log(`🎉 CONNECTION SUCCESSFUL!`, sessionId);
            log(`🎉 User: ${userName}`, sessionId);
            log(`🎉 Phone: ${userPhone}`, sessionId);
            log(`🎉 Session ID: ${sessionId}`, sessionId);
            log(`🎉 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`, sessionId);

            updateSessionState(sessionId, 'CONNECTED', `Connected as ${userName}`, '', '');

            // 🔧 FIX: Notify booking-backend that session is connected
            const webhookData = {
                event: 'connection-success',
                sessionId,
                userName,
                userPhone,
                status: 'CONNECTED'
            };
            log(`📤 Sending webhook notification to backend:`, sessionId);
            log(`   ${JSON.stringify(webhookData, null, 2)}`, sessionId);
            postToWebhook(webhookData);
        }
    });

    // Ensure session exists before setting sock property
    const session = sessions.get(sessionId);
    if (session) {
        session.sock = sock;
        sessions.set(sessionId, session);
    } else {
        log(`Warning: Session ${sessionId} not found when trying to set socket`, sessionId);
    }
}

function getSessionsDetails(userEmail = null, isAdmin = false) {
    return Array.from(sessions.values())
        .filter(s => {
            // Admin can see all sessions
            if (isAdmin) return true;
            // Regular users can only see their own sessions
            return s.owner === userEmail;
        })
        .map(s => ({
            sessionId: s.sessionId,
            status: s.status,
            detail: s.detail,
            qr: s.qr,
            token: sessionTokens.get(s.sessionId) || null,
            owner: s.owner || 'system' // Include owner info
        }));
}

// API Endpoints
app.get('/sessions', (req, res) => {
    const currentUser = getCurrentUser(req);
    if (currentUser) {
        res.json(getSessionsDetails(currentUser.email, currentUser.role === 'admin'));
    } else {
        // For backwards compatibility, show all sessions if not authenticated
        res.json(getSessionsDetails());
    }
});

async function createSession(sessionId, createdBy = null) {
    if (sessions.has(sessionId)) {
        throw new Error('Session already exists');
    }

    // Check session limit
    if (sessions.size >= MAX_SESSIONS) {
        throw new Error(`Maximum session limit (${MAX_SESSIONS}) reached. Please delete unused sessions.`);
    }

    const token = randomUUID();
    sessionTokens.set(sessionId, token);
    saveTokens();

    // Set a placeholder before async connection with owner info
    sessions.set(sessionId, {
        sessionId: sessionId,
        status: 'CREATING',
        detail: 'Session is being created.',
        owner: createdBy // Track who created this session
    });

    // Track session ownership in user manager
    if (createdBy) {
        await userManager.addSessionToUser(createdBy, sessionId);
    }

    // Auto-cleanup inactive sessions after timeout
    // Fix for timeout overflow on 32-bit systems - cap at 24 hours max
    const timeoutMs = Math.min(SESSION_TIMEOUT_HOURS * 60 * 60 * 1000, 24 * 60 * 60 * 1000);
    setTimeout(async () => {
        const session = sessions.get(sessionId);
        if (session && session.status !== 'CONNECTED') {
            await deleteSession(sessionId);
            log(`Auto-deleted inactive session after ${SESSION_TIMEOUT_HOURS} hours: ${sessionId}`, 'SYSTEM');
        }
    }, timeoutMs);

    connectToWhatsApp(sessionId);
    return { status: 'success', message: `Session ${sessionId} created.`, token };
}

app.get('/api/v1/sessions/:sessionId/qr', async (req, res) => {
    const { sessionId } = req.params;
    const session = sessions.get(sessionId);
    if (!session) {
        return res.status(404).json({ error: 'Session not found' });
    }
    log(`QR code requested for ${sessionId}`, sessionId);
    updateSessionState(sessionId, 'GENERATING_QR', 'QR code requested by user.', '', '');
    // The connection logic will handle the actual QR generation and broadcast.
    res.status(200).json({ message: 'QR generation triggered.' });
});

async function deleteSession(sessionId) {
    const session = sessions.get(sessionId);

    // 🔧 FIX: Clean up event listeners and intervals BEFORE logout
    if (session && session.sock) {
        try {
            // Remove all event listeners to prevent memory leaks
            session.sock.ev.removeAllListeners();
            log(`🧹 Removed all event listeners for session ${sessionId}`, sessionId);
        } catch (err) {
            log(`Warning: Could not remove event listeners for ${sessionId}: ${err.message}`, sessionId);
        }

        try {
            await session.sock.logout();
        } catch (err) {
            log(`Error during logout for session ${sessionId}: ${err.message}`, sessionId);
        }
    }

    // 🔧 FIX: Clear cleanup interval for this session
    if (sessionCleanupIntervals.has(sessionId)) {
        clearInterval(sessionCleanupIntervals.get(sessionId));
        sessionCleanupIntervals.delete(sessionId);
        log(`🧹 Cleared cleanup interval for session ${sessionId}`, sessionId);
    }

    // 🔧 FIX: Clear processed messages cache for this session
    if (sessionProcessedMessages.has(sessionId)) {
        sessionProcessedMessages.get(sessionId).clear();
        sessionProcessedMessages.delete(sessionId);
        log(`🧹 Cleared message deduplication cache for session ${sessionId}`, sessionId);
    }

    // 🔧 FIX: Clear credentials mutex for this session
    if (credsMutexes.has(sessionId)) {
        credsMutexes.delete(sessionId);
        log(`🧹 Cleared credentials mutex for session ${sessionId}`, sessionId);
    }

    // Remove session ownership
    if (session && session.owner) {
        await userManager.removeSessionFromUser(session.owner, sessionId);
    }

    sessions.delete(sessionId);
    sessionTokens.delete(sessionId);
    saveTokens();
    const sessionDir = path.join(SESSIONS_DIR, sessionId);
    if (fs.existsSync(sessionDir)) {
        fs.rmSync(sessionDir, { recursive: true, force: true });
    }
    log(`Session ${sessionId} deleted and data cleared.`, 'SYSTEM');
    broadcast({ type: 'session-update', data: getSessionsDetails() });
}

// 🚨 EMERGENCY: Delete ALL sessions (memory + disk)
async function deleteAllSessions(keepSessions = []) {
    log('🚨 EMERGENCY CLEANUP: Deleting all sessions...', 'SYSTEM');

    // 1. Delete from memory
    const allSessionIds = Array.from(sessions.keys());
    log(`Found ${allSessionIds.length} sessions in memory`, 'SYSTEM');

    for (const sessionId of allSessionIds) {
        if (keepSessions.includes(sessionId)) {
            log(`🔒 Keeping session: ${sessionId}`, 'SYSTEM');
            continue;
        }

        const session = sessions.get(sessionId);
        if (session && session.sock) {
            try {
                await session.sock.logout();
            } catch (err) {
                log(`Error during logout for ${sessionId}: ${err.message}`, sessionId);
            }
        }

        if (session && session.owner) {
            await userManager.removeSessionFromUser(session.owner, sessionId);
        }

        sessions.delete(sessionId);
        sessionTokens.delete(sessionId);
        log(`✅ Deleted from memory: ${sessionId}`, 'SYSTEM');
    }

    // 2. Delete from disk (even orphaned folders)
    const sessionsDir = SESSIONS_DIR;
    if (fs.existsSync(sessionsDir)) {
        const sessionFolders = fs.readdirSync(sessionsDir);
        log(`Found ${sessionFolders.length} session folders on disk`, 'SYSTEM');

        for (const folder of sessionFolders) {
            if (keepSessions.includes(folder)) {
                log(`🔒 Keeping folder: ${folder}`, 'SYSTEM');
                continue;
            }

            const folderPath = path.join(sessionsDir, folder);
            if (fs.statSync(folderPath).isDirectory()) {
                fs.rmSync(folderPath, { recursive: true, force: true });
                log(`✅ Deleted folder: ${folder}`, 'SYSTEM');
            }
        }
    }

    saveTokens();
    broadcast({ type: 'session-update', data: getSessionsDetails() });

    const remaining = sessions.size;
    log(`🎉 Cleanup complete. Remaining sessions: ${remaining}`, 'SYSTEM');
    return { deleted: allSessionIds.length - remaining, remaining };
}

const PORT = process.env.PORT || 3000;

// Handle memory errors gracefully
process.on('uncaughtException', (error) => {
    if (error.message && error.message.includes('Out of memory')) {
        console.error('FATAL: Out of memory error. The application will exit.');
        console.error('Consider reducing MAX_SESSIONS or upgrading your hosting plan.');
        process.exit(1);
    }
    console.error('Uncaught Exception:', error);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

async function initializeExistingSessions() {
    const sessionsDir = SESSIONS_DIR;
    if (fs.existsSync(sessionsDir)) {
        const sessionFolders = fs.readdirSync(sessionsDir);
        log(`Found ${sessionFolders.length} folder(s) on disk. Checking for valid sessions...`);

        // Only initialize sessions that have a valid token
        let initialized = 0;
        let cleaned = 0;

        for (const sessionId of sessionFolders) {
            const sessionPath = path.join(sessionsDir, sessionId);
            if (fs.statSync(sessionPath).isDirectory()) {
                // Check if this session has a valid token
                if (sessionTokens.has(sessionId)) {
                    log(`Re-initializing session: ${sessionId}`);
                    await createSession(sessionId);
                    initialized++;
                } else {
                    // Session without token - skip re-initialization but KEEP the folder
                    // This preserves sessions if token file is lost/corrupted
                    log(`⏭️  Skipping session ${sessionId} (no token found, keeping folder intact)`, 'SYSTEM');
                    cleaned++;
                }
            }
        }

        log(`Session initialization complete: ${initialized} initialized, ${cleaned} orphaned folders cleaned`);
    }
}

loadSystemLogFromDisk();
server.listen(PORT, () => {
    log(`Server is running on port ${PORT}`);
    log('Admin dashboard available at http://localhost:3000/admin/dashboard.html');
    loadTokens(); // Load tokens at startup
    initializeExistingSessions();

    // Start campaign scheduler
    startCampaignScheduler();
});

// Campaign scheduler to automatically start campaigns at their scheduled time
function startCampaignScheduler() {
    console.log('📅 Campaign scheduler started - checking every minute for scheduled campaigns');

    setInterval(async () => {
        await checkAndStartScheduledCampaigns();
    }, 60000); // Check every minute (60,000 ms)
}

// Use the scheduler function from the API router
async function checkAndStartScheduledCampaigns() {
    if (v1ApiRouter && v1ApiRouter.checkAndStartScheduledCampaigns) {
        return await v1ApiRouter.checkAndStartScheduledCampaigns();
    } else {
        console.log('⏳ API router not initialized yet, skipping scheduler check');
        return { error: 'API router not initialized' };
    }
}


