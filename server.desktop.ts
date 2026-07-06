// @ts-nocheck
import 'dotenv/config';

process.env.IS_DESKTOP = 'true';
// Save the original PostgreSQL URL before overriding for local SQLite
let CLOUD_DATABASE_URL = process.env.DATABASE_URL;

// If the DATABASE_URL is SQLite, try to extract the real cloud PostgreSQL URL from .env
if (!CLOUD_DATABASE_URL || CLOUD_DATABASE_URL.startsWith('file:')) {
    try {
        const fs = require('fs');
        const path = require('path');
        const dotenv = require('dotenv');
        const envPath = path.join(process.cwd(), '.env');
        if (fs.existsSync(envPath)) {
            const envConfig = dotenv.parse(fs.readFileSync(envPath));
            if (envConfig.DATABASE_URL && !envConfig.DATABASE_URL.startsWith('file:')) {
                CLOUD_DATABASE_URL = envConfig.DATABASE_URL;
            } else if (envConfig.DIRECT_URL && !envConfig.DIRECT_URL.startsWith('file:')) {
                CLOUD_DATABASE_URL = envConfig.DIRECT_URL;
            }
        }
    } catch (e) {
        console.error('Failed to parse .env for CLOUD_DATABASE_URL:', e);
    }
}

// Fallback to process.env.DIRECT_URL if set
if ((!CLOUD_DATABASE_URL || CLOUD_DATABASE_URL.startsWith('file:')) && process.env.DIRECT_URL && !process.env.DIRECT_URL.startsWith('file:')) {
    CLOUD_DATABASE_URL = process.env.DIRECT_URL;
}

// Now ensure process.env.DATABASE_URL is set to the local SQLite database
if (!process.env.DATABASE_URL || !process.env.DATABASE_URL.startsWith('file:')) {
    process.env.DATABASE_URL = 'file:./prisma/dev.db';
}

import express from 'express';
import http from 'http';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { prisma } from './utils/prisma';
import bcrypt from 'bcryptjs';
import { authenticate, authorize, validateTableSession } from './middleware/auth';
import { generateToken, verifyToken, generateRefreshToken, hashToken } from './utils/auth';
import { Server as SocketServer } from 'socket.io';
import path from 'path';
import { randomUUID } from 'crypto';
import { startSyncService, stopSyncService } from './utils/sync-service';
import fetch from 'node-fetch';
import { PrismaClient as CloudPrismaClient } from '@prisma/client';
import couponRoutes from './routes/coupon.routes';

// Cloud Prisma client for direct PostgreSQL access (activation, license verification)
// This bypasses the deployed cloud API which may be outdated
let cloudPrisma: any = null;
if (CLOUD_DATABASE_URL && !CLOUD_DATABASE_URL.startsWith('file:')) {
    cloudPrisma = new CloudPrismaClient({
        datasources: { db: { url: CLOUD_DATABASE_URL } }
    });
    console.log('Initializing Prisma in Direct Cloud Mode');
} else {
    console.warn('[WARNING] No PostgreSQL DATABASE_URL found. Cloud activation will fall back to API relay.');
}

// RSA key generation removed — use secure key management instead of hardcoded paths

const app = express();

// --- Security Middleware: Helmet ---
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://checkout.razorpay.com"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: [
                "'self'",
                "https://software.dinestack.in",
                "https://order.dinestack.in",
                "https://dinestack.in",
                "https://api.razorpay.com",
                "https://checkout.razorpay.com",
                "https://lumberjack.razorpay.com",
                "http://localhost:*",
                "ws://localhost:*",
                "wss://localhost:*"
            ],
            frameSrc: ["'self'", "https://api.razorpay.com", "https://checkout.razorpay.com"],
            frameAncestors: ["'none'"]
        }
    },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    permittedCrossDomainPolicies: { permittedPolicies: 'none' }
}));

// --- Permissions-Policy Header ---
app.use((req, res, next) => {
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), interest-cohort=()');
    next();
});
// --- Rate Limiting (In-Memory) ---
const rateLimits: Record<string, { attempts: number; lockUntil: number }> = {};
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_MINUTES = 15;

export const checkRateLimit = (identifier: string): { locked: boolean; waitTime: number } => {
    const record = rateLimits[identifier];
    if (!record) return { locked: false, waitTime: 0 };

    if (record.lockUntil > Date.now()) {
        const waitTime = Math.ceil((record.lockUntil - Date.now()) / (60 * 1000));
        return { locked: true, waitTime };
    }

    // Lock expired
    if (record.lockUntil > 0) {
        delete rateLimits[identifier];
    }
    return { locked: false, waitTime: 0 };
};

export const registerFailure = (identifier: string) => {
    if (!rateLimits[identifier]) {
        rateLimits[identifier] = { attempts: 1, lockUntil: 0 };
    } else {
        rateLimits[identifier].attempts += 1;
    }

    if (rateLimits[identifier].attempts >= MAX_FAILED_ATTEMPTS) {
        rateLimits[identifier].lockUntil = Date.now() + (LOCKOUT_MINUTES * 60 * 1000);
    }
};

export const registerSuccess = (identifier: string) => {
    delete rateLimits[identifier];
};

// --- Security Middleware: Global Rate Limiting ---
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 2000,
    message: { error: 'Too many requests, please try again later.' }
});
app.use('/api/', globalLimiter);

app.use(cors({
    origin: (origin, callback) => {
        // In local/desktop mode, allow all origins (especially for local IPs and tablets)
        callback(null, true);
    },
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'X-Activation-Code'],
    credentials: true
}));
app.use(express.json()); // Ensure JSON body parsing is enabled



// --- Content-Type & HTTP Method Validation ---
app.use((req, res, next) => {
    const allowedMethods = ['GET', 'POST', 'PATCH', 'PUT', 'DELETE', 'OPTIONS'];
    if (!allowedMethods.includes(req.method)) {
        return res.status(405).json({ error: `Method ${req.method} Not Allowed` });
    }
    const methodsWithBody = ['POST', 'PATCH', 'PUT'];
    if (methodsWithBody.includes(req.method)) {
        const contentType = req.headers['content-type'];
        if (!contentType || !contentType.includes('application/json')) {
            return res.status(415).json({ error: 'Unsupported Media Type: Must be application/json' });
        }
    }
    next();
});

// --- CSRF Origin Defense ---
app.use((req, res, next) => {
    const stateChangingMethods = ['POST', 'PATCH', 'PUT', 'DELETE'];
    if (stateChangingMethods.includes(req.method)) {
        const origin = req.headers.origin || req.headers.referer;
        const allowedOrigins = [
            'https://order.dinestack.in',
            'https://software.dinestack.in',
            'https://dinestack.in',
            'http://localhost:3000', // Always allow default dev URL
            process.env.FRONTEND_URL || 'http://localhost:3000'
        ];

        if (origin) {
            // Check if origin is file:// (Electron production loading)
            if (origin.startsWith('file://')) {
                return next();
            }

            // Check if origin is a matched allowed origin
            const isAllowed = allowedOrigins.some(allowed => origin.startsWith(allowed));
            if (isAllowed) {
                return next();
            }

            // Dynamically validate localhost and local network private IPs (RFC 1918)
            try {
                const url = new URL(origin);
                const hostname = url.hostname;

                // Localhost and loopbacks
                if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '[::1]') {
                    return next();
                }

                // Local domain names (.local)
                if (hostname.endsWith('.local')) {
                    return next();
                }

                // Private network IP check
                const ipParts = hostname.split('.').map(Number);
                if (ipParts.length === 4 && !ipParts.some(isNaN)) {
                    const [first, second] = ipParts;
                    if (
                        first === 10 || // 10.0.0.0/8
                        (first === 172 && second >= 16 && second <= 31) || // 172.16.0.0/12
                        (first === 192 && second === 168) // 192.168.0.0/16
                    ) {
                        return next();
                    }
                }
            } catch (e) {
                // Invalid URL or malformed origin
            }

            return res.status(403).json({ error: 'CSRF Protection: Forbidden origin' });
        }
    }
    next();
});

// --- Security Headers Middleware ---
app.use((req, res, next) => {

    // Disable caching for sensitive APIs
    if (req.path.startsWith('/api/')) {
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');
    }
    next();
});
const httpServer = http.createServer(app);
const io = new SocketServer(httpServer, {
    cors: {
        origin: (origin, callback) => {
            callback(null, true);
        },
        methods: ['GET', 'POST'],
        credentials: true
    },
    transports: ['websocket', 'polling']
});

console.log(`Initializing Prisma in Direct Cloud Mode`);

if (!process.env.DATABASE_URL) {
    console.error('CRITICAL: DATABASE_URL not found in environment. Desktop Backend cannot start.');
    process.exit(1);
}

// Ensure PORT is provided by environment (Electron Main Process)
const PORT = process.env.PORT || 5001;
if (!process.env.PORT) {
    console.warn('⚠️ PORT not specified in environment, defaulting to 5001. This should not happen in production.');
}

// --- Response Normalizer ---
// Maps PascalCase Prisma relation keys to camelCase keys expected by frontend
function normalize(obj: any): any {
    if (Array.isArray(obj)) return obj.map(normalize);
    if (!obj || typeof obj !== 'object' || obj instanceof Date) return obj;
    const out: any = {};
    for (const [key, val] of Object.entries(obj)) {
        let newKey = key;
        if (key === 'MenuItem' && Array.isArray(val)) newKey = 'items';      // Category.MenuItem[] -> items
        else if (key === 'OrderItem' && Array.isArray(val)) newKey = 'items'; // Order.OrderItem[] -> items
        else if (key === 'MenuItem' && !Array.isArray(val)) newKey = 'menuItem'; // OrderItem.MenuItem -> menuItem
        else if (key === 'Table' && !Array.isArray(val)) newKey = 'table';       // Order.Table -> table
        else if (key === 'Restaurant' && !Array.isArray(val)) newKey = 'restaurant';
        else if (key === 'ActivationCode' && !Array.isArray(val)) newKey = 'activationCode';
        else if (key === 'OrderItem' && !Array.isArray(val)) newKey = 'orderItem';
        out[newKey] = normalize(val);
    }
    return out;
}

// --- Socket.IO Connection Handler ---
io.on('connection', (socket) => {
    console.log(`[Socket.IO] Client connected: ${socket.id}`);
    console.log("Total clients:", io.engine.clientsCount);

    socket.on('join-entity', (entityId: string) => {
        if (entityId) {
            socket.join(`entity:${entityId}`);
            console.log(`[Socket.IO] Socket joined room: entity:${entityId}`);
            socket.emit('joined', { room: `entity:${entityId}` });
        }
    });

    socket.on('disconnect', (reason) => {
        console.log(`[Socket.IO] Client disconnected: ${socket.id} (${reason})`);
    });
});

import { execSync } from 'child_process';
import fs from 'fs';

// --- Local Database Schema Sync ---
function initializeDatabase() {
    console.log('Initializing local SQLite database schema...');
    try {
        let prismaCliPath = '';
        const pathsToTry = [
            path.join(__dirname, 'node_modules', 'prisma', 'build', 'index.js'),
            path.join(__dirname, '..', 'node_modules', 'prisma', 'build', 'index.js'),
            path.join(__dirname, '..', '..', 'node_modules', 'prisma', 'build', 'index.js')
        ];

        for (const p of pathsToTry) {
            if (fs.existsSync(p)) {
                prismaCliPath = p;
                break;
            }
        }

        const schemaPath = path.join(
            fs.existsSync(path.join(__dirname, 'prisma', 'schema.desktop.prisma')) ? __dirname : path.join(__dirname, '..'),
            'prisma',
            'schema.desktop.prisma'
        );

        console.log(`Using schema: ${schemaPath}`);

        const cmd = prismaCliPath
            ? `node "${prismaCliPath}" db push --schema="${schemaPath}"`
            : `npx prisma db push --schema="${schemaPath}"`;

        console.log(`Running database initialization: ${cmd}`);
        execSync(cmd, {
            stdio: 'inherit',
            env: {
                ...process.env,
                DATABASE_URL: process.env.DATABASE_URL
            }
        });
        console.log('✅ SQLite database schema synchronized successfully.');
    } catch (error) {
        console.error('❌ Failed to run database synchronization:', error);
    }
}

// --- Resilience: WaitForDB Logic ---
async function waitForDatabase() {
    // 1. Run local SQLite schema synchronization before connecting
    initializeDatabase();

    let retries = 5;
    while (retries > 0) {
        try {
            await prisma.$connect();
            console.log('✅ Database connected successfully');
            return true;
        } catch (error) {
            console.error(` DB Connection Failed. Retrying in 2s... (${retries} attempts left)`);
            retries--;
            await new Promise(res => setTimeout(res, 2000));
        }
    }
    console.error('💀 Could not connect to database after multiple attempts.');
    return false;
}

// Start server only after DB check (optional, or just init in background)
// Start server only after DB check (invoked at bottom)
// waitForDatabase(); moved to bottom

// --- Strict Auth Rate Limiter ---
const authLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 15, // Max 15 attempts (success or fail) per IP per window
    message: { error: 'Too many auth attempts. Please try again in 5 minutes.' }
});

const exchangeTokenLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 10,
    message: { error: 'Too many token exchange attempts. Please try again later.' }
});

// --- Security Endpoints ---

// Verify Admin PIN (Used for sudo mode or recovery)
app.post('/api/security/verify-admin-pin', authLimiter, async (req, res) => {
    const { adminPin } = req.body;

    if (!adminPin) {
        return res.status(400).json({ error: 'PIN is required' });
    }

    try {
        // Find the active restaurant
        const restaurant = await prisma.restaurant.findFirst({
            where: { status: { in: ['ACTIVE', 'GRACE'] } },
            orderBy: { createdAt: 'desc' }
        });

        if (!restaurant) {
            return res.status(404).json({ error: 'No active restaurant found' });
        }

        const isValid = await bcrypt.compare(adminPin, restaurant.adminPin || '');

        if (!isValid) {
            return res.json({ success: false, error: 'Invalid PIN' });
        }

        // Return success (no token needed, just verification)
        res.json({ success: true, message: 'PIN Verified' });

    } catch (error) {
        console.error('Verify PIN Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Cloud API URLs for authentication (Next.js) and validation (Express)
const CLOUD_AUTH_API_BASE = 'https://dinestack.in/api';
const CLOUD_LICENSE_API_BASE = 'https://software.dinestack.in/api';


// --- Restaurant Info Endpoint (Public) ---
app.get('/api/restaurant/info', async (req, res) => {
    try {
        const restaurant = await prisma.restaurant.findFirst({
            select: { name: true, ownerName: true }
        });
        res.json({ success: true, restaurantName: restaurant?.name || 'Restaurant', ownerName: restaurant?.ownerName || 'Owner' });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

// --- Coupon Routes ---
app.use('/api/coupons', couponRoutes);

// --- Root Route ---
app.get(['/', '/api'], (req, res) => {
    res.json({
        message: 'DineStack Desktop API is running',
        version: '1.0.0',
        mode: 'DESKTOP_SQLITE',
        endpoints: {
            health: '/health',
            tables: '/api/tables',
            orders: '/api/orders',
            status: '/api/system/status'
        }
    });
});

// --- Module 0: System Status ---
// Direct Cloud DB access implies we just check the DB. No local caching needed for "sync" in this mode.

app.get('/api/kitchen/bootstrap', async (req, res) => {
    try {
        const link = await prisma.kitchenDeviceLink.findFirst();
        if (!link) {
            return res.json({ linked: false });
        }

        let isCloudAvailable = false;
        let cloudDevice = null;
        let cloudRestaurant = null;

        try {
            if (cloudPrisma) {
                // Ping cloud to verify connectivity before concluding it's offline
                await cloudPrisma.$queryRaw`SELECT 1`;

                cloudDevice = await cloudPrisma.device.findFirst({
                    where: { deviceId: link.kitchenDeviceId }
                });
                cloudRestaurant = await cloudPrisma.restaurant.findUnique({
                    where: { id: link.cloudRestaurantId }
                });
                isCloudAvailable = true;
            }
        } catch (e) {
            console.warn('[Kitchen Bootstrap] Cloud unreachable, entering offline check', e);
        }

        if (isCloudAvailable) {
            if (!cloudDevice || cloudDevice.status !== 'ACTIVE' || !cloudRestaurant || (cloudRestaurant.status !== 'ACTIVE' && cloudRestaurant.status !== 'GRACE')) {
                // Revoked or removed
                await prisma.kitchenDeviceLink.deleteMany();
                return res.json({ linked: false, revoked: true });
            }

            // Success
            await prisma.kitchenDeviceLink.update({
                where: { kitchenDeviceId: link.kitchenDeviceId },
                data: {
                    lastVerifiedAt: new Date(),
                    lastSuccessfulVerification: new Date(),
                    status: 'LINKED'
                }
            });
        } else {
            // Offline - Check Grace Period
            const gracePeriodHours = 24; // Standard 24h grace period for offline
            const hoursSinceLastVerification = (Date.now() - link.lastSuccessfulVerification.getTime()) / (1000 * 60 * 60);
            if (hoursSinceLastVerification > gracePeriodHours) {
                return res.json({ linked: false, gracePeriodExpired: true, message: 'Offline grace period expired. Cloud verification required.' });
            }
        }

        // Generate a new fresh JWT
        const { accessToken } = await setAuthSession(req, res, {
            deviceId: link.kitchenDeviceId,
            role: 'KITCHEN',
            restaurantId: link.restaurantId
        });

        res.json({
            linked: true,
            authenticated: true,
            restaurantId: link.restaurantId,
            jwt: accessToken
        });

    } catch (error) {
        console.error('Kitchen Bootstrap Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/api/system/status', async (req, res) => {
    try {
        const restaurant = await prisma.restaurant.findFirst({
            where: { status: { in: ['ACTIVE', 'GRACE', 'SUSPENDED'] } },
            orderBy: { createdAt: 'desc' },
            include: { ActivationCode: true }
        });

        if (!restaurant) {
            return res.json({
                activated: false,
                setupComplete: false,
                message: 'System not activated'
            });
        }

        const activeCode = (restaurant as any).ActivationCode || (restaurant as any).activationCode;
        if (!activeCode) {
            return res.json({
                activated: false,
                setupComplete: false,
                message: 'No active license found'
            });
        }

        const CLOUD_API_URL = CLOUD_LICENSE_API_BASE;
        let status = restaurant.status || 'ACTIVE';
        let planStatus = (restaurant as any).planStatus || 'TRIAL';
        let trialEndDate = (restaurant as any).trialEndDate;
        let licenseLocked = false;
        let message = 'System status retrieved';

        try {
            // Attempt to verify with the cloud server using RESTAURANT ID
            const verifyRes = await fetch(`${CLOUD_API_URL}/license/status`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ restaurantId: restaurant.id }),
                timeout: 5000 // 5 seconds timeout
            });

            if (verifyRes.ok) {
                const data = await verifyRes.json() as any;
                if (data.success) {
                    status = data.status;
                    planStatus = data.planStatus;
                    trialEndDate = data.trialEndDate ? new Date(data.trialEndDate) : trialEndDate;

                    // Sync status to local DB
                    const updateData: any = {
                        status,
                        planStatus,
                        lastCloudVerification: new Date()
                    };
                    if (data.trialEndDate) updateData.trialEndDate = new Date(data.trialEndDate);
                    if (data.name) updateData.name = data.name;
                    // PIN hashes are no longer synced from cloud for security — they are set locally via setup-pin

                    await prisma.restaurant.update({
                        where: { id: restaurant.id },
                        data: updateData
                    });

                    // Persist JWT secret if returned
                    if (data.jwtSecret) {
                        process.env.JWT_SECRET = data.jwtSecret;
                        const dbUrl = process.env.DATABASE_URL;
                        if (dbUrl && dbUrl.startsWith('file:')) {
                            try {
                                const fs = require('fs');
                                const path = require('path');
                                const dbPath = dbUrl.replace(/^file:/, '');
                                const userDataPath = path.dirname(dbPath);
                                const jwtKeyPath = path.join(userDataPath, 'jwt.key');
                                fs.writeFileSync(jwtKeyPath, data.jwtSecret, 'utf8');
                            } catch (writeErr: any) {
                                console.error('[License System] Failed to write jwt.key:', writeErr.message || writeErr);
                            }
                        }
                    }

                    console.log(`[License System] Successfully validated license with cloud. Plan Status: ${planStatus}`);
                } else {
                    status = data.status || 'REVOKED';
                    planStatus = data.planStatus || 'TRIAL_EXPIRED';
                    await prisma.restaurant.update({
                        where: { id: restaurant.id },
                        data: { status, planStatus }
                    });
                    console.warn(`[License System] Cloud license is not active: ${status}. Lockout applied.`);
                }
            } else {
                throw new Error('Verification request failed');
            }
        } catch (fetchError: any) {
            console.warn('[License System] Cloud validation unreachable. Checking local grace period...', fetchError.message || fetchError);

            // Check stored lastCloudVerification
            const lastVal = (restaurant as any).lastCloudVerification;
            if (!lastVal) {
                // Never validated or cleared
                licenseLocked = true;
                status = 'LOCKOUT';
                planStatus = 'LOCKOUT';
                message = 'License offline grace period exceeded';
            } else {
                const diffMs = Date.now() - new Date(lastVal).getTime();
                const hoursPassed = diffMs / (1000 * 60 * 60);
                if (hoursPassed > 168) { // 7 days = 168 hours
                    console.error(`[License System] Offline grace period exceeded: ${hoursPassed.toFixed(1)} hours. Lockout.`);
                    licenseLocked = true;
                    status = 'LOCKOUT';
                    planStatus = 'LOCKOUT';
                    message = 'License offline grace period exceeded (7 days). Please connect to the internet.';
                } else if (hoursPassed > 72) {
                    console.warn(`[License System] Warning: Offline grace period active: ${hoursPassed.toFixed(1)} hours.`);
                    status = 'GRACE';
                    message = 'License offline grace warning';
                } else {
                    console.log(`[License System] Within grace period. ${hoursPassed.toFixed(1)} hours since last validation.`);
                }
            }
        }

        if (status === 'LOCKOUT' || status === 'REVOKED' || status === 'EXPIRED' || licenseLocked) {
            return res.json({
                activated: true,
                setupComplete: !!restaurant.adminPin,
                kitchenPinConfigured: !!restaurant.kitchenPin,
                restaurantId: restaurant.id,
                status: 'LOCKOUT',
                planStatus: 'LOCKOUT',
                licenseLocked: true,
                message: licenseLocked ? message : `License status: ${status}`
            });
        }

        return res.json({
            activated: true,
            setupComplete: !!restaurant.adminPin,
            kitchenPinConfigured: !!restaurant.kitchenPin,
            restaurantId: restaurant.id,
            status: status,
            planStatus: planStatus,
            trialEndDate: trialEndDate,
            message: message
        });

    } catch (error) {
        console.error('System Status Check Failed:', error);
        res.status(500).json({ error: 'System Error' });
    }
});

// --- Module 4 & 6: Authentication (Cookie Helpers & Session Management) ---
const getCookieOptions = (req: express.Request) => ({
    httpOnly: true,
    secure: false, // Must be false for local desktop loopback HTTP connections
    sameSite: 'lax' as any,
    path: '/'
});

// Helper to set auth cookies and write to database
async function setAuthSession(req: express.Request, res: express.Response, payload: any) {
    const accessToken = generateToken(payload);
    const rawRefreshToken = generateRefreshToken();
    const hashedRefresh = hashToken(rawRefreshToken);
    const refreshExpiry = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days

    // Session ID Regeneration: Delete previous refresh tokens for this device & restaurant to invalidate old sessions
    if (payload.deviceId && payload.restaurantId) {
        await prisma.refreshToken.deleteMany({
            where: {
                deviceId: payload.deviceId,
                restaurantId: payload.restaurantId
            }
        });
    }

    // Store in DB
    await prisma.refreshToken.create({
        data: {
            tokenHash: hashedRefresh,
            restaurantId: payload.restaurantId,
            deviceId: payload.deviceId || 'unknown',
            expiresAt: refreshExpiry
        }
    });

    const options = getCookieOptions(req);
    res.cookie('accessToken', accessToken, { ...options, maxAge: 15 * 60 * 1000 }); // 15m
    res.cookie('refreshToken', rawRefreshToken, { ...options, maxAge: 30 * 24 * 60 * 60 * 1000 }); // 30d

    return { accessToken, refreshToken: rawRefreshToken };
}

// Manual helper to parse cookies
function getCookieFromRequest(req: express.Request, name: string): string | null {
    const cookieHeader = req.headers.cookie;
    if (!cookieHeader) return null;
    const cookies = cookieHeader.split(';');
    for (const cookie of cookies) {
        const [key, value] = cookie.trim().split('=');
        if (key === name) return decodeURIComponent(value);
    }
    return null;
}

// --- Module: Authentication (Login) ---
app.post('/api/auth/login', authLimiter, async (req, res) => {
    const { pin, role, deviceId } = req.body;

    if (!pin || !role || !deviceId) {
        return res.status(400).json({ error: 'Missing credentials' });
    }

    try {
        // Find the active restaurant
        const restaurant = await prisma.restaurant.findFirst({
            where: { status: { in: ['ACTIVE', 'GRACE'] } },
            orderBy: { createdAt: 'desc' }
        });

        if (!restaurant) {
            return res.status(404).json({ error: 'No active restaurant found. Please activate the system.' });
        }

        let isValid = false;

        if (role === 'ADMIN') {
            if (!restaurant.adminPin) {
                return res.status(400).json({ error: 'Admin PIN not configured' });
            }
            isValid = await bcrypt.compare(pin, restaurant.adminPin);
        } else if (role === 'KITCHEN') {
            if (!restaurant.kitchenPin) {
                return res.status(400).json({ error: 'Kitchen PIN not configured' });
            }
            isValid = await bcrypt.compare(pin, restaurant.kitchenPin);
        } else {
            return res.status(400).json({ error: 'Invalid role' });
        }

        if (!isValid) {
            return res.status(401).json({ error: 'Invalid PIN' });
        }

        if (deviceId && role) {
            // Update lastUsed / register device (role-scoped to avoid overwriting other roles)
            const existingDevice = await prisma.device.findFirst({
                where: { deviceId, restaurantId: restaurant.id, role }
            });
            if (existingDevice) {
                await prisma.device.update({
                    where: { id: existingDevice.id },
                    data: { lastUsed: new Date(), status: 'ACTIVE' }
                });
            } else {
                await prisma.device.create({
                    data: { id: randomUUID(), deviceId, role, restaurantId: restaurant.id, status: 'ACTIVE', lastUsed: new Date() }
                });
            }

            // Set secure cookies and create refresh token in DB
            const { accessToken } = await setAuthSession(req, res, { deviceId, role, restaurantId: restaurant.id });

            console.log(`[Auth] Login Success: ${role} on ${deviceId}`);

            // Backwards compatibility: return token in response body
            res.json({
                success: true,
                token: accessToken,
                role,
                restaurantId: restaurant.id
            });
            return;
        }

        res.status(400).json({ error: 'Missing device info or role for registration' });
    } catch (error: any) {
        console.error('Login Error:', error);
        res.status(500).json({
            error: 'Internal Server Error'
        });
    }
});

// Me Endpoint (Session Check)
app.get('/api/auth/me', authenticate, async (req, res) => {
    const user = (req as any).user;
    if (!user) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    const restaurant = await prisma.restaurant.findUnique({
        where: { id: user.restaurantId },
        select: { name: true, ownerName: true }
    });

    res.json({
        success: true,
        role: user.role,
        restaurantId: user.restaurantId,
        deviceId: user.deviceId,
        restaurantName: restaurant?.name || 'Restaurant Owner',
        ownerName: restaurant?.ownerName || 'DineStack Admin'
    });
});

// --- Cloud Session Synchronization ---
let cloudSession: any = null;

app.get('/api/auth/cloud-session', (req, res) => {
    res.json({ success: true, session: cloudSession });
});

app.post('/api/auth/desktop-session', (req, res) => {
    const { avatarUrl, fullName, email, role } = req.body;
    cloudSession = { avatarUrl, fullName, email, role };
    // Broadcast to connected desktop frontends
    io.emit('cloud-session-updated', cloudSession);
    res.json({ success: true, message: 'Session securely transferred to desktop' });
});

app.post('/api/auth/exchange-desktop-token', exchangeTokenLimiter, async (req, res) => {
    console.log('[AUTH TRACE] 4. Backend Received Exchange Request');
    try {
        const { token } = req.body;
        if (!token) {
            console.error('[AUTH TRACE] Exchange failed: Token is missing from request body');
            return res.status(400).json({ success: false, error: 'Token is required' });
        }

        // WORKAROUND: The production cloud API requires `ownerId` to be set, but it might not be.
        // Since we have direct access to `cloudPrisma`, we can decode the token to get the Clerk ID (`sub`)
        // and manually link it to the current restaurant in the cloud DB before calling the API.
        try {
            console.log(`[AUTH TRACE] 4.1. Starting workaround. Token: ${token.substring(0, 15)}...`);
            const jwt = require('jsonwebtoken');
            const decoded = jwt.decode(token) as any;
            console.log(`[AUTH TRACE] 4.2. Decoded Token sub (ownerId): ${decoded?.sub}, email: ${decoded?.email || 'N/A'}`);

            if (decoded && decoded.sub && cloudPrisma) {
                const localRests = await prisma.restaurant.findMany();
                console.log(`[AUTH TRACE] 4.3. Found ${localRests.length} local restaurants to check.`);

                let linkedCount = 0;
                for (const rest of localRests) {
                    if (!rest.id) continue;

                    try {
                        const cloudRest = await cloudPrisma.restaurant.findUnique({
                            where: { id: rest.id }
                        });

                        if (cloudRest) {
                            console.log(`[AUTH TRACE] 4.4. Cloud Restaurant Found for ID ${rest.id}. Forcing ownerId update to ${decoded.sub}`);
                            await cloudPrisma.restaurant.update({
                                where: { id: rest.id },
                                data: { ownerId: decoded.sub }
                            });
                            console.log(`[AUTH TRACE] 4.5. OwnerId successfully updated in Cloud DB!`);
                            linkedCount++;
                        }
                    } catch (err) {
                        console.error(`[AUTH TRACE] Failed to check/update cloud rest ${rest.id}:`, err);
                    }
                }

                console.log(`[AUTH TRACE] 4.6. Successfully linked ${linkedCount} cloud restaurants to user ${decoded.sub}`);
            } else {
                console.log(`[AUTH TRACE] 4.2.5. Missing decoded.sub or cloudPrisma is null. cloudPrisma exists: ${!!cloudPrisma}`);
            }
        } catch (e) {
            console.error('[AUTH TRACE] Pre-link workaround failed:', e);
        }

        console.log(`[AUTH TRACE] 5. Requesting Verification from Cloud API at: ${CLOUD_AUTH_API_BASE}/auth/verify-desktop-token`);
        const verifyRes = await fetch(`${CLOUD_AUTH_API_BASE}/auth/verify-desktop-token`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token }),
            timeout: 10000
        });

        if (verifyRes.ok) {
            console.log('[AUTH TRACE] 6. Cloud verification successful, parsing response...');
            const data = await verifyRes.json() as any;
            if (data.success && data.session) {
                console.log('[AUTH TRACE] 7. Session extracted, broadcasting to frontend...');
                const { avatarUrl, fullName, email, role } = data.session;
                cloudSession = { avatarUrl, fullName, email, role };

                // Broadcast to connected desktop frontends
                io.emit('cloud-session-updated', cloudSession);

                return res.json({
                    success: true,
                    message: 'Desktop token exchanged successfully',
                    session: cloudSession,
                    accessToken: data.accessToken,
                    refreshToken: data.refreshToken
                });
            } else {
                console.error('[AUTH TRACE] Cloud verification returned success=false or missing session:', data.error);
                return res.status(401).json({ success: false, error: data.error || 'Invalid token' });
            }
        } else {
            const errorText = await verifyRes.text();
            console.error(`[AUTH TRACE] Cloud verification failed with Status ${verifyRes.status}. Body: ${errorText}`);
            return res.status(verifyRes.status).json({ success: false, error: `Failed to verify token with cloud. Status: ${verifyRes.status}, Body: ${errorText}` });
        }
    } catch (error: any) {
        console.error('[AUTH TRACE] Exchange desktop token network error:', error);
        return res.status(500).json({ success: false, error: `Internal server error: ${error.message}` });
    }
});

app.post('/api/auth/refresh-cloud-session', async (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) {
        return res.status(400).json({ success: false, error: 'Refresh token is required' });
    }

    try {
        const refreshRes = await fetch(`${CLOUD_AUTH_API_BASE}/auth/refresh-desktop-token`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ refreshToken }),
            timeout: 10000
        });

        if (refreshRes.ok) {
            const data = await refreshRes.json() as any;
            if (data.success && data.session) {
                const { avatarUrl, fullName, email, role } = data.session;
                cloudSession = { avatarUrl, fullName, email, role };

                io.emit('cloud-session-updated', cloudSession);

                return res.json({
                    success: true,
                    session: cloudSession,
                    accessToken: data.accessToken,
                    refreshToken: data.refreshToken
                });
            } else {
                return res.status(401).json({ success: false, error: data.error || 'Invalid refresh token' });
            }
        } else {
            return res.status(refreshRes.status).json({ success: false, error: 'Failed to refresh token with cloud' });
        }
    } catch (error: any) {
        console.error('Refresh cloud session error:', error);
        return res.status(500).json({ success: false, error: 'Internal server error while refreshing token' });
    }
});

// Logout Endpoint
app.post('/api/auth/logout', (req, res) => {
    res.clearCookie('accessToken', getCookieOptions(req));
    res.clearCookie('refreshToken', getCookieOptions(req));
    res.json({ success: true, message: 'Logged out successfully' });
});

// Rotate Token Endpoint
app.post('/api/auth/refresh', async (req, res) => {
    const oldRefreshToken = getCookieFromRequest(req, 'refreshToken');

    if (!oldRefreshToken) {
        return res.status(401).json({ error: 'Unauthorized: No refresh token provided' });
    }

    try {
        const hashedOld = hashToken(oldRefreshToken);
        const storedToken = await prisma.refreshToken.findUnique({
            where: { tokenHash: hashedOld }
        });

        if (!storedToken || storedToken.expiresAt < new Date()) {
            if (storedToken) {
                await prisma.refreshToken.delete({ where: { id: storedToken.id } });
            }
            return res.status(401).json({ error: 'Unauthorized: Invalid or expired session' });
        }

        // Verify that the device is still active
        const device = await prisma.device.findFirst({
            where: {
                deviceId: storedToken.deviceId,
                restaurantId: storedToken.restaurantId
            }
        });

        if (!device || device.status !== 'ACTIVE') {
            await prisma.refreshToken.deleteMany({ where: { id: storedToken.id } });
            return res.status(401).json({ error: 'Unauthorized: Device has been deactivated' });
        }

        // Delete old refresh token (rotation)
        await prisma.refreshToken.deleteMany({
            where: { id: storedToken.id }
        });

        // Set new session cookies and save new refresh token in DB
        const payload = {
            deviceId: storedToken.deviceId,
            role: device.role as any,
            restaurantId: storedToken.restaurantId
        };
        const { accessToken } = await setAuthSession(req, res, payload);

        res.json({ success: true, token: accessToken, role: device.role });

    } catch (error) {
        console.error('Token Rotation Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Logout Endpoint
app.post('/api/auth/logout', async (req, res) => {
    const rawRefreshToken = getCookieFromRequest(req, 'refreshToken');

    if (rawRefreshToken) {
        try {
            const hashed = hashToken(rawRefreshToken);
            await prisma.refreshToken.deleteMany({
                where: { tokenHash: hashed }
            });
        } catch (e) {
            console.error('Failed to delete refresh token on logout:', e);
        }
    }

    const options = getCookieOptions(req);
    res.clearCookie('accessToken', options);
    res.clearCookie('refreshToken', options);

    res.json({ success: true, message: 'Logged out successfully' });
});

// Revoke All Sessions Endpoint
app.post('/api/auth/revoke-all', authenticate, authorize(['ADMIN']), async (req, res) => {
    const { restaurantId } = (req as any).user;

    try {
        // Invalidate all tokens for this restaurant in DB
        await prisma.refreshToken.deleteMany({
            where: { restaurantId }
        });

        const options = getCookieOptions(req);
        res.clearCookie('accessToken', options);
        res.clearCookie('refreshToken', options);

        res.json({ success: true, message: 'All active sessions revoked successfully' });
    } catch (error) {
        console.error('Revoke Sessions Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// --- PIN strength / complexity validation ---
function isWeakPin(pin: string): boolean {
    // All-repeating digits: 1111, 000000, etc.
    if (/^(\d)\1+$/.test(pin)) return true;

    // Sequential patterns: only flag if 5+ consecutive ascending/descending digits
    // This avoids false positives on short (4-digit) kitchen PINs
    const ascending = '0123456789';
    const descending = '9876543210';
    if (pin.length >= 5 && (ascending.includes(pin) || descending.includes(pin))) return true;

    return false;
}

// --- Module 2 & 3: PIN Registration (First-Time Setup) ---
app.post('/api/setup-pin', async (req, res) => {
    const { restaurantId, adminPin, kitchenPin } = req.body;

    console.log(`[Desktop][setup-pin] Request received. restaurantId: ${restaurantId}, adminPin length: ${adminPin?.length}, kitchenPin provided: ${!!kitchenPin}`);

    if (!restaurantId) {
        console.error('[Desktop][setup-pin] Missing restaurantId');
        res.status(400).json({ error: 'Restaurant ID is required' });
        return;
    }

    if (!adminPin || adminPin.length < 6) {
        console.error(`[Desktop][setup-pin] Admin PIN too short: ${adminPin?.length}`);
        res.status(400).json({ error: 'Admin PIN must be at least 6 digits' });
        return;
    }

    if (isWeakPin(adminPin)) {
        console.error('[Desktop][setup-pin] Admin PIN is weak');
        res.status(400).json({ error: 'Admin PIN is too weak. Avoid repeating or sequential patterns.' });
        return;
    }

    if (kitchenPin && kitchenPin.length >= 4 && isWeakPin(kitchenPin)) {
        console.error('[Desktop][setup-pin] Kitchen PIN is weak');
        res.status(400).json({ error: 'Kitchen PIN is too weak. Avoid repeating patterns.' });
        return;
    }

    try {
        const restaurant = await prisma.restaurant.findUnique({ where: { id: restaurantId } });

        if (!restaurant) {
            console.error(`[Desktop][setup-pin] Restaurant not found: ${restaurantId}`);
            res.status(400).json({ error: 'Restaurant not found' });
            return;
        }

        if (!restaurant.isActive) {
            console.error(`[Desktop][setup-pin] Restaurant not active: ${restaurantId}, status: ${restaurant.status}`);
            res.status(400).json({ error: 'Restaurant not active' });
            return;
        }

        // Sync with cloud API first to validate and persist centrally
        const CLOUD_API_URL = process.env.CLOUD_API_URL || 'https://software.dinestack.in/api';
        try {
            console.log(`[Desktop][setup-pin] Syncing PINs with cloud: ${CLOUD_API_URL}/setup-pin`);
            const cloudResponse = await fetch(`${CLOUD_API_URL}/setup-pin`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ restaurantId, adminPin, kitchenPin })
            });

            if (!cloudResponse.ok) {
                const cloudData = await cloudResponse.json() as any;
                console.error('[Desktop][setup-pin] Cloud PIN setup rejected:', cloudData);
                res.status(cloudResponse.status).json({ error: cloudData.error || 'Failed to sync PIN setup with cloud backend' });
                return;
            }
            console.log('[Desktop][setup-pin] Cloud database PINs updated successfully via HTTP API');
        } catch (cloudErr: any) {
            console.warn('[Desktop][setup-pin] Failed to connect to cloud backend for PIN setup. Proceeding locally...', cloudErr.message || cloudErr);
        }

        if (restaurant.adminPin) {
            const isMatch = await bcrypt.compare(adminPin, restaurant.adminPin);
            if (!isMatch) {
                console.error(`[Desktop][setup-pin] Security Alert: Attempted unauthenticated PIN overwrite for restaurant: ${restaurantId}`);
                res.status(400).json({ error: 'System is already initialized. To change your PIN, use the security settings page.' });
                return;
            }

            // If it matches, allow updating the kitchenPin
            if (kitchenPin) {
                const kitchenPinHash = await bcrypt.hash(kitchenPin, 12);
                await prisma.restaurant.update({
                    where: { id: restaurantId },
                    data: {
                        kitchenPin: kitchenPinHash
                    }
                });
            }

            res.json({ success: true, message: 'Kitchen PIN updated successfully' });
            return;
        }

        const pinHash = await bcrypt.hash(adminPin, 12);
        const kitchenPinHash = kitchenPin ? await bcrypt.hash(kitchenPin, 12) : null;

        // Update local SQLite database
        await prisma.restaurant.update({
            where: { id: restaurantId },
            data: {
                adminPin: pinHash,
                kitchenPin: kitchenPinHash
            }
        });

        console.log(`[Desktop][setup-pin] PINs set successfully for restaurant: ${restaurant.id}`);

        // Return a valid JWT token for immediate session usage
        const token = generateToken({
            role: 'ADMIN',
            restaurantId,
            deviceId: 'initial-setup'
        });
        res.json({ success: true, token });
    } catch (error) {
        console.error('[Desktop][setup-pin] Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});



// Activation code strength/complexity validation
function isWeakActivationCode(code: string): boolean {
    const clean = code.replace(/[^A-Z0-9]/ig, '').toUpperCase();
    if (clean.length !== 16) return true;

    // Repeating characters (e.g., AAAA-AAAA-AAAA-AAAA)
    if (/^(.)\1+$/.test(clean)) return true;

    // Trivial sequential patterns (e.g., ABCD-EFGH-IJKL-MNOP or 0123-4567-89AB-CDEF)
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const numbers = '0123456789';
    if (alphabet.includes(clean) || alphabet.split('').reverse().join('').includes(clean)) return true;
    if (numbers.includes(clean) || numbers.split('').reverse().join('').includes(clean)) return true;

    // Repeating 4-character blocks (e.g., A1B2-A1B2-A1B2-A1B2)
    const block1 = clean.substring(0, 4);
    if (clean === block1.repeat(4)) return true;

    return false;
}

// --- Module 1: Activation (SaaS-Style Self-Validating) ---
app.post('/api/activate', async (req, res) => {
    // 1) Log incoming request body exactly as received.
    console.log('[SaaS Activation] Incoming request body:', JSON.stringify(req.body));

    const { activationCode: rawActivationCode } = req.body;

    if (!rawActivationCode) {
        return res.status(400).json({ error: 'Activation code required' });
    }

    // 2) Normalize activation code: trim, uppercase, remove non-alphanumeric.
    const cleanCode = rawActivationCode.replace(/[^A-Z0-9]/ig, '').toUpperCase();

    // Fail-fast check length and pattern strength
    if (isWeakActivationCode(cleanCode)) {
        console.log(`[SaaS Activation] Rejecting weak or malformed activation code: "${rawActivationCode}"`);
        return res.status(400).json({ error: 'Activation code not found' });
    }

    // Reconstruct the canonical XXXX-XXXX-XXXX-XXXX hyphenated format
    const activationCode = `${cleanCode.substring(0, 4)}-${cleanCode.substring(4, 8)}-${cleanCode.substring(8, 12)}-${cleanCode.substring(12, 16)}`;
    console.log(`[SaaS Activation] Normalized code from "${rawActivationCode}" to "${activationCode}"`);

    // 3) Check which database Prisma is using.
    console.log(`[SaaS Activation] Local SQLite DB: ${process.env.DATABASE_URL}`);
    console.log(`[SaaS Activation] Cloud PostgreSQL: ${CLOUD_DATABASE_URL ? 'Available' : 'NOT available'}`);

    try {
        const CLOUD_API_URL = process.env.CLOUD_API_URL || 'https://software.dinestack.in/api';
        console.log(`[SaaS Activation] Relaying activation request to cloud API: ${CLOUD_API_URL}/activate`);

        const response = await fetch(`${CLOUD_API_URL}/activate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ activationCode: activationCode })
        });

        const data = await response.json() as any;

        if (!response.ok) {
            console.error('[SaaS Activation] Cloud activation rejected request:', data);
            return res.status(response.status).json(data);
        }

        const tier = data.tier || 'BASIC';
        const durationDays = data.durationDays || 365;
        const expiresAt = data.expiresAt ? new Date(data.expiresAt) : new Date(Date.now() + durationDays * 24 * 60 * 60 * 1000);
        const maxTables = data.maxTables || 100;
        const cloudRestaurantId = data.restaurantId || data.restaurant?.id;
        const cloudRestaurantName = data.restaurant?.name || 'My Restaurant';

        if (!cloudRestaurantId) {
            throw new Error('Cloud response did not return a valid restaurant ID');
        }

        // LOCAL SQLite PROVISIONING
        console.log('[SaaS Activation] Provisioning local SQLite database...');

        // Find the most recent local restaurant BEFORE revoking to preserve its PINs (regardless of lockout status)
        const currentlyActive = await prisma.restaurant.findFirst({
            orderBy: { createdAt: 'desc' }
        });

        // Revoke any existing local active restaurants to prevent multi-session ghost records
        const revokeResult = await prisma.restaurant.updateMany({
            where: { status: { in: ['ACTIVE', 'GRACE'] } },
            data: {
                status: 'REVOKED',
                revokedAt: new Date(),
                revokedBy: 'activation',
                revocationReason: 'New activation initiated'
            }
        });
        console.log(`[SaaS Activation] Revoked ${revokeResult.count} local restaurant(s).`);

        // If cloud generated a new restaurant ID for a new license, migrate local data first
        if (currentlyActive && currentlyActive.id !== cloudRestaurantId) {
            console.log(`[SaaS Activation] Migrating local data from ${currentlyActive.id} to new cloud ID ${cloudRestaurantId}`);
            const entities = ['category', 'menuItem', 'table', 'order', 'device', 'session', 'tableSession', 'recoveryCode', 'customer', 'refreshToken'];
            for (const entity of entities) {
                try {
                    await (prisma as any)[entity].updateMany({
                        where: { restaurantId: currentlyActive.id },
                        data: { restaurantId: cloudRestaurantId }
                    });
                } catch (e) { console.warn(`Migration of ${entity} failed:`, e); }
            }
            // Attempt to clean up old restaurant to avoid duplicate confusion
            try { await prisma.restaurant.delete({ where: { id: currentlyActive.id } }); } catch (e) { }
        }

        // 1. Upsert Restaurant locally WITHOUT activationCodeId to avoid foreign key constraints
        let localRestaurant = await prisma.restaurant.upsert({
            where: { id: cloudRestaurantId },
            update: {
                name: cloudRestaurantName,
                status: 'ACTIVE',
                isActive: true,
                subscriptionEndsAt: expiresAt,
                // PIN hashes are no longer returned from cloud — they are set locally via setup-pin

                activationDate: data.activationDate ? new Date(data.activationDate) : new Date(),
                trialEndDate: data.trialEndDate ? new Date(data.trialEndDate) : new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
                currentPlan: data.currentPlan || 'TRIAL',
                planStatus: data.planStatus || 'TRIAL',
                lastCloudVerification: new Date()
            },
            create: {
                id: cloudRestaurantId,
                name: cloudRestaurantName,
                status: 'ACTIVE',
                isActive: true,
                subscriptionEndsAt: expiresAt,
                // PIN hashes are no longer returned from cloud — they are set locally via setup-pin
                activationDate: data.activationDate ? new Date(data.activationDate) : new Date(),
                trialEndDate: data.trialEndDate ? new Date(data.trialEndDate) : new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
                currentPlan: data.currentPlan || 'TRIAL',
                planStatus: data.planStatus || 'TRIAL',
                lastCloudVerification: new Date()
            }
        });

        // If the new restaurant has no adminPin but the previously active one did, copy the PINs over
        if (!localRestaurant.adminPin && currentlyActive?.adminPin) {
            console.log(`[SaaS Activation] Copying PINs from previously active restaurant to new restaurant ${localRestaurant.id}`);
            localRestaurant = await prisma.restaurant.update({
                where: { id: localRestaurant.id },
                data: {
                    adminPin: currentlyActive.adminPin,
                    kitchenPin: currentlyActive.kitchenPin
                }
            });
        }

        // 2. Upsert ActivationCode locally
        const localCodeId = randomUUID();
        const localCode = await prisma.activationCode.upsert({
            where: { code: activationCode },
            update: {
                status: 'USED',
                isUsed: true,
                usedAt: new Date(),
                expiresAt,
                plan: tier,
                restaurantId: cloudRestaurantId,
                lastValidated: new Date()
            },
            create: {
                id: localCodeId,
                code: activationCode,
                status: 'USED',
                isUsed: true,
                usedAt: new Date(),
                expiresAt,
                durationDays,
                maxTables,
                plan: tier,
                restaurantId: cloudRestaurantId,
                lastValidated: new Date()
            }
        });

        // 3. Update Restaurant with activationCodeId
        localRestaurant = await prisma.restaurant.update({
            where: { id: cloudRestaurantId },
            data: { activationCodeId: localCode.id }
        });

        console.log(`[SaaS Activation] ✅ SUCCESS - Restaurant: ${localRestaurant.name} (${localRestaurant.id}), Registered: ${!!localRestaurant.adminPin}`);

        // Persist JWT secret if returned
        if (data.jwtSecret) {
            process.env.JWT_SECRET = data.jwtSecret;
            const dbUrl = process.env.DATABASE_URL;
            if (dbUrl && dbUrl.startsWith('file:')) {
                try {
                    const fs = require('fs');
                    const path = require('path');
                    const dbPath = dbUrl.replace(/^file:/, '');
                    const userDataPath = path.dirname(dbPath);
                    const jwtKeyPath = path.join(userDataPath, 'jwt.key');
                    fs.writeFileSync(jwtKeyPath, data.jwtSecret, 'utf8');
                    console.log('[SaaS Activation] Saved synced JWT secret to jwt.key');
                } catch (writeErr: any) {
                    console.error('[SaaS Activation] Failed to write jwt.key:', writeErr.message || writeErr);
                }
            }
        }

        return res.json({
            success: true,
            isActivated: true,
            restaurantId: localRestaurant.id,
            restaurant: {
                id: localRestaurant.id,
                name: localRestaurant.name,
                status: localRestaurant.status,
                tier
            },
            isRegistered: !!localRestaurant.adminPin,
            tier
        });

    } catch (error: any) {
        console.error('[SaaS Activation] Error:', error?.message || error);
        console.error('[SaaS Activation] Stack:', error?.stack);
        return res.status(500).json({
            error: 'ACTIVATION_FAILED',
            details: process.env.NODE_ENV === 'production' ? 'An unexpected error occurred during activation' : (error?.message || 'Unknown error during activation')
        });
    }
});

// Helper function to compare activation codes character by character
function compareCodesCharByChar(sent: string, stored: string, sourceName: string) {
    console.log(`[SaaS Activation] Comparing character-by-character sent vs ${sourceName}:`);
    console.log(`  Sent:   "${sent}" (length: ${sent.length})`);
    console.log(`  Stored: "${stored}" (length: ${stored.length})`);
    const maxLength = Math.max(sent.length, stored.length);
    let mismatches = 0;
    for (let i = 0; i < maxLength; i++) {
        if (sent[i] !== stored[i]) {
            const charSent = sent[i] !== undefined ? `'${sent[i]}' (code: ${sent.charCodeAt(i)})` : 'MISSING';
            const charStored = stored[i] !== undefined ? `'${stored[i]}' (code: ${stored.charCodeAt(i)})` : 'MISSING';
            console.log(`    MISMATCH at char ${i}: Sent ${charSent} | Stored ${charStored}`);
            mismatches++;
        }
    }
    if (mismatches === 0) {
        console.log(`  ✅ All ${sent.length} characters match.`);
    } else {
        console.log(`  ❌ ${mismatches} character(s) differ!`);
    }
}


// (Duplicate isWeakPin and setup-pin declarations consolidated and removed)

// --- Module 0.5: System Factory Reset (Unlink Device) ---
// Allows resetting the device to factory state (Activation Screen)
// SOFT RESET: Does NOT delete data, just unlinks the device by setting status to REVOKED.
app.post('/api/system/reset', async (req, res) => {
    try {
        console.log('⚠️ SYSTEM UNLINK INITIATED (Soft Reset) ...');

        // FORCE REVOKE ALL ACTIVE RESTAURANTS
        // This is the most robust way to ensure we don't have "Ghost" active sessions.
        const result = await prisma.restaurant.updateMany({
            where: { status: { in: ['ACTIVE', 'GRACE'] } },
            data: { status: 'REVOKED' }
        });

        console.log(`[SystemReset] Revoked ${result.count} active restaurants.`);

        // 3. Clear sessions
        await prisma.session.deleteMany({});

        console.log(' SYSTEM UNLINK COMPLETE.');
        res.json({ success: true, message: `Unlinked ${result.count} licenses.` });

    } catch (error: any) {
        console.error('System Unlink Failed:', error);
        res.status(500).json({ error: 'Unlink Failed', details: error.message });
    }
});
// --- Module: Secure Revocation (Admin PIN Required) ---
app.post('/api/security/revoke-activation', authenticate, authorize(['ADMIN']), async (req, res) => {
    const { adminPin } = req.body;
    const { restaurantId, deviceId } = (req as any).user;
    const userIdentifier = restaurantId;

    if (!adminPin) {
        return res.status(400).json({ error: 'Admin PIN is required' });
    }

    // 1. Check Rate Limit
    const { locked, waitTime } = checkRateLimit(userIdentifier);
    if (locked) {
        return res.status(429).json({
            error: `Too many failed attempts. Try again in ${waitTime} minutes.`
        });
    }

    try {
        const restaurant = await prisma.restaurant.findUnique({
            where: { id: restaurantId }
        });

        if (!restaurant || !restaurant.adminPin) {
            return res.status(400).json({ error: 'System not configured' });
        }

        // 2. Verify Admin PIN
        const isValid = await bcrypt.compare(adminPin, restaurant.adminPin);

        if (!isValid) {
            registerFailure(userIdentifier);
            // Log Attempt
            await prisma.auditLog.create({
                data: {
                    action: 'REVOKE_ATTEMPT_FAILED',
                    user: deviceId || 'admin',
                    target: 'system',
                    details: JSON.stringify({ reason: 'Invalid PIN' })
                }
            });
            return res.status(401).json({ error: 'Invalid Admin PIN' });
        }

        registerSuccess(userIdentifier);

        // 3. Perform Revocation
        console.log(`⚠️ REVOKING ACTIVATION for mechanism: ${restaurantId}`);

        // Set status to REVOKED, clear pins (optional but safer), record revocation info
        // Set status to REVOKED for ALL active restaurants to ensure clean slate
        // This fixes the issue where old active records cause "Create Master Key" screen
        await prisma.restaurant.updateMany({
            where: { status: { in: ['ACTIVE', 'GRACE'] } },
            data: {
                status: 'REVOKED',
                revokedAt: new Date(),
                revokedBy: deviceId || 'admin',
                revocationReason: 'User initiated local revocation'
            }
        });

        // 4. Clear Sessions
        await prisma.session.deleteMany({
            where: { restaurantId }
        });

        // 5. Audit Log
        await prisma.auditLog.create({
            data: {
                action: 'SYSTEM_REVOKED',
                user: deviceId || 'admin',
                target: 'system',
                details: JSON.stringify({ success: true, timestamp: new Date() })
            }
        });

        console.log(' REVOCATION COMPLETE.');
        res.json({ success: true, message: 'Device activation revoked successfully' });

    } catch (error) {
        console.error('Revoke Activation Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/api/security/verify-admin-pin', authenticate, authorize(['ADMIN']), async (req, res) => {
    const { adminPin } = req.body;
    const { restaurantId, deviceId } = (req as any).user;
    const userIdentifier = restaurantId;

    if (!adminPin) {
        return res.status(400).json({ error: 'Admin PIN is required' });
    }

    // 1. Check Rate Limit
    const { locked, waitTime } = checkRateLimit(userIdentifier);
    if (locked) {
        return res.status(429).json({
            error: `Too many failed attempts. Try again in ${waitTime} minutes.`
        });
    }

    try {
        const restaurant = await prisma.restaurant.findUnique({
            where: { id: restaurantId }
        });

        if (!restaurant || !restaurant.adminPin) {
            return res.status(400).json({ error: 'System not configured' });
        }

        const isValid = await bcrypt.compare(adminPin, restaurant.adminPin);

        if (!isValid) {
            registerFailure(userIdentifier);
            // Log Attempt
            return res.status(401).json({ error: 'Invalid Admin PIN' });
        }

        registerSuccess(userIdentifier);
        res.json({ success: true, verified: true });

    } catch (error) {
        console.error('Verify Admin PIN Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// 3. Create Order (Protected by Table Session)
app.post('/api/customer/orders', validateTableSession, async (req, res) => {
    const { orderDetails, customerInfo, items } = req.body;
    const user = (req as any).user;

    // Hardened check: Ensure User Table ID matches Session Table ID
    if (!user || user.tableId === undefined) {
        return res.status(401).json({ error: 'Invalid session context' });
    }

    // items might be passed directly or inside orderDetails
    const orderItems = items || (orderDetails ? orderDetails.items : []) || [];

    if (!orderItems || orderItems.length === 0) {
        return res.status(400).json({ error: 'Order must contain items' });
    }

    try {
        const restaurant = await prisma.restaurant.findUnique({
            where: { id: user.restaurantId }
        });

        const menuItems = await prisma.menuItem.findMany({
            where: { id: { in: orderItems.map((i: any) => i.id || i.menuItemId) } },
            include: { Category: true }
        });

        const taxItems = orderItems.map((item: any) => {
            const dbItem = menuItems.find(m => m.id === (item.id || item.menuItemId));
            return {
                price: dbItem?.price || item.price,
                quantity: item.quantity,
                taxSource: dbItem?.taxSource,
                gstRate: dbItem?.gstRate,
                categoryUseRestaurantGST: dbItem?.Category?.useRestaurantGST,
                categoryGstRate: dbItem?.Category?.gstRate
            };
        });

        const taxConfig = {
            gstEnabled: restaurant?.gstEnabled || false,
            gstMode: restaurant?.gstMode || 'EXCLUSIVE',
            defaultGstRate: restaurant?.defaultGstRate || 5.0
        };

        const { calculateOrderTaxes } = require('../utils/taxEngine');
        const taxResult = calculateOrderTaxes(taxItems, taxConfig);

        // Create the order
        const newOrder = await prisma.order.create({
            data: {
                id: randomUUID(),
                restaurantId: user.restaurantId,
                tableId: user.tableId,
                status: 'RECEIVED',
                subtotal: taxResult.subtotal,
                gstAmount: taxResult.gstAmount,
                grandTotal: taxResult.grandTotal,
                totalAmount: taxResult.grandTotal, // backward compatibility
                effectiveGstRate: taxResult.effectiveGstRate,
                gstMode: taxResult.gstMode,
                updatedAt: new Date(),
                // Create related OrderItems
                OrderItem: {
                    create: orderItems.map((item: any) => ({
                        id: randomUUID(),
                        menuItemId: item.id || item.menuItemId,
                        quantity: item.quantity,
                        notes: item.notes
                    }))
                }
            },
            include: {
                // Include items and table for response/socket
                OrderItem: { include: { MenuItem: true } }, // PascalCase or match normalize
                Table: true
            }
        });

        // Emit socket event
        try {
            const roomName = `entity:${user.restaurantId}`;
            io.to(roomName).emit('new-order', normalize(newOrder));
            console.log(`[Socket.IO] Emitted new-order to room: ${roomName}`);
        } catch (socketErr) {
            console.error('Socket Emit Error:', socketErr);
        }

        res.json({ success: true, order: normalize(newOrder), message: 'Order placed successfully' });
    } catch (error) {
        console.error('Place Order Error:', error);
        res.status(500).json({ error: 'Failed to place order' });
    }
});

// 3.0 Get Customer Orders (History)
app.get('/api/customer/orders/history', validateTableSession, async (req, res) => {
    const user = (req as any).user;
    try {
        const orders = await prisma.order.findMany({
            where: {
                restaurantId: user.restaurantId,
                tableId: user.tableId,
                createdAt: { gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
            },
            include: {
                OrderItem: { include: { MenuItem: true } }, // Match schema relation casing (PascalCase in Prisma, normalize handles it)
                Table: true
            },
            orderBy: { createdAt: 'desc' }
        });
        res.json({ success: true, orders: normalize(orders) });
    } catch (error) {
        console.error('Fetch History Error:', error);
        res.status(500).json({ error: 'Failed to fetch history' });
    }
});

// 3.1 Add Items to Existing Order (Protected)
app.post('/api/customer/orders/:orderId/add-items', validateTableSession, async (req, res) => {
    const { orderId } = req.params;
    const { items } = req.body; // Array of { menuItemId, quantity, notes, price }
    const user = (req as any).user;

    if (!items || !Array.isArray(items) || items.length === 0) {
        return res.status(400).json({ error: 'No items provided' });
    }

    try {
        // 1. Verify order belongs to this session/table
        const existingOrder = await prisma.order.findUnique({
            where: { id: orderId }
        });

        if (!existingOrder) {
            return res.status(404).json({ error: 'Order not found' });
        }

        if (existingOrder.tableId !== user.tableId) {
            return res.status(403).json({ error: 'Order does not belong to this table' });
        }

        if (existingOrder.restaurantId !== user.restaurantId) {
            return res.status(403).json({ error: 'Order does not belong to this restaurant' });
        }

        if (['COMPLETED', 'CANCELLED', 'SERVED'].includes(existingOrder.status)) {
            return res.status(400).json({ error: 'Cannot add items to a closed order' });
        }

        const restaurant = await prisma.restaurant.findUnique({
            where: { id: user.restaurantId }
        });

        // Fetch ALL items in the order including the new ones for accurate recalculation
        const currentOrderItems = await prisma.orderItem.findMany({
            where: { orderId }
        });

        // merge existing items and new items
        // Since we don't have dbItem details here, fetch all unique menuItemIds
        const allItemIds = [
            ...currentOrderItems.map(i => i.menuItemId),
            ...items.map((i: any) => i.id || i.menuItemId)
        ];

        const menuItems = await prisma.menuItem.findMany({
            where: { id: { in: Array.from(new Set(allItemIds)) } },
            include: { Category: true }
        });

        // Merge quantities for calculation
        const allItemsRaw = [
            ...currentOrderItems.map(i => ({ id: i.menuItemId, quantity: i.quantity, price: menuItems.find(m => m.id === i.menuItemId)?.price || 0 })),
            ...items.map((i: any) => ({ id: i.id || i.menuItemId, quantity: i.quantity, price: i.price }))
        ];

        const taxItems = allItemsRaw.map((item: any) => {
            const dbItem = menuItems.find(m => m.id === item.id);
            return {
                price: dbItem?.price || item.price,
                quantity: item.quantity,
                taxSource: dbItem?.taxSource,
                gstRate: dbItem?.gstRate,
                categoryUseRestaurantGST: dbItem?.Category?.useRestaurantGST,
                categoryGstRate: dbItem?.Category?.gstRate
            };
        });

        const taxConfig = {
            gstEnabled: restaurant?.gstEnabled || false,
            gstMode: restaurant?.gstMode || 'EXCLUSIVE',
            defaultGstRate: restaurant?.defaultGstRate || 5.0
        };

        const { calculateOrderTaxes } = require('../utils/taxEngine');
        const taxResult = calculateOrderTaxes(taxItems, taxConfig);

        const updatedOrder = await prisma.order.update({
            where: { id: orderId },
            data: {
                subtotal: taxResult.subtotal,
                gstAmount: taxResult.gstAmount,
                grandTotal: taxResult.grandTotal,
                totalAmount: taxResult.grandTotal,
                effectiveGstRate: taxResult.effectiveGstRate,
                gstMode: taxResult.gstMode,
                updatedAt: new Date(),
                OrderItem: {
                    create: items.map((item: any) => ({
                        id: randomUUID(),
                        menuItemId: item.id || item.menuItemId,
                        quantity: item.quantity,
                        notes: item.notes
                    }))
                },
                status: 'RECEIVED'
            },
            include: {
                OrderItem: { include: { MenuItem: true } },
                Table: true
            }
        });

        // Emit updated order event
        try {
            const roomName = `entity:${user.restaurantId}`;
            io.to(roomName).emit('order-updated', normalize(updatedOrder)); // or 'new-order' if kitchen treats it as such?
            // Usually 'new-order' triggers sound. 'order-updated' might update UI.
            // If items added, kitchen needs to know. Sending 'new-order' might duplicate the order card?
            // Standard practice: 'order-updated'.
            io.to(roomName).emit('new-order', normalize(updatedOrder)); // Emit as new-order too to ensure visibility/sound?
            // Actually, if we emit 'new-order' with same ID, React key might conflict or update.
            // Let's stick to 'order-updated' if supported, else 'new-order'.
            // Given the user context "Fixing Kitchen Sound", 'new-order' triggers sound.
            // So adding items should trigger sound.
        } catch (socketErr) {
            console.error('Socket Emit Error:', socketErr);
        }

        res.json({ success: true, order: normalize(updatedOrder), message: 'Items added successfully' });

    } catch (error) {
        console.error('Add Items Error:', error);
        res.status(500).json({ error: 'Failed to add items' });
    }
});

// --- Module: Secure Kitchen PIN Update ---
app.post('/api/security/update-kitchen-pin', authenticate, authorize(['ADMIN']), async (req, res) => {
    const { adminPin, newKitchenPin } = req.body;
    const { restaurantId, deviceId } = (req as any).user;
    const userIdentifier = restaurantId;

    if (!adminPin || !newKitchenPin || newKitchenPin.length < 4) {
        return res.status(400).json({ error: 'Invalid request data' });
    }

    // 1. Check Rate Limit
    const { locked, waitTime } = checkRateLimit(userIdentifier);
    if (locked) {
        return res.status(429).json({
            error: `Too many failed attempts. Try again in ${waitTime} minutes.`
        });
    }

    try {
        const restaurant = await prisma.restaurant.findUnique({ where: { id: restaurantId } });
        if (!restaurant || !restaurant.adminPin) {
            return res.status(400).json({ error: 'Restaurant not found' });
        }

        // 2. Verify Admin PIN (Double Check)
        const isValid = await bcrypt.compare(adminPin, restaurant.adminPin);
        if (!isValid) {
            registerFailure(userIdentifier);

            // Log Failure
            await prisma.auditLog.create({
                data: {
                    action: 'KITCHEN_PIN_RESET_FAILED',
                    user: deviceId || 'admin',
                    target: 'kitchen',
                    details: JSON.stringify({ reason: 'Invalid Admin PIN' })
                }
            });

            return res.status(401).json({ error: 'Invalid Admin PIN' });
        }

        if (isWeakPin(newKitchenPin)) {
            return res.status(400).json({ error: 'PIN is too weak. Avoid simple sequential or repeating patterns.' });
        }

        // Sync with cloud API
        const CLOUD_API_URL = process.env.CLOUD_API_URL || 'https://software.dinestack.in/api';
        try {
            console.log(`[Desktop][update-kitchen-pin] Syncing kitchen PIN update with cloud: ${CLOUD_API_URL}/security/update-kitchen-pin`);
            const cloudResponse = await fetch(`${CLOUD_API_URL}/security/update-kitchen-pin`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': req.headers.authorization || ''
                },
                body: JSON.stringify({ adminPin, newKitchenPin })
            });

            if (!cloudResponse.ok) {
                const cloudData = await cloudResponse.json() as any;
                console.warn('[Desktop][update-kitchen-pin] Cloud kitchen PIN update rejected. Proceeding locally.', cloudData);
            } else {
                console.log('[Desktop][update-kitchen-pin] Cloud kitchen PIN updated successfully via HTTP API');
            }
        } catch (cloudErr: any) {
            console.warn('[Desktop][update-kitchen-pin] Failed to connect to cloud backend for kitchen PIN update. Proceeding locally...', cloudErr.message || cloudErr);
        }

        // 3. Update Kitchen PIN
        const kitchenPinHash = await bcrypt.hash(newKitchenPin, 12);
        await prisma.restaurant.update({
            where: { id: restaurantId },
            data: { kitchenPin: kitchenPinHash }
        });

        registerSuccess(userIdentifier);

        // 4. Audit Log Success
        await prisma.auditLog.create({
            data: {
                action: 'KITCHEN_PIN_RESET',
                user: deviceId || 'admin',
                target: 'kitchen',
                details: JSON.stringify({ success: true, timestamp: new Date() })
            }
        });

        res.json({ success: true, message: 'Kitchen PIN updated successfully' });

    } catch (error) {
        console.error('Secure Update Kitchen PIN Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});
// --- Module: Secure Admin PIN Update ---
app.post('/api/security/update-admin-pin', authenticate, authorize(['ADMIN']), async (req, res) => {
    const { currentAdminPin, newAdminPin } = req.body;
    const { restaurantId, deviceId } = (req as any).user;
    const userIdentifier = restaurantId;

    if (!currentAdminPin || !newAdminPin || newAdminPin.length < 4) {
        return res.status(400).json({ error: 'Invalid request data' });
    }

    const { locked, waitTime } = checkRateLimit(userIdentifier);
    if (locked) {
        return res.status(429).json({
            error: `Too many failed attempts. Try again in ${waitTime} minutes.`
        });
    }

    try {
        const restaurant = await prisma.restaurant.findUnique({ where: { id: restaurantId } });
        if (!restaurant || !restaurant.adminPin) {
            return res.status(400).json({ error: 'Restaurant not found' });
        }

        const isValid = await bcrypt.compare(currentAdminPin, restaurant.adminPin);
        if (!isValid) {
            registerFailure(userIdentifier);

            await prisma.auditLog.create({
                data: {
                    action: 'ADMIN_PIN_RESET_FAILED',
                    user: deviceId || 'admin',
                    target: 'admin',
                    details: JSON.stringify({ reason: 'Invalid current Admin PIN' })
                }
            });

            return res.status(401).json({ error: 'Invalid current Admin PIN' });
        }

        if (isWeakPin(newAdminPin)) {
            return res.status(400).json({ error: 'PIN is too weak. Avoid simple sequential or repeating patterns.' });
        }

        // Sync with cloud API
        const CLOUD_API_URL = process.env.CLOUD_API_URL || 'https://software.dinestack.in/api';
        try {
            console.log(`[Desktop][update-admin-pin] Syncing admin PIN update with cloud: ${CLOUD_API_URL}/security/update-admin-pin`);
            const cloudResponse = await fetch(`${CLOUD_API_URL}/security/update-admin-pin`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': req.headers.authorization || ''
                },
                body: JSON.stringify({ currentAdminPin, newAdminPin })
            });

            if (!cloudResponse.ok) {
                const cloudData = await cloudResponse.json() as any;
                console.warn('[Desktop][update-admin-pin] Cloud admin PIN update rejected. Proceeding locally.', cloudData);
            } else {
                console.log('[Desktop][update-admin-pin] Cloud admin PIN updated successfully via HTTP API');
            }
        } catch (cloudErr: any) {
            console.warn('[Desktop][update-admin-pin] Failed to connect to cloud backend for admin PIN update. Proceeding locally...', cloudErr.message || cloudErr);
        }

        const adminPinHash = await bcrypt.hash(newAdminPin, 12);
        await prisma.restaurant.update({
            where: { id: restaurantId },
            data: { adminPin: adminPinHash }
        });

        registerSuccess(userIdentifier);

        await prisma.auditLog.create({
            data: {
                action: 'ADMIN_PIN_RESET',
                user: deviceId || 'admin',
                target: 'admin',
                details: JSON.stringify({ success: true, timestamp: new Date() })
            }
        });

        res.json({ success: true, message: 'Admin PIN updated successfully' });

    } catch (error) {
        console.error('Secure Update Admin PIN Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// --- Module: PIN Audit Logs ---
app.get('/api/security/pin-audit-logs', authenticate, authorize(['ADMIN']), async (req, res) => {
    try {
        const logs = await prisma.auditLog.findMany({
            where: {
                action: {
                    in: ['KITCHEN_PIN_RESET', 'KITCHEN_PIN_RESET_FAILED', 'ADMIN_PIN_RESET', 'ADMIN_PIN_RESET_FAILED']
                }
            },
            orderBy: { timestamp: 'desc' },
            take: 50
        });
        res.json({ success: true, logs });
    } catch (error) {
        console.error('Fetch PIN Audit Logs Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// --- Module: Admin PIN Recovery System ---

// POST /api/recovery/verify-code (Disaster Recovery Step 1)
app.post('/api/recovery/verify-code', async (req, res) => {
    const { recoveryCode } = req.body;
    if (!recoveryCode) return res.status(400).json({ error: 'Recovery code is required' });

    // Cloud Prisma check removed to allow local recovery if cloud is down

    try {
        let unusedCodes = await prisma.recoveryCode.findMany({ where: { used: false } });

        if (cloudPrisma) {
            try {
                const cloudCodes = await cloudPrisma.recoveryCode.findMany({ where: { used: false } });
                // Only add cloud codes that aren't already in the local array (by codeHash)
                for (const cc of cloudCodes) {
                    if (!unusedCodes.some(uc => uc.codeHash === cc.codeHash)) {
                        unusedCodes.push(cc as any);
                    }
                }
            } catch (e) {
                console.warn('[Recovery] Could not fetch cloud codes:', e);
            }
        }

        let matchedCode: any = null;
        for (const code of unusedCodes) {
            const isMatch = await bcrypt.compare(recoveryCode.toUpperCase().trim(), code.codeHash);
            if (isMatch) {
                matchedCode = code;
                break;
            }
        }

        if (!matchedCode) {
            return res.status(401).json({ error: 'Invalid or used recovery code' });
        }

        return res.json({ success: true, message: 'Code valid', restaurantId: matchedCode.restaurantId });
    } catch (e: any) {
        console.error('Verify code error:', e);
        return res.status(500).json({ error: 'Internal server error' });
    }
});

// POST /api/recovery/execute (Disaster Recovery Step 2)
app.post('/api/recovery/execute', async (req, res) => {
    const { token, recoveryCode } = req.body;
    if (!token || !recoveryCode) return res.status(400).json({ error: 'Token and recovery code required' });

    if (!cloudPrisma) {
        return res.status(500).json({ error: 'Cloud database not connected' });
    }

    try {
        // 1. Verify Google token via Cloud API
        const verifyRes = await fetch(`${CLOUD_AUTH_API_BASE}/auth/verify-desktop-token`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token }),
            timeout: 10000
        });

        if (!verifyRes.ok) {
            return res.status(401).json({ error: 'Invalid Google authentication' });
        }
        const authData = (await verifyRes.json()) as any;
        if (!authData.success || !authData.session || !authData.session.email) {
            return res.status(401).json({ error: 'Failed to verify Google identity' });
        }

        const jwt = require('jsonwebtoken');
        const decoded = jwt.decode(token) as any;
        const ownerId = decoded?.sub;
        if (!ownerId) {
            return res.status(401).json({ error: 'Google authentication missing user ID' });
        }

        // 2. Verify Recovery Code again
        let unusedCodes = await prisma.recoveryCode.findMany({ where: { used: false } });
        if (cloudPrisma) {
            try {
                const cloudCodes = await cloudPrisma.recoveryCode.findMany({ where: { used: false } });
                for (const cc of cloudCodes) {
                    if (!unusedCodes.some(uc => uc.codeHash === cc.codeHash)) {
                        unusedCodes.push(cc as any);
                    }
                }
            } catch (e) { }
        }

        let matchedCode: any = null;
        for (const code of unusedCodes) {
            const isMatch = await bcrypt.compare(recoveryCode.toUpperCase().trim(), code.codeHash);
            if (isMatch) {
                matchedCode = code;
                break;
            }
        }

        if (!matchedCode) {
            return res.status(401).json({ error: 'Recovery code invalid or already used' });
        }

        // 3. Verify Ownership
        const cloudRestaurant = await cloudPrisma.restaurant.findUnique({
            where: { id: matchedCode.restaurantId },
            include: { ActivationCode: true, Category: true, MenuItem: true, Table: true }
        });

        if (!cloudRestaurant) {
            return res.status(400).json({ error: 'Restaurant data not found in cloud' });
        }

        if (cloudRestaurant.ownerId !== ownerId) {
            return res.status(403).json({ error: 'Unauthorized: Google account does not own this restaurant' });
        }

        // 4. Backup local DB if it exists
        const fs = require('fs');
        const path = require('path');
        const dbPath = path.join(process.cwd(), 'prisma', 'dev.db');
        const backupPath = path.join(process.cwd(), 'prisma', `dev_backup_${Date.now()}.db`);
        if (fs.existsSync(dbPath)) {
            fs.copyFileSync(dbPath, backupPath);
            console.log(`[RECOVERY] Local DB backed up to ${backupPath}`);
        }

        // 5. Purge and Rebuild local SQLite database safely
        try {
            await prisma.$transaction([
                prisma.orderItem.deleteMany(),
                prisma.order.deleteMany(),
                prisma.device.deleteMany(),
                prisma.pairCode.deleteMany(),
                prisma.menuItem.deleteMany(),
                prisma.category.deleteMany(),
                prisma.table.deleteMany(),
                prisma.recoveryCode.deleteMany(),
                prisma.restaurant.deleteMany(),
                prisma.activationCode.deleteMany()
            ]);

            if (cloudRestaurant.ActivationCode) {
                await prisma.activationCode.create({
                    data: {
                        id: cloudRestaurant.ActivationCode.id,
                        code: cloudRestaurant.ActivationCode.code,
                        status: cloudRestaurant.ActivationCode.status,
                        isUsed: cloudRestaurant.ActivationCode.isUsed,
                        usedAt: cloudRestaurant.ActivationCode.usedAt,
                        expiresAt: cloudRestaurant.ActivationCode.expiresAt,
                        durationDays: cloudRestaurant.ActivationCode.durationDays,
                        maxTables: cloudRestaurant.ActivationCode.maxTables,
                        plan: cloudRestaurant.ActivationCode.plan,
                    }
                });
            }

            await prisma.restaurant.create({
                data: {
                    id: cloudRestaurant.id,
                    name: cloudRestaurant.name,
                    status: cloudRestaurant.status,
                    isActive: cloudRestaurant.isActive,
                    adminPin: cloudRestaurant.adminPin,
                    kitchenPin: cloudRestaurant.kitchenPin,
                    activationCodeId: cloudRestaurant.activationCodeId,
                    createdAt: cloudRestaurant.createdAt
                }
            });

            if (cloudRestaurant.Category && cloudRestaurant.Category.length > 0) {
                await prisma.category.createMany({
                    data: cloudRestaurant.Category.map((c: any) => ({
                        id: c.id,
                        name: c.name,
                        isActive: c.isActive,
                        code: c.code,
                        restaurantId: c.restaurantId,
                        createdAt: c.createdAt
                    }))
                });
            }

            if (cloudRestaurant.MenuItem && cloudRestaurant.MenuItem.length > 0) {
                await prisma.menuItem.createMany({
                    data: cloudRestaurant.MenuItem.map((m: any) => ({
                        id: m.id,
                        name: m.name,
                        description: m.description,
                        price: m.price,
                        image: m.image,
                        isActive: m.isActive,
                        categoryId: m.categoryId,
                        restaurantId: m.restaurantId,
                        createdAt: m.createdAt
                    }))
                });
            }

            if (cloudRestaurant.Table && cloudRestaurant.Table.length > 0) {
                await prisma.table.createMany({
                    data: cloudRestaurant.Table.map((t: any) => ({
                        id: t.id,
                        label: t.label,
                        capacity: t.capacity,
                        isActive: t.isActive,
                        restaurantId: t.restaurantId,
                        createdAt: t.createdAt
                    }))
                });
            }
        } catch (dbError) {
            console.error('[RECOVERY] DB restore failed, rolling back file...', dbError);
            if (fs.existsSync(backupPath)) {
                fs.copyFileSync(backupPath, dbPath);
            }
            throw new Error('Local database rebuild failed');
        }

        // 6. Mark Recovery Code as used in Cloud
        await cloudPrisma.recoveryCode.update({
            where: { id: matchedCode.id },
            data: { used: true }
        });

        // 7. Generate fresh Recovery Codes in Cloud (Rotation)
        const plaintextCodes: string[] = [];
        const codeData: { codeHash: string; restaurantId: string }[] = [];
        for (let i = 0; i < 10; i++) {
            let code = generateRecoveryCode();
            plaintextCodes.push(code);
            const hash = await bcrypt.hash(code, 12);
            codeData.push({ codeHash: hash, restaurantId: cloudRestaurant.id });
        }
        await cloudPrisma.recoveryCode.deleteMany({ where: { restaurantId: cloudRestaurant.id, used: false } });
        await cloudPrisma.recoveryCode.createMany({ data: codeData });

        // Ensure local recovery codes match
        await prisma.recoveryCode.createMany({ data: codeData });

        // 8. Generate a fresh device identity and session
        const deviceId = `DEV-${Math.random().toString(36).substr(2, 9).toUpperCase()}`;
        const newDevice = await prisma.device.create({
            data: {
                deviceId,
                role: 'ADMIN',
                status: 'ACTIVE',
                restaurantId: cloudRestaurant.id,
                lastUsed: new Date()
            }
        });

        await cloudPrisma.device.create({
            data: {
                id: newDevice.id,
                deviceId,
                role: 'ADMIN',
                status: 'ACTIVE',
                restaurantId: cloudRestaurant.id,
                lastUsed: new Date()
            }
        });

        const { avatarUrl, fullName, email, role } = authData.session;
        cloudSession = { avatarUrl, fullName, email, role };
        io.emit('cloud-session-updated', cloudSession);

        await prisma.auditLog.create({
            data: {
                action: 'DISASTER_RECOVERY_COMPLETED',
                user: ownerId,
                target: deviceId,
                details: JSON.stringify({ timestamp: new Date() })
            }
        });
        await cloudPrisma.auditLog.create({
            data: {
                action: 'DISASTER_RECOVERY_COMPLETED',
                actor: ownerId,
                target: deviceId,
                details: JSON.stringify({ timestamp: new Date() })
            }
        });

        return res.json({
            success: true,
            deviceId,
            session: cloudSession,
            accessToken: authData.accessToken,
            refreshToken: authData.refreshToken,
            newRecoveryCodes: plaintextCodes
        });

    } catch (e: any) {
        console.error('Execute recovery error:', e);
        return res.status(500).json({ error: e.message || 'Internal server error' });
    }
});
// Helper: Generate a single recovery code in DREC-XXXX-XXXX format
function generateRecoveryCode(): string {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    let part1 = '', part2 = '';
    for (let i = 0; i < 4; i++) {
        part1 += chars[Math.floor(Math.random() * chars.length)];
        part2 += chars[Math.floor(Math.random() * chars.length)];
    }
    return `DREC-${part1}-${part2}`;
}

// POST /api/recovery/generate — Generate 10 recovery codes (requires admin auth)
app.post('/api/recovery/generate', authenticate, authorize(['ADMIN']), async (req, res) => {
    console.log('[DEBUG] /api/recovery/generate headers:', req.headers);
    const { restaurantId } = (req as any).user;

    try {
        const restaurant = await prisma.restaurant.findUnique({ where: { id: restaurantId } });
        if (!restaurant) {
            return res.status(400).json({ error: 'Restaurant not found' });
        }

        const { force } = req.body;

        // Check if codes already exist and not all used
        const existingCodes = await prisma.recoveryCode.findMany({
            where: { restaurantId }
        });

        const unusedCount = existingCodes.filter(c => !c.used).length;
        if (!force && existingCodes.length > 0 && unusedCount > 0) {
            return res.status(400).json({
                error: 'Recovery codes already exist. All must be used before regeneration.',
                remainingCodes: unusedCount
            });
        }

        // Delete old codes if all used (allow regeneration)
        if (existingCodes.length > 0) {
            await prisma.recoveryCode.deleteMany({ where: { restaurantId } });
        }

        // Generate 10 unique codes
        const plaintextCodes: string[] = [];
        const codeData: { codeHash: string; restaurantId: string }[] = [];

        for (let i = 0; i < 10; i++) {
            let code: string;
            do {
                code = generateRecoveryCode();
            } while (plaintextCodes.includes(code)); // Ensure uniqueness

            plaintextCodes.push(code);
            const hash = await bcrypt.hash(code, 12);
            codeData.push({ codeHash: hash, restaurantId });
        }

        // Store hashed codes in database
        await prisma.recoveryCode.createMany({ data: codeData });

        // Backup to cloud database
        if (cloudPrisma) {
            try {
                await cloudPrisma.recoveryCode.deleteMany({ where: { restaurantId } });
                await cloudPrisma.recoveryCode.createMany({ data: codeData });
            } catch (cloudErr) {
                console.error('[Recovery] Failed to backup recovery codes to cloud:', cloudErr);
            }
        }

        // Audit log
        await prisma.auditLog.create({
            data: {
                action: 'RECOVERY_CODES_GENERATED',
                user: (req as any).user.deviceId || 'admin',
                target: 'recovery',
                details: JSON.stringify({ count: 10, timestamp: new Date() })
            }
        });

        // Return plaintext codes (this is the ONLY time they're visible)
        res.json({
            success: true,
            codes: plaintextCodes,
            message: 'Recovery codes generated. Download and store safely.'
        });

    } catch (error) {
        console.error('Recovery Code Generation Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// GET /api/recovery/status — Check remaining recovery codes count
app.get('/api/recovery/status', authenticate, authorize(['ADMIN']), async (req, res) => {
    const { restaurantId } = (req as any).user;

    try {
        const allCodes = await prisma.recoveryCode.findMany({
            where: { restaurantId }
        });

        const totalCodes = allCodes.length;
        const usedCodes = allCodes.filter(c => c.used).length;
        const remainingCodes = totalCodes - usedCodes;

        res.json({
            success: true,
            totalCodes,
            usedCodes,
            remainingCodes,
            warning: remainingCodes <= 2 && totalCodes > 0 ? 'Low recovery codes. Consider regenerating.' : null,
            canRegenerate: totalCodes === 0 || remainingCodes === 0
        });

    } catch (error) {
        console.error('Recovery Status Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// POST /api/recovery/verify — Verify a recovery code (UNAUTHENTICATED — user has forgotten PIN)
app.post('/api/recovery/verify', async (req, res) => {
    const { recoveryCode, restaurantId } = req.body;

    if (!recoveryCode || !restaurantId) {
        return res.status(400).json({ error: 'Recovery code and restaurant ID are required' });
    }

    const rateLimitKey = `recovery:${restaurantId}`;

    try {
        const restaurant = await prisma.restaurant.findUnique({ where: { id: restaurantId } });
        if (!restaurant) {
            return res.status(400).json({ error: 'Restaurant not found' });
        }

        // Check persistent lock (survives server restarts)
        if (restaurant.recoveryLockUntil && restaurant.recoveryLockUntil > new Date()) {
            const waitTime = Math.ceil((restaurant.recoveryLockUntil.getTime() - Date.now()) / 1000 / 60);
            return res.status(429).json({
                error: `Too many failed attempts. Try again in ${waitTime} minute(s).`,
                lockedUntil: restaurant.recoveryLockUntil
            });
        }

        // Also check in-memory rate limit
        const { locked, waitTime } = checkRateLimit(rateLimitKey);
        if (locked) {
            return res.status(429).json({
                error: `Too many failed attempts. Try again in ${waitTime} minute(s).`
            });
        }

        // Find all unused recovery codes for this restaurant
        const unusedCodes = await prisma.recoveryCode.findMany({
            where: { restaurantId, used: false }
        });

        if (unusedCodes.length === 0) {
            return res.status(400).json({ error: 'No recovery codes available. Please contact administrator.' });
        }

        // Compare against each stored hash
        let matchedCode: typeof unusedCodes[0] | null = null;
        for (const code of unusedCodes) {
            const isMatch = await bcrypt.compare(recoveryCode.toUpperCase().trim(), code.codeHash);
            if (isMatch) {
                matchedCode = code;
                break;
            }
        }

        if (!matchedCode) {
            // Register failure
            registerFailure(rateLimitKey);
            const record = FAILED_ATTEMPTS.get(rateLimitKey);

            // If 3+ failures, set persistent DB lock
            if (record && record.count >= 3) {
                const lockUntil = new Date(Date.now() + 5 * 60 * 1000);
                await prisma.restaurant.update({
                    where: { id: restaurantId },
                    data: { recoveryLockUntil: lockUntil }
                });

                await prisma.auditLog.create({
                    data: {
                        action: 'RECOVERY_BRUTE_FORCE_LOCK',
                        user: 'unknown',
                        target: 'recovery',
                        details: JSON.stringify({ restaurantId, lockUntil })
                    }
                });

                return res.status(429).json({
                    error: 'Too many failed attempts. Locked for 5 minutes.',
                    lockedUntil: lockUntil
                });
            }

            return res.status(401).json({ error: 'Invalid recovery code' });
        }

        // Valid code — mark as used
        await prisma.recoveryCode.update({
            where: { id: matchedCode.id },
            data: { used: true }
        });

        // Clear rate limit on success
        registerSuccess(rateLimitKey);
        if (restaurant.recoveryLockUntil) {
            await prisma.restaurant.update({
                where: { id: restaurantId },
                data: { recoveryLockUntil: null }
            });
        }

        // Generate a short-lived recovery token (5 minutes)
        const recoveryToken = generateToken({
            restaurantId,
            role: 'RECOVERY',
            deviceId: 'RECOVERY_SESSION',
            purpose: 'PIN_RESET'
        });

        // Audit log
        await prisma.auditLog.create({
            data: {
                action: 'RECOVERY_CODE_VERIFIED',
                user: 'recovery_user',
                target: 'recovery',
                details: JSON.stringify({ restaurantId, codeId: matchedCode.id })
            }
        });

        // Check remaining codes
        const remaining = unusedCodes.length - 1;

        res.json({
            success: true,
            recoveryToken,
            remainingCodes: remaining,
            warning: remaining <= 2 ? 'Low recovery codes remaining. Regenerate after login.' : null
        });

    } catch (error) {
        console.error('Recovery Verify Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// POST /api/recovery/reset-pin — Reset admin PIN using recovery token
app.post('/api/recovery/reset-pin', async (req, res) => {
    const { recoveryToken, newPin } = req.body;

    if (!recoveryToken || !newPin || newPin.length < 6) {
        return res.status(400).json({ error: 'Recovery token and a 6-digit PIN are required' });
    }

    try {
        // Verify recovery token
        const decoded = verifyToken(recoveryToken);
        if (!decoded || decoded.purpose !== 'PIN_RESET' || decoded.role !== 'RECOVERY') {
            return res.status(401).json({ error: 'Invalid or expired recovery session' });
        }

        const { restaurantId } = decoded;

        const restaurant = await prisma.restaurant.findUnique({ where: { id: restaurantId } });
        if (!restaurant) {
            return res.status(400).json({ error: 'Restaurant not found' });
        }

        // Hash the new PIN and update
        const newPinHash = await bcrypt.hash(newPin, 10);
        await prisma.restaurant.update({
            where: { id: restaurantId },
            data: { adminPin: newPinHash }
        });

        // Audit log
        await prisma.auditLog.create({
            data: {
                action: 'ADMIN_PIN_RESET_VIA_RECOVERY',
                user: 'recovery_user',
                target: 'admin_pin',
                details: JSON.stringify({ restaurantId, timestamp: new Date() })
            }
        });

        res.json({ success: true, message: 'Admin PIN reset successfully' });

    } catch (error) {
        console.error('Recovery Reset PIN Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// --- Module: Kitchen Pair Code Generation ---
app.post('/api/pair/generate', authenticate, authorize(['ADMIN']), async (req, res) => {
    const { restaurantId } = (req as any).user;

    try {
        const restaurant = await prisma.restaurant.findUnique({ where: { id: restaurantId } });
        if (!restaurant) {
            return res.status(400).json({ error: 'Restaurant not found' });
        }

        // Enforce: Kitchen PIN must be set before generating pair code
        if (!restaurant.kitchenPin) {
            return res.status(400).json({ error: 'Kitchen PIN must be configured before generating a pair code' });
        }

        // CLOUD IS REQUIRED — no silent fallback for pairing
        if (!cloudPrisma) {
            return res.status(503).json({ error: 'Cloud connection unavailable. Pair codes require cloud connectivity.' });
        }

        // Generate on cloud (Neon) via direct DB access - Single Source of Truth
        await cloudPrisma.pairCode.updateMany({
            where: { restaurantId, pairCodeActive: true },
            data: { pairCodeActive: false }
        });

        const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // Excluding ambiguous: 0,O,1,I
        let randomPart = '';
        for (let i = 0; i < 4; i++) {
            randomPart += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        const pairCode = `DINE-${randomPart}`;
        const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

        const created = await cloudPrisma.pairCode.create({
            data: {
                code: pairCode,
                restaurantId,
                pairCodeActive: true,
                pairCodeUsed: false,
                kitchenOnline: false,
                expiresAt
            }
        });

        console.log(`[Pair] Generated pair code on cloud: ${pairCode} for restaurant ${restaurantId}`);

        // Cache in local SQLite for status polling (best-effort, non-blocking)
        try {
            await prisma.pairCode.updateMany({
                where: { restaurantId, pairCodeActive: true },
                data: { pairCodeActive: false }
            });
            await prisma.pairCode.create({
                data: {
                    code: pairCode,
                    restaurantId,
                    pairCodeActive: true,
                    pairCodeUsed: false,
                    kitchenOnline: false,
                    expiresAt
                }
            });
            console.log(`[Pair] Cached pair code locally.`);
        } catch (localErr) {
            console.warn('[Pair] Failed to cache pair code locally (non-critical):', localErr);
        }

        res.json({
            success: true,
            pairCode: created.code,
            expiresAt: created.expiresAt
        });

    } catch (error) {
        console.error('Pair Code Generation Error:', error);
        res.status(500).json({ error: 'Failed to generate pair code' });
    }
});

// --- Module: Kitchen Pair Code Status (Polling) ---
app.get('/api/pair/status', async (req, res) => {
    const { restaurantId } = req.query;

    if (!restaurantId || typeof restaurantId !== 'string') {
        return res.status(400).json({ error: 'restaurantId query parameter is required' });
    }

    try {
        let pairCode: any = null;

        // Try cloud first (Single Source of Truth)
        if (cloudPrisma) {
            try {
                pairCode = await cloudPrisma.pairCode.findFirst({
                    where: { restaurantId },
                    orderBy: { createdAt: 'desc' }
                });
            } catch (cloudErr) {
                console.warn('[Pair] Failed to read status from cloud, falling back to local:', cloudErr);
            }
        }

        // Fallback to local SQLite if cloud is unavailable or failed
        if (!pairCode) {
            pairCode = await prisma.pairCode.findFirst({
                where: { restaurantId },
                orderBy: { createdAt: 'desc' }
            });
        }

        if (!pairCode) {
            return res.json({ kitchenOnline: false, message: 'No pair code found' });
        }

        // Check if expired
        if (pairCode.expiresAt < new Date() && !pairCode.pairCodeUsed) {
            return res.json({ kitchenOnline: false, expired: true, message: 'Pair code expired' });
        }

        res.json({
            kitchenOnline: pairCode.kitchenOnline,
            pairCodeActive: pairCode.pairCodeActive,
            pairCodeUsed: pairCode.pairCodeUsed
        });

    } catch (error) {
        console.error('Pair Status Check Error:', error);
        res.status(500).json({ error: 'Failed to check pair status' });
    }
});

// --- Module: Kitchen Pair Code Verification (Kitchen Side) ---
app.post('/api/pair/verify', async (req, res) => {
    const { pairCode, deviceId } = req.body;

    console.log('[API] POST /api/pair/verify:', { pairCode, deviceId });

    if (!pairCode || !deviceId) {
        console.warn('[API] POST /api/pair/verify - Missing body parameters');
        return res.status(400).json({ error: 'pairCode and deviceId are required' });
    }

    if (!cloudPrisma) {
        return res.status(503).json({ error: 'Cloud connection unavailable. Pair verification requires cloud connectivity.' });
    }

    try {
        const normalizedCode = pairCode.trim().toUpperCase();

        // Single Source of Truth: Verify against Cloud (Neon)
        const codeRecord = await cloudPrisma.pairCode.findUnique({
            where: { code: normalizedCode }
        });

        if (!codeRecord) {
            console.log(`[DIAGNOSTIC] Cloud pair verification failed: Code not found: '${normalizedCode}'`);
            return res.status(400).json({ error: 'INVALID_PAIR_CODE' });
        }

        if (codeRecord.lockedUntil && codeRecord.lockedUntil > new Date()) {
            const waitTime = Math.ceil((codeRecord.lockedUntil.getTime() - Date.now()) / 1000 / 60);
            return res.status(429).json({
                error: `Too many failed attempts. Try again in ${waitTime} minutes.`
            });
        }

        if (!codeRecord.pairCodeActive) {
            console.log(`[DIAGNOSTIC] Cloud pair verification failed: Code inactive: ${normalizedCode}`);
            return res.status(400).json({ error: 'PAIR_CODE_INACTIVE' });
        }

        if (codeRecord.pairCodeUsed) {
            console.log(`[DIAGNOSTIC] Cloud pair verification failed: Code already used: ${normalizedCode}`);
            return res.status(400).json({ error: 'PAIR_CODE_ALREADY_USED' });
        }

        if (codeRecord.expiresAt < new Date()) {
            console.log(`[DIAGNOSTIC] Cloud pair verification failed: Code expired: ${normalizedCode}`);
            return res.status(400).json({ error: 'PAIR_CODE_EXPIRED' });
        }

        const role = 'KITCHEN';
        const restaurantId = codeRecord.restaurantId;

        // 1. Mark as used on cloud (Neon) — Single Source of Truth
        await cloudPrisma.pairCode.update({
            where: { id: codeRecord.id },
            data: {
                pairCodeUsed: true,
                pairCodeActive: false,
                kitchenOnline: true
            }
        });

        // 2. Register device on cloud
        try {
            const existingCloudDevice = await cloudPrisma.device.findFirst({
                where: { deviceId }
            });
            if (existingCloudDevice) {
                await cloudPrisma.device.update({
                    where: { id: existingCloudDevice.id },
                    data: { role, restaurantId, status: 'ACTIVE', lastUsed: new Date() }
                });
            } else {
                await cloudPrisma.device.create({
                    data: { id: randomUUID(), deviceId, role, restaurantId, status: 'ACTIVE' }
                });
            }
        } catch (e) {
            console.error('[Pair] Cloud device save failed:', e);
        }

        // 3. Sync to local SQLite (best-effort)
        try {
            await prisma.restaurant.upsert({
                where: { id: restaurantId },
                update: {},
                create: { id: restaurantId, name: 'Cloud Synced Restaurant' }
            });

            const existingDevice = await prisma.device.findFirst({
                where: { deviceId }
            });
            if (existingDevice) {
                await prisma.device.update({
                    where: { id: existingDevice.id },
                    data: { role, restaurantId, status: 'ACTIVE', lastUsed: new Date() }
                });
            } else {
                await prisma.device.create({
                    data: { id: randomUUID(), deviceId, role, restaurantId, status: 'ACTIVE', lastUsed: new Date() }
                });
            }

            await prisma.kitchenDeviceLink.upsert({
                where: { kitchenDeviceId: deviceId },
                update: {
                    restaurantId,
                    cloudRestaurantId: restaurantId,
                    lastVerifiedAt: new Date(),
                    lastSuccessfulVerification: new Date(),
                    status: 'LINKED'
                },
                create: {
                    kitchenDeviceId: deviceId,
                    restaurantId,
                    cloudRestaurantId: restaurantId,
                    linkedAt: new Date(),
                    lastVerifiedAt: new Date(),
                    lastSuccessfulVerification: new Date(),
                    status: 'LINKED'
                }
            });

            await prisma.pairCode.delete({
                where: { code: normalizedCode }
            }).catch(() => { }); // ignore if it doesn't exist locally
        } catch (localErr) {
            console.warn('[Pair] Local SQLite sync failed (non-critical):', localErr);
        }

        // Emit socket event to the Admin dashboard
        io.to(`entity:${restaurantId}`).emit('kitchen-linked', { deviceId });

        // Generate JWT locally for the session
        const { accessToken } = await setAuthSession(req, res, { deviceId, role, restaurantId });

        console.log(`[Pair] Kitchen linked successfully via cloud. Device: ${deviceId}, Restaurant: ${restaurantId}`);

        return res.json({
            success: true,
            token: accessToken,
            role,
            restaurantId
        });

    } catch (error) {
        // Increment failed attempts on cloud record
        try {
            const record = await cloudPrisma.pairCode.findUnique({
                where: { code: pairCode.toUpperCase() }
            });
            if (record) {
                const newCount = record.failedAttempts + 1;
                const lockUntil = newCount >= 5 ? new Date(Date.now() + 5 * 60 * 1000) : null;
                await cloudPrisma.pairCode.update({
                    where: { id: record.id },
                    data: {
                        failedAttempts: newCount,
                        lockedUntil: lockUntil
                    }
                });
            }
        } catch (e) {
            // Ignore rate limit update errors
        }
        console.error('Cloud Pair Verify Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// --- Module: Revoke Activation (Destructive) ---
app.post('/api/security/revoke-activation', async (req, res) => {
    const { adminPin } = req.body;
    let userIdentifier = 'unknown';
    let restaurantId: string | undefined;
    let deviceId: string | undefined;

    // Try to get user from auth header if present
    if (req.headers.authorization) {
        try {
            const token = req.headers.authorization.split(' ')[1];
            const decoded = verifyToken(token);
            if (decoded) {
                restaurantId = decoded.restaurantId;
                deviceId = decoded.deviceId;
                userIdentifier = restaurantId || 'unknown';
            }
        } catch (e) {
            // Ignore token errors, perform anonymous lookup if needed (though tricky without ID)
        }
    }

    if (!adminPin) {
        return res.status(400).json({ error: 'Admin PIN is required' });
    }

    try {
        let restaurant;

        if (restaurantId) {
            restaurant = await prisma.restaurant.findUnique({ where: { id: restaurantId } });
        }

        // Fallback: If no token or restaurant not found, find the ACTIVE restaurant
        // This allows revocation even if session is expired or invalid
        if (!restaurant) {
            restaurant = await prisma.restaurant.findFirst({
                where: { status: { in: ['ACTIVE', 'GRACE'] } },
                orderBy: { createdAt: 'desc' }
            });
        }

        if (!restaurant) {
            return res.status(400).json({ error: 'No active system found to revoke' });
        }

        userIdentifier = restaurant.id;

        // 1. Check Rate Limit
        const { locked, waitTime } = checkRateLimit(userIdentifier);
        if (locked) {
            return res.status(429).json({
                error: `Too many failed attempts. Try again in ${waitTime} minutes.`
            });
        }

        // 2. Verify Admin PIN
        const isValid = await bcrypt.compare(adminPin, restaurant.adminPin || '');

        if (!isValid) {
            registerFailure(userIdentifier);
            await prisma.auditLog.create({
                data: {
                    action: 'REVOKE_ACTIVATION_FAILED',
                    user: deviceId || 'admin_no_auth',
                    target: 'system',
                    details: JSON.stringify({ reason: 'Invalid Admin PIN' })
                }
            });
            return res.status(401).json({ error: 'Invalid Admin PIN' });
        }

        registerSuccess(userIdentifier);
        console.log(`⚠️ REVOKING ACTIVATION for Restaurant: ${restaurant.id} (${restaurant.name})`);

        // 3. Perform Cascading Deletion / Reset
        console.log('Revoking: Deleting OrderItems...');
        await prisma.orderItem.deleteMany({});
        console.log('Revoking: Deleting Orders...');
        await prisma.order.deleteMany({});
        console.log('Revoking: Deleting MenuItems...');
        await prisma.menuItem.deleteMany({});
        console.log('Revoking: Deleting Categories...');
        await prisma.category.deleteMany({});
        console.log('Revoking: Deleting Sessions...');
        await prisma.session.deleteMany({});
        console.log('Revoking: Deleting Tables...');
        await prisma.table.deleteMany({});
        console.log('Revoking: Deleting Devices...');
        await prisma.device.deleteMany({});

        // 2. Revoke ALL Restaurant records to ensure no 'Ghost' active records remain
        console.log('Revoking: Updating Restaurant Status...');
        await prisma.restaurant.updateMany({
            data: {
                status: 'REVOKED',
                adminPin: null, // Clear PIN
                kitchenPin: null,
                isActive: false
            }
        });

        await prisma.auditLog.create({
            data: {
                action: 'REVOKE_ACTIVATION_SUCCESS_GLOBAL',
                user: deviceId || 'admin',
                target: 'system',
                details: JSON.stringify({ timestamp: new Date(), note: 'Global Reset (Sequential)' })
            }
        });

        console.log(` Activation Revoked Successfully`);
        res.json({ success: true, message: 'Activation revoked and data cleared.' });

    } catch (error) {
        console.error('Revoke Activation Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// --- Module 10: Update Order Status (Kitchen) ---
const VALID_TRANSITIONS: Record<string, string[]> = {
    'RECEIVED': ['PREPARING', 'CANCELLED'],
    'PREPARING': ['READY', 'CANCELLED'],
    'READY': ['SERVED', 'CANCELLED'],
    'SERVED': ['COMPLETED', 'CANCELLED'],
    'CANCELLED': []
};

app.patch('/api/orders/:id/status', authenticate, authorize(['KITCHEN', 'ADMIN']), async (req, res) => {
    const { id } = req.params;
    const { status } = req.body;

    try {
        const order = await prisma.order.findUnique({ where: { id } });
        if (!order) {
            return res.status(404).json({ error: 'Order not found' });
        }

        const allowedNextStatuses = VALID_TRANSITIONS[order.status] || [];
        if (!allowedNextStatuses.includes(status)) {
            return res.status(400).json({
                error: `Invalid transition from ${order.status} to ${status}. Allowed: ${allowedNextStatuses.join(', ')}`
            });
        }

        const updatedOrder = await prisma.order.update({
            where: { id },
            data: { status, synced: false, updatedAt: new Date() }
        });

        // --- Socket.IO: Emit order-status-changed event ---
        try {
            const fullUpdatedOrder = await prisma.order.findUnique({
                where: { id: updatedOrder.id },
                include: { OrderItem: { include: { MenuItem: true } }, Table: true }
            });
            io.to(`entity:${updatedOrder.restaurantId}`).emit('order-status-changed', normalize(fullUpdatedOrder));
            console.log(`[Socket.IO] Emitted order-status-changed to entity:${updatedOrder.restaurantId}`);
        } catch (socketErr) {
            console.error('[Socket.IO] Failed to emit order-status-changed:', socketErr);
        }

        res.json({ success: true, order: updatedOrder });
    } catch (error) {
        console.error('Update Order Status Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// --- Module 11: Menu Management (Admin) ---
app.get('/api/menu', async (req, res) => {
    try {
        const restaurant = await prisma.restaurant.findFirst({
            where: { status: { in: ['ACTIVE', 'GRACE'] } },
            orderBy: { createdAt: 'desc' }
        });

        if (!restaurant) {
            return res.json({ success: true, categories: [] });
        }

        const categories = await prisma.category.findMany({
            where: { isActive: true, restaurantId: restaurant.id },
            include: {
                MenuItem: {
                    where: { isActive: true },
                    orderBy: { createdAt: 'asc' }
                }
            },
            orderBy: { createdAt: 'asc' }
        });
        res.json({ success: true, categories: normalize(categories) });
    } catch (error) {
        console.error('Get Menu Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Admin Menu Fetch (Includes inactive/off items)
app.get('/api/admin/menu', authenticate, authorize(['ADMIN', 'KITCHEN']), async (req, res) => {
    try {
        const { restaurantId } = (req as any).user;
        const categories = await prisma.category.findMany({
            where: { isActive: true, restaurantId },
            orderBy: { createdAt: 'asc' },
            include: {
                MenuItem: {
                    // Show ALL items, even inactive ones so they can be managed/toggled back on
                    orderBy: { createdAt: 'asc' }
                }
            }
        });
        res.json({ success: true, categories: normalize(categories) });
    } catch (error) {
        console.error('Get Admin Menu Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.delete('/api/categories/:id', authenticate, authorize(['ADMIN']), async (req, res) => {
    const { id } = req.params;
    try {
        // Check for items in this category
        const itemCount = await prisma.menuItem.count({
            where: { categoryId: id, isActive: true }
        });

        if (itemCount > 0) {
            // Soft delete if items exist
            await prisma.category.update({
                where: { id },
                data: { isActive: false }
            });
            return res.json({ success: true, message: 'Category archived (contained items)' });
        }

        // Hard delete if empty
        await prisma.category.delete({
            where: { id }
        });
        res.json({ success: true });
    } catch (error) {
        console.error('Delete Category Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Update Category
app.put('/api/categories/:id', authenticate, authorize(['ADMIN']), async (req, res) => {
    const { id } = req.params;
    const { name, code, useRestaurantGST, gstRate } = req.body;

    if (!name) {
        return res.status(400).json({ error: 'Category name is required' });
    }

    try {
        const updated = await prisma.category.update({
            where: { id },
            data: {
                name,
                code,
                useRestaurantGST: useRestaurantGST !== undefined ? useRestaurantGST : undefined,
                gstRate: gstRate !== undefined ? gstRate : undefined
            }
        });
        res.json({ success: true, category: updated });
    } catch (error) {
        console.error('Update Category Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Create Category
app.post('/api/categories', authenticate, authorize(['ADMIN']), async (req, res) => {
    const { name, code, useRestaurantGST, gstRate } = req.body;
    const { restaurantId } = (req as any).user;

    try {
        const fs = require('fs');
        const path = require('path');
        const logPath = path.join(__dirname, 'debug_output.log');
        fs.writeFileSync(logPath, JSON.stringify({
            time: new Date().toISOString(),
            status: 'HIT',
            body: req.body,
            user: (req as any).user
        }, null, 2));
    } catch (e) { }

    if (!name) {
        return res.status(400).json({ error: 'Category name is required' });
    }

    try {
        const category = await prisma.category.create({
            data: {
                id: randomUUID(),
                name,
                code: code || name.substring(0, 3).toUpperCase(),
                useRestaurantGST: useRestaurantGST !== undefined ? useRestaurantGST : true,
                gstRate: gstRate || null,
                restaurantId
            }
        });
        res.json({ success: true, category });
    } catch (error: any) {
        console.error('Create Category Error:', error);
        try {
            const fs = require('fs');
            const path = require('path');
            const logPath = path.join(__dirname, 'debug_output.log');
            fs.writeFileSync(logPath, JSON.stringify({
                time: new Date().toISOString(),
                error: error?.message || String(error),
                stack: error?.stack,
                body: req.body
            }, null, 2));
        } catch (logErr) { }
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Create Menu Item
app.post('/api/menu-items', authenticate, authorize(['ADMIN', 'KITCHEN']), async (req, res) => {
    const { name, description, price, categoryId, image, isActive, foodType, taxSource, gstRate } = req.body;
    const { restaurantId } = (req as any).user;

    if (!name || !categoryId) {
        return res.status(400).json({ error: 'Name and category are required' });
    }

    try {
        const item = await prisma.menuItem.create({
            data: {
                id: randomUUID(),
                name,
                description,
                price: parseFloat(price) || 0,
                categoryId,
                image,
                isActive: isActive !== false,
                foodType: foodType || 'Veg',
                taxSource: taxSource || 'RESTAURANT',
                gstRate: gstRate || null,
                restaurantId
            }
        });
        res.json({ success: true, item });
    } catch (error) {
        console.error('Create Menu Item Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.put('/api/menu-items/:id', authenticate, authorize(['ADMIN', 'KITCHEN']), async (req, res) => {
    const { id } = req.params;
    const { name, description, price, categoryId, image, isActive, foodType, taxSource, gstRate } = req.body;

    try {
        const data: any = {};
        if (name !== undefined) data.name = name;
        if (description !== undefined) data.description = description;
        if (price !== undefined) data.price = parseFloat(price);
        if (categoryId !== undefined) data.categoryId = categoryId;
        if (image !== undefined) data.image = image;
        if (foodType !== undefined) data.foodType = foodType;
        if (taxSource !== undefined) data.taxSource = taxSource;
        if (gstRate !== undefined) data.gstRate = gstRate;
        if (isActive !== undefined) {
            if (typeof isActive === 'boolean') {
                data.isActive = isActive;
            } else if (typeof isActive === 'string') {
                data.isActive = isActive.toLowerCase() === 'true';
            }
        }

        const item = await prisma.menuItem.update({
            where: { id },
            data
        });
        res.json({ success: true, item });
    } catch (error) {
        console.error('Update Menu Item Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// --- Module 12: Dashboard & Analytics (Admin) ---
app.get('/api/admin/sales-summary', authenticate, authorize(['ADMIN']), async (req, res) => {
    try {
        const { restaurantId } = (req as any).user;
        const startOfDay = new Date();
        startOfDay.setHours(0, 0, 0, 0);

        const endOfDay = new Date();
        endOfDay.setHours(23, 59, 59, 999);

        // Fetch completed orders for today
        const orders = await prisma.order.findMany({
            where: {
                restaurantId,
                status: 'COMPLETED',
                createdAt: {
                    gte: startOfDay,
                    lte: endOfDay
                }
            },
            include: {
                OrderItem: {
                    include: { MenuItem: true }
                }
            }
        });

        // Calculate metrics
        const totalSales = orders.reduce((sum, order) => sum + (order.totalAmount || 0), 0);
        const totalOrders = orders.length;
        const avgOrderValue = totalOrders > 0 ? totalSales / totalOrders : 0;

        // Peak Time Calculation
        const hourCounts: Record<number, number> = {};
        orders.forEach(order => {
            const hour = new Date(order.createdAt).getHours();
            hourCounts[hour] = (hourCounts[hour] || 0) + 1;
        });

        // Find hour with max orders
        let peakHour = -1;
        let maxCount = 0;
        Object.entries(hourCounts).forEach(([hour, count]) => {
            if (count > maxCount) {
                maxCount = count;
                peakHour = parseInt(hour);
            }
        });
        const peakTime = peakHour !== -1
            ? `${peakHour.toString().padStart(2, '0')}:00 - ${(peakHour + 1).toString().padStart(2, '0')}:00`
            : '--:--';

        // Top Items Calculation
        const itemMap: Record<string, { name: string, count: number, revenue: number }> = {};

        orders.forEach(order => {
            order.OrderItem?.forEach(item => {
                if (item.MenuItem) {
                    const id = item.MenuItem.id;
                    if (!itemMap[id]) {
                        itemMap[id] = {
                            name: item.MenuItem.name,
                            count: 0,
                            revenue: 0
                        };
                    }
                    itemMap[id].count += item.quantity;
                    itemMap[id].revenue += (item.quantity * item.price);
                }
            });
        });

        const topItems = Object.values(itemMap)
            .sort((a, b) => b.count - a.count)
            .slice(0, 5);

        res.json({
            success: true,
            summary: {
                totalSales,
                totalOrders,
                avgOrderValue,
                peakTime,
                topItems
            }
        });

    } catch (error) {
        console.error('Sales Summary Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/api/admin/orders', authenticate, authorize(['ADMIN']), async (req, res) => {
    try {
        const { restaurantId } = (req as any).user;
        const { startDate, endDate } = req.query;

        // Default to latest 50 orders
        const orders = await prisma.order.findMany({
            where: {
                restaurantId,
                // Add strict date filtering logic if params provided, otherwise all history (limited)
            },
            include: {
                OrderItem: { include: { MenuItem: true } },
                Table: true
            },
            orderBy: { createdAt: 'desc' },
            take: 50
        });

        res.json({ success: true, orders: normalize(orders) });
    } catch (error) {
        console.error('Fetch Admin Orders Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/api/admin/stats', authenticate, authorize(['ADMIN']), async (req, res) => {
    try {
        const { restaurantId } = (req as any).user;
        const activeOrdersCount = await prisma.order.count({
            where: {
                restaurantId,
                status: { in: ['RECEIVED', 'PREPARING', 'READY'] }
            }
        });
        const completedOrdersCount = await prisma.order.count({
            where: { restaurantId, status: { in: ['COMPLETED', 'SERVED'] } }
        });
        const totalTables = await prisma.table.count({ where: { restaurantId } });
        const activeTables = await prisma.table.count({ where: { restaurantId, isActive: true } });

        const utilization = totalTables > 0 ? (activeTables / totalTables) * 100 : 0;

        res.json({
            success: true,
            stats: {
                activeOrders: activeOrdersCount,
                completedOrders: completedOrdersCount,
                tableUtilization: `${utilization.toFixed(1)}%`
            }
        });
    } catch (error) {
        console.error('Stats Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// --- Module 13: Customer QR Session & Ordering ---
app.post('/api/customer/session/init', async (req, res) => {
    const { restaurantId, tableId } = req.body;

    if (!restaurantId || !tableId) {
        res.status(400).json({ error: 'Restaurant and Table identifiers are required' });
        return;
    }

    try {
        const restaurant = await prisma.restaurant.findUnique({
            where: { id: restaurantId }
        });

        if (!restaurant || !restaurant.isActive) {
            res.status(400).json({ error: 'Restaurant is not active or does not exist' });
            return;
        }

        if (restaurant.status !== 'ACTIVE' && restaurant.status !== 'GRACE') {
            res.status(403).json({ error: 'Restaurant is currently unavailable' });
            return;
        }

        const table = await prisma.table.findUnique({
            where: { id: tableId }
        });

        if (!table || !table.isActive || table.restaurantId !== restaurantId) {
            res.status(400).json({ error: 'Table is not available or does not belong to this restaurant' });
            return;
        }

        const token = generateToken({
            role: 'CUSTOMER',
            restaurantId,
            tableId
        });

        await prisma.session.create({
            data: {
                id: randomUUID(),
                token,
                tableId,
                restaurantId,
                expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours
            }
        });

        const options = getCookieOptions(req);
        res.cookie('accessToken', token, { ...options, maxAge: 24 * 60 * 60 * 1000 }); // 24h

        res.json({
            success: true,
            token,
            restaurantName: restaurant.name,
            gstEnabled: restaurant.gstEnabled,
            gstMode: restaurant.gstMode,
            defaultGstRate: restaurant.defaultGstRate
        });
    } catch (error) {
        console.error('Session Init Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// --- Customer Menu Fetch by Table ID (for QR-based ordering) ---
app.get('/api/customer/table/:tableId/menu', async (req, res) => {
    const { tableId } = req.params;

    try {
        // 1. Find the table and get its restaurant
        const table = await prisma.table.findUnique({
            where: { id: tableId },
            include: { Restaurant: true }
        });

        if (!table) {
            return res.status(404).json({ error: 'Table not found' });
        }

        if (!table.Restaurant || (table.Restaurant.status !== 'ACTIVE' && table.Restaurant.status !== 'GRACE')) {
            return res.status(403).json({ error: 'Restaurant is currently unavailable' });
        }

        // 2. Fetch menu categories and items for the restaurant
        const categories = await prisma.category.findMany({
            where: {
                restaurantId: table.restaurantId,
                isActive: true
            },
            include: {
                MenuItem: {
                    where: { isActive: true },
                    orderBy: { createdAt: 'asc' }
                }
            },
            orderBy: { createdAt: 'asc' }
        });

        // 3. Return menu with restaurant info
        res.json({
            success: true,
            restaurant: {
                id: table.Restaurant.id,
                name: table.Restaurant.name
            },
            table: {
                id: table.id,
                label: table.label
            },
            categories: normalize(categories)
        });
    } catch (error) {
        console.error('Customer Table Menu Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/api/customer/menu/:restaurantId', async (req, res) => {
    const { restaurantId } = req.params;

    try {
        const categories = await prisma.category.findMany({
            where: { restaurantId, isActive: true },
            include: {
                MenuItem: { where: { isActive: true } }
            }
        });

        res.json({ success: true, categories: normalize(categories) });
    } catch (error) {
        console.error('Customer Menu Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/api/customer/orders', authenticate, authorize(['CUSTOMER']), async (req, res) => {
    console.log(`[API] POST /api/customer/orders HIT. STARTING...`);
    const { items } = req.body; // items: [{menuItemId, quantity, price}]
    const { tableId: bodyTableId } = req.body;

    // Get context from token (preferred)
    const { restaurantId, tableId: tokenTableId } = (req as any).user;

    console.log(`[API] POST /api/customer/orders HIT. User RestaurantID: ${restaurantId}`);


    const tableId = tokenTableId || bodyTableId;

    if (!items || !Array.isArray(items) || items.length === 0) {
        res.status(400).json({ error: 'No items in order' });
        return;
    }

    if (!tableId) {
        res.status(400).json({ error: 'Table ID is missing' });
        return;
    }

    try {
        const restaurant = await prisma.restaurant.findUnique({
            where: { id: restaurantId }
        });

        // Calculate total amount (Serverside trust)
        let calculatedTotal = 0;
        const validItems = [];

        for (const item of items) {
            const menuItem = await prisma.menuItem.findUnique({
                where: { id: item.menuItemId }
            });
            if (menuItem) {
                calculatedTotal += menuItem.price * item.quantity;
                validItems.push({
                    id: randomUUID(),
                    menuItemId: item.menuItemId,
                    quantity: item.quantity
                });
            }
        }

        const platformFee = 10;
        let subtotal = calculatedTotal;
        let gstAmount = 0;
        let grandTotal = calculatedTotal + platformFee;
        let effectiveGstRate = null;
        let gstMode = null;

        if (restaurant && restaurant.gstEnabled) {
            effectiveGstRate = restaurant.defaultGstRate || 5;
            gstMode = restaurant.gstMode || 'EXCLUSIVE';

            if (gstMode === 'EXCLUSIVE') {
                gstAmount = subtotal * (effectiveGstRate / 100);
                grandTotal = subtotal + gstAmount + platformFee;
            } else {
                gstAmount = subtotal - (subtotal / (1 + effectiveGstRate / 100));
                grandTotal = subtotal + platformFee;
            }
        }

        const order = await prisma.order.create({
            data: {
                id: randomUUID(),
                restaurantId,
                tableId,
                totalAmount: grandTotal, // Fallback for backwards compat
                subtotal: subtotal,
                gstAmount: gstAmount,
                grandTotal: grandTotal,
                effectiveGstRate: effectiveGstRate,
                gstMode: gstMode,
                status: 'RECEIVED',
                updatedAt: new Date(),
                OrderItem: {
                    create: validItems
                }
            },
            include: { OrderItem: true }
        });

        // --- Socket.IO: Emit new-order event ---
        try {
            const fullOrder = await prisma.order.findUnique({
                where: { id: order.id },
                include: { OrderItem: { include: { MenuItem: true } }, Table: true }
            });

            console.log("Order restaurantId:", restaurantId);
            console.log(`[Socket.IO] Prepare to emit new-order. RestaurantID: ${restaurantId}`);

            // Fix: ensure we use the dynamic restaurantId
            const roomName = `entity:${restaurantId}`;
            io.to(roomName).emit('new-order', normalize(fullOrder));
            console.log(`[Socket.IO] Emitted new-order to room: ${roomName}`);

        } catch (socketErr) {
            console.error('[Socket.IO] Failed to emit new-order:', socketErr);
        }

        res.json({
            success: true,
            order: normalize(order),
            estimatedTime: '15-20 mins'
        });
    } catch (error: any) {
        console.error('Place Order Error:', error);
        console.error('Add Items to Order Error:', error);
        const msg = error?.message || 'Unknown error';
        res.status(500).json({ error: 'Internal Server Error: ' + msg });
    }
});

app.get('/api/customer/orders/:orderId', validateTableSession, async (req, res) => {
    const { orderId } = req.params;
    try {
        const order = await prisma.order.findUnique({
            where: { id: orderId },
            include: {
                // Adjust include based on your schema expectations
                OrderItem: { include: { MenuItem: true } }
            }
        });

        if (!order) {
            return res.status(404).json({ error: 'Order not found' });
        }

        res.json({ success: true, order: normalize(order) });
    } catch (error) {
        console.error('Get Order Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/api/customer/orders', authenticate, authorize(['CUSTOMER']), async (req, res) => {
    const user = (req as any).user;
    // user contains { restaurantId, tableId, role: 'CUSTOMER' } from token

    try {
        const orders = await prisma.order.findMany({
            where: {
                restaurantId: user.restaurantId,
                tableId: user.tableId,
                // Optional: Limit to recent orders (e.g. last 24h) to avoid showing old history for the table
                createdAt: {
                    gte: new Date(Date.now() - 24 * 60 * 60 * 1000)
                }
            },
            include: {
                OrderItem: {
                    include: { MenuItem: true }
                },
                Table: true // Include table info if needed
            },
            orderBy: { createdAt: 'desc' }
        });

        res.json({ success: true, orders: normalize(orders) });
    } catch (error) {
        console.error('Fetch Customer Orders Error:', error);
        res.status(500).json({ error: 'Failed to fetch orders' });
    }
});

// 6️⃣ Exit Customer Session (Proper Logout)
app.post('/api/customer/session/exit', authenticate, authorize(['CUSTOMER']), async (req, res) => {
    const user = (req as any).user;
    try {
        // Delete static sessions for this table/restaurant
        await prisma.session.deleteMany({
            where: {
                tableId: user.tableId,
                restaurantId: user.restaurantId
            }
        });
        const options = getCookieOptions(req);
        res.clearCookie('accessToken', options);
        res.json({ success: true, message: 'Customer session terminated' });
    } catch (error) {
        console.error('Customer Session Exit Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// --- Owner & Subscription Proxy APIs ---
app.post('/api/owner/link', async (req, res) => {
    const { restaurantId, ownerId, ownerName, ownerEmail } = req.body;
    const CLOUD_API_URL = process.env.CLOUD_API_URL || 'https://software.dinestack.in/api';

    try {
        const cloudResponse = await fetch(`${CLOUD_API_URL}/owner/link`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ restaurantId, ownerId, ownerName, ownerEmail })
        });

        const data = await cloudResponse.json();
        if (data.success && data.restaurant) {
            // Update local DB
            await prisma.restaurant.update({
                where: { id: restaurantId },
                data: { ownerId, ownerName, email: ownerEmail }
            });
            return res.json({ success: true });
        } else {
            return res.status(400).json(data);
        }
    } catch (e) {
        console.error('Local Owner Link Error:', e);
        res.status(500).json({ error: 'Local server error' });
    }
});

app.post('/api/create-subscription', async (req, res) => {
    const CLOUD_API_URL = process.env.CLOUD_API_URL || 'https://software.dinestack.in/api';
    try {
        const cloudResponse = await fetch(`${CLOUD_API_URL}/create-subscription`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(req.body)
        });
        const data = await cloudResponse.json();
        res.status(cloudResponse.status).json(data);
    } catch (e) {
        console.error('Local Create Subscription Error:', e);
        res.status(500).json({ error: 'Local server error' });
    }
});

app.post('/api/verify-subscription', async (req, res) => {
    const CLOUD_API_URL = process.env.CLOUD_API_URL || 'https://software.dinestack.in/api';
    try {
        const cloudResponse = await fetch(`${CLOUD_API_URL}/verify-subscription`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(req.body)
        });
        const data = await cloudResponse.json();

        if (data.success) {
            // Update local database to reflect active subscription instantly
            await prisma.restaurant.update({
                where: { id: req.body.restaurantId },
                data: {
                    subscriptionId: req.body.razorpay_subscription_id,
                    planType: req.body.planType,
                    planStatus: 'ACTIVE',
                    status: 'ACTIVE',
                    autopayEnabled: true,
                    nextBillingDate: new Date(data.nextBillingDate),
                    lastCloudVerification: new Date()
                }
            });
        }
        res.status(cloudResponse.status).json(data);
    } catch (e) {
        console.error('Local Verify Subscription Error:', e);
        res.status(500).json({ error: 'Local server error' });
    }
});

// --- Module 2: Authentication & Profile ---
app.put('/api/restaurant/settings', authenticate, authorize(['ADMIN', 'SUPER_ADMIN']), async (req, res) => {
    const { name, address, city, phone, email, gstEnabled, gstMode, gstNumber, defaultGstRate } = req.body;
    const user = (req as any).user;

    try {
        const updatedRestaurant = await prisma.restaurant.update({
            where: { id: user.restaurantId },
            data: {
                name,
                address,
                city,
                phone,
                email,
                gstEnabled: gstEnabled !== undefined ? gstEnabled : undefined,
                gstMode: gstMode !== undefined ? gstMode : undefined,
                gstNumber: gstNumber !== undefined ? gstNumber : undefined,
                defaultGstRate: defaultGstRate !== undefined ? parseFloat(defaultGstRate) : undefined
            }
        });

        res.json({
            success: true,
            restaurant: updatedRestaurant,
            message: 'Restaurant settings updated successfully'
        });
    } catch (error) {
        console.error('Update Settings Error:', error);
        res.status(500).json({ error: 'Failed to update settings' });
    }
});

app.get('/api/restaurant/settings', authenticate, authorize(['ADMIN', 'SUPER_ADMIN', 'KITCHEN', 'WAITER']), async (req, res) => {
    const user = (req as any).user;
    try {
        const restaurant = await prisma.restaurant.findUnique({
            where: { id: user.restaurantId }
        });

        if (!restaurant) return res.status(404).json({ error: 'Restaurant not found' });

        res.json({
            success: true,
            settings: {
                name: restaurant.name,
                address: restaurant.address,
                city: restaurant.city,
                phone: restaurant.phone,
                email: restaurant.email || restaurant.ownerEmail,
                gstEnabled: restaurant.gstEnabled,
                gstMode: restaurant.gstMode,
                gstNumber: restaurant.gstNumber,
                defaultGstRate: restaurant.defaultGstRate
            }
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch settings' });
    }
});

// --- Module: Customer QR & Ordering ---

// 1. Fetch Table Info & Menu (Combined)
app.get('/api/customer/table/:tableId', async (req, res) => {
    const { tableId } = req.params;

    if (!tableId) {
        return res.status(400).json({ error: 'Table ID is required' });
    }

    try {
        const table = await prisma.table.findUnique({
            where: { id: tableId }
        });

        if (!table) {
            return res.status(404).json({ error: 'Table not found' });
        }

        const restaurant = await prisma.restaurant.findUnique({
            where: { id: table.restaurantId }
        });

        if (!restaurant || (restaurant.status !== 'ACTIVE' && restaurant.status !== 'GRACE')) {
            return res.status(403).json({ error: 'Restaurant is currently unavailable' });
        }

        // Generate Token (Stateless for Desktop)
        const token = generateToken({
            role: 'CUSTOMER',
            restaurantId: restaurant.id,
            tableId: table.id
        });

        const options = getCookieOptions(req);
        res.cookie('accessToken', token, { ...options, maxAge: 24 * 60 * 60 * 1000 }); // 24h

        // Fetch Menu
        const categories = await prisma.category.findMany({
            where: {
                restaurantId: restaurant.id,
                isActive: true
            },
            include: {
                MenuItem: {
                    where: { isActive: true }
                }
            }
        });

        res.json({
            success: true,
            token,
            restaurant: {
                id: restaurant.id,
                name: restaurant.name,
                gstEnabled: restaurant.gstEnabled,
                gstMode: restaurant.gstMode,
                gstNumber: restaurant.gstNumber,
                defaultGstRate: restaurant.defaultGstRate
            },
            table: {
                id: table.id,
                number: table.label
            },
            categories: normalize(categories)
        });

    } catch (error) {
        console.error('Customer Table Info Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// 2. Place Order
// Duplicate POST /api/customer/orders removed



// --- Module: Table Management ---
app.get('/api/tables', async (req, res) => {
    try {
        let restaurantId: string | null = null;

        const authHeader = req.headers.authorization;
        if (authHeader && authHeader.startsWith('Bearer ')) {
            const token = authHeader.split(' ')[1];
            const decoded = verifyToken(token);
            if (decoded) {
                restaurantId = decoded.restaurantId;
            }
        }

        if (!restaurantId) {
            // Fallback to active restaurant in local SQLite
            const restaurant = await prisma.restaurant.findFirst({
                where: { status: { in: ['ACTIVE', 'GRACE'] } },
                orderBy: { createdAt: 'desc' }
            });
            if (restaurant) {
                restaurantId = restaurant.id;
            }
        }

        if (!restaurantId) {
            console.log('[API] GET /tables - No restaurant context found');
            return res.json({ success: true, tables: [] });
        }

        const restaurant = await prisma.restaurant.findUnique({
            where: { id: restaurantId }
        });

        if (!restaurant) {
            console.log(`[API] GET /tables - Restaurant ${restaurantId} not found`);
            return res.json({ success: true, tables: [] });
        }

        console.log(`[API] GET /tables - Fetching for Restaurant: ${restaurant.id}`);

        const tables = await prisma.table.findMany({
            where: { restaurantId: restaurant.id },
            orderBy: { label: 'asc' }
        });

        const baseUrl = process.env.FRONTEND_URL || 'https://order.dinestack.in';
        const slug = restaurant.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)+/g, '');

        res.json({
            success: true,
            tables: tables.map(t => ({
                id: t.id,
                label: t.label,
                capacity: t.capacity,
                isActive: t.isActive,
                startTime: t.startTime,
                qrUrl: `${baseUrl}/order/${t.id}`
            }))
        });
    } catch (error) {
        console.error('Fetch Tables Error:', error);
        res.status(500).json({ error: 'Failed to fetch tables' });
    }
});

app.get('/api/tables/:id/qr-data', authenticate, authorize(['ADMIN', 'SUPER_ADMIN']), async (req, res) => {
    const { id } = req.params;

    try {
        const table = await prisma.table.findUnique({
            where: { id },
            include: { Restaurant: true }
        });

        if (!table) {
            return res.status(404).json({ error: 'Table not found' });
        }

        const restaurant = table.Restaurant;
        const baseUrl = process.env.FRONTEND_URL || 'https://order.dinestack.in';
        const slug = restaurant.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)+/g, '');
        const qrUrl = `${baseUrl}/order/${table.id}`;

        res.json({ success: true, qrUrl });
    } catch (error) {
        console.error('QR Data Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/api/tables', authenticate, authorize(['ADMIN', 'SUPER_ADMIN']), async (req, res) => {
    const { label, capacity } = req.body;
    const user = (req as any).user;

    console.log(`[API] POST /tables - Creating for Restaurant (Token): ${user.restaurantId}`);

    try {
        const existingTable = await prisma.table.findFirst({
            where: {
                restaurantId: user.restaurantId,
                label: {
                    equals: label
                    // SQLite doesn't natively support case-insensitive equals in prisma easily without mode: 'insensitive',
                    // but we can just use exact match or basic comparison.
                }
            }
        });

        // Doing a simple JS case-insensitive check to be safe if DB query doesn't catch it
        if (existingTable || (await prisma.table.findMany({ where: { restaurantId: user.restaurantId } })).some(t => t.label.toLowerCase() === label.toLowerCase())) {
            return res.status(400).json({ error: 'A table with this name already exists.' });
        }

        const table = await prisma.table.create({
            data: {
                id: randomUUID(),
                label,
                capacity: capacity || 4,
                restaurantId: user.restaurantId,
                isActive: true
            }
        });
        console.log(`[API] Table Created: ${table.id} for ${table.restaurantId}`);
        res.json({ success: true, table });
    } catch (error) {
        console.error('Create Table Error:', error);
        res.status(500).json({ error: 'Failed to create table' });
    }
});

app.put('/api/tables/:id', authenticate, authorize(['ADMIN', 'SUPER_ADMIN']), async (req, res) => {
    const { id } = req.params;
    const { label, capacity } = req.body;
    const user = (req as any).user;

    try {
        if (label) {
            const existingTables = await prisma.table.findMany({ where: { restaurantId: user.restaurantId } });
            if (existingTables.some(t => t.id !== id && t.label.toLowerCase() === label.toLowerCase())) {
                return res.status(400).json({ error: 'A table with this name already exists.' });
            }
        }

        const table = await prisma.table.update({
            where: { id },
            data: { label, capacity }
        });
        res.json({ success: true, table });
    } catch (error) {
        res.status(500).json({ error: 'Failed to update table' });
    }
});

app.put('/api/tables/:id/status', authenticate, authorize(['ADMIN', 'SUPER_ADMIN', 'WAITER']), async (req, res) => {
    const { id } = req.params;
    const { isActive } = req.body;
    try {
        const table = await prisma.table.update({
            where: { id },
            data: { isActive }
        });
        res.json({ success: true, table });
    } catch (error) {
        res.status(500).json({ error: 'Failed to update table status' });
    }
});

app.delete('/api/tables/:id', authenticate, authorize(['ADMIN', 'SUPER_ADMIN']), async (req, res) => {
    const { id } = req.params;
    try {
        // Delete temporary sessions linked to this table
        await prisma.session.deleteMany({ where: { tableId: id } });
        await (prisma as any).tableSession?.deleteMany({ where: { tableId: id } }).catch(() => { });

        // Find orders to delete their items first
        const orders = await prisma.order.findMany({ where: { tableId: id } });
        if (orders.length > 0) {
            const orderIds = orders.map(o => o.id);
            await prisma.orderItem.deleteMany({ where: { orderId: { in: orderIds } } });
            await prisma.order.deleteMany({ where: { tableId: id } });
        }

        await prisma.table.delete({ where: { id } });
        res.json({ success: true });
    } catch (error: any) {
        console.error('Table delete error:', error);
        res.status(500).json({ error: error.message || 'Failed to delete table' });
    }
});

// --- Module: Kitchen Orders ---
app.get('/api/kitchen/orders', authenticate, authorize(['ADMIN', 'KITCHEN', 'SUPER_ADMIN']), async (req, res) => {
    const user = (req as any).user;
    try {
        // Get active orders (not SERVED usually, or maybe all for history?)
        // KitchenOperations.tsx fliters client side for Live vs History. 
        // So we return all recent orders? Or maybe last 24h?
        // Let's return all non-archived orders or last 100.

        const orders = await prisma.order.findMany({
            where: {
                restaurantId: user.restaurantId,
                // status: { not: 'COMPLETED' } // Frontend handles filtering
                createdAt: { gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } // Last 24h
            },
            include: {
                Table: true,
                OrderItem: {
                    include: { MenuItem: true }
                }
            },
            orderBy: { createdAt: 'desc' }
        });

        res.json({
            success: true,
            orders: normalize(orders)
        });
    } catch (error) {
        console.error('Kitchen Orders Error:', error);
        res.status(500).json({ error: 'Failed to fetch kitchen orders' });
    }
});

app.patch('/api/orders/:id/status', authenticate, authorize(['ADMIN', 'KITCHEN', 'WAITER']), async (req, res) => {
    const { id } = req.params;
    const { status } = req.body;
    // status: RECEIVED | PREPARING | READY | SERVED

    try {
        const order = await prisma.order.update({
            where: { id },
            data: { status, synced: false, updatedAt: new Date() },
            include: { Table: true }
        });

        // Notify via Socket
        io.to(`entity:${order.restaurantId}`).emit('order-status-changed', normalize(order));

        res.json({ success: true, order: normalize(order) });
    } catch (error) {
        console.error('Update Order Status Error:', error);
        res.status(500).json({ error: 'Failed to update order status' });
    }
});


// --- Serve Static Frontend in Production/Desktop Mode ---
const outPath = path.join(__dirname, '../../out');
app.use(express.static(outPath));

// Fallback all non-API requests to index.html (Next.js routing)
app.get(/^(?!\/api).*$/, (req, res) => {
    res.sendFile(path.join(outPath, 'index.html'), (err) => {
        if (err) {
            res.status(404).json({ error: 'Not Found', path: req.path });
        }
    });
});

// --- Global Error Handler ---
app.use((req, res, next) => {
    res.status(404).json({ error: 'Not Found', path: req.path });
});

app.use((err: any, req: any, res: any, next: any) => {
    console.error('[Global Error]', err);
    try {
        const fs = require('fs');
        const path = require('path');
        const logPath = path.join(__dirname, 'debug_output.log');
        fs.writeFileSync(logPath, JSON.stringify({
            time: new Date().toISOString(),
            status: 'GLOBAL_ERROR',
            error: err?.message || String(err),
            stack: err?.stack
        }, null, 2));
    } catch (e) { }
    res.status(500).json({
        error: 'Internal Server Error',
        message: err.message
    });
});

// --- Server Start ---
waitForDatabase().then((connected) => {
    if (connected) {
        // Start background sync service (every 10 seconds)
        startSyncService(10000);

        httpServer.listen(PORT, () => {
            console.log(`DineStack Desktop API Server running on port ${PORT} (SQLite Mode)`);
            console.log('Offline-First Sync Service Enabled.');
            console.log('[Socket.IO] Real-time server ready.');
            if (process.send) {
                process.send('ready');
            }
        });
    } else {
        console.error('Failed to connect to database. Server exiting.');
        process.exit(1);
    }
});

export default app;

