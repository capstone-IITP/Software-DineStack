import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
import crypto, { randomUUID } from 'crypto';
import { generateToken, verifyToken, generateRefreshToken, hashToken, runtimeSecret } from './utils/auth';
import { prisma } from './utils/prisma';
import { authenticate, authorize, validateTableSession } from './middleware/auth';
import { validate } from './middleware/validate';
import {
    activateSchema, licenseVerifySchema, licenseStatusSchema, loginSchema,
    setupPinSchema, pairCodeVerifySchema, ownerLinkSchema, createSubscriptionSchema,
    verifySubscriptionSchema, deviceSyncSchema, tableCreateSchema, tableUpdateSchema,
    tableStatusSchema, categoryCreateSchema, categoryUpdateSchema, menuItemCreateSchema,
    menuItemUpdateSchema, orderStatusSchema, customerSessionSchema, customerOrderSchema,
    addItemsSchema, createLicenseSchema, linkRestaurantSchema, verifyAdminPinSchema,
    updateKitchenPinSchema, idParamSchema, restaurantIdQuerySchema, tableIdParamSchema,
    orderIdParamSchema, restaurantIdParamSchema, deviceTokenQuerySchema
} from './middleware/schemas';
import recoveryRoutes from './routes/recovery.routes';
import couponRoutes from './routes/coupon.routes';
import { EntityPolicy } from './policies/EntityPolicy';

const app = express();
// Prisma instance imported from utils/prisma.ts
const PORT = process.env.PORT || 5001;
if (!process.env.PORT) {
    console.log('PORT not specified, defaulting to 5001');
}

async function findReservedRestaurantByName(client: any, name: string) {
    const candidates = await client.restaurant.findMany({
        where: { name },
        select: { id: true, name: true, status: true, isActive: true },
        orderBy: { createdAt: 'desc' }
    });
    return candidates.find((restaurant: any) => EntityPolicy.isNameReserved(restaurant)) || null;
}

async function assertActiveNameAvailable(client: any, name: string) {
    const existing = await findReservedRestaurantByName(client, name);
    if (existing) {
        const error: any = new Error(`An active restaurant already exists with the name "${name}".`);
        error.code = 'ACTIVE_NAME_RESERVED';
        error.restaurant = existing;
        throw error;
    }
}

// Log Active DB (Masked)
const dbUrl = process.env.DATABASE_URL;
if (!dbUrl) {
    console.error('CRITICAL: DATABASE_URL not found in environment.');
    process.exit(1);
}
console.log(`≡ƒöÇ Connecting to Database: ${dbUrl.includes('@') ? dbUrl.split('@')[1] : 'Local/Embedded'}`);
// 11: Remove hardcoded code

// --- Security Middleware: Helmet ---
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://checkout.razorpay.com"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'", "https://software.dinestack.in", "https://api.razorpay.com", "https://lumberjack.razorpay.com"],
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

// --- Security Middleware: Global Rate Limiting ---
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 2000,
    message: { error: 'Too many requests, please try again later.' }
});
app.use('/api/', globalLimiter);

app.use(cors({
    origin: [
        'https://order.dinestack.in',
        'https://software.dinestack.in',
        process.env.FRONTEND_URL || 'http://localhost:3000'
    ],
    credentials: true
}));
app.use(express.json());

// --- HTTPS Redirection in Production ---
app.use((req, res, next) => {
    if (process.env.NODE_ENV === 'production' && !req.secure && req.headers['x-forwarded-proto'] !== 'https') {
        return res.redirect(`https://${req.headers.host}${req.url}`);
    }
    next();
});

// --- Content-Type & HTTP Method Validation ---
app.use((req, res, next) => {
    const allowedMethods = ['GET', 'POST', 'PATCH', 'OPTIONS'];
    if (!allowedMethods.includes(req.method)) {
        return res.status(405).json({ error: `Method ${req.method} Not Allowed` });
    }
    const methodsWithBody = ['POST', 'PATCH'];
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
    const stateChangingMethods = ['POST', 'PATCH'];
    if (stateChangingMethods.includes(req.method)) {
        const origin = req.headers.origin || req.headers.referer;
        const allowedOrigins = [
            'https://order.dinestack.in',
            'https://software.dinestack.in',
            process.env.FRONTEND_URL || 'http://localhost:3000'
        ];

        if (origin) {
            const isAllowed = allowedOrigins.some(allowed => origin.startsWith(allowed));
            if (!isAllowed) {
                return res.status(403).json({ error: 'CSRF Protection: Forbidden origin' });
            }
        }
    }
    next();
});

// --- Security Headers Middleware ---
app.use((req, res, next) => {
    // Set HSTS unconditionally in production (Vercel always terminates TLS)
    if (process.env.NODE_ENV === 'production' || req.secure || req.headers['x-forwarded-proto'] === 'https') {
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
    }

    // Disable caching for sensitive APIs
    if (req.path.startsWith('/api/')) {
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');
    }
    next();
});

// --- Targeted Rate Limiters ---
const activationLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: { error: 'Too many activation attempts. Please try again later.' }
});

const licenseLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 15,
    message: { error: 'Too many license verification requests. Please try again later.' }
});

const subscriptionLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: { error: 'Too many subscription requests. Please try again later.' }
});

const setupLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: { error: 'Too many setup attempts. Please try again later.' }
});

app.use('/api/recovery', recoveryRoutes);
app.use('/api/coupons', couponRoutes);

// --- Root Route ---
app.get(['/', '/api'], (req, res) => {
    res.json({
        message: 'DineStack API is running',
        version: '1.0.0',
        endpoints: {
            health: '/health',
            tables: '/api/tables',
            orders: '/api/orders',
            status: '/api/system/status'
        }
    });
});

// --- Module 0: System Status ---
app.get('/api/system/status', async (req, res) => {
    try {
        // Find the single active restaurant for this installation
        // We take the most recent one to be safe
        const restaurant = await prisma.restaurant.findFirst({
            orderBy: { createdAt: 'desc' }
        });

        if (!restaurant) {
            return res.json({
                activated: false,
                setupComplete: false,
                message: 'System not activated'
            });
        }

        // Check if setup is complete (Admin PIN set)
        const setupComplete = !!restaurant.adminPin;

        res.json({
            activated: true,
            setupComplete,
            kitchenPinConfigured: !!restaurant.kitchenPin,
            restaurantId: restaurant.id,
            status: restaurant.status,
            message: 'System status retrieved'
        });
    } catch (error) {
        console.error('System Status Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// --- Middleware ---
// Middleware extracted to middleware/auth.ts

// --- Activation Status Constants (matching Admin Panel schema) ---
const ACTIVATION_STATUS = {
    ACTIVE: 'ACTIVE',       // Code is valid and can be used
    USED: 'USED',           // Code has been used to activate a restaurant
    INVALIDATED: 'INVALIDATED', // Code was revoked by admin
    EXPIRED: 'EXPIRED'      // Code has expired (time-based)
} as const;

// --- Single Source of Truth for Activation Code Eligibility ---
interface CodeEligibilityInput {
    status: string;
    isUsed: boolean;
    expiresAt: Date | null;
    usedAt: Date | null;
    hasRestaurant: boolean; // true if bound to a restaurant via relation
}

interface CodeEligibilityResult {
    eligible: boolean;
    reason: 'VALID' | 'USED' | 'REVOKED' | 'EXPIRED';
}

function getCodeEligibility(code: CodeEligibilityInput): CodeEligibilityResult {
    // Check revocation first (explicit admin action)
    if (code.status === ACTIVATION_STATUS.INVALIDATED) {
        return { eligible: false, reason: 'REVOKED' };
    }

    // Check expiration (time-based)
    if (code.expiresAt && code.expiresAt < new Date()) {
        return { eligible: false, reason: 'EXPIRED' };
    }

    // Check if already used (any of these indicate prior use)
    if (code.status === ACTIVATION_STATUS.USED || code.isUsed || code.usedAt || code.hasRestaurant) {
        return { eligible: false, reason: 'USED' };
    }

    // All checks passed - code is valid for activation
    return { eligible: true, reason: 'VALID' };
}

// --- Session Logic ---
const TABLE_SESSION_TIMEOUT = 20 * 60 * 1000; // 20 minutes

async function getOrCreateTableSession(tableId: string, restaurantId: string) {
    // 1. Check for valid active session
    const existingSession = await (prisma as any).tableSession.findFirst({
        where: {
            tableId,
            restaurantId,
            isActive: true,
            status: 'ACTIVE',
            expiresAt: { gt: new Date() }
        },
        orderBy: { createdAt: 'desc' }
    });

    if (existingSession) {
        return existingSession;
    }

    // 2. Mark any old sessions as inactive (cleanup)
    // Optional but good for hygiene
    await (prisma as any).tableSession.updateMany({
        where: {
            tableId,
            isActive: true
        },
        data: {
            isActive: false,
            status: 'CLOSED' // or EXPIRED
        }
    });

    // 3. Create new session
    const newSession = await (prisma as any).tableSession.create({
        data: {
            tableId,
            restaurantId,
            expiresAt: new Date(Date.now() + TABLE_SESSION_TIMEOUT),
            status: 'ACTIVE',
            isActive: true
        }
    });

    return newSession;
}

// --- Cloud License Verification Endpoint ---
app.post('/api/license/verify', licenseLimiter, validate({ body: licenseVerifySchema }), async (req, res) => {
    const { activationCode } = req.body;

    if (!activationCode) {
        return res.status(400).json({ error: 'ACTIVATION_CODE_REQUIRED' });
    }

    try {
        const codeRecord = await prisma.activationCode.findUnique({
            where: { code: activationCode },
            include: { restaurant: true }
        });

        if (!codeRecord) {
            return res.json({ success: false, status: 'INVALID', error: 'LICENSE_INVALID' });
        }

        if (codeRecord.status === 'INVALIDATED' || codeRecord.status === 'REVOKED') {
            return res.json({ success: false, status: codeRecord.status, error: 'LICENSE_REVOKED' });
        }

        const GRACE_PERIOD_MS = 7 * 24 * 60 * 60 * 1000; // 7 days grace period
        if (codeRecord.expiresAt && codeRecord.expiresAt < new Date()) {
            const timePassed = Date.now() - new Date(codeRecord.expiresAt).getTime();
            if (timePassed < GRACE_PERIOD_MS) {
                return res.json({
                    success: true,
                    status: 'GRACE',
                    expiresAt: codeRecord.expiresAt,
                    restaurantId: codeRecord.restaurant?.id,
                    message: 'Subscription has expired. You are currently in a grace period.'
                });
            }
            return res.json({ success: false, status: 'EXPIRED', error: 'LICENSE_EXPIRED' });
        }

        if (codeRecord.restaurant &&
            (codeRecord.restaurant as any).status !== 'ACTIVE' &&
            (codeRecord.restaurant as any).status !== 'GRACE') {
            return res.json({ success: false, status: (codeRecord.restaurant as any).status, error: 'RESTAURANT_INACTIVE' });
        }

        const restaurant = codeRecord.restaurant;
        const systemSecret = runtimeSecret as string;
        const restaurantJwtSecret = restaurant ? crypto.createHmac('sha256', systemSecret).update(restaurant.id).digest('hex') : '';

        console.log(`[DIAGNOSTIC] License verified for restaurant ${restaurant?.id || 'unknown'} (${restaurant?.name || 'unknown'}), status: ${restaurant?.status || 'unknown'}`);

        return res.json({
            success: true,
            status: (restaurant as any)?.status || 'ACTIVE',
            expiresAt: codeRecord.expiresAt,
            restaurantId: restaurant?.id,
            name: restaurant?.name,
            hasAdminPin: !!restaurant?.adminPin,
            hasKitchenPin: !!restaurant?.kitchenPin,
            jwtSecret: restaurantJwtSecret
        });
    } catch (error) {
        console.error('License Verification Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// --- Cloud License Status Endpoint (Restaurant ID based) ---
app.post('/api/license/status', licenseLimiter, validate({ body: licenseStatusSchema }), async (req, res) => {
    const { restaurantId } = req.body;

    if (!restaurantId) {
        return res.status(400).json({ error: 'RESTAURANT_ID_REQUIRED' });
    }

    try {
        const restaurant = await prisma.restaurant.findUnique({
            where: { id: restaurantId },
            include: { activationCode: true }
        });

        if (!restaurant) {
            return res.json({ success: false, status: 'INVALID', error: 'RESTAURANT_NOT_FOUND' });
        }

        const now = new Date();

        // Trial Validation Logic
        if (restaurant.planStatus === 'TRIAL' && restaurant.trialEndDate && now > restaurant.trialEndDate) {
            // Update to TRIAL_EXPIRED
            const updated = await prisma.restaurant.update({
                where: { id: restaurant.id },
                data: { planStatus: 'TRIAL_EXPIRED', status: 'SUSPENDED' }
            });
            restaurant.planStatus = updated.planStatus;
            restaurant.status = updated.status;
        }

        const systemSecret = runtimeSecret as string;
        const restaurantJwtSecret = crypto.createHmac('sha256', systemSecret).update(restaurant.id).digest('hex');

        return res.json({
            success: true,
            restaurantId: restaurant.id,
            name: restaurant.name,
            status: restaurant.status,
            planStatus: restaurant.planStatus,
            currentPlan: restaurant.currentPlan,
            trialEndDate: restaurant.trialEndDate,
            activationDate: restaurant.activationDate,
            hasAdminPin: !!restaurant.adminPin,
            hasKitchenPin: !!restaurant.kitchenPin,
            jwtSecret: restaurantJwtSecret,
            expiresAt: restaurant.subscriptionEndsAt || restaurant.activationCode?.expiresAt
        });
    } catch (error) {
        console.error('License Status Check Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// --- Owner Linking API ---
app.post('/api/owner/link', authenticate, authorize(['ADMIN']), validate({ body: ownerLinkSchema }), async (req, res) => {
    const { restaurantId, ownerId, ownerName, ownerEmail } = req.body;
    if (!restaurantId || !ownerId) {
        return res.status(400).json({ error: 'restaurantId and ownerId required' });
    }
    try {
        const restaurant = await prisma.restaurant.update({
            where: { id: restaurantId },
            data: { ownerId, ownerName, email: ownerEmail }
        });
        res.json({ success: true, restaurant });
    } catch (e) {
        console.error('Owner Link Error:', e);
        res.status(500).json({ error: 'Failed to link owner' });
    }
});

// --- Subscription APIs (Razorpay) ---
import Razorpay from 'razorpay';

app.post('/api/create-subscription', authenticate, authorize(['ADMIN']), subscriptionLimiter, validate({ body: createSubscriptionSchema }), async (req, res) => {
    const { restaurantId, planId } = req.body;
    if (!restaurantId || !planId) return res.status(400).json({ error: 'Missing parameters' });

    try {
        const rzp = new Razorpay({
            key_id: process.env.RAZORPAY_KEY_ID || '',
            key_secret: process.env.RAZORPAY_KEY_SECRET || ''
        });

        // Create a razorpay subscription
        const subscription = await rzp.subscriptions.create({
            plan_id: planId,
            customer_notify: 1,
            total_count: 120 // usually unlimited or long term
        });

        res.json({ success: true, subscriptionId: subscription.id });
    } catch (error) {
        console.error('Create Subscription Error:', error);
        res.status(500).json({ error: 'Payment gateway error' });
    }
});

app.post('/api/verify-subscription', subscriptionLimiter, validate({ body: verifySubscriptionSchema }), async (req, res) => {
    const { razorpay_payment_id, razorpay_subscription_id, razorpay_signature, restaurantId, planType } = req.body;

    try {
        const rzpSecret = process.env.RAZORPAY_KEY_SECRET || '';
        const expectedSignature = crypto.createHmac('sha256', rzpSecret)
            .update(razorpay_payment_id + '|' + razorpay_subscription_id)
            .digest('hex');

        if (expectedSignature === razorpay_signature) {
            // Subscription valid, update DB
            const expiry = new Date();
            expiry.setDate(expiry.getDate() + (planType === 'YEARLY' ? 365 : 30));

            const updated = await prisma.restaurant.update({
                where: { id: restaurantId },
                data: {
                    subscriptionId: razorpay_subscription_id,
                    planType,
                    planStatus: 'ACTIVE',
                    status: 'ACTIVE',
                    autopayEnabled: true,
                    nextBillingDate: expiry,
                    lastCloudVerification: new Date()
                }
            });
            return res.json({ success: true, status: 'ACTIVE', nextBillingDate: expiry });
        } else {
            return res.status(400).json({ success: false, error: 'Invalid signature' });
        }
    } catch (e) {
        console.error('Verify Subscription Error:', e);
        res.status(500).json({ error: 'Server error' });
    }
});

// --- Cloud Device Sync Endpoint ---
app.get('/api/devices', authenticate, async (req, res) => {
    try {
        const restaurantId = (req as any).user.restaurantId;
        const devices = await prisma.device.findMany({
            where: { restaurantId },
            orderBy: { createdAt: 'desc' }
        });
        res.json({ success: true, devices });
    } catch (error) {
        console.error('Failed to fetch devices:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


app.post('/api/devices/sync', authenticate, validate({ body: deviceSyncSchema }), async (req, res) => {
    const { restaurantId, deviceId, role, status, type } = req.body;

    if (!restaurantId || !deviceId || !role) {
        return res.status(400).json({ error: 'restaurantId, deviceId, and role are required' });
    }

    try {
        const device = await prisma.device.upsert({
            where: { deviceId },
            update: {
                role,
                status: status || 'ACTIVE',
                type: type || 'UNKNOWN',
                lastUsed: new Date(),
                lastSeen: new Date()
            },
            create: {
                restaurantId,
                deviceId,
                role,
                status: status || 'ACTIVE',
                type: type || 'UNKNOWN',
                lastSeen: new Date()
            }
        });

        res.json({ success: true, device });
    } catch (error) {
        console.error('[Device Sync] Error upserting device in cloud:', error);
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
app.post('/api/activate', activationLimiter, validate({ body: activateSchema }), async (req, res) => {
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

    // 3) Check which database file Prisma is using.
    const dbUrl = process.env.DATABASE_URL || 'unknown';
    console.log(`[SaaS Activation] Prisma Database URL in use: ${dbUrl}`);

    try {
        console.log(`[SaaS Activation] Finding activation code: "${activationCode}"`);

        // 4) Query activation code and log full result.
        const codeRecord = await prisma.activationCode.findUnique({
            where: { code: activationCode },
            include: { restaurant: true }
        });

        console.log(`[SaaS Activation] Query activation code result:`, JSON.stringify(codeRecord, null, 2));

        // Validation: Code must exist
        if (!codeRecord) {
            console.log(`[SaaS Activation] Code not found: ${activationCode}`);
            return res.status(400).json({ error: 'Activation code not found' });
        }

        // 10) Compare frontend-sent code with DB code character by character.
        compareCodesCharByChar(activationCode, codeRecord.code, 'Cloud DB');

        // 5) Verify status = ACTIVE, isUsed = false, expiresAt > now.
        const now = new Date();
        const isStatusActive = codeRecord.status === 'ACTIVE' || codeRecord.status === ACTIVATION_STATUS.ACTIVE;
        const isNotUsed = !codeRecord.isUsed && codeRecord.status !== 'USED' && codeRecord.status !== ACTIVATION_STATUS.USED;
        const isNotExpired = !codeRecord.expiresAt || new Date(codeRecord.expiresAt) > now;

        console.log(`[SaaS Activation] Verifying activation criteria:`, {
            isStatusActive,
            status: codeRecord.status,
            isNotUsed,
            isUsedField: codeRecord.isUsed,
            isNotExpired,
            expiresAt: codeRecord.expiresAt,
            now: now.toISOString()
        });

        // Validation: Check if revoked/invalidated
        if (codeRecord.status === 'INVALIDATED' || codeRecord.status === 'REVOKED' || codeRecord.status === ACTIVATION_STATUS.INVALIDATED) {
            console.log(`[SaaS Activation] Code is revoked/invalidated: status = ${codeRecord.status}`);
            return res.status(400).json({ error: 'LICENSE_REVOKED', details: `Code status is ${codeRecord.status}` });
        }

        // Validation: Check expiration
        if (!isNotExpired) {
            console.log(`[SaaS Activation] Code expired: expiresAt = ${codeRecord.expiresAt}`);
            return res.status(400).json({ error: 'LICENSE_EXPIRED', details: `Code expired on ${codeRecord.expiresAt}` });
        }

        // If code is already used, check if the linked restaurant status is active.
        // If the restaurant is suspended or revoked, reject reactivation.
        if (!isNotUsed && codeRecord.restaurant) {
            if (codeRecord.restaurant.status !== 'ACTIVE' && codeRecord.restaurant.status !== 'GRACE') {
                console.log(`[DIAGNOSTIC] Activation rejected: Associated restaurant is inactive. Status: ${codeRecord.restaurant.status}`);
                return res.status(400).json({
                    error: 'RESTAURANT_INACTIVE',
                    details: `Associated restaurant status is ${codeRecord.restaurant.status}`
                });
            }
            console.log(`[DIAGNOSTIC] Activation code is already active. Allowing device registration/reactivation for restaurant: ${codeRecord.restaurant.name}`);
        }

        // Get or create the restaurant (SaaS-style: auto-provision on first activation)
        let restaurant = codeRecord.restaurant;

        if (!restaurant) {
            if (!codeRecord.entityName && !codeRecord.restaurantName) {
                console.log(`[SaaS Activation] Activation rejected: Code has no entityName (unassigned).`);
                return res.status(400).json({
                    error: 'UNASSIGNED_CODE',
                    details: 'This activation code is unassigned. Please generate a code with a specific entity name.'
                });
            }

            const restaurantName = codeRecord.entityName || codeRecord.restaurantName;
            await assertActiveNameAvailable(prisma, restaurantName);

            // Truly new restaurant (Immutable Identity: Never attempt to relink by mutable name)
            console.log(`[SaaS Activation] Creating NEW restaurant: ${restaurantName}`);
            restaurant = await prisma.restaurant.create({
                data: {
                    name: restaurantName,
                    status: 'ACTIVE',
                    isActive: true,
                    subscriptionEndsAt: codeRecord.expiresAt,
                    activationCodeId: codeRecord.id,
                    activationDate: new Date(),
                    trialEndDate: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
                    currentPlan: 'TRIAL',
                    planStatus: 'TRIAL',
                    lastCloudVerification: new Date()
                }
            });

            console.log(`[SaaS Activation] Activated restaurant: ${restaurant.id} (${restaurant.name})`);
        } else {
            console.log(`[SaaS Activation] Existing restaurant found: ${restaurant.id}`);
        }

        // Mark code as used if not already marked
        if (!codeRecord.isUsed || codeRecord.status !== ACTIVATION_STATUS.USED) {
            console.log(`[SaaS Activation] Updating activationCode state in DB. ID: ${codeRecord.id}`);
            const updatedCode = await prisma.activationCode.update({
                where: { id: codeRecord.id },
                data: {
                    isUsed: true,
                    usedAt: new Date(),
                    status: ACTIVATION_STATUS.USED
                }
            });
            console.log(`[SaaS Activation] Confirmed DB update - isUsed: ${updatedCode.isUsed}, status: ${updatedCode.status}`);
        }

        console.log(`[SaaS Activation] Success - Restaurant: ${restaurant.name}`);

        const systemSecret = runtimeSecret as string;
        const restaurantJwtSecret = crypto.createHmac('sha256', systemSecret).update(restaurant.id).digest('hex');

        console.log(`[DIAGNOSTIC] Successful activation resolved. Restaurant: ${restaurant.name} (${restaurant.id}), Active: true`);

        // Return success with restaurant details
        return res.json({
            success: true,
            isActivated: true,
            restaurantId: restaurant.id,
            restaurant: {
                id: restaurant.id,
                name: restaurant.name,
                status: restaurant.status,
                tier: codeRecord.plan || 'BASIC'
            },
            isRegistered: !!restaurant.adminPin,
            hasAdminPin: !!restaurant.adminPin,
            hasKitchenPin: !!restaurant.kitchenPin,
            jwtSecret: restaurantJwtSecret,
            tier: codeRecord.plan || 'BASIC',
            expiresAt: codeRecord.expiresAt,
            durationDays: codeRecord.durationDays,
            maxTables: codeRecord.maxTables,
            activationDate: restaurant.activationDate,
            trialEndDate: restaurant.trialEndDate,
            currentPlan: restaurant.currentPlan,
            planStatus: restaurant.planStatus,
            lastCloudVerification: restaurant.lastCloudVerification
        });

    } catch (error: any) {
        console.error('[SaaS Activation] Error in cloud activation controller:', error);
        if (error?.code === 'ACTIVE_NAME_RESERVED') {
            return res.status(409).json({ error: error.code, details: error.message });
        }
        // Return detailed error for debugging
        const errorMessage = error?.message || 'Unknown error';
        const errorCode = error?.code || 'UNKNOWN';
        console.error(`[SaaS Activation] Details: ${errorCode} - ${errorMessage}`);
        return res.status(500).json({
            error: 'ACTIVATION_FAILED',
            details: process.env.NODE_ENV === 'production' ? 'An unexpected error occurred during activation' : errorMessage
        });
    }
});

// Helper function to compare activation codes character by character
function compareCodesCharByChar(sent: string, stored: string, sourceName: string) {
    console.log(`[SaaS Activation] Comparing character-by-character sent vs ${sourceName}:`);
    console.log(`  Sent:   "${sent}" (length: ${sent.length})`);
    console.log(`  Stored: "${stored}" (length: ${stored.length})`);
    const maxLength = Math.max(sent.length, stored.length);
    let details = '';
    for (let i = 0; i < maxLength; i++) {
        const charSent = sent[i] !== undefined ? `'${sent[i]}' (code: ${sent.charCodeAt(i)})` : 'MISSING';
        const charStored = stored[i] !== undefined ? `'${stored[i]}' (code: ${stored.charCodeAt(i)})` : 'MISSING';
        const match = sent[i] === stored[i] ? 'MATCH' : 'MISMATCH';
        details += `    Char ${i}: Sent ${charSent} | Stored ${charStored} | ${match}\n`;
    }
    console.log(details);
}

// PIN strength / complexity validation
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
app.post('/api/setup-pin', setupLimiter, validate({ body: setupPinSchema }), async (req, res) => {
    const { restaurantId, adminPin, kitchenPin } = req.body;

    if (!adminPin || adminPin.length < 6) {
        res.status(400).json({ error: 'Admin PIN must be at least 6 digits' });
        return;
    }

    if (isWeakPin(adminPin) || (kitchenPin && isWeakPin(kitchenPin))) {
        res.status(400).json({ error: 'PIN is too weak. Avoid simple sequential or repeating patterns.' });
        return;
    }

    try {
        const restaurant = await prisma.restaurant.findUnique({ where: { id: restaurantId } });
        if (!restaurant || !restaurant.isActive) {
            res.status(400).json({ error: 'Restaurant not active' });
            return;
        }

        if (restaurant.adminPin) {
            const isMatch = await bcrypt.compare(adminPin, restaurant.adminPin);
            if (!isMatch) {
                console.error(`[Security Alert] Attempted unauthenticated PIN overwrite for already initialized restaurant: ${restaurantId}`);
                res.status(400).json({ error: 'System is already initialized. To change your PIN, use the security settings page.' });
                return;
            }

            // If it matches, allow updating the kitchenPin
            if (kitchenPin) {
                const kitchenPinHash = await bcrypt.hash(kitchenPin, 12);
                await (prisma as any).restaurant.update({
                    where: { id: restaurantId },
                    data: {
                        kitchenPin: kitchenPinHash
                    }
                });
            }

            res.json({ success: true, message: 'Kitchen PIN updated successfully' });
            return;
        }

        const pinHash = await bcrypt.hash(adminPin, 12); // cost factor 12
        const kitchenPinHash = kitchenPin ? await bcrypt.hash(kitchenPin, 12) : null; // cost factor 12

        await (prisma as any).restaurant.update({
            where: { id: restaurantId },
            data: {
                adminPin: pinHash,     // Storing hash in the adminPin column
                kitchenPin: kitchenPinHash
                // isRegistered is implied by adminPin existence
            }
        });

        console.log(`System PINs Set for: ${restaurant.id}`);
        res.json({ success: true, token: 'valid-session' });
    } catch (error) {
        console.error('Setup PIN Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// --- Strict Auth Rate Limiter ---
const authLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 15, // Max 15 attempts (success or fail) per IP per window
    message: { error: 'Too many auth attempts. Please try again in 5 minutes.' }
});

// --- Module: Security Verification (Admin PIN) ---
app.post('/api/security/verify-admin-pin', authenticate, authorize(['ADMIN']), authLimiter, validate({ body: verifyAdminPinSchema }), async (req, res) => {
    const { adminPin } = req.body;
    const { restaurantId, deviceId } = (req as any).user;
    const userIdentifier = restaurantId; // Rate limit by restaurant, not device, for PIN security

    if (!adminPin) {
        return res.status(400).json({ error: 'Admin PIN is required' });
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
            // Log Attempt (Optional for pure verification, but good for security)
            return res.status(401).json({ error: 'Invalid Admin PIN' });
        }
        res.json({ success: true, verified: true });

    } catch (error) {
        console.error('Verify Admin PIN Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// --- Module: Secure Kitchen PIN Update ---
app.post('/api/security/update-kitchen-pin', authenticate, authorize(['ADMIN']), authLimiter, validate({ body: updateKitchenPinSchema }), async (req, res) => {
    const { adminPin, newKitchenPin } = req.body;
    const { restaurantId, deviceId } = (req as any).user;
    const userIdentifier = restaurantId;

    if (!adminPin || !newKitchenPin || newKitchenPin.length < 4) {
        return res.status(400).json({ error: 'Invalid request data' });
    }

    try {
        const restaurant = await prisma.restaurant.findUnique({ where: { id: restaurantId } });
        if (!restaurant || !restaurant.adminPin) {
            return res.status(400).json({ error: 'Restaurant not found' });
        }

        // 2. Verify Admin PIN (Double Check)
        const isValid = await bcrypt.compare(adminPin, restaurant.adminPin);
        if (!isValid) {
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

        // 3. Update Kitchen PIN
        const kitchenPinHash = await bcrypt.hash(newKitchenPin, 12);
        await prisma.restaurant.update({
            where: { id: restaurantId },
            data: { kitchenPin: kitchenPinHash }
        });

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
app.post('/api/security/update-admin-pin', authenticate, authorize(['ADMIN']), authLimiter, async (req, res) => {
    const { currentAdminPin, newAdminPin } = req.body;
    const { restaurantId, deviceId } = (req as any).user;

    if (!currentAdminPin || !newAdminPin || newAdminPin.length < 4) {
        return res.status(400).json({ error: 'Invalid request data' });
    }

    try {
        const restaurant = await prisma.restaurant.findUnique({ where: { id: restaurantId } });
        if (!restaurant || !restaurant.adminPin) {
            return res.status(400).json({ error: 'Restaurant not found' });
        }

        const isValid = await bcrypt.compare(currentAdminPin, restaurant.adminPin);
        if (!isValid) {
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
            return res.status(400).json({ error: 'PIN is too weak.' });
        }

        const adminPinHash = await bcrypt.hash(newAdminPin, 12);
        await prisma.restaurant.update({
            where: { id: restaurantId },
            data: { adminPin: adminPinHash }
        });

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

        // Invalidate all existing active pair codes for this restaurant
        await (prisma as any).pairCode.updateMany({
            where: { restaurantId, pairCodeActive: true },
            data: { pairCodeActive: false }
        });

        // Generate random DINE-XXXX code (4 alphanumeric uppercase chars)
        const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // Excluding ambiguous: 0,O,1,I
        let randomPart = '';
        for (let i = 0; i < 4; i++) {
            randomPart += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        const pairCode = `DINE-${randomPart}`;

        // Store in database with 10-minute expiry
        const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
        const created = await (prisma as any).pairCode.create({
            data: {
                code: pairCode,
                restaurantId,
                pairCodeActive: true,
                pairCodeUsed: false,
                kitchenOnline: false,
                expiresAt
            }
        });

        console.log(`[Pair] Generated pair code: ${pairCode} for restaurant ${restaurantId}`);

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
        // Find the most recent active or just-used pair code for this restaurant
        const pairCode = await (prisma as any).pairCode.findFirst({
            where: { restaurantId },
            orderBy: { createdAt: 'desc' }
        });

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
app.post('/api/pair/verify', authLimiter, validate({ body: pairCodeVerifySchema }), async (req, res) => {
    const { pairCode, deviceId } = req.body;

    if (!pairCode || !deviceId) {
        return res.status(400).json({ error: 'pairCode and deviceId are required' });
    }

    try {
        // Trim and normalize casing
        const normalizedCode = pairCode.trim().toUpperCase();

        // Find the pair code record
        const codeRecord = await (prisma as any).pairCode.findUnique({
            where: { code: normalizedCode }
        });

        if (!codeRecord) {
            return res.status(400).json({ error: 'INVALID_PAIR_CODE' });
        }

        // Rate limiting: check if locked
        if (codeRecord.lockedUntil && codeRecord.lockedUntil > new Date()) {
            const waitTime = Math.ceil((codeRecord.lockedUntil.getTime() - Date.now()) / 1000 / 60);
            return res.status(429).json({
                error: `Too many failed attempts. Try again in ${waitTime} minutes.`
            });
        }

        // Validate pair code state
        if (!codeRecord.pairCodeActive) {
            return res.status(400).json({ error: 'PAIR_CODE_INACTIVE' });
        }

        if (codeRecord.pairCodeUsed) {
            return res.status(400).json({ error: 'PAIR_CODE_ALREADY_USED' });
        }

        if (codeRecord.expiresAt < new Date()) {
            return res.status(400).json({ error: 'PAIR_CODE_EXPIRED' });
        }

        // Success: Register device as KITCHEN
        const role = 'KITCHEN';
        const restaurantId = codeRecord.restaurantId;

        // Create or update device record properly (avoiding upsert which requires @unique constraint not present in SQLite schema)
        try {
            const existingDevice = await (prisma as any).device.findFirst({
                where: { deviceId }
            });
            if (existingDevice) {
                await (prisma as any).device.update({
                    where: { id: existingDevice.id },
                    data: { role, restaurantId, status: 'ACTIVE', lastUsed: new Date() }
                });
            } else {
                await (prisma as any).device.create({
                    data: { id: randomUUID(), deviceId, role, restaurantId, status: 'ACTIVE', lastUsed: new Date() }
                });
            }
        } catch (e) {
            console.error('[Pair] Failed to save device record:', e);
        }

        // Update pair code: mark as used, kitchen online
        await (prisma as any).pairCode.update({
            where: { id: codeRecord.id },
            data: {
                pairCodeUsed: true,
                pairCodeActive: false,
                kitchenOnline: true
            }
        });

        // Generate JWT for the kitchen device
        const { accessToken } = await setAuthSession(req, res, { deviceId, role, restaurantId });

        console.log(`[Pair] Kitchen linked successfully. Device: ${deviceId}, Restaurant: ${restaurantId}`);

        res.json({
            success: true,
            token: accessToken,
            role,
            restaurantId
        });

    } catch (error) {
        // On any validation failure, increment failed attempts
        if (req.body.pairCode) {
            try {
                const record = await (prisma as any).pairCode.findUnique({
                    where: { code: req.body.pairCode.toUpperCase() }
                });
                if (record) {
                    const newCount = record.failedAttempts + 1;
                    const lockUntil = newCount >= 5 ? new Date(Date.now() + 5 * 60 * 1000) : null;
                    await (prisma as any).pairCode.update({
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
        }
        console.error('Pair Verify Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// --- Module: Kitchen Bootstrap (Kitchen Side) ---
app.get('/api/kitchen/bootstrap', authenticate, async (req, res) => {
    try {
        const user = (req as any).user;
        if (!user || user.role !== 'KITCHEN') {
            return res.status(403).json({ error: 'Forbidden' });
        }
        
        const device = await prisma.device.findFirst({
            where: { deviceId: user.deviceId, restaurantId: user.restaurantId }
        });

        if (!device || device.status !== 'ACTIVE') {
            return res.json({ linked: false });
        }

        let jwt = null;
        const authHeader = req.headers.authorization;
        if (authHeader && authHeader.startsWith('Bearer ')) {
            jwt = authHeader.split(' ')[1];
        }
        if (!jwt) {
            const cookieHeader = req.headers.cookie;
            if (cookieHeader) {
                const cookies = cookieHeader.split(';');
                for (const cookie of cookies) {
                    const [key, value] = cookie.trim().split('=');
                    if (key === 'accessToken') {
                        jwt = decodeURIComponent(value);
                        break;
                    }
                }
            }
        }

        res.json({
            linked: true,
            jwt,
            restaurantId: user.restaurantId
        });
    } catch (error) {
        console.error('Kitchen Bootstrap Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// --- Module 4 & 6: Authentication (Single PIN Access & Device JWT) ---
const isProduction = process.env.NODE_ENV === 'production';
const getCookieOptions = (req: express.Request) => ({
    httpOnly: true,
    secure: isProduction || req.secure || req.headers['x-forwarded-proto'] === 'https',
    sameSite: isProduction ? 'none' : 'lax' as any,
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

// --- Module 4 & 6: Authentication (Single PIN Access & Device JWT) ---
app.post('/api/auth/login', authLimiter, validate({ body: loginSchema }), async (req, res) => {
    const { pin, deviceId, role } = req.body;

    if (!pin || !role || !deviceId) {
        return res.status(400).json({ error: 'Missing credentials' });
    }

    try {
        const restaurant = await prisma.restaurant.findFirst({
            where: { adminPin: { not: null } },
            orderBy: { createdAt: 'desc' }
        });

        const isRegistered = !!restaurant?.adminPin;

        if (!restaurant || !isRegistered) {
            res.status(400).json({ error: 'System not activated or fully setup' });
            return;
        }

        if (restaurant.status !== 'ACTIVE' && restaurant.status !== 'GRACE') {
            res.status(403).json({ error: 'Access Denied: System is disabled' });
            return;
        }

        // Rate Limit handled by authLimiter

        const isKitchen = role === 'KITCHEN';
        const targetHash = isKitchen ? restaurant.kitchenPin : restaurant.adminPin;

        if (!targetHash) {
            res.status(400).json({ error: `${role} access not configured` });
            return;
        }

        const isValid = await bcrypt.compare(pin, targetHash);
        if (!isValid) {
            res.status(401).json({ error: 'Invalid PIN' });
            return;
        }

        if (deviceId && role) {
            // Update lastUsed / register device (role-scoped to avoid overwriting other roles)
            const existingDevice = await (prisma as any).device.findFirst({
                where: { deviceId, restaurantId: restaurant.id, role }
            });
            if (existingDevice) {
                await (prisma as any).device.update({
                    where: { id: existingDevice.id },
                    data: { lastUsed: new Date(), status: 'ACTIVE' }
                });
            } else {
                await (prisma as any).device.upsert({
                    where: { deviceId },
                    update: { role, restaurantId: restaurant.id, status: 'ACTIVE', lastUsed: new Date() },
                    create: { deviceId, role, restaurantId: restaurant.id, status: 'ACTIVE' }
                });
            }

            // Set secure cookies and create refresh token in DB
            const { accessToken } = await setAuthSession(req, res, { deviceId, role, restaurantId: restaurant.id });

            // Backwards compatibility: return token in response body
            res.json({ success: true, token: accessToken, role });
            return;
        }

        res.status(400).json({ error: 'Missing device info or role for registration' });
    } catch (error) {
        console.error('Login Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Me Endpoint (Session Check)
app.get('/api/auth/me', authenticate, async (req, res) => {
    const user = (req as any).user;
    if (!user) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    res.json({
        success: true,
        role: user.role,
        restaurantId: user.restaurantId,
        deviceId: user.deviceId
    });
});

// Logout Endpoint (primary implementation is below with refresh token cleanup)

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
            await prisma.refreshToken.delete({ where: { id: storedToken.id } });
            return res.status(401).json({ error: 'Unauthorized: Device has been deactivated' });
        }

        // Delete old refresh token (rotation)
        await prisma.refreshToken.delete({
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

// --- Module 5 & 7: Table Management ---
app.post('/api/tables', authenticate, authorize(['ADMIN']), validate({ body: tableCreateSchema }), async (req, res) => {
    const { label, capacity } = req.body;
    // Input validated by tableCreateSchema middleware

    if (!label) {
        res.status(400).json({ error: 'Label is required' });
        return;
    }

    try {
        const restaurant = await prisma.restaurant.findFirst({
            where: { adminPin: { not: null } }
        });
        if (!restaurant) {
            res.status(400).json({ error: 'Restaurant not initialized' });
            return;
        }

        const existingTables = await (prisma as any).table.findMany({ where: { restaurantId: restaurant.id } });
        if (existingTables.some((t: any) => t.label.toLowerCase() === label.toLowerCase())) {
            res.status(400).json({ error: 'A table with this name already exists.' });
            return;
        }

        const table = await (prisma as any).table.create({
            data: {
                label,
                capacity: capacity || 4,
                restaurantId: restaurant.id
            }
        });

        res.json({ success: true, table });
    } catch (error) {
        console.error('Create Table Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

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
            return res.status(401).json({ error: 'Unauthorized: No restaurant context found' });
        }

        const restaurant = await (prisma as any).restaurant.findUnique({
            where: { id: restaurantId }
        });

        if (!restaurant) {
            return res.status(404).json({ error: 'Restaurant not found' });
        }

        const tables = await (prisma as any).table.findMany({
            where: { restaurantId },
            orderBy: { label: 'asc' }
        });

        const baseUrl = process.env.FRONTEND_URL || 'https://order.dinestack.in';
        const slug = restaurant.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)+/g, '');

        res.json({
            success: true,
            tables: tables.map((t: any) => ({
                id: t.id,
                label: t.label,
                capacity: t.capacity,
                isActive: t.isActive,
                startTime: t.startTime,
                qrUrl: `${baseUrl}/order/${t.id}`
            }))
        });
    } catch (error) {
        console.error('Get Tables Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.put('/api/tables/:id/status', authenticate, authorize(['ADMIN']), async (req, res) => {
    const { id } = req.params;
    const { isActive } = req.body;

    try {
        const table = await (prisma as any).table.update({
            where: { id },
            data: { isActive }
        });
        res.json({ success: true, table });
    } catch (error) {
        console.error('Update Table Status Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.put('/api/tables/:id', authenticate, authorize(['ADMIN']), validate({ params: idParamSchema, body: tableUpdateSchema }), async (req, res) => {
    const { id } = req.params;
    const { label, capacity } = req.body;

    try {
        const user = (req as any).user;
        if (label) {
            const existingTables = await (prisma as any).table.findMany({ where: { restaurantId: user.restaurantId } });
            if (existingTables.some((t: any) => t.id !== id && t.label.toLowerCase() === label.toLowerCase())) {
                res.status(400).json({ error: 'A table with this name already exists.' });
                return;
            }
        }

        const table = await (prisma as any).table.update({
            where: { id },
            data: {
                label,
                capacity: capacity ? parseInt(capacity) : undefined
            }
        });
        res.json({ success: true, table });
    } catch (error) {
        console.error('Update Table Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.delete('/api/tables/:id', authenticate, authorize(['ADMIN']), async (req, res) => {
    const { id } = req.params;

    try {
        // Delete temporary sessions linked to this table
        await (prisma as any).session?.deleteMany({ where: { tableId: id } }).catch(() => {});
        await (prisma as any).tableSession?.deleteMany({ where: { tableId: id } }).catch(() => {});

        // Find orders to delete their items first
        const orders = await (prisma as any).order.findMany({ where: { tableId: id } });
        if (orders.length > 0) {
            const orderIds = orders.map((o: any) => o.id);
            await (prisma as any).orderItem.deleteMany({ where: { orderId: { in: orderIds } } });
            await (prisma as any).order.deleteMany({ where: { tableId: id } });
        }

        await (prisma as any).table.delete({
            where: { id }
        });
        res.json({ success: true });
    } catch (error) {
        console.error('Delete Table Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// --- Module 8: QR Code Data Generation (Admin) ---
app.get('/api/tables/:id/qr-data', authenticate, authorize(['ADMIN']), async (req, res) => {
    const { id } = req.params;

    try {
        const table = await (prisma as any).table.findUnique({
            where: { id },
            include: { restaurant: true }
        });

        if (!table) {
            res.status(404).json({ error: 'Table not found' });
            return;
        }

        const restaurant = table.restaurant;
        const baseUrl = process.env.FRONTEND_URL || 'https://order.dinestack.in';
        const slug = restaurant.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)+/g, '');
        const qrUrl = `${baseUrl}/order/${table.id}`;

        res.json({ success: true, qrUrl });
    } catch (error) {
        console.error('QR Data Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// --- Module 9: Kitchen Order Feed ---
app.get('/api/kitchen/orders', authenticate, authorize(['KITCHEN', 'ADMIN']), async (req, res) => {
    try {
        const activeOrders = await (prisma as any).order.findMany({
            where: {
                status: {
                    in: ['RECEIVED', 'PREPARING', 'READY', 'SERVED']
                }
            },
            include: {
                items: {
                    include: { menuItem: true }
                },
                table: true
            },
            orderBy: { createdAt: 'asc' }
        });

        res.json({ success: true, orders: activeOrders });
    } catch (error) {
        console.error('Kitchen Feed Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// --- Module: Activation Codes (Admin) ---

// Helper function to generate unique activation code (XXXX-XXXX-XXXX-XXXX format)
function generateActivationCode(): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    const segments: string[] = [];
    for (let i = 0; i < 4; i++) {
        let segment = '';
        for (let j = 0; j < 4; j++) {
            segment += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        segments.push(segment);
    }
    return segments.join('-');
}

// --- Create New License (Activation Code + Restaurant) ---
app.post('/api/admin/licenses', authenticate, authorize(['ADMIN']), validate({ body: createLicenseSchema }), async (req, res) => {
    const { entityName, plan, durationDays, maxTables } = req.body;

    if (!entityName) {
        return res.status(400).json({ error: 'Entity name is required' });
    }

    try {
        await assertActiveNameAvailable(prisma, entityName);

        // Generate unique code
        let code = generateActivationCode();

        // Ensure code is unique (retry if collision)
        let attempts = 0;
        while (attempts < 5) {
            const existing = await prisma.activationCode.findUnique({ where: { code } });
            if (!existing) break;
            code = generateActivationCode();
            attempts++;
        }

        // Create both activation code and restaurant in a transaction
        const result = await prisma.$transaction(async (tx) => {
            // 1. Create activation code
            const activationCode = await tx.activationCode.create({
                data: {
                    code,
                    entityName,
                    plan: plan || 'BASIC',
                    durationDays: durationDays || 365,
                    maxTables: maxTables || 10,
                    expiresAt: new Date(Date.now() + (durationDays || 365) * 24 * 60 * 60 * 1000),
                    status: 'ACTIVE',
                    isUsed: false
                }
            });

            // 2. Create restaurant and link to activation code
            const restaurant = await tx.restaurant.create({
                data: {
                    name: entityName,
                    status: 'ACTIVE',
                    isActive: true,
                    activationCodeId: activationCode.id
                }
            });

            return { activationCode, restaurant };
        });

        console.log(` Created license: ${result.activationCode.code} for ${entityName}`);

        res.json({
            success: true,
            license: {
                id: result.activationCode.id,
                code: result.activationCode.code,
                entityName: result.activationCode.entityName,
                plan: result.activationCode.plan,
                durationDays: result.activationCode.durationDays,
                maxTables: result.activationCode.maxTables,
                expiresAt: result.activationCode.expiresAt,
                status: result.activationCode.status
            },
            restaurant: {
                id: result.restaurant.id,
                name: result.restaurant.name,
                status: result.restaurant.status
            }
        });

    } catch (error: any) {
        console.error('Create License Error:', error);
        if (error?.code === 'ACTIVE_NAME_RESERVED') {
            return res.status(409).json({ error: error.code, details: error.message });
        }
        res.status(500).json({ error: 'Failed to create license' });
    }
});

app.get('/api/admin/activation-codes', authenticate, authorize(['ADMIN']), async (req, res) => {
    try {
        const codes = await prisma.activationCode.findMany({
            orderBy: { createdAt: 'desc' },
            include: {
                restaurant: {
                    select: {
                        id: true,
                        name: true
                    }
                }
            }
        });

        // Add computed eligibility for each code (single source of truth)
        const codesWithEligibility = codes.map(code => {
            const eligibility = getCodeEligibility({
                status: code.status,
                isUsed: code.isUsed,
                expiresAt: code.expiresAt,
                usedAt: code.usedAt,
                hasRestaurant: !!code.restaurant
            });
            return {
                ...code,
                token: code.code, // Alias for frontend compatibility
                entity: code.entityName || code.restaurant?.name || 'Unassigned', // Alias for frontend compatibility
                eligibility: eligibility.reason,
                canActivate: eligibility.eligible
            };
        });

        res.json({ success: true, codes: codesWithEligibility });
    } catch (error) {
        console.error('Get Activation Codes Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// --- Force Reset Activation Code (Admin Only) ---
app.post('/api/admin/activation-codes/:id/force-reset', authenticate, authorize(['ADMIN']), async (req, res) => {
    const { id } = req.params;
    const user = (req as any).user;

    try {
        // Find the code with its linked restaurant
        const existingCode = await prisma.activationCode.findUnique({
            where: { id },
            include: { restaurant: true }
        });

        if (!existingCode) {
            res.status(404).json({ error: 'Activation code not found' });
            return;
        }

        // If there's a linked restaurant, break the link first
        if (existingCode.restaurant) {
            await prisma.restaurant.update({
                where: { id: existingCode.restaurant.id },
                data: { activationCodeId: null }
            });
        }

        // Reset the activation code to ACTIVE status
        const updatedCode = await prisma.activationCode.update({
            where: { id },
            data: {
                status: ACTIVATION_STATUS.ACTIVE, // Back to valid state
                usedAt: null,
                isUsed: false
            }
        });

        // Log the action for audit purposes
        await prisma.auditLog.create({
            data: {
                action: 'ACTIVATION_CODE_FORCE_RESET',
                user: user.deviceId || 'admin',
                target: existingCode.code,
                details: JSON.stringify({
                    codeId: id,
                    previousStatus: existingCode.status,
                    previousRestaurantId: existingCode.restaurant?.id,
                    previousRestaurantName: existingCode.restaurant?.name,
                    resetAt: new Date().toISOString()
                })
            }
        });

        console.log(`≡ƒöä Activation code ${existingCode.code} force-reset by ${user.deviceId || 'admin'}`);

        res.json({
            success: true,
            message: 'Activation code has been reset and is now available for use',
            code: {
                id: updatedCode.id,
                code: updatedCode.code,
                status: updatedCode.status,
                eligibility: 'VALID',
                canActivate: true
            }
        });
    } catch (error) {
        console.error('Force Reset Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// --- Link Existing Unlinked Code to New Restaurant ---
app.post('/api/admin/activation-codes/:id/link-restaurant', authenticate, authorize(['ADMIN']), async (req, res) => {
    const { id } = req.params;
    const { entityName } = req.body;

    try {
        // Find the activation code
        const existingCode = await prisma.activationCode.findUnique({
            where: { id },
            include: { restaurant: true }
        });

        if (!existingCode) {
            return res.status(404).json({ error: 'Activation code not found' });
        }

        // Check if already linked
        if (existingCode.restaurant) {
            return res.status(400).json({
                error: 'Activation code is already linked to a restaurant',
                linkedRestaurant: existingCode.restaurant.name
            });
        }

        const restaurantName = entityName || existingCode.entityName || 'New Restaurant';
        await assertActiveNameAvailable(prisma, restaurantName);

        // Create restaurant and link
        const restaurant = await prisma.restaurant.create({
            data: {
                name: restaurantName,
                status: 'ACTIVE',
                isActive: true,
                activationCodeId: existingCode.id
            }
        });

        // Update entityName on code if provided
        if (entityName && entityName !== existingCode.entityName) {
            await prisma.activationCode.update({
                where: { id },
                data: { entityName }
            });
        }

        console.log(` Linked code ${existingCode.code} to new restaurant: ${restaurant.name}`);

        res.json({
            success: true,
            message: 'Restaurant created and linked to activation code',
            code: existingCode.code,
            restaurant: {
                id: restaurant.id,
                name: restaurant.name,
                status: restaurant.status
            }
        });

    } catch (error: any) {
        console.error('Link Restaurant Error:', error);
        if (error?.code === 'ACTIVE_NAME_RESERVED') {
            return res.status(409).json({ error: error.code, details: error.message });
        }
        res.status(500).json({ error: 'Failed to link restaurant' });
    }
});

// --- Module 10: Update Order Status (Kitchen) ---
const VALID_TRANSITIONS: Record<string, string[]> = {
    'RECEIVED': ['PREPARING', 'CANCELLED'],
    'PREPARING': ['READY', 'CANCELLED'],
    'READY': ['SERVED', 'CANCELLED'],
    'SERVED': ['COMPLETED']
};

app.patch('/api/orders/:id/status', authenticate, authorize(['KITCHEN', 'ADMIN']), validate({ params: idParamSchema, body: orderStatusSchema }), async (req, res) => {
    const { id } = req.params;
    const { status } = req.body;

    try {
        const order = await (prisma as any).order.findUnique({ where: { id } });
        if (!order) {
            res.status(404).json({ error: 'Order not found' });
            return;
        }

        const allowedNextStatuses = VALID_TRANSITIONS[order.status] || [];
        if (!allowedNextStatuses.includes(status)) {
            res.status(400).json({
                error: `Invalid transition from ${order.status} to ${status}. Allowed: ${allowedNextStatuses.join(', ')}`
            });
            return;
        }

        const updatedOrder = await (prisma as any).order.update({
            where: { id },
            data: { status }
        });

        // --- NEW: Bill Close / Session Logic ---
        // If order is COMPLETED, we close the table session to prevent reuse
        if (status === 'COMPLETED') {
            await (prisma as any).tableSession.updateMany({
                where: {
                    tableId: order.tableId,
                    isActive: true
                },
                data: {
                    isActive: false,
                    status: 'CLOSED'
                }
            });
            console.log(`[Session] Closed session for table ${order.tableId} due to order completion`);
        }

        res.json({ success: true, order: updatedOrder });
    } catch (error) {
        console.error('Update Order Status Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// --- Bidirectional Offline-First Order Sync Endpoint ---
app.post('/api/sync/orders', async (req, res) => {
    const { orders, tables, categories, menuItems, coupons } = req.body;
    let restaurantId: string | null = null;

    // Authenticate: Either via standard JWT or X-Activation-Code header
    const authHeader = req.headers.authorization;
    const activationHeader = req.headers['x-activation-code'];

    if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.split(' ')[1];
        const decoded = verifyToken(token);
        if (decoded && (decoded.role === 'ADMIN' || decoded.role === 'KITCHEN')) {
            restaurantId = decoded.restaurantId;
        }
    } else if (activationHeader) {
        const codeRecord = await (prisma as any).activationCode.findFirst({
            where: {
                code: String(activationHeader),
                status: 'USED'
            },
            include: { restaurant: true }
        });

        if (codeRecord && codeRecord.restaurant && codeRecord.restaurant.status === 'ACTIVE') {
            restaurantId = codeRecord.restaurant.id;
        }
    }

    if (!restaurantId) {
        res.status(401).json({ error: 'Unauthorized: Invalid authentication credentials' });
        return;
    }

    if (!Array.isArray(orders)) {
        res.status(400).json({ error: 'orders must be an array' });
        return;
    }

    try {
        // 1. Sync Categories
        if (Array.isArray(categories)) {
            for (const cat of categories) {
                try {
                    await (prisma as any).category.upsert({
                        where: { id: cat.id },
                        update: {
                            name: cat.name,
                            isActive: cat.isActive,
                            code: cat.code
                        },
                        create: {
                            id: cat.id,
                            name: cat.name,
                            isActive: cat.isActive,
                            code: cat.code,
                            restaurantId,
                            createdAt: cat.createdAt ? new Date(cat.createdAt) : undefined
                        }
                    });
                } catch (err) {
                    console.error(`Failed to sync category ${cat.id} to cloud:`, err);
                }
            }
        }

        // 2. Sync Menu Items
        if (Array.isArray(menuItems)) {
            for (const item of menuItems) {
                try {
                    await (prisma as any).menuItem.upsert({
                        where: { id: item.id },
                        update: {
                            name: item.name,
                            description: item.description,
                            price: parseFloat(item.price),
                            image: item.image,
                            isActive: item.isActive,
                            categoryId: item.categoryId
                        },
                        create: {
                            id: item.id,
                            name: item.name,
                            description: item.description,
                            price: parseFloat(item.price),
                            image: item.image,
                            isActive: item.isActive,
                            categoryId: item.categoryId,
                            restaurantId,
                            createdAt: item.createdAt ? new Date(item.createdAt) : undefined
                        }
                    });
                } catch (err) {
                    console.error(`Failed to sync menu item ${item.id} to cloud:`, err);
                }
            }
        }

        // 3. Sync Tables
        if (Array.isArray(tables)) {
            for (const tbl of tables) {
                try {
                    await (prisma as any).table.upsert({
                        where: { id: tbl.id },
                        update: {
                            label: tbl.label,
                            capacity: tbl.capacity,
                            isActive: tbl.isActive
                        },
                        create: {
                            id: tbl.id,
                            label: tbl.label,
                            capacity: tbl.capacity,
                            isActive: tbl.isActive,
                            restaurantId,
                            createdAt: tbl.createdAt ? new Date(tbl.createdAt) : undefined
                        }
                    });
                } catch (err) {
                    console.error(`Failed to sync table ${tbl.id} to cloud:`, err);
                }
            }
        }

        const syncedCouponIds: string[] = [];

        // 4. Sync Coupons (Configuration Data only from local to cloud)
        if (Array.isArray(coupons)) {
            for (const coupon of coupons) {
                try {
                    await (prisma as any).coupon.upsert({
                        where: { id: coupon.id },
                        update: {
                            code: coupon.code,
                            discountType: coupon.discountType,
                            discountValue: coupon.discountValue,
                            minOrderValue: coupon.minOrderValue,
                            maxDiscount: coupon.maxDiscount,
                            maxUsage: coupon.maxUsage,
                            expiresAt: coupon.expiresAt ? new Date(coupon.expiresAt) : null,
                            status: coupon.status,
                            // NEVER update cloud usageCount from local.
                            updatedAt: coupon.updatedAt ? new Date(coupon.updatedAt) : new Date()
                        },
                        create: {
                            id: coupon.id,
                            code: coupon.code,
                            discountType: coupon.discountType,
                            discountValue: coupon.discountValue,
                            minOrderValue: coupon.minOrderValue,
                            maxDiscount: coupon.maxDiscount,
                            maxUsage: coupon.maxUsage,
                            expiresAt: coupon.expiresAt ? new Date(coupon.expiresAt) : null,
                            status: coupon.status,
                            restaurantId,
                            usageCount: 0,
                            createdAt: coupon.createdAt ? new Date(coupon.createdAt) : new Date(),
                            updatedAt: coupon.updatedAt ? new Date(coupon.updatedAt) : new Date()
                        }
                    });
                    syncedCouponIds.push(coupon.id);
                } catch (err) {
                    console.error(`Failed to sync coupon ${coupon.id} to cloud:`, err);
                }
            }
        }

        const syncedOrderIds: string[] = [];

        for (const localOrder of orders) {
            try {
                // Check if order exists in cloud
                const cloudOrder = await (prisma as any).order.findUnique({
                    where: { id: localOrder.id },
                    include: { items: true }
                });

                if (!cloudOrder) {
                    // Create in cloud
                    await (prisma as any).order.create({
                        data: {
                            id: localOrder.id,
                            restaurantId,
                            tableId: localOrder.tableId,
                            status: localOrder.status,
                            totalAmount: localOrder.totalAmount,
                            subtotal: localOrder.subtotal || 0,
                            gstAmount: localOrder.gstAmount || 0,
                            grandTotal: localOrder.grandTotal || 0,
                            effectiveGstRate: localOrder.effectiveGstRate || null,
                            gstMode: localOrder.gstMode || null,
                            couponId: localOrder.couponId || null,
                            couponCode: localOrder.couponCode || null,
                            couponType: localOrder.couponType || null,
                            couponValue: localOrder.couponValue || null,
                            discountAmount: localOrder.discountAmount || 0,
                            customerId: localOrder.customerId || null,
                            createdAt: new Date(localOrder.createdAt),
                            updatedAt: new Date(localOrder.updatedAt),
                            items: {
                                create: localOrder.items?.map((item: any) => ({
                                    id: item.id,
                                    menuItemId: item.menuItemId,
                                    quantity: item.quantity,
                                    notes: item.notes || null,
                                    createdAt: item.createdAt ? new Date(item.createdAt) : new Date()
                                })) || []
                            }
                        }
                    });
                } else {
                    // Conflict Resolution
                    const localUpdated = new Date(localOrder.updatedAt).getTime();
                    const cloudUpdated = new Date(cloudOrder.updatedAt).getTime();

                    if (localUpdated > cloudUpdated) {
                        // Update cloud status/updatedAt
                        await (prisma as any).order.update({
                            where: { id: localOrder.id },
                            data: {
                                status: localOrder.status,
                                totalAmount: localOrder.totalAmount,
                                subtotal: localOrder.subtotal || 0,
                                gstAmount: localOrder.gstAmount || 0,
                                grandTotal: localOrder.grandTotal || 0,
                                effectiveGstRate: localOrder.effectiveGstRate || null,
                                gstMode: localOrder.gstMode || null,
                                couponId: localOrder.couponId || null,
                                couponCode: localOrder.couponCode || null,
                                couponType: localOrder.couponType || null,
                                couponValue: localOrder.couponValue || null,
                                discountAmount: localOrder.discountAmount || 0,
                                updatedAt: new Date(localOrder.updatedAt)
                            }
                        });
                    }
                }
                syncedOrderIds.push(localOrder.id);
            } catch (err) {
                console.error(`Failed to sync order ${localOrder.id} to cloud:`, err);
            }
        }

        // Fetch all orders from the cloud for this restaurant to sync down to desktop
        const cloudOrders = await (prisma as any).order.findMany({
            where: {
                restaurantId,
                updatedAt: { gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) }
            },
            include: {
                items: {
                    include: { menuItem: true }
                },
                table: true
            }
        });

        // Fetch all coupons from the cloud for this restaurant to sync down to desktop
        const cloudCoupons = await (prisma as any).coupon.findMany({
            where: { restaurantId }
        });

        res.json({
            success: true,
            syncedOrderIds,
            cloudOrders,
            syncedCouponIds,
            cloudCoupons
        });
    } catch (error) {
        console.error('Order Sync Endpoint Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// --- Module 11: Menu Management (Admin) ---
// --- Module 11: Menu Management (Admin) ---
app.get('/api/menu', async (req, res) => {
    try {
        const categories = await (prisma as any).category.findMany({
            where: { isActive: true },
            include: {
                items: {
                    where: { isActive: true },
                    orderBy: { createdAt: 'asc' }
                }
            },
            orderBy: { createdAt: 'asc' }
        });
        res.json({ success: true, categories });
    } catch (error) {
        console.error('Get Menu Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Admin Menu Fetch (Includes inactive/off items)
app.get('/api/admin/menu', authenticate, authorize(['ADMIN', 'KITCHEN']), async (req, res) => {
    try {
        const { restaurantId } = (req as any).user;
        const categories = await (prisma as any).category.findMany({
            // Show all categories, even inactive ones if you want, or just active ones
            // User requested "whatever I delete should go away", so filtering active:
            where: { isActive: true, restaurantId },
            orderBy: { createdAt: 'asc' },
            include: {
                items: {
                    orderBy: { createdAt: 'asc' }
                }
            }
        });
        res.json({ success: true, categories });
    } catch (error) {
        console.error('Get Admin Menu Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.delete('/api/categories/:id', authenticate, authorize(['ADMIN']), async (req, res) => {
    const { id } = req.params;
    try {
        // Check for items in this category
        const itemCount = await (prisma as any).menuItem.count({
            where: { categoryId: id, isActive: true }
        });

        if (itemCount > 0) {
            // Soft delete if items exist
            await (prisma as any).category.update({
                where: { id },
                data: { isActive: false }
            });
            return res.json({ success: true, message: 'Category archived (contained items)' });
        }

        // Hard delete if empty
        await (prisma as any).category.delete({
            where: { id }
        });
        res.json({ success: true });
    } catch (error) {
        console.error('Delete Category Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/api/categories', authenticate, authorize(['ADMIN']), validate({ body: categoryCreateSchema }), async (req, res) => {
    const { name, code } = req.body;
    const { restaurantId } = (req as any).user;
    try {
        const category = await (prisma as any).category.create({
            data: { name, code, restaurantId }
        });
        res.json({ success: true, category });
    } catch (error) {
        console.error('Create Category Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Update Category
app.put('/api/categories/:id', authenticate, authorize(['ADMIN']), async (req, res) => {
    const { id } = req.params;
    const { name, code } = req.body;

    if (!name) {
        return res.status(400).json({ error: 'Category name is required' });
    }

    try {
        const updated = await (prisma as any).category.update({
            where: { id },
            data: { name, code }
        });
        res.json({ success: true, category: updated });
    } catch (error) {
        console.error('Update Category Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/api/menu-items', authenticate, authorize(['ADMIN', 'KITCHEN']), validate({ body: menuItemCreateSchema }), async (req, res) => {
    const { name, description, price, categoryId, image } = req.body;
    const { restaurantId } = (req as any).user;
    try {
        const item = await (prisma as any).menuItem.create({
            data: {
                name,
                description,
                price: parseFloat(price),
                categoryId,
                image,
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
    const { name, description, price, categoryId, image, isActive } = req.body;

    try {
        const data: any = {};
        if (name !== undefined) data.name = name;
        if (description !== undefined) data.description = description;
        if (price !== undefined) data.price = parseFloat(price);
        if (categoryId !== undefined) data.categoryId = categoryId;
        if (image !== undefined) data.image = image;
        if (isActive !== undefined) {
            // Handle boolean or string 'true'/'false'
            if (typeof isActive === 'boolean') {
                data.isActive = isActive;
            } else if (typeof isActive === 'string') {
                data.isActive = isActive.toLowerCase() === 'true';
            }
        }

        const item = await (prisma as any).menuItem.update({
            where: { id },
            data
        });
        res.json({ success: true, item });
    } catch (error) {
        console.error('Update Menu Item Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.delete('/api/menu-items/:id', authenticate, authorize(['ADMIN', 'KITCHEN']), async (req, res) => {
    const { id } = req.params;
    try {
        const orderCount = await (prisma as any).orderItem.count({
            where: { menuItemId: id }
        });

        if (orderCount > 0) {
            const item = await (prisma as any).menuItem.update({
                where: { id },
                data: { isActive: false }
            });
            return res.json({ success: true, message: 'Item archived due to history', item });
        }

        await (prisma as any).menuItem.delete({
            where: { id }
        });
        res.json({ success: true });
    } catch (error) {
        console.error('Delete Menu Item Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// --- Module 12: Dashboard & Analytics (Admin) ---
app.get('/api/admin/stats', authenticate, authorize(['ADMIN']), async (req, res) => {
    try {
        // Defensive: Check if models exist before querying
        let activeOrdersCount = 0;
        let completedOrdersCount = 0;
        let totalTables = 0;
        let activeTables = 0;

        // Try to count orders if the model exists
        if ((prisma as any).order) {
            try {
                activeOrdersCount = await (prisma as any).order.count({
                    where: {
                        status: { in: ['RECEIVED', 'PREPARING', 'READY'] }
                    }
                });
                completedOrdersCount = await (prisma as any).order.count({
                    where: { status: { in: ['COMPLETED', 'SERVED'] } }
                });
            } catch { /* Model may not exist in DB */ }
        }

        // Try to count tables if the model exists
        if ((prisma as any).table) {
            try {
                totalTables = await (prisma as any).table.count();
                activeTables = await (prisma as any).table.count({ where: { isActive: true } });
            } catch { /* Model may not exist in DB */ }
        }

        // Table utilization (very basic: active tables / total tables)
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

// 1️⃣ QR Validation & Session Creation
app.post('/api/customer/session/init', validate({ body: customerSessionSchema }), async (req, res) => {
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

        // STRICT CHECK: Restaurant Status must be ACTIVE or GRACE
        if (restaurant.status !== 'ACTIVE' && restaurant.status !== 'GRACE') {
            res.status(403).json({ error: 'Restaurant is currently unavailable' });
            return;
        }

        const table = await (prisma as any).table.findUnique({
            where: { id: tableId }
        });

        if (!table || !table.isActive || table.restaurantId !== restaurantId) {
            res.status(400).json({ error: 'Table is not available or does not belong to this restaurant' });
            return;
        }

        // --- NEW: Table Session Logic ---
        const session = await getOrCreateTableSession(tableId, restaurantId);

        // Create a temporary session token linked to session ID
        const token = generateToken({
            role: 'CUSTOMER',
            restaurantId,
            tableId,
            sessionId: session.id // NEW: Bind token to session
        });

        // Set HttpOnly access cookie for the customer session
        const options = getCookieOptions(req);
        res.cookie('accessToken', token, { ...options, maxAge: 20 * 60 * 1000 }); // 20m

        res.json({
            success: true,
            token, // Kept in body for backwards compatibility with non-cookie fallback, but client won't store in localStorage
            sessionId: session.id, // Return explicitly?
            restaurantName: restaurant.name,
            tableNumber: table.label || table.id.substring(0, 4).toUpperCase(),
            gstEnabled: restaurant.gstEnabled,
            gstMode: restaurant.gstMode,
            defaultGstRate: restaurant.defaultGstRate
        });
    } catch (error) {
        console.error('Session Init Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// 1.5️⃣ Combined Table Info + Session + Menu (for path-based QR routing)
// GET /api/customer/table/:tableId - Resolves table, creates session, returns menu
app.get('/api/customer/table/:tableId', async (req, res) => {
    const { tableId } = req.params;

    if (!tableId) {
        res.status(400).json({ error: 'Table ID is required' });
        return;
    }

    try {
        // 1. Fetch table with restaurant
        const table = await (prisma as any).table.findUnique({
            where: { id: tableId },
            include: { restaurant: true }
        });

        if (!table) {
            res.status(404).json({ error: 'Table not found. Please scan a valid QR code.' });
            return;
        }

        if (!table.isActive) {
            res.status(400).json({ error: 'This table is not currently active.' });
            return;
        }

        const restaurant = table.restaurant;
        if (!restaurant || (restaurant.status !== 'ACTIVE' && restaurant.status !== 'GRACE')) {
            res.status(403).json({ error: 'Restaurant is currently unavailable.' });
            return;
        }

        // --- NEW: Table Session Logic ---
        const session = await getOrCreateTableSession(table.id, restaurant.id);

        // 2. Create session token linked to session ID
        const token = generateToken({
            role: 'CUSTOMER',
            restaurantId: restaurant.id,
            tableId: table.id,
            sessionId: session.id
        });

        // Set HttpOnly access cookie for the customer session
        const options = getCookieOptions(req);
        res.cookie('accessToken', token, { ...options, maxAge: 20 * 60 * 1000 }); // 20m

        // 3. Fetch menu categories with items
        const categories = await (prisma as any).category.findMany({
            where: {
                restaurantId: restaurant.id,
                isActive: true
            },
            include: {
                items: {
                    where: { isActive: true }
                }
            }
        });

        // 4. Return combined response
        res.json({
            success: true,
            token, // Kept in body for compatibility, but client won't store in localStorage
            sessionId: session.id, // Explicit return
            restaurant: {
                id: restaurant.id,
                name: restaurant.name,
                gstEnabled: restaurant.gstEnabled,
                gstMode: restaurant.gstMode,
                defaultGstRate: restaurant.defaultGstRate
            },
            table: {
                id: table.id,
                number: table.label || table.id.substring(0, 4).toUpperCase()
            },
            categories
        });

    } catch (error) {
        console.error('Table Info Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// 2️⃣ Fetch Menu for Customer
app.get('/api/customer/menu/:restaurantId', async (req, res) => {
    const { restaurantId } = req.params;

    try {
        // STRICT CHECK: Ensure restaurant is ACTIVE before returning menu
        const restaurant = await prisma.restaurant.findUnique({
            where: { id: restaurantId }
        });

        if (!restaurant || ((restaurant as any).status !== 'ACTIVE' && (restaurant as any).status !== 'GRACE')) {
            res.status(403).json({ error: 'Restaurant is currently unavailable' });
            return;
        }

        const categories = await (prisma as any).category.findMany({
            where: {
                restaurantId,
                isActive: true
            },
            include: {
                items: {
                    where: {
                        isActive: true
                    }
                }
            }
        });

        res.json({ success: true, categories });
    } catch (error) {
        console.error('Customer Menu Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// 3️⃣ Create Order (Customer)
app.post('/api/customer/orders', authenticate, authorize(['CUSTOMER']), validateTableSession, validate({ body: customerOrderSchema }), async (req, res) => {
    const { items, idempotencyKey, tableId: bodyTableId, deviceToken, couponCode } = req.body;
    const { restaurantId, tableId: tokenTableId } = (req as any).user;

    // Use tableId from token (preferred) or body (fallback)
    const tableId = tokenTableId || bodyTableId;

    if (!items || !Array.isArray(items) || items.length === 0) {
        res.status(400).json({ error: 'No items provided' });
        return;
    }

    if (!tableId) {
        res.status(400).json({ error: 'Table ID is missing. Please re-scan QR code.' });
        return;
    }

    try {
        // STRICT CHECK: Validate Restaurant Status Live
        const restaurant = await prisma.restaurant.findUnique({
            where: { id: restaurantId }
        });

        if (!restaurant || ((restaurant as any).status !== 'ACTIVE' && (restaurant as any).status !== 'GRACE')) {
            res.status(403).json({ error: 'Restaurant is currently unavailable' });
            return;
        }

        // Use Prisma Transaction for order creation and coupon consumption
        const order = await prisma.$transaction(async (tx: any) => {
            // Prevent duplicates - check recent orders (10s window) for same table
            const recentOrder = await tx.order.findFirst({
                where: {
                    tableId,
                    createdAt: {
                        gt: new Date(Date.now() - 10 * 1000)
                    }
                }
            });

            if (recentOrder) {
                throw new Error('Duplicate order detected. Please wait a moment.');
            }

            // Server-side validation of menu items and calculation of totalAmount
            const dbItems = await tx.menuItem.findMany({
                where: {
                    id: { in: items.map((i: any) => i.menuItemId) },
                    restaurantId
                }
            });

            if (dbItems.length !== items.length) {
                throw new Error('Some ordered items are invalid or unavailable');
            }

            let calculatedTotal = 0;
            const itemCreates = [];

            for (const item of items) {
                const dbItem = dbItems.find((m: any) => m.id === item.menuItemId);
                if (!dbItem || !dbItem.isActive) {
                    throw new Error(`Item ${item.menuItemId} is not currently active`);
                }
                calculatedTotal += dbItem.price * item.quantity;
                itemCreates.push({
                    menuItemId: item.menuItemId,
                    quantity: item.quantity
                });
            }
            
            // --- Coupon Validation & Application ---
            let finalDiscountAmount = 0;
            let appliedCoupon = null;

            if (couponCode) {
                const normalizedCode = couponCode.trim().toUpperCase();
                const coupon = await tx.coupon.findFirst({
                    where: { code: normalizedCode, restaurantId }
                });

                if (!coupon) {
                    throw new Error('Coupon not found for this restaurant');
                }
                if (coupon.status !== 'ACTIVE') {
                    throw new Error('Coupon is disabled');
                }
                if (coupon.expiresAt && new Date(coupon.expiresAt) < new Date()) {
                    throw new Error('Coupon has expired');
                }
                if (coupon.maxUsage && coupon.usageCount >= coupon.maxUsage) {
                    throw new Error('Coupon usage limit reached');
                }
                if (coupon.minOrderValue && calculatedTotal < coupon.minOrderValue) {
                    throw new Error(`Minimum order of ₹${coupon.minOrderValue} required`);
                }

                if (coupon.discountType === 'PERCENTAGE') {
                    finalDiscountAmount = calculatedTotal * (coupon.discountValue / 100);
                    if (coupon.maxDiscount && finalDiscountAmount > coupon.maxDiscount) {
                        finalDiscountAmount = coupon.maxDiscount;
                    }
                } else if (coupon.discountType === 'FLAT') {
                    finalDiscountAmount = coupon.discountValue;
                }

                if (finalDiscountAmount > calculatedTotal) {
                    finalDiscountAmount = calculatedTotal;
                }
                
                appliedCoupon = coupon;

                // Increment usage counter inside transaction
                await tx.coupon.update({
                    where: { id: coupon.id },
                    data: { usageCount: { increment: 1 } }
                });
            }

            // Handle Customer / Device Token
            let customerId: string | undefined;

            if (deviceToken) {
                let customer = await tx.customer.findUnique({
                    where: {
                        deviceToken_restaurantId: {
                            deviceToken,
                            restaurantId
                        }
                    }
                });

                if (!customer) {
                    customer = await tx.customer.create({
                        data: {
                            deviceToken,
                            restaurantId
                        }
                    });
                }
                customerId = customer.id;
            }

            const platformFee = 10;
            let subtotal = calculatedTotal;
            let taxableAmount = Math.max(0, subtotal - finalDiscountAmount);
            let gstAmount = 0;
            let grandTotal = taxableAmount + platformFee;
            let effectiveGstRate = null;
            let gstMode = null;

            if ((restaurant as any).gstEnabled) {
                effectiveGstRate = (restaurant as any).defaultGstRate || 5;
                gstMode = (restaurant as any).gstMode || 'EXCLUSIVE';

                if (gstMode === 'EXCLUSIVE') {
                    gstAmount = taxableAmount * (effectiveGstRate / 100);
                    grandTotal = taxableAmount + gstAmount + platformFee;
                } else {
                    gstAmount = taxableAmount - (taxableAmount / (1 + effectiveGstRate / 100));
                    grandTotal = taxableAmount + platformFee; 
                }
            }

            return await tx.order.create({
                data: {
                    restaurantId,
                    tableId,
                    customerId,
                    totalAmount: grandTotal,
                    subtotal: subtotal,
                    gstAmount: gstAmount,
                    grandTotal: grandTotal,
                    effectiveGstRate: effectiveGstRate,
                    gstMode: gstMode,
                    status: 'RECEIVED',
                    couponId: appliedCoupon?.id || null,
                    couponCode: appliedCoupon?.code || null,
                    couponType: appliedCoupon?.discountType || null,
                    couponValue: appliedCoupon?.discountValue || null,
                    discountAmount: finalDiscountAmount,
                    items: {
                        create: itemCreates
                    }
                },
                include: { items: true }
            });
        });

        res.json({ success: true, order });
    } catch (error: any) {
        console.error('Create Order Error:', error);
        // Distinguish business logic errors from Prisma Transaction errors
        if (error.message && !error.message.includes('prisma')) {
             res.status(400).json({ error: error.message });
        } else {
             res.status(500).json({ error: 'Internal Server Error' });
        }
    }
});

// 3.5 Customer Order History
app.get('/api/customer/orders/history', authenticate, authorize(['CUSTOMER']), validateTableSession, async (req, res) => {
    const { deviceToken } = req.query;
    const { restaurantId } = (req as any).user;

    if (!deviceToken || typeof deviceToken !== 'string') {
        res.status(400).json({ error: 'Device token is required' });
        return;
    }

    try {
        const customer = await prisma.customer.findUnique({
            where: {
                deviceToken_restaurantId: {
                    deviceToken,
                    restaurantId
                }
            },
            include: {
                orders: {
                    orderBy: { createdAt: 'desc' },
                    include: {
                        items: {
                            include: { menuItem: true }
                        },
                        table: {
                            select: { label: true }
                        }
                    }
                }
            }
        });

        if (!customer) {
            res.json({ success: true, orders: [] });
            return;
        }

        res.json({ success: true, orders: customer.orders });
    } catch (error) {
        console.error('Order History Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// 4️⃣ Customer Order Status Tracking
app.get('/api/customer/orders/:orderId', authenticate, authorize(['CUSTOMER']), validateTableSession, async (req, res) => {
    const { orderId } = req.params;
    const { tableId } = (req as any).user;

    try {
        const order = await (prisma as any).order.findUnique({
            where: { id: orderId },
            select: {
                id: true,
                status: true,
                totalAmount: true,
                tableId: true,
                createdAt: true
            }
        });

        if (!order || order.tableId !== tableId) {
            res.status(404).json({ error: 'Order not found' });
            return;
        }

        // STRICT CHECK: Validate Restaurant Status Live
        const restaurant = await prisma.restaurant.findUnique({
            where: { id: (req as any).user.restaurantId } // Using session info
        });

        if (!restaurant || ((restaurant as any).status !== 'ACTIVE' && (restaurant as any).status !== 'GRACE')) {
            res.status(403).json({ error: 'Restaurant is currently unavailable' });
            return;
        }

        // Map internal statuses to customer-friendly statuses if needed
        // For now, we return the internal status but filtered via 'select'
        res.json({ success: true, order });
    } catch (error) {
        console.error('Order Status Tracking Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// 5️⃣ Add More Items
app.post('/api/customer/orders/:orderId/add-items', authenticate, authorize(['CUSTOMER']), validateTableSession, validate({ body: addItemsSchema }), async (req, res) => {
    const { orderId } = req.params;
    const { items } = req.body;
    const { tableId } = (req as any).user;

    try {
        const order = await (prisma as any).order.findUnique({
            where: { id: orderId },
            include: { items: true }
        });

        if (!order || order.tableId !== tableId) {
            res.status(404).json({ error: 'Order not found' });
            return;
        }

        // STRICT CHECK: Validate Restaurant Status Live
        const restaurant = await prisma.restaurant.findUnique({
            where: { id: (req as any).user.restaurantId }
        });

        if (!restaurant || ((restaurant as any).status !== 'ACTIVE' && (restaurant as any).status !== 'GRACE')) {
            res.status(403).json({ error: 'Restaurant is currently unavailable' });
            return;
        }

        if (['SERVED', 'COMPLETED', 'CANCELLED'].includes(order.status)) {
            res.status(400).json({ error: 'Cannot add items to a completed or cancelled order' });
            return;
        }

        // Server-side validation and calculation of additional amount
        const dbItems = await prisma.menuItem.findMany({
            where: {
                id: { in: items.map((i: any) => i.menuItemId) },
                restaurantId: (req as any).user.restaurantId
            }
        });

        if (dbItems.length !== items.length) {
            res.status(400).json({ error: 'Some added items are invalid or unavailable' });
            return;
        }

        let calculatedAdditional = 0;
        const itemCreates = [];

        for (const item of items) {
            const dbItem = dbItems.find(m => m.id === item.menuItemId);
            if (!dbItem || !dbItem.isActive) {
                res.status(400).json({ error: `Item ${item.menuItemId} is not active` });
                return;
            }
            calculatedAdditional += dbItem.price * item.quantity;
            itemCreates.push({
                menuItemId: item.menuItemId,
                quantity: item.quantity
            });
        }

        const updatedOrder = await (prisma as any).order.update({
            where: { id: orderId },
            data: {
                totalAmount: order.totalAmount + calculatedAdditional,
                items: {
                    create: itemCreates
                }
            },
            include: { items: true }
        });

        res.json({ success: true, order: updatedOrder });
    } catch (error) {
        console.error('Add Items Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// 6️⃣ Exit Customer Session (Proper Logout)
app.post('/api/customer/session/exit', authenticate, authorize(['CUSTOMER']), async (req, res) => {
    const { sessionId } = (req as any).user;
    try {
        if (sessionId) {
            await (prisma as any).tableSession.update({
                where: { id: sessionId },
                data: { isActive: false, status: 'CLOSED' }
            });
        }
        const options = getCookieOptions(req);
        res.clearCookie('accessToken', options);
        res.json({ success: true, message: 'Customer session terminated' });
    } catch (error) {
        console.error('Customer Session Exit Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// --- DEBUG route removed for production security ---

// =============================================================================
// MODULE 14: System Status Check (App Boot)
// =============================================================================
app.get('/api/device/status', async (req, res) => {
    try {
        const { restaurantId } = req.query;
        const restaurant = await prisma.restaurant.findFirst({
            select: {
                id: true,
                name: true,
                isActive: true,
                status: true
            }
        });

        if (!restaurant) {
            res.json({
                isActivated: false,
                restaurantStatus: null,
                forceActivation: true,
                resetReason: 'NOT_FOUND'
            });
            return;
        }

        // STRICT CHECK: If client thinks it's Restaurant A, but we are Restaurant B, force reset.
        if (restaurantId && restaurantId !== restaurant.id) {
            res.json({
                isActivated: false,
                restaurantStatus: 'MISMATCH',
                forceActivation: true,
                resetReason: 'MISMATCH'
            });
            return;
        }

        const isRevoked = restaurant.status === 'REVOKED' || restaurant.status === 'SUSPENDED';
        const forceActivation = !restaurant.isActive || isRevoked;

        res.json({
            isActivated: restaurant.isActive,
            restaurantStatus: restaurant.status,
            forceActivation,
            resetReason: isRevoked ? restaurant.status : null
        });

    } catch (error) {
        console.error('System Status Check Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// --- Entity Deletion Saga (Cloud Entry Point) ---
import { EntityDeletionManager } from './saga/EntityDeletionManager';

app.delete('/api/admin/restaurants/:id', authenticate, authorize(['SUPER_ADMIN']), async (req, res) => {
    const { id } = req.params;
    const { reason } = req.body;
    const initiatedBy = (req as any).user?.id || 'SUPER_ADMIN';

    try {
        const restaurant = await prisma.restaurant.findUnique({ where: { id } });
        if (!restaurant) {
            return res.status(404).json({ error: 'Restaurant not found' });
        }
        
        if (restaurant.status === 'DELETED') {
            return res.json({ success: true, message: 'Restaurant already deleted' });
        }

        // Trigger the Saga Orchestrator for the Cloud
        // In a true hybrid setup, Cloud and Desktop share the same orchestrator logic 
        // with different Delete Policies.
        await EntityDeletionManager.initiateDeletionSaga(id, initiatedBy, reason || 'Cloud Admin Deletion', id);
        
        // Return 202 Accepted as the Saga is asynchronous
        res.status(202).json({ success: true, message: 'Entity deletion saga initiated.' });
    } catch (error) {
        console.error('Failed to initiate deletion saga:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// --- Coupon Routes ---
app.use('/api/coupons', couponRoutes);

// --- Health Check ---
app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date() });
});

// --- Catch-All 404 Handler (Debug) ---
app.use((req, res) => {
    res.status(404).json({
        error: 'Route not found',
        path: req.path,
        url: req.url,
        originalUrl: req.originalUrl,
        method: req.method,
        timestamp: new Date()
    });
});

// --- Export for Vercel Serverless ---
export default app;

// --- Start Server (only when not in Vercel) ---
if (process.env.VERCEL !== '1') {
    app.listen(PORT, () => {
        console.log(`Server running on http://localhost:${PORT}`);
    });
}
