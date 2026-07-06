import { z } from 'zod';

// --- Common Validators ---

/** CUID/UUID-like ID validator (permissive: 20-36 chars alphanumeric with hyphens/underscores) */
const idString = z.string().min(1).max(128).regex(/^[a-zA-Z0-9_-]+$/, 'Invalid ID format');

/** Strict enum for user roles */
const roleEnum = z.enum(['ADMIN', 'KITCHEN', 'CUSTOMER', 'RECOVERY', 'SUPER_ADMIN', 'WAITER']);

/** Safe string: no control characters, limited length */
const safeString = (maxLen = 255) => z.string().min(1).max(maxLen).regex(/^[^\x00-\x1F]*$/, 'Contains invalid characters');

/** PIN: digits only */
const pinString = (minLen = 4, maxLen = 12) => z.string().min(minLen).max(maxLen).regex(/^\d+$/, 'PIN must contain only digits');

/** Email (optional, permissive) */
const optionalEmail = z.string().email().max(320).optional().or(z.literal(''));

// --- Endpoint Schemas ---

// Activation
export const activateSchema = z.object({
    activationCode: z.string().min(1).max(32)
});

// License Verify
export const licenseVerifySchema = z.object({
    activationCode: z.string().min(1).max(32)
});

// License Status
export const licenseStatusSchema = z.object({
    restaurantId: idString
});

// Login
export const loginSchema = z.object({
    pin: pinString(4, 12),
    role: z.enum(['ADMIN', 'KITCHEN']),
    deviceId: safeString(128)
});

// Setup PIN
export const setupPinSchema = z.object({
    restaurantId: idString,
    adminPin: pinString(6, 12),
    kitchenPin: pinString(4, 12).optional()
});

// Pair Code Verify
export const pairCodeVerifySchema = z.object({
    pairCode: z.string().min(1).max(16).regex(/^[A-Za-z0-9-]+$/, 'Invalid pair code format'),
    deviceId: safeString(128)
});

// Owner Link
export const ownerLinkSchema = z.object({
    restaurantId: idString,
    ownerId: safeString(128),
    ownerName: safeString(255).optional(),
    ownerEmail: optionalEmail
});

// Create Subscription
export const createSubscriptionSchema = z.object({
    restaurantId: idString,
    planId: safeString(128)
});

// Verify Subscription
export const verifySubscriptionSchema = z.object({
    razorpay_payment_id: safeString(128),
    razorpay_subscription_id: safeString(128),
    razorpay_signature: z.string().min(1).max(512),
    restaurantId: idString,
    planType: z.enum(['MONTHLY', 'YEARLY']).optional()
});

// Device Sync
export const deviceSyncSchema = z.object({
    restaurantId: idString,
    deviceId: safeString(128),
    role: safeString(32),
    status: safeString(32).optional(),
    type: safeString(32).optional()
});

// Table Create/Update
export const tableCreateSchema = z.object({
    label: safeString(64),
    capacity: z.number().int().positive().max(100).optional()
});

export const tableUpdateSchema = z.object({
    label: safeString(64).optional(),
    capacity: z.union([z.number().int().positive().max(100), z.string().regex(/^\d+$/)]).optional()
});

export const tableStatusSchema = z.object({
    isActive: z.boolean()
});

// Category
export const categoryCreateSchema = z.object({
    name: safeString(128),
    code: safeString(32).optional()
});

export const categoryUpdateSchema = z.object({
    name: safeString(128),
    code: safeString(32).optional()
});

// Menu Item Create
export const menuItemCreateSchema = z.object({
    name: safeString(255),
    description: safeString(2000).optional(),
    price: z.union([z.number().nonnegative(), z.string().regex(/^\d+(\.\d+)?$/)]),
    categoryId: idString,
    image: z.string().max(5000).optional()
});

// Menu Item Update
export const menuItemUpdateSchema = z.object({
    name: safeString(255).optional(),
    description: safeString(2000).optional().nullable(),
    price: z.union([z.number().nonnegative(), z.string().regex(/^\d+(\.\d+)?$/)]).optional(),
    categoryId: idString.optional(),
    image: z.string().max(5000).optional().nullable(),
    isActive: z.union([z.boolean(), z.string()]).optional()
});

// Order Status Update
export const orderStatusSchema = z.object({
    status: z.enum(['RECEIVED', 'PREPARING', 'READY', 'SERVED', 'COMPLETED', 'CANCELLED'])
});

// Customer Session Init
export const customerSessionSchema = z.object({
    restaurantId: idString,
    tableId: idString
});

// Customer Order Items
export const customerOrderSchema = z.object({
    items: z.array(z.object({
        menuItemId: idString,
        quantity: z.number().int().positive().max(100)
    })).min(1).max(50),
    idempotencyKey: z.string().max(128).optional(),
    tableId: idString.optional(),
    deviceToken: z.string().max(512).optional()
});

// Add Items to Order
export const addItemsSchema = z.object({
    items: z.array(z.object({
        menuItemId: idString,
        quantity: z.number().int().positive().max(100)
    })).min(1).max(50)
});

// License Management (Admin)
export const createLicenseSchema = z.object({
    entityName: safeString(255),
    plan: z.string().max(32).optional(),
    durationDays: z.number().int().positive().max(3650).optional(),
    maxTables: z.number().int().positive().max(1000).optional()
});

export const linkRestaurantSchema = z.object({
    entityName: safeString(255).optional()
});

// Security: Verify Admin PIN
export const verifyAdminPinSchema = z.object({
    adminPin: pinString(4, 12)
});

// Security: Update Kitchen PIN
export const updateKitchenPinSchema = z.object({
    adminPin: pinString(4, 12),
    newKitchenPin: pinString(4, 12)
});

// Desktop Session
export const desktopSessionSchema = z.object({
    avatarUrl: z.string().url().max(2000).optional().or(z.literal('')),
    fullName: safeString(255).optional(),
    email: optionalEmail,
    role: safeString(32).optional()
});

// Exchange Desktop Token
export const exchangeDesktopTokenSchema = z.object({
    token: z.string().min(1).max(8192)
});

// ID Param Schema (for :id in route params)
export const idParamSchema = z.object({
    id: idString
});

// Restaurant ID Query Schema
export const restaurantIdQuerySchema = z.object({
    restaurantId: idString
});

// Table ID Param Schema
export const tableIdParamSchema = z.object({
    tableId: idString
});

// Order ID Param Schema
export const orderIdParamSchema = z.object({
    orderId: idString
});

// Restaurant ID Param Schema
export const restaurantIdParamSchema = z.object({
    restaurantId: idString
});

// Device Token Query Schema
export const deviceTokenQuerySchema = z.object({
    deviceToken: z.string().min(1).max(512)
});
