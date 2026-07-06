import express from 'express';
import { verifyToken } from '../utils/auth';
import { prisma } from '../utils/prisma';
import jwt from 'jsonwebtoken';

// Helper to extract cookies without third-party cookie-parser
function getCookie(req: express.Request, name: string): string | null {
    const cookieHeader = req.headers.cookie;
    if (!cookieHeader) return null;
    const cookies = cookieHeader.split(';');
    for (const cookie of cookies) {
        const [key, value] = cookie.trim().split('=');
        if (key === name) return decodeURIComponent(value);
    }
    return null;
}

export const authenticate = async (req: express.Request, res: express.Response, next: express.NextFunction): Promise<void> => {
    // 1. Try to get token from httpOnly cookie first, fallback to Authorization header
    let token = getCookie(req, 'accessToken');
    const authHeader = req.headers.authorization;

    if (!token) {
        if (authHeader && authHeader.startsWith('Bearer ')) {
            token = authHeader.split(' ')[1];
        }
    }

    // Decode token without verification to extract details for debugging
    let decodedPayload: any = null;
    if (token) {
        try {
            decodedPayload = jwt.decode(token);
        } catch (e) {}
    }

    if (!token) {
        const rejectionReason = 'No token provided in cookies or Authorization header';
        console.warn('[Auth Middleware Rejection]', {
            path: req.path,
            receivedAuthHeader: authHeader ? authHeader.substring(0, 20) + '...' : 'none',
            decodedTokenPayload: null,
            tokenExpiry: null,
            rejectionReason,
            initializationContext: null,
            activationContext: null
        });
        res.status(401).json({ error: `Unauthorized: ${rejectionReason}` });
        return;
    }

    const decoded = verifyToken(token);

    if (!decoded) {
        const tokenExpiry = decodedPayload && decodedPayload.exp ? new Date(decodedPayload.exp * 1000).toISOString() : 'unknown';
        const rejectionReason = 'Invalid or expired token signature';
        
        // Load active restaurant context to log activation/initialization details
        const activeRestaurant = await prisma.restaurant.findFirst({
            where: { status: { in: ['ACTIVE', 'GRACE'] } },
            orderBy: { createdAt: 'desc' }
        });

        console.warn('[Auth Middleware Rejection]', {
            path: req.path,
            receivedAuthHeader: authHeader ? authHeader.substring(0, 20) + '...' : 'none',
            decodedTokenPayload: decodedPayload,
            tokenExpiry,
            rejectionReason,
            initializationContext: activeRestaurant ? {
                restaurantId: activeRestaurant.id,
                name: activeRestaurant.name,
                hasAdminPin: !!activeRestaurant.adminPin,
                hasKitchenPin: !!activeRestaurant.kitchenPin
            } : 'none',
            activationContext: activeRestaurant ? {
                status: activeRestaurant.status,
                isActive: activeRestaurant.isActive
            } : 'none'
        });

        res.status(401).json({ error: 'Unauthorized: Invalid or expired token', code: 'TOKEN_EXPIRED' });
        return;
    }

    try {
        // 2. Global Restaurant Status Check
        const restaurant = await prisma.restaurant.findUnique({
            where: { id: decoded.restaurantId },
            select: { id: true, status: true, isActive: true, name: true, adminPin: true, kitchenPin: true }
        });

        if (!restaurant) {
            const rejectionReason = `Restaurant not found for ID ${decoded.restaurantId}`;
            console.warn('[Auth Middleware Rejection]', {
                path: req.path,
                receivedAuthHeader: authHeader ? authHeader.substring(0, 20) + '...' : 'none',
                decodedTokenPayload: decoded,
                tokenExpiry: decoded && (decoded as any).exp ? new Date((decoded as any).exp * 1000).toISOString() : 'unknown',
                rejectionReason,
                initializationContext: null,
                activationContext: null
            });
            res.status(401).json({ error: `Unauthorized: ${rejectionReason}` });
            return;
        }

        if ((restaurant as any).status !== 'ACTIVE' && (restaurant as any).status !== 'GRACE') {
            const rejectionReason = `Restaurant status is not active (status: ${(restaurant as any).status})`;
            console.warn('[Auth Middleware Rejection]', {
                path: req.path,
                receivedAuthHeader: authHeader ? authHeader.substring(0, 20) + '...' : 'none',
                decodedTokenPayload: decoded,
                tokenExpiry: decoded && (decoded as any).exp ? new Date((decoded as any).exp * 1000).toISOString() : 'unknown',
                rejectionReason,
                initializationContext: {
                    restaurantId: restaurant.id,
                    name: restaurant.name,
                    hasAdminPin: !!restaurant.adminPin,
                    hasKitchenPin: !!restaurant.kitchenPin
                },
                activationContext: {
                    status: restaurant.status,
                    isActive: restaurant.isActive
                }
            });
            res.status(403).json({ error: `Access Denied: ${rejectionReason}` });
            return;
        }

        // 3. Strict Device Invalidation Check for Admin & Kitchen (bypass for initial-setup)
        if ((decoded.role === 'ADMIN' || decoded.role === 'KITCHEN') && decoded.deviceId && decoded.deviceId !== 'initial-setup') {
            const device = await prisma.device.findFirst({
                where: {
                    deviceId: decoded.deviceId,
                    restaurantId: decoded.restaurantId,
                    role: decoded.role
                }
            });

            if (!device || device.status !== 'ACTIVE') {
                const rejectionReason = `Device ${decoded.deviceId} has been revoked or deactivated`;
                console.warn('[Auth Middleware Rejection]', {
                    path: req.path,
                    receivedAuthHeader: authHeader ? authHeader.substring(0, 20) + '...' : 'none',
                    decodedTokenPayload: decoded,
                    tokenExpiry: decoded && (decoded as any).exp ? new Date((decoded as any).exp * 1000).toISOString() : 'unknown',
                    rejectionReason,
                    initializationContext: {
                        restaurantId: restaurant.id,
                        name: restaurant.name,
                        hasAdminPin: !!restaurant.adminPin,
                        hasKitchenPin: !!restaurant.kitchenPin
                    },
                    activationContext: {
                        status: restaurant.status,
                        isActive: restaurant.isActive
                    }
                });
                res.status(401).json({ error: `Unauthorized: ${rejectionReason}` });
                return;
            }
        }

        (req as any).user = decoded;
        next();
    } catch (error) {
        console.error('Auth Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
};

export const authorize = (roles: string[]) => {
    return (req: express.Request, res: express.Response, next: express.NextFunction) => {
        const user = (req as any).user;
        if (!user || !roles.includes(user.role)) {
            res.status(403).json({ error: 'Forbidden: Insufficient permissions' });
            return;
        }
        next();
    };
};

// --- Dedicated Table Session Validation Middleware ---
export const validateTableSession = async (req: express.Request, res: express.Response, next: express.NextFunction): Promise<void> => {
    const user = (req as any).user;

    if (!user || !user.sessionId) {
        res.status(401).json({ error: 'Session invalid. Please re-scan QR.', code: 'SESSION_INVALID' });
        return;
    }

    try {
        const session = await (prisma as any).tableSession.findUnique({
            where: { id: user.sessionId }
        });

        if (!session || !session.isActive || session.status !== 'ACTIVE') {
            res.status(401).json({ error: 'Session expired. Please re-scan QR.', code: 'SESSION_EXPIRED' });
            return;
        }

        if (session.expiresAt < new Date()) {
            await (prisma as any).tableSession.update({
                where: { id: session.id },
                data: { isActive: false, status: 'EXPIRED' }
            });
            res.status(401).json({ error: 'Session expired. Please re-scan QR.', code: 'SESSION_EXPIRED' });
            return;
        }

        const TABLE_SESSION_TIMEOUT = 1200 * 1000;
        await (prisma as any).tableSession.update({
            where: { id: session.id },
            data: { expiresAt: new Date(Date.now() + TABLE_SESSION_TIMEOUT) }
        });

        next();
    } catch (error) {
        console.error('Session Validation Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
};
