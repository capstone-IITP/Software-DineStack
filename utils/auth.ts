import jwt from 'jsonwebtoken';
import crypto from 'crypto';

// Dynamically generate a fallback secret if not provided in env.
// This ensures that if the environment variable is missing, tokens
// are signed securely and cannot be forged, though they will invalidate on server restart.
export let runtimeSecret = process.env.JWT_SECRET;
if (!runtimeSecret) {
    runtimeSecret = crypto.randomBytes(64).toString('hex');
    console.warn('⚠️ WARNING: JWT_SECRET environment variable is missing. Using a dynamically generated ephemeral secret. Sessions will invalidate on restart.');
}

export interface DeviceTokenPayload {
    deviceId?: string;
    role: 'ADMIN' | 'KITCHEN' | 'CUSTOMER' | 'RECOVERY';
    restaurantId: string;
    tableId?: string;
    sessionId?: string;
    purpose?: string;
}

// Access tokens are short-lived (15 minutes)
export const generateToken = (payload: DeviceTokenPayload) => {
    const expiry = payload.purpose === 'PIN_RESET' ? '5m' : '15m';
    return jwt.sign(payload, runtimeSecret as string, { expiresIn: expiry });
};

// Verify JWT Access Token
export const verifyToken = (token: string): DeviceTokenPayload | null => {
    try {
        // Try verifying with the global system secret first
        try {
            return jwt.verify(token, runtimeSecret as string) as DeviceTokenPayload;
        } catch (error) {
            // If it fails, decode to check for a restaurantId (desktop tokens are signed with a derived secret)
            const decoded = jwt.decode(token) as any;
            if (decoded && decoded.restaurantId) {
                const restaurantJwtSecret = crypto.createHmac('sha256', runtimeSecret as string).update(decoded.restaurantId).digest('hex');
                return jwt.verify(token, restaurantJwtSecret) as DeviceTokenPayload;
            }
            throw error; // Rethrow if no fallback is possible
        }
    } catch (error) {
        return null;
    }
};

// Generate cryptographically secure Refresh Token
export const generateRefreshToken = (): string => {
    return crypto.randomBytes(40).toString('hex');
};

// Hash Refresh Token for DB storage
export const hashToken = (token: string): string => {
    return crypto.createHash('sha256').update(token).digest('hex');
};
