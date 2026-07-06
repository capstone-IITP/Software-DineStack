
import express from 'express';
import bcrypt from 'bcryptjs';
import { authenticate, authorize } from '../middleware/auth';
import { prisma } from '../utils/prisma';

const router = express.Router();

/**
 * Helper: Generate a single recovery code in DREC-XXXX-XXXX format
 */
function generateRecoveryCode(): string {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    let part1 = '', part2 = '';
    for (let i = 0; i < 4; i++) {
        part1 += chars[Math.floor(Math.random() * chars.length)];
        part2 += chars[Math.floor(Math.random() * chars.length)];
    }
    return `DREC-${part1}-${part2}`;
}

/**
 * POST /api/recovery/generate
 * Requires ADMIN authentication
 * Generates 10 recovery codes, hashes them, and stores them in the DB.
 * Returns plaintext codes to the user ONE TIME ONLY.
 */
router.post('/generate', authenticate, authorize(['ADMIN']), async (req: express.Request, res: express.Response) => {
    const { restaurantId } = (req as any).user;

    try {
        const restaurant = await prisma.restaurant.findUnique({ where: { id: restaurantId } });
        if (!restaurant) {
            res.status(404).json({ error: 'Restaurant not found' });
            return;
        }

        // Check if codes already exist and are unused
        const existingUnused = await prisma.recoveryCode.count({
            where: { restaurantId, used: false }
        });

        if (existingUnused > 0) {
            // Optional: You could allow regeneration which invalidates old ones, but for safety we might block it or require a force flag.
            // For now, let's implement a "regenerate" logic where we invalidate old ones if requested, or just fail.
            // But per requirements, let's just generate new ones and delete old unused ones to keep it clean.
            // Actually, best practice is to invalidate old unused codes when generating new ones.
            await prisma.recoveryCode.deleteMany({
                where: { restaurantId } // Clear all for this restaurant to start fresh
            });
        }

        const codes = [];
        const codeData = [];
        const plaintextCodes = [];

        for (let i = 0; i < 10; i++) {
            const code = generateRecoveryCode();
            const hash = await bcrypt.hash(code, 12);

            codes.push(code);
            plaintextCodes.push(code);

            codeData.push({
                codeHash: hash,
                restaurantId,
                used: false
            });
        }

        // Batch insert
        await prisma.recoveryCode.createMany({
            data: codeData
        });

        // Setup success log (optional)
        console.log(`[Recovery] Generated 10 new codes for restaurant ${restaurantId}`);

        res.json({
            success: true,
            codes: plaintextCodes,
            message: 'Recovery codes generated. Download and store safely. These will not be shown again.'
        });

    } catch (error) {
        console.error('Generate Recovery Codes Error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

console.log("Recovery routes loaded");

export default router;
