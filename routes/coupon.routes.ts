import express from 'express';
import { prisma } from '../utils/prisma';
import { authenticate } from '../middleware/auth';
import { randomUUID } from 'crypto';

const router = express.Router();

// GET all coupons for the restaurant
router.get('/', authenticate, async (req: any, res) => {
    try {
        const restaurantId = req.user.restaurantId;
        const coupons = await prisma.coupon.findMany({
            where: { restaurantId },
            orderBy: { createdAt: 'desc' }
        });
        res.json({ success: true, coupons });
    } catch (error) {
        console.error('Error fetching coupons:', error);
        res.status(500).json({ success: false, error: 'Failed to fetch coupons' });
    }
});

// POST create a new coupon
router.post('/', authenticate, async (req: any, res) => {
    try {
        const restaurantId = req.user.restaurantId;
        const { code, discountType, discountValue, expiresAt, minOrderValue, maxDiscount, maxUsage } = req.body;

        if (!code || !discountType || discountValue === undefined) {
            return res.status(400).json({ success: false, error: 'Missing required fields' });
        }

        const normalizedCode = code.trim().toUpperCase();

        const existing = await prisma.coupon.findFirst({
            where: { code: normalizedCode, restaurantId }
        });

        if (existing) {
            return res.status(400).json({ success: false, error: 'Coupon code already exists for this restaurant' });
        }

        const coupon = await prisma.coupon.create({
            data: {
                code: normalizedCode,
                discountType,
                discountValue,
                expiresAt: expiresAt ? new Date(expiresAt) : null,
                minOrderValue,
                maxDiscount,
                maxUsage,
                restaurantId
            }
        });

        res.json({ success: true, coupon });
    } catch (error: any) {
        console.error('Error creating coupon:', error);
        res.status(500).json({ success: false, error: 'Failed to create coupon' });
    }
});

// PATCH update coupon status
router.patch('/:id', authenticate, async (req: any, res) => {
    try {
        const restaurantId = req.user.restaurantId;
        const { id } = req.params;
        const { status } = req.body;

        const coupon = await prisma.coupon.updateMany({
            where: { id, restaurantId },
            data: { status }
        });

        if (coupon.count === 0) {
            return res.status(404).json({ success: false, error: 'Coupon not found' });
        }

        res.json({ success: true });
    } catch (error) {
        console.error('Error updating coupon:', error);
        res.status(500).json({ success: false, error: 'Failed to update coupon' });
    }
});

// DELETE delete coupon (or disable if used)
router.delete('/:id', authenticate, async (req: any, res) => {
    try {
        const restaurantId = req.user.restaurantId;
        const { id } = req.params;

        const coupon = await prisma.coupon.findFirst({
            where: { id, restaurantId }
        });

        if (!coupon) {
            return res.status(404).json({ success: false, error: 'Coupon not found' });
        }

        if (coupon.usageCount > 0) {
            // Soft delete - disable it to preserve historical integrity
            await prisma.coupon.update({
                where: { id },
                data: { status: 'DISABLED' }
            });
            return res.json({ success: true, message: 'Coupon disabled (cannot delete because it has usage history)' });
        } else {
            // Hard delete
            await prisma.coupon.delete({
                where: { id }
            });
            return res.json({ success: true, message: 'Coupon deleted successfully' });
        }
    } catch (error) {
        console.error('Error deleting coupon:', error);
        res.status(500).json({ success: false, error: 'Failed to delete coupon' });
    }
});

// GET available coupons for a restaurant (for customer app)
router.get('/available/:restaurantId', async (req, res) => {
    try {
        const { restaurantId } = req.params;
        
        if (!restaurantId) {
            return res.status(400).json({ success: false, error: 'Restaurant ID is required' });
        }

        const coupons = await prisma.coupon.findMany({
            where: {
                restaurantId,
                status: 'ACTIVE'
            },
            orderBy: { createdAt: 'desc' }
        });

        // Filter out expired coupons or max usage reached
        const now = new Date();
        const availableCoupons = coupons.filter(coupon => {
            if (coupon.expiresAt && new Date(coupon.expiresAt) < now) return false;
            if (coupon.maxUsage && coupon.usageCount >= coupon.maxUsage) return false;
            return true;
        });

        res.json({ success: true, coupons: availableCoupons });
    } catch (error) {
        console.error('Error fetching available coupons:', error);
        res.status(500).json({ success: false, error: 'Failed to fetch available coupons' });
    }
});

// POST validate coupon (for customer app)
router.post('/validate', async (req, res) => {
    try {
        const { code, subtotal, restaurantId } = req.body;

        if (!code || !subtotal || !restaurantId) {
            return res.status(400).json({ success: false, error: 'Missing required fields' });
        }

        const normalizedCode = code.trim().toUpperCase();

        // First check if the coupon exists at all (global lookup to see if it's the wrong restaurant)
        const anyCoupon = await prisma.coupon.findFirst({
            where: { code: normalizedCode }
        });

        if (!anyCoupon) {
            return res.json({ success: false, error: 'Coupon not found' });
        }

        if (anyCoupon.restaurantId !== restaurantId) {
            return res.json({ success: false, error: 'Coupon belongs to another restaurant' });
        }

        const coupon = await prisma.coupon.findFirst({
            where: {
                code: normalizedCode,
                restaurantId
            }
        });

        if (!coupon) {
            // Should theoretically never hit this given the check above, but for safety
            return res.json({ success: false, error: 'Coupon not found for this restaurant' });
        }

        if (coupon.status !== 'ACTIVE') {
            return res.json({ success: false, error: 'Coupon disabled' });
        }

        if (coupon.expiresAt && new Date(coupon.expiresAt) < new Date()) {
            return res.json({ success: false, error: 'Coupon expired' });
        }

        if (coupon.maxUsage && coupon.usageCount >= coupon.maxUsage) {
            return res.json({ success: false, error: 'Coupon already used' });
        }

        if (coupon.minOrderValue && subtotal < coupon.minOrderValue) {
            return res.json({ success: false, error: `Minimum order ₹${coupon.minOrderValue} required` });
        }

        // Calculate discount
        let discountAmount = 0;
        if (coupon.discountType === 'PERCENTAGE') {
            discountAmount = subtotal * (coupon.discountValue / 100);
            if (coupon.maxDiscount && discountAmount > coupon.maxDiscount) {
                discountAmount = coupon.maxDiscount;
            }
        } else if (coupon.discountType === 'FLAT') {
            discountAmount = coupon.discountValue;
        }

        if (discountAmount > subtotal) {
            discountAmount = subtotal;
        }

        res.json({
            success: true,
            discountAmount,
            couponCode: coupon.code
        });

    } catch (error) {
        console.error('Error validating coupon:', error);
        res.status(500).json({ success: false, error: 'Failed to validate coupon' });
    }
});

export default router;
