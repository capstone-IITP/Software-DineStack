export interface TaxEngineItem {
    price: number;
    quantity: number;
    taxSource?: string; // "RESTAURANT", "CATEGORY", "CUSTOM"
    gstRate?: number | null; // Value like 5, 12, 18, 28
    categoryUseRestaurantGST?: boolean;
    categoryGstRate?: number | null;
}

export interface TaxEngineConfig {
    gstEnabled: boolean;
    gstMode: string; // "EXCLUSIVE" or "INCLUSIVE"
    defaultGstRate: number;
}

export interface TaxCalculationResult {
    subtotal: number;
    gstAmount: number;
    grandTotal: number;
    effectiveGstRate: number;
    gstMode: string;
    breakdown: { rate: number; amount: number }[];
}

export function calculateOrderTaxes(items: TaxEngineItem[], config: TaxEngineConfig): TaxCalculationResult {
    if (!config.gstEnabled) {
        const subtotal = items.reduce((sum, item) => sum + item.price * item.quantity, 0);
        return {
            subtotal,
            gstAmount: 0,
            grandTotal: subtotal,
            effectiveGstRate: 0,
            gstMode: config.gstMode,
            breakdown: []
        };
    }

    let subtotal = 0;
    let gstAmount = 0;
    const rateAmounts: Record<number, number> = {};

    for (const item of items) {
        let appliedRate = config.defaultGstRate;

        if (item.taxSource === 'CUSTOM' && item.gstRate !== undefined && item.gstRate !== null) {
            appliedRate = item.gstRate;
        } else if (item.taxSource === 'CATEGORY' || (!item.taxSource && item.categoryUseRestaurantGST === false)) {
            if (item.categoryUseRestaurantGST === false && item.categoryGstRate !== undefined && item.categoryGstRate !== null) {
                appliedRate = item.categoryGstRate;
            } else {
                appliedRate = config.defaultGstRate;
            }
        }

        const lineTotal = item.price * item.quantity;
        let itemSubtotal = 0;
        let itemGst = 0;

        if (config.gstMode === 'INCLUSIVE') {
            // formula: price = subtotal + (subtotal * rate / 100)
            // subtotal = price / (1 + rate / 100)
            itemSubtotal = lineTotal / (1 + appliedRate / 100);
            itemGst = lineTotal - itemSubtotal;
        } else {
            // EXCLUSIVE
            itemSubtotal = lineTotal;
            itemGst = lineTotal * (appliedRate / 100);
        }

        subtotal += itemSubtotal;
        gstAmount += itemGst;

        if (!rateAmounts[appliedRate]) {
            rateAmounts[appliedRate] = 0;
        }
        rateAmounts[appliedRate] += itemGst;
    }

    const grandTotal = config.gstMode === 'INCLUSIVE' ? subtotal + gstAmount : subtotal + gstAmount;

    // effective rate = (gstAmount / subtotal) * 100
    const effectiveGstRate = subtotal > 0 ? (gstAmount / subtotal) * 100 : 0;

    const breakdown = Object.keys(rateAmounts).map(rate => ({
        rate: parseFloat(rate),
        amount: rateAmounts[parseFloat(rate)]
    }));

    return {
        subtotal,
        gstAmount,
        grandTotal,
        effectiveGstRate,
        gstMode: config.gstMode,
        breakdown
    };
}
