import { prisma } from './prisma';
import fetch from 'node-fetch';
import { PrismaClient as CloudPrismaClient } from '@prisma/client';

const CLOUD_API_URL = process.env.CLOUD_API_URL || 'https://software.dinestack.in/api';
let syncInterval: NodeJS.Timeout | null = null;
let isSyncing = false;
let useDirectSync = false;

// Cloud Prisma client for direct PostgreSQL database sync fallback
let cloudPrisma: any = null;
let CLOUD_DATABASE_URL = process.env.DATABASE_URL;

// Parse the real cloud PostgreSQL DATABASE_URL from .env if needed
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
        console.error('Failed to parse .env for CLOUD_DATABASE_URL in sync-service:', e);
    }
}

// Fallback to process.env.DIRECT_URL if set
if ((!CLOUD_DATABASE_URL || CLOUD_DATABASE_URL.startsWith('file:')) && process.env.DIRECT_URL && !process.env.DIRECT_URL.startsWith('file:')) {
    CLOUD_DATABASE_URL = process.env.DIRECT_URL;
}

if (CLOUD_DATABASE_URL && !CLOUD_DATABASE_URL.startsWith('file:')) {
    cloudPrisma = new CloudPrismaClient({
        datasources: { db: { url: CLOUD_DATABASE_URL } }
    });
}

async function runDirectSync(
    restaurantId: string,
    orders: any[],
    tables: any[],
    categories: any[],
    menuItems: any[]
) {
    if (!cloudPrisma) {
        throw new Error('Direct Cloud DB connection not initialized');
    }

    // 0. Sync ActivationCode and Restaurant to satisfy Foreign Keys
    try {
        const localRest = await prisma.restaurant.findUnique({ 
            where: { id: restaurantId },
            include: { ActivationCode: true }
        });
        
        let cloudActivationCodeId: string | null = localRest?.activationCodeId || null;
        const upsertActivationCode = async (withRestaurantId: boolean) => {
            if (!localRest?.ActivationCode) return;
            const upserted = await cloudPrisma.activationCode.upsert({
                where: { code: localRest.ActivationCode.code },
                update: {
                    code: localRest.ActivationCode.code,
                    status: localRest.ActivationCode.status,
                    isUsed: localRest.ActivationCode.isUsed,
                    usedAt: localRest.ActivationCode.usedAt,
                    expiresAt: localRest.ActivationCode.expiresAt,
                    durationDays: localRest.ActivationCode.durationDays,
                    maxTables: localRest.ActivationCode.maxTables,
                    plan: localRest.ActivationCode.plan,
                    ...(withRestaurantId && { restaurantId: restaurantId })
                },
                create: {
                    id: localRest.ActivationCode.id,
                    code: localRest.ActivationCode.code,
                    status: localRest.ActivationCode.status,
                    isUsed: localRest.ActivationCode.isUsed,
                    usedAt: localRest.ActivationCode.usedAt,
                    expiresAt: localRest.ActivationCode.expiresAt,
                    durationDays: localRest.ActivationCode.durationDays,
                    maxTables: localRest.ActivationCode.maxTables,
                    plan: localRest.ActivationCode.plan,
                    ...(withRestaurantId && { restaurantId: restaurantId })
                }
            });
            cloudActivationCodeId = upserted.id;
        };

        try {
            await upsertActivationCode(false); // First pass: without restaurantId to avoid FK errors if restaurant doesn't exist
        } catch (err: any) {
            console.warn(`[Sync Service] Initial ActivationCode upsert failed: ${err.message}`);
        }

        if (localRest) {
            try {
                await cloudPrisma.restaurant.upsert({
                    where: { id: restaurantId },
                    update: {
                        name: localRest.name,
                        status: localRest.status,
                        isActive: localRest.isActive,
                        adminPin: localRest.adminPin,
                        kitchenPin: localRest.kitchenPin,
                        activationCodeId: cloudActivationCodeId
                    },
                    create: {
                        id: localRest.id,
                        name: localRest.name,
                        status: localRest.status,
                        isActive: localRest.isActive,
                        adminPin: localRest.adminPin,
                        kitchenPin: localRest.kitchenPin,
                        activationCodeId: cloudActivationCodeId,
                        createdAt: localRest.createdAt || new Date()
                    }
                });
            } catch (upsertErr: any) {
                if (upsertErr.code === 'P2002' && upsertErr.meta?.target?.includes('name')) {
                    const uniqueName = `${localRest.name} (${restaurantId.substring(0, 8)})`;
                    console.log(`[Sync Service] Restaurant name conflict. Retrying with name: ${uniqueName}`);
                    await cloudPrisma.restaurant.upsert({
                        where: { id: restaurantId },
                        update: {
                            name: uniqueName,
                            status: localRest.status,
                            isActive: localRest.isActive,
                            adminPin: localRest.adminPin,
                            kitchenPin: localRest.kitchenPin,
                            activationCodeId: cloudActivationCodeId
                        },
                        create: {
                            id: localRest.id,
                            name: uniqueName,
                            status: localRest.status,
                            isActive: localRest.isActive,
                            adminPin: localRest.adminPin,
                            kitchenPin: localRest.kitchenPin,
                            activationCodeId: cloudActivationCodeId,
                            createdAt: localRest.createdAt || new Date()
                        }
                    });
                } else {
                    throw upsertErr;
                }
            }
            
            try {
                await upsertActivationCode(true); // Second pass: now link the restaurantId
            } catch (err: any) {
                console.warn(`[Sync Service] Secondary ActivationCode upsert failed: ${err.message}`);
            }
        }
    } catch (err) {
        console.error(`Failed to sync restaurant ${restaurantId} directly to cloud:`, err);
    }

    // 1. Sync Categories
    if (Array.isArray(categories)) {
        for (const cat of categories) {
            try {
                await cloudPrisma.category.upsert({
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
                console.error(`Failed to sync category ${cat.id} directly to cloud:`, err);
            }
        }
    }

    // 2. Sync Menu Items
    if (Array.isArray(menuItems)) {
        for (const item of menuItems) {
            try {
                await cloudPrisma.menuItem.upsert({
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
                console.error(`Failed to sync menu item ${item.id} directly to cloud:`, err);
            }
        }
    }

    // 3. Sync Tables
    if (Array.isArray(tables)) {
        for (const tbl of tables) {
            try {
                await cloudPrisma.table.upsert({
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
                console.error(`Failed to sync table ${tbl.id} directly to cloud:`, err);
            }
        }
    }

    const syncedOrderIds: string[] = [];

    for (const localOrder of orders) {
        try {
            // Check if order exists in cloud
            const cloudOrder = await cloudPrisma.order.findUnique({
                where: { id: localOrder.id },
                include: { items: true }
            });

            if (!cloudOrder) {
                // Create in cloud
                await cloudPrisma.order.create({
                    data: {
                        id: localOrder.id,
                        restaurantId,
                        tableId: localOrder.tableId,
                        status: localOrder.status,
                        totalAmount: localOrder.totalAmount,
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
                    await cloudPrisma.order.update({
                        where: { id: localOrder.id },
                        data: {
                            status: localOrder.status,
                            totalAmount: localOrder.totalAmount,
                            updatedAt: new Date(localOrder.updatedAt)
                        }
                    });
                }
            }
            syncedOrderIds.push(localOrder.id);
        } catch (err) {
            console.error(`Failed to sync order ${localOrder.id} directly to cloud:`, err);
        }
    }

    // Fetch all orders from the cloud for this restaurant to sync down to desktop
    const cloudOrders = await cloudPrisma.order.findMany({
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

    // 4. Sync Pair Codes
    try {
        // Upload local active pair codes to cloud
        const localActiveCodes = await prisma.pairCode.findMany({
            where: { restaurantId, pairCodeActive: true }
        });
        for (const code of localActiveCodes) {
            await cloudPrisma.pairCode.upsert({
                where: { code: code.code },
                update: {
                    pairCodeActive: code.pairCodeActive,
                    pairCodeUsed: code.pairCodeUsed,
                    kitchenOnline: code.kitchenOnline,
                    expiresAt: code.expiresAt
                },
                create: {
                    id: code.id,
                    code: code.code,
                    restaurantId,
                    pairCodeActive: code.pairCodeActive,
                    pairCodeUsed: code.pairCodeUsed,
                    kitchenOnline: code.kitchenOnline,
                    expiresAt: code.expiresAt
                }
            }).catch((e: any) => console.error(`[Sync Service] Failed to upload PairCode ${code.code}:`, e.message));
        }

        // Pull remote pair code statuses back to local
        const remotePairCodes = await cloudPrisma.pairCode.findMany({
            where: { restaurantId }
        });
        for (const remoteCode of remotePairCodes) {
            const localCode = await prisma.pairCode.findUnique({
                where: { code: remoteCode.code }
            });
            if (localCode) {
                // If remote pair code was used or kitchen went online, sync it back
                if (remoteCode.pairCodeUsed !== localCode.pairCodeUsed || remoteCode.kitchenOnline !== localCode.kitchenOnline) {
                    await prisma.pairCode.update({
                        where: { id: localCode.id },
                        data: {
                            pairCodeUsed: remoteCode.pairCodeUsed,
                            pairCodeActive: remoteCode.pairCodeActive,
                            kitchenOnline: remoteCode.kitchenOnline
                        }
                    });
                }
            } else {
                // If generated remotely, create it locally
                await prisma.pairCode.create({
                    data: {
                        id: remoteCode.id,
                        code: remoteCode.code,
                        restaurantId,
                        pairCodeActive: remoteCode.pairCodeActive,
                        pairCodeUsed: remoteCode.pairCodeUsed,
                        kitchenOnline: remoteCode.kitchenOnline,
                        expiresAt: remoteCode.expiresAt
                    }
                }).catch((e: any) => console.error(`[Sync Service] Failed to create local PairCode ${remoteCode.code}:`, e.message));
            }
        }
    } catch (pairSyncErr: any) {
        console.error('[Sync Service] Failed to sync PairCodes:', pairSyncErr.message);
    }

    // 5. Sync Devices
    try {
        // Upload local devices
        const localDevices = await prisma.device.findMany({
            where: { restaurantId }
        });
        for (const dev of localDevices) {
            await cloudPrisma.device.upsert({
                where: { deviceId: dev.deviceId },
                update: {
                    role: dev.role,
                    status: dev.status,
                    lastUsed: dev.lastUsed
                },
                create: {
                    id: dev.id,
                    deviceId: dev.deviceId,
                    role: dev.role,
                    status: dev.status,
                    restaurantId,
                    createdAt: dev.createdAt,
                    lastUsed: dev.lastUsed
                }
            }).catch((e: any) => console.error(`[Sync Service] Failed to upload Device ${dev.deviceId}:`, e.message));
        }

        // Pull remote devices
        const remoteDevices = await cloudPrisma.device.findMany({
            where: { restaurantId }
        });
        for (const dev of remoteDevices) {
            if (!dev.deviceId) continue;
            const localDev = await prisma.device.findFirst({
                where: { deviceId: dev.deviceId }
            });
            if (localDev) {
                if (dev.status !== localDev.status || dev.role !== localDev.role) {
                    await prisma.device.update({
                        where: { id: localDev.id },
                        data: {
                            status: dev.status,
                            role: dev.role,
                            lastUsed: dev.lastUsed ? new Date(dev.lastUsed) : undefined
                        }
                    });
                }
            } else {
                await prisma.device.create({
                    data: {
                        id: dev.id,
                        deviceId: dev.deviceId,
                        role: dev.role || 'UNKNOWN',
                        status: dev.status || 'ACTIVE',
                        restaurantId,
                        createdAt: dev.createdAt ? new Date(dev.createdAt) : undefined,
                        lastUsed: dev.lastUsed ? new Date(dev.lastUsed) : undefined
                    }
                }).catch((e: any) => console.error(`[Sync Service] Failed to create local Device ${dev.deviceId}:`, e.message));
            }
        }
    } catch (deviceSyncErr: any) {
        console.error('[Sync Service] Failed to sync Devices:', deviceSyncErr.message);
    }

    return {
        success: true,
        syncedOrderIds,
        cloudOrders
    };
}


export async function runSync() {
    if (isSyncing) return;
    isSyncing = true;

    try {
        // 1. Get the active restaurant activation code from local DB
        const activeCode = await prisma.activationCode.findFirst({
            where: {
                isUsed: true,
                status: 'USED',
                Restaurant: {
                    status: 'ACTIVE'
                }
            },
            include: { Restaurant: true },
            orderBy: { usedAt: 'desc' }
        });

        if (!activeCode || !activeCode.Restaurant) {
            // System not activated yet, skip
            isSyncing = false;
            return;
        }

        const activationCode = activeCode.code;
        const restaurantId = activeCode.Restaurant.id;

        // 2. Fetch unsynced local orders
        const unsyncedOrders = await prisma.order.findMany({
            where: { synced: false, restaurantId },
            include: { OrderItem: true }
        });

        if (unsyncedOrders.length > 0) {
            console.log(`[Sync Service] Found ${unsyncedOrders.length} unsynced orders. Uploading...`);
        }

        const ordersToUpload = unsyncedOrders.map(order => ({
            id: order.id,
            status: order.status,
            totalAmount: order.totalAmount,
            tableId: order.tableId,
            customerId: order.customerId,
            createdAt: order.createdAt,
            updatedAt: order.updatedAt,
            items: order.OrderItem.map((item: any) => ({
                id: item.id,
                menuItemId: item.menuItemId,
                quantity: item.quantity,
                notes: item.notes,
                createdAt: item.createdAt
            }))
        }));

        // Fetch tables, categories, and menu items to sync to the cloud database
        const tablesToUpload = await prisma.table.findMany({
            where: { restaurantId }
        });

        const categoriesToUpload = await prisma.category.findMany({
            where: { restaurantId }
        });

        const menuItemsToUpload = await prisma.menuItem.findMany({
            where: { restaurantId }
        });

        // 3. Post to cloud with direct DB fallback
        let data: any = null;
        if (useDirectSync && cloudPrisma) {
            data = await runDirectSync(
                restaurantId,
                ordersToUpload,
                tablesToUpload,
                categoriesToUpload,
                menuItemsToUpload
            );
        } else {
            try {
                const response = await fetch(`${CLOUD_API_URL}/sync/orders`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Activation-Code': activationCode
                    },
                    body: JSON.stringify({
                        orders: ordersToUpload,
                        tables: tablesToUpload,
                        categories: categoriesToUpload,
                        menuItems: menuItemsToUpload
                    })
                });

                if (response.status === 404) {
                    if (cloudPrisma) {
                        useDirectSync = true;
                        console.log(`[Sync Service] Cloud sync endpoint returned 404. Permanently switching to Direct DB Sync mode.`);
                        data = await runDirectSync(
                            restaurantId,
                            ordersToUpload,
                            tablesToUpload,
                            categoriesToUpload,
                            menuItemsToUpload
                        );
                    } else {
                        throw new Error(`Cloud Sync failed with status: 404`);
                    }
                } else if (!response.ok) {
                    throw new Error(`Cloud Sync failed with status: ${response.status}`);
                } else {
                    data = (await response.json()) as any;
                }
            } catch (httpError: any) {
                console.warn(`[Sync Service] HTTP Sync failed (${httpError.message || httpError}). Falling back to Direct DB Sync...`);
                if (cloudPrisma) {
                    data = await runDirectSync(
                        restaurantId,
                        ordersToUpload,
                        tablesToUpload,
                        categoriesToUpload,
                        menuItemsToUpload
                    );
                } else {
                    throw httpError;
                }
            }
        }

        if (data.success) {
            // 4. Mark local orders as synced
            if (data.syncedOrderIds && data.syncedOrderIds.length > 0) {
                await prisma.order.updateMany({
                    where: { id: { in: data.syncedOrderIds } },
                    data: { synced: true }
                });
                console.log(`[Sync Service] Successfully uploaded and marked ${data.syncedOrderIds.length} orders as synced.`);
            }

            // 5. Download cloud orders and save locally
            if (data.cloudOrders && data.cloudOrders.length > 0) {
                let downloadCount = 0;
                let skippedCount = 0;
                for (const cloudOrder of data.cloudOrders) {
                    try {
                        const localOrder = await prisma.order.findUnique({
                            where: { id: cloudOrder.id }
                        });

                        if (!localOrder) {
                            // Ensure table exists locally
                            if (cloudOrder.table) {
                                await prisma.table.upsert({
                                    where: { id: cloudOrder.table.id },
                                    update: {},
                                    create: {
                                        id: cloudOrder.table.id,
                                        label: cloudOrder.table.label,
                                        capacity: cloudOrder.table.capacity,
                                        isActive: false, // Inactive because it was missing locally
                                        restaurantId: cloudOrder.restaurantId,
                                        createdAt: cloudOrder.table.createdAt ? new Date(cloudOrder.table.createdAt) : new Date()
                                    }
                                }).catch(() => {});
                            }

                            // Ensure menu items and categories exist locally
                            if (cloudOrder.items && Array.isArray(cloudOrder.items)) {
                                for (const item of cloudOrder.items) {
                                    if (item.menuItem) {
                                        if (item.menuItem.categoryId) {
                                            const catExists = await prisma.category.findUnique({
                                                where: { id: item.menuItem.categoryId }
                                            });
                                            if (!catExists) {
                                                await prisma.category.create({
                                                    data: {
                                                        id: item.menuItem.categoryId,
                                                        name: "Unknown Category",
                                                        isActive: false,
                                                        restaurantId: cloudOrder.restaurantId,
                                                    }
                                                }).catch(() => {});
                                            }
                                        }

                                        await prisma.menuItem.upsert({
                                            where: { id: item.menuItem.id },
                                            update: {},
                                            create: {
                                                id: item.menuItem.id,
                                                name: item.menuItem.name,
                                                description: item.menuItem.description,
                                                price: item.menuItem.price,
                                                image: item.menuItem.image,
                                                isActive: false, // Inactive because it was missing locally
                                                categoryId: item.menuItem.categoryId,
                                                restaurantId: cloudOrder.restaurantId,
                                                createdAt: item.menuItem.createdAt ? new Date(item.menuItem.createdAt) : new Date()
                                            }
                                        }).catch(() => {});
                                    }
                                }
                            }

                            await prisma.order.create({
                                data: {
                                    id: cloudOrder.id,
                                    restaurantId: cloudOrder.restaurantId,
                                    tableId: cloudOrder.tableId,
                                    status: cloudOrder.status,
                                    totalAmount: cloudOrder.totalAmount,
                                    customerId: null,
                                    createdAt: new Date(cloudOrder.createdAt),
                                    updatedAt: new Date(cloudOrder.updatedAt),
                                    synced: true,
                                    OrderItem: {
                                        create: cloudOrder.items?.map((item: any) => ({
                                            id: item.id,
                                            menuItemId: item.menuItemId,
                                            quantity: item.quantity,
                                            notes: item.notes || null,
                                            createdAt: item.createdAt ? new Date(item.createdAt) : new Date()
                                        })) || []
                                    }
                                }
                            });
                            downloadCount++;
                        } else {
                            // Conflict Resolution: If cloud is newer, update locally
                            const localUpdated = new Date(localOrder.updatedAt).getTime();
                            const cloudUpdated = new Date(cloudOrder.updatedAt).getTime();

                            if (cloudUpdated > localUpdated) {
                                await prisma.order.update({
                                    where: { id: cloudOrder.id },
                                    data: {
                                        status: cloudOrder.status,
                                        totalAmount: cloudOrder.totalAmount,
                                        updatedAt: new Date(cloudOrder.updatedAt),
                                        synced: true
                                    }
                                });
                                downloadCount++;
                            }
                        }
                    } catch (err: any) {
                        // Suppress verbose Prisma stack trace and just increment count
                        skippedCount++;
                    }
                }
                if (downloadCount > 0) {
                    console.log(`[Sync Service] Successfully synced/downloaded ${downloadCount} orders from cloud.`);
                }
                if (skippedCount > 0) {
                    console.warn(`[Sync Service] Skipped syncing down ${skippedCount} orders due to missing local constraints (tables/items).`);
                }
            }
        }
    } catch (error) {
        console.error('[Sync Service Error] Exception during sync execution:', error);
    } finally {
        isSyncing = false;
    }
}

export function startSyncService(intervalMs: number = 10000) {
    if (syncInterval) {
        return;
    }

    console.log(`[Sync Service] Starting background sync service (Interval: ${intervalMs}ms)...`);
    // Run immediately
    runSync();

    syncInterval = setInterval(() => {
        runSync();
    }, intervalMs);
}

export function stopSyncService() {
    if (syncInterval) {
        clearInterval(syncInterval);
        syncInterval = null;
        console.log('[Sync Service] Background sync service stopped.');
    }
}
