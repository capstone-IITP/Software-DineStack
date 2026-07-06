
import { PrismaClient as PostgresPrismaClient } from '@prisma/client';

// Prevent multiple instances of Prisma Client in development
declare global {
    var prisma: any | undefined;
}

let prismaInstance: any;

// Detect if we are running in local/desktop mode
const isDesktop = process.env.IS_DESKTOP === 'true' || 
                  (process.env.DATABASE_URL && process.env.DATABASE_URL.startsWith('file:')) ||
                  (process.argv && process.argv.some(arg => arg.includes('server.desktop')));

if (isDesktop) {
    try {
        const { PrismaClient: SqlitePrismaClient } = require('prisma-desktop-client');
        
        // Resolve target database URL:
        // In local development, default to 'file:./prisma/dev.db' (relative to backend/ directory, matching migrations)
        // In production / packaged mode, use process.env.DATABASE_URL (which has the absolute path to dinestack.db)
        let dbUrl = process.env.DATABASE_URL;
        if (!dbUrl || !dbUrl.startsWith('file:')) {
            dbUrl = 'file:./prisma/dev.db';
        }
        
        prismaInstance = global.prisma || new SqlitePrismaClient({
            datasources: {
                db: {
                    url: dbUrl
                }
            }
        });
        if (process.env.NODE_ENV !== 'production') {
            global.prisma = prismaInstance;
        }
    } catch (error) {
        console.error('Failed to load prisma-desktop-client. Falling back to default client.', error);
        prismaInstance = global.prisma || new PostgresPrismaClient();
        if (process.env.NODE_ENV !== 'production') {
            global.prisma = prismaInstance;
        }
    }
} else {
    prismaInstance = global.prisma || new PostgresPrismaClient();
    if (process.env.NODE_ENV !== 'production') {
        global.prisma = prismaInstance;
    }
}

export const prisma = prismaInstance;

