export class EntityLockManager {
    // In production, this would use Redis with NX and EX to handle distributed leases.
    // Since this is demonstrating the local Desktop node architecture, we simulate it in-memory.
    private static locks: Map<string, { leaseExpiresAt: Date, operationId: string }> = new Map();

    public static async acquireLock(entityId: string, operationId: string, leaseMs: number = 30000): Promise<boolean> {
        const now = new Date();
        const existingLock = this.locks.get(entityId);
        
        if (existingLock) {
            if (existingLock.leaseExpiresAt > now) {
                // Lock is active and held by another (or same) operation
                return existingLock.operationId === operationId;
            } else {
                // Orphan lock detected, it expired. We can reap it and acquire.
                console.warn(`[EntityLockManager] Orphan lock detected for entity ${entityId}. Reaping and reacquiring.`);
            }
        }
        
        this.locks.set(entityId, {
            leaseExpiresAt: new Date(now.getTime() + leaseMs),
            operationId
        });
        
        return true;
    }

    public static async extendLock(entityId: string, operationId: string, leaseMs: number = 30000): Promise<boolean> {
        const existingLock = this.locks.get(entityId);
        if (existingLock && existingLock.operationId === operationId) {
            existingLock.leaseExpiresAt = new Date(Date.now() + leaseMs);
            this.locks.set(entityId, existingLock);
            return true;
        }
        return false;
    }

    public static async releaseLock(entityId: string, operationId: string): Promise<void> {
        const existingLock = this.locks.get(entityId);
        if (existingLock && existingLock.operationId === operationId) {
            this.locks.delete(entityId);
        }
    }

    public static isLocked(entityId: string): boolean {
        const lock = this.locks.get(entityId);
        if (!lock) return false;
        if (lock.leaseExpiresAt < new Date()) {
            this.locks.delete(entityId); // reap stale lock
            return false;
        }
        return true;
    }
}
