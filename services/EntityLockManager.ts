import { IEntityLockManager } from "../core/interfaces";

export class EntityLockManager implements IEntityLockManager {
  private locks: Map<string, string> = new Map();

  public async acquireLock(entityId: string, operationType: string): Promise<boolean> {
    if (this.locks.has(entityId)) {
      return false; // Lock already held
    }
    
    this.locks.set(entityId, operationType);
    return true;
  }

  public async releaseLock(entityId: string, operationType: string): Promise<void> {
    const currentLock = this.locks.get(entityId);
    if (currentLock === operationType) {
      this.locks.delete(entityId);
    }
  }

  public getLockOwner(entityId: string): string | undefined {
    return this.locks.get(entityId);
  }
}

// Global instance for simple usage
export const systemLockManager = new EntityLockManager();
