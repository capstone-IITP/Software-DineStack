export interface IDeletionStrategy {
  execute(entityId: string, context?: any): Promise<void>;
}

export class CloudDeletionStrategy implements IDeletionStrategy {
  public async execute(entityId: string, context?: any): Promise<void> {
    // Cloud specific cleanup logic
    console.log(`[CloudDeletionStrategy] Executing cloud cleanup for ${entityId}`);
  }
}

export class FactoryResetStrategy implements IDeletionStrategy {
  public async execute(entityId: string, context?: any): Promise<void> {
    // Factory reset specific cleanup logic
    console.log(`[FactoryResetStrategy] Executing factory reset cleanup for ${entityId}`);
  }
}

export class LicenseRevokeStrategy implements IDeletionStrategy {
  public async execute(entityId: string, context?: any): Promise<void> {
    // License revoke specific cleanup logic
    console.log(`[LicenseRevokeStrategy] Executing license revoke cleanup for ${entityId}`);
  }
}

export class SystemResetStrategy implements IDeletionStrategy {
  public async execute(entityId: string, context?: any): Promise<void> {
    // System reset specific cleanup logic
    console.log(`[SystemResetStrategy] Executing system reset cleanup for ${entityId}`);
  }
}
