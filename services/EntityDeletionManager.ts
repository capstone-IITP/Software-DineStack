import { IEntityLifecycleService, IEntityLockManager, ILifecycleEventBus, IEntityPersistenceService, IClock } from "../core/interfaces";
import { LifecycleResult, PolicyResult, LifecycleError } from "../core/models";
import { EntityPolicy } from "../policies/EntityPolicy";
import { DeletionPolicy } from "../policies/DeletionPolicy";

export class EntityDeletionManager {
  constructor(
    private lifecycleService: IEntityLifecycleService,
    private lockManager: IEntityLockManager,
    private deletionPolicy: DeletionPolicy,
    private purgeService: IEntityPersistenceService,
    private eventBus: ILifecycleEventBus,
    private clock: IClock
  ) {}

  public async deleteEntity(entityId: string, context?: any): Promise<LifecycleResult<any>> {
    const lockAcquired = await this.lockManager.acquireLock(entityId, "DELETION");
    if (!lockAcquired) {
      return LifecycleResult.failure("LOCK_ACQUIRED", "Deletion is already in progress or entity is locked.");
    }

    try {
      const entity = await this.lifecycleService.getEntity(entityId);
      
      if (!EntityPolicy.canDelete(entity.status)) {
         return LifecycleResult.failure("NOT_ALLOWED", "Cannot delete entity in this state.");
      }

      const policyResult = await this.deletionPolicy.evaluate(entity, context);
      const strategy = policyResult.context?.strategy || "SystemResetStrategy";
      
      const deletedEntity = await this.lifecycleService.transitionToDeleted(entity);
      
      await this.eventBus.publish({
        type: "ENTITY_DELETED",
        eventId: `${Date.now()}-${Math.random()}`,
        operationId: context?.operationId || `OP-${Date.now()}`,
        correlationId: context?.correlationId || `CORR-${Date.now()}`,
        entityId: entityId,
        entityVersion: deletedEntity.entityVersion,
        lifecycleRevision: deletedEntity.lifecycleRevision,
        timestamp: this.clock.utcNow(),
        strategy: strategy
      });

      return LifecycleResult.success({ status: "DELETED", strategy });
    } catch (err: any) {
      return LifecycleResult.failure("DELETION_FAILED", err.message);
    } finally {
      await this.lockManager.releaseLock(entityId, "DELETION");
    }
  }
}
