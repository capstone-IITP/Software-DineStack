import { IEntityLifecycleService, IEntityRepository, IClock, IEntityPersistenceService } from "../core/interfaces";
import { LifecycleResult, LifecycleError } from "../core/models";
import { EntityPolicy } from "../policies/EntityPolicy";
import { DeletionPolicy } from "../policies/DeletionPolicy";

export class EntityLifecycleService implements IEntityLifecycleService {
  constructor(
    private entityRepository: IEntityRepository,
    private persistenceService: IEntityPersistenceService,
    private clock: IClock
  ) {}

  public async getEntity(restaurantId: string): Promise<any> {
    const entity = await this.entityRepository.findById(restaurantId);
    if (!entity) throw new LifecycleError("Entity not found", "ENTITY_NOT_FOUND");
    return entity;
  }

  public async getLifecycle(restaurantId: string): Promise<any> {
    const entity = await this.getEntity(restaurantId);
    return {
      status: entity.status,
      entityVersion: entity.entityVersion,
      lifecycleRevision: entity.lifecycleRevision,
      deletedAt: entity.deletedAt
    };
  }

  public async transitionToDeleted(entity: any): Promise<any> {
    if (!EntityPolicy.canDelete(entity.status)) {
        throw new Error(`Cannot delete entity in state ${entity.status}`);
    }

    const newName = DeletionPolicy.shouldReleaseNamespace(entity.status) 
        ? DeletionPolicy.generateDeletionIdentity(entity.name, entity.id) 
        : entity.name;

    const mutatedEntity = {
        ...entity,
        name: newName,
        status: 'DELETED',
        isActive: false,
        deletedAt: new Date(this.clock.utcNow()),
        lifecycleRevision: (entity.lifecycleRevision || 0) + 1,
        entityVersion: (entity.entityVersion || 0) + 1
    };

    return await this.persistenceService.applyDeletionTransition(mutatedEntity);
  }

  public async transitionState(entity: any, newState: string): Promise<any> {
    const mutatedEntity = {
        ...entity,
        status: newState,
        isActive: newState === 'ACTIVE',
        lifecycleRevision: (entity.lifecycleRevision || 0) + 1,
        entityVersion: (entity.entityVersion || 0) + 1,
        updatedAt: new Date(this.clock.utcNow())
    };
    return await this.persistenceService.applyStateTransition(mutatedEntity);
  }

  public async updateLifecycle(entity: any, metadata: any): Promise<any> {
    const mutatedEntity = {
        ...entity,
        ...metadata,
        lifecycleRevision: (entity.lifecycleRevision || 0) + 1,
        entityVersion: (entity.entityVersion || 0) + 1,
        updatedAt: new Date(this.clock.utcNow())
    };
    return await this.persistenceService.applyMetadataUpdate(mutatedEntity, metadata);
  }

  public async incrementEntityVersion(entity: any): Promise<any> {
    const mutatedEntity = {
        ...entity,
        entityVersion: (entity.entityVersion || 0) + 1,
        updatedAt: new Date(this.clock.utcNow())
    };
    return await this.persistenceService.applyMetadataUpdate(mutatedEntity, { entityVersion: mutatedEntity.entityVersion });
  }

  public async incrementLifecycleRevision(entity: any): Promise<any> {
    const mutatedEntity = {
        ...entity,
        lifecycleRevision: (entity.lifecycleRevision || 0) + 1,
        updatedAt: new Date(this.clock.utcNow())
    };
    return await this.persistenceService.applyMetadataUpdate(mutatedEntity, { lifecycleRevision: mutatedEntity.lifecycleRevision });
  }
}
