export interface IEntityLifecycleService {
  getEntity(restaurantId: string): Promise<any>;
  getLifecycle(restaurantId: string): Promise<any>;
  transitionState(entity: any, newState: string): Promise<any>;
  transitionToDeleted(entity: any): Promise<any>;
  updateLifecycle(entity: any, metadata: any): Promise<any>;
  incrementEntityVersion(entity: any): Promise<any>;
  incrementLifecycleRevision(entity: any): Promise<any>;
}

export interface IEntityRepository {
  findById(id: string): Promise<any>;
  findByName(name: string): Promise<any>;
  save(entity: any): Promise<any>;
  delete(id: string): Promise<void>;
  update(id: string, data: any): Promise<any>;
}

export interface ITransactionManager {
  execute<T>(operation: (tx: any) => Promise<T>): Promise<T>;
}

export interface IEntityLockManager {
  acquireLock(entityId: string, operationType: string): Promise<boolean>;
  releaseLock(entityId: string, operationType: string): Promise<void>;
}

export interface ILifecycleEventBus {
  publish(event: any): Promise<void>;
  subscribe(eventType: string, handler: (event: any) => Promise<void>): void;
}

export interface IStructuralValidator {
  validate(entity: any): Promise<boolean>;
}

export interface ILifecycleValidator {
  validateTransition(entity: any, targetState: string): Promise<boolean>;
}

export interface IPolicy<T> {
  evaluate(entity: T, context?: any): Promise<any>;
}

export interface IPolicyCoordinator {
  coordinate(policies: IPolicy<any>[], entity: any): Promise<any>;
}

export interface IEntityPersistenceService {
  applyDeletionTransition(mutatedEntity: any): Promise<any>;
  applyStateTransition(mutatedEntity: any): Promise<any>;
  applyMetadataUpdate(mutatedEntity: any, metadata: any): Promise<any>;
  purge(entityId: string): Promise<void>;
  createEntity(entity: any): Promise<any>;
  updateEntity(entity: any): Promise<any>;
  transitionEntity(entity: any): Promise<any>;
  deleteEntity(entityId: string): Promise<void>;
}

export interface IAuditService {
  log(namespace: string, entry: any): Promise<void>;
}

export interface IClock {
  now(): number;
  utcNow(): string;
}
