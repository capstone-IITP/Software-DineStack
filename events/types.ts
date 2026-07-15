export interface BaseDomainEvent {
  eventId: string;
  operationId: string;
  correlationId: string;
  entityId: string;
  entityVersion: number;
  lifecycleRevision: number;
  timestamp: string;
}

export interface EntityCreatedEvent extends BaseDomainEvent {
  type: "ENTITY_CREATED";
  payload: any;
}

export interface EntityActivatedEvent extends BaseDomainEvent {
  type: "ENTITY_ACTIVATED";
  activationId: string;
}

export interface EntityDeletedEvent extends BaseDomainEvent {
  type: "ENTITY_DELETED";
  strategy: string;
}

export interface EntityPurgedEvent extends BaseDomainEvent {
  type: "ENTITY_PURGED";
}

export interface EntityRecoveredEvent extends BaseDomainEvent {
  type: "ENTITY_RECOVERED";
  recoveryType: string;
}

export type LifecycleEvent = 
  | EntityCreatedEvent
  | EntityActivatedEvent
  | EntityDeletedEvent
  | EntityPurgedEvent
  | EntityRecoveredEvent;
