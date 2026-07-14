export type FailureClassification = 'RETRYABLE' | 'RECOVERABLE' | 'NON_RECOVERABLE' | 'MANUAL_INTERVENTION_REQUIRED';

export interface FailureResult {
    operationId: string;
    correlationId: string;
    step: string;
    failureReason: string;
    recoveryAction?: string;
    compensationExecuted: boolean;
    timestamp: Date;
    classification: FailureClassification;
}

export type SagaStep = 
    | 'PREPARE_STARTED'
    | 'LOCK_ACQUIRED'
    | 'CONTEXT_INITIALIZED'
    | 'NODES_NOTIFIED'
    | 'QUORUM_REACHED'
    | 'RUNTIME_INVALIDATED'
    | 'DATABASE_COMPLETED'
    | 'ARTIFACTS_REMOVED'
    | 'FINALIZED'
    | 'COMPLETED'
    | 'FAILED'
    | 'COMPENSATION_STARTED'
    | 'COMPENSATION_COMPLETED'
    | 'RECOVERY_STARTED'
    | 'RECOVERY_COMPLETED';

export interface DeletionContext {
    operationId: string;
    correlationId: string;
    entityId: string;
    cloudRestaurantId?: string;
    activationId?: string;
    licenseId?: string;
    deletionPolicy: DeletionPolicyResult;
    initiatedBy: string;
    timestamp: Date;
    reason: string;
}

export interface DeletionPolicyResult {
    strategy: 'HARD_DELETE' | 'TOMBSTONE';
    anonymizePII: boolean;
    invalidateBackups: boolean;
    retainAuditLogs: boolean;
}

export interface IdempotencyRecord {
    operationId: string;
    correlationId: string;
    status: 'IN_PROGRESS' | 'COMPLETED' | 'FAILED';
    lastCheckpoint: SagaStep;
    timestamp: Date;
    context: string; // JSON serialized DeletionContext
}

export interface AuditRecord {
    operationId: string;
    correlationId: string;
    currentStep: SagaStep;
    previousStep?: SagaStep;
    timestamp: Date;
    durationMs: number;
    result: 'SUCCESS' | 'FAILURE';
    recoveryClassification?: FailureClassification;
    details?: string;
}
