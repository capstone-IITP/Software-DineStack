export class LifecycleResult<T> {
  public readonly success: boolean;
  public readonly code: string;
  public readonly message: string;
  public readonly data?: T;

  private constructor(success: boolean, code: string, message: string, data?: T) {
    this.success = success;
    this.code = code;
    this.message = message;
    this.data = data;
  }

  static success<T>(data?: T): LifecycleResult<T> {
    return new LifecycleResult<T>(true, "SUCCESS", "Operation completed successfully.", data);
  }

  static failure<T>(code: string, message: string, data?: T): LifecycleResult<T> {
    return new LifecycleResult<T>(false, code, message, data);
  }
}

export class PolicyResult {
  public readonly success: boolean;
  public readonly code: string;
  public readonly message: string;
  public readonly context?: any;

  constructor(success: boolean, code: string, message: string, context?: any) {
    this.success = success;
    this.code = code;
    this.message = message;
    this.context = context;
  }

  static allowed(context?: any): PolicyResult {
    return new PolicyResult(true, "ALLOWED", "Policy evaluation passed.", context);
  }

  static denied(code: string, message: string, context?: any): PolicyResult {
    return new PolicyResult(false, code, message, context);
  }
}

export interface LifecycleContext {
  operationId: string;
  correlationId: string;
  entityId: string;
  actor: string;
  timestamp: string;
  metadata?: any;
}

export enum DecisionType {
  CONTINUE = "CONTINUE",
  ACTIVATION_REQUIRED = "ACTIVATION_REQUIRED",
  RESUME_DELETION = "RESUME_DELETION",
  REPAIR = "REPAIR",
  MANUAL_INTERVENTION = "MANUAL_INTERVENTION"
}

export class LifecycleDecision {
  public readonly type: DecisionType;
  public readonly severity: string;
  public readonly reason: string;
  public readonly metadata?: any;

  constructor(type: DecisionType, severity: string, reason: string, metadata?: any) {
    this.type = type;
    this.severity = severity;
    this.reason = reason;
    this.metadata = metadata;
  }
}

// Custom Errors
export class LifecycleError extends Error {
  constructor(message: string, public code: string = "LIFECYCLE_ERROR") {
    super(message);
    this.name = "LifecycleError";
  }
}

export class ActivationError extends LifecycleError {
  constructor(message: string) {
    super(message, "ACTIVATION_ERROR");
    this.name = "ActivationError";
  }
}

export class DeletionError extends LifecycleError {
  constructor(message: string) {
    super(message, "DELETION_ERROR");
    this.name = "DeletionError";
  }
}

export class RecoveryError extends LifecycleError {
  constructor(message: string) {
    super(message, "RECOVERY_ERROR");
    this.name = "RecoveryError";
  }
}

export class BackupError extends LifecycleError {
  constructor(message: string) {
    super(message, "BACKUP_ERROR");
    this.name = "BackupError";
  }
}

export class SyncError extends LifecycleError {
  constructor(message: string) {
    super(message, "SYNC_ERROR");
    this.name = "SyncError";
  }
}

export class UpdateError extends LifecycleError {
  constructor(message: string) {
    super(message, "UPDATE_ERROR");
    this.name = "UpdateError";
  }
}
