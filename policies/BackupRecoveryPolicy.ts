import { IPolicy } from "../core/interfaces";
import { PolicyResult } from "../core/models";
import { TERMINAL_ENTITY_STATES } from "../core/constants";

export class BackupPolicy implements IPolicy<any> {
  public async evaluate(entity: any, context?: any): Promise<PolicyResult> {
    if (!entity) {
      return PolicyResult.denied("ENTITY_NOT_FOUND", "Entity does not exist.");
    }

    if (TERMINAL_ENTITY_STATES.includes(entity.status)) {
      return PolicyResult.denied("ENTITY_DELETED", "Deleted entities cannot be backed up.");
    }

    return PolicyResult.allowed();
  }
}

export class RecoveryPolicy implements IPolicy<any> {
  public async evaluate(entity: any, context?: any): Promise<PolicyResult> {
    if (!entity) {
      // During recovery from cloud, the entity might not exist locally yet.
      // This is allowed if context has valid cloud data.
      if (context?.cloudData) {
        return PolicyResult.allowed({ type: "FULL_RESTORE" });
      }
      return PolicyResult.denied("ENTITY_NOT_FOUND", "Entity does not exist and no cloud data provided.");
    }

    if (TERMINAL_ENTITY_STATES.includes(entity.status)) {
      return PolicyResult.denied("ENTITY_DELETED", "Deleted entities cannot be recovered.");
    }

    return PolicyResult.allowed({ type: "MERGE" });
  }
}
