import { IStructuralValidator, ILifecycleValidator } from "../core/interfaces";
import { TERMINAL_ENTITY_STATES } from "../core/constants";

export class StructuralValidator implements IStructuralValidator {
  public async validate(entity: any): Promise<boolean> {
    if (!entity) return false;
    if (!entity.id || typeof entity.id !== "string") return false;
    
    // Check version metadata types
    if (typeof entity.entityVersion !== "number" || entity.entityVersion < 1) return false;
    if (typeof entity.lifecycleRevision !== "number" || entity.lifecycleRevision < 1) return false;
    
    // DeletedAt consistency
    const isTerminal = TERMINAL_ENTITY_STATES.includes(entity.status);
    const hasDeletedAt = !!entity.deletedAt;
    
    if (isTerminal && !hasDeletedAt) {
      // Data corruption: marked terminal but no deleted timestamp
      return false;
    }
    
    if (!isTerminal && hasDeletedAt) {
      // Data corruption: not terminal but has deleted timestamp
      return false;
    }

    return true;
  }
}

export class LifecycleValidator implements ILifecycleValidator {
  public async validateTransition(entity: any, targetState: string): Promise<boolean> {
    if (!entity) return false;
    
    const currentState = entity.status;
    
    // Terminal states cannot transition to anything
    if (TERMINAL_ENTITY_STATES.includes(currentState)) {
      return false;
    }

    // Example simple lifecycle transition map (extend as needed)
    const validTransitions: Record<string, string[]> = {
      "PROVISIONED": ["LICENSE_ASSIGNED", "DELETED"],
      "LICENSE_ASSIGNED": ["ACTIVATED", "DELETED"],
      "ACTIVATED": ["RUNNING", "SUSPENDED", "DELETED"],
      "RUNNING": ["SUSPENDED", "DELETED"],
      "SUSPENDED": ["RUNNING", "REVOKED", "DELETED"],
      "REVOKED": ["DELETED", "PURGED"],
      "ACTIVE": ["SUSPENDED", "DELETED"] // Legacy support
    };

    const allowed = validTransitions[currentState] || [];
    return allowed.includes(targetState);
  }
}
