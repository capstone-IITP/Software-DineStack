import { IPolicy } from "../core/interfaces";
import { PolicyResult } from "../core/models";
import { TERMINAL_ENTITY_STATES } from "../core/constants";

export class SyncPolicy implements IPolicy<any> {
  public async evaluate(entity: any, context?: any): Promise<PolicyResult> {
    if (!entity) {
      return PolicyResult.denied("ENTITY_NOT_FOUND", "Entity does not exist.");
    }

    if (TERMINAL_ENTITY_STATES.includes(entity.status)) {
      return PolicyResult.denied("ENTITY_DELETED", "Deleted entities cannot synchronize.");
    }
    
    // Check if the entity lifecycle revision provided by the client is stale
    if (context?.clientLifecycleRevision !== undefined) {
      if (context.clientLifecycleRevision < entity.lifecycleRevision) {
        return PolicyResult.denied("STALE_LIFECYCLE_STATE", "Client lifecycle state is stale. Must re-authenticate.");
      }
    }

    return PolicyResult.allowed();
  }
}
