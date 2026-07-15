import { IPolicy } from "../core/interfaces";
import { PolicyResult } from "../core/models";
import { NON_ACTIVE_ENTITY_STATES } from "../core/constants";

export class ActivationPolicy implements IPolicy<any> {
  public async evaluate(entity: any, context?: any): Promise<PolicyResult> {
    if (!entity) {
      return PolicyResult.denied("ENTITY_NOT_FOUND", "Restaurant entity does not exist.");
    }

    // Display names are NOT used for activation logic.
    // We only check if the entity itself is in a state allowing activation.
    if (!NON_ACTIVE_ENTITY_STATES.includes(entity.status) && entity.status !== "ACTIVE") {
      // If it's already RUNNING or some other active state, we might deny reactivation
      // depending on business rules. Let's say if it's already running, you can't activate again
      // unless forceReactivation is true.
      if (entity.status === "RUNNING" && !entity.forceReactivation) {
        return PolicyResult.denied("ALREADY_ACTIVE", "Restaurant is already active and running.");
      }
    }

    if (entity.status === "DELETED" || entity.status === "PURGED") {
      return PolicyResult.denied("ENTITY_DELETED", "Cannot activate a deleted restaurant.");
    }

    return PolicyResult.allowed({ activationDate: new Date().toISOString() });
  }
}
