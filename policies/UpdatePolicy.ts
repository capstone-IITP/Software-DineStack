import { IPolicy } from "../core/interfaces";
import { PolicyResult } from "../core/models";
import { TERMINAL_ENTITY_STATES } from "../core/constants";

export class UpdatePolicy implements IPolicy<any> {
  public async evaluate(entity: any, context?: any): Promise<PolicyResult> {
    if (!entity) {
      return PolicyResult.denied("ENTITY_NOT_FOUND", "Entity does not exist.");
    }

    if (TERMINAL_ENTITY_STATES.includes(entity.status)) {
      return PolicyResult.denied("ENTITY_DELETED", "Deleted entities cannot receive updates.");
    }

    return PolicyResult.allowed();
  }
}
