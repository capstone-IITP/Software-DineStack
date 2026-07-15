import { LifecycleDecision, DecisionType, PolicyResult } from "../core/models";
import { IPolicyCoordinator } from "../core/interfaces";

export class LifecycleDecisionEngine implements IPolicyCoordinator {
  /**
   * Evaluates multiple policies and determines the overall lifecycle decision.
   * This centralizes all logic for deciding how the system should proceed.
   */
  public async coordinate(policies: { evaluate: (entity: any, context?: any) => Promise<PolicyResult> }[], entity: any, context?: any): Promise<LifecycleDecision> {
    
    for (const policy of policies) {
      const result = await policy.evaluate(entity, context);
      
      if (!result.success) {
        // Here we map specific policy rejection codes to lifecycle decisions
        switch (result.code) {
          case "ENTITY_DELETED":
          case "ALREADY_PURGED":
            return new LifecycleDecision(DecisionType.MANUAL_INTERVENTION, "CRITICAL", result.message, result.context);
          
          case "ALREADY_ACTIVE":
            // Maybe continue but block reactivation
            return new LifecycleDecision(DecisionType.CONTINUE, "INFO", result.message, result.context);
            
          case "STALE_LIFECYCLE_STATE":
            return new LifecycleDecision(DecisionType.REPAIR, "WARNING", result.message, result.context);
            
          case "ACTIVATION_REQUIRED":
            return new LifecycleDecision(DecisionType.ACTIVATION_REQUIRED, "WARNING", result.message, result.context);

          default:
            return new LifecycleDecision(DecisionType.MANUAL_INTERVENTION, "ERROR", result.message, result.context);
        }
      }
    }

    return new LifecycleDecision(DecisionType.CONTINUE, "INFO", "All policies passed.", {});
  }
}
