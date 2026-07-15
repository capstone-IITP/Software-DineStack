import { IPolicy } from "../core/interfaces";
import { PolicyResult } from "../core/models";

export class DeletionPolicy implements IPolicy<any> {
  public async evaluate(entity: any, context?: any): Promise<PolicyResult> {
    const strategy = context?.strategy || "SystemResetStrategy";
    return PolicyResult.allowed({ strategy });
  }

  public static generateDeletionIdentity(entityName: string, entityId: string): string {
    const timestamp = Date.now();
    const shortId = entityId.substring(0, 6);
    return `${entityName} [DELETED-${timestamp}-${shortId}]`;
  }

  public static shouldReleaseNamespace(entityStatus: string): boolean {
    return true;
  }
}
