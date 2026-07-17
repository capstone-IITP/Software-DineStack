export class EntityPolicy {
    static ACTIVE_STATES = ['PROVISIONED', 'LICENSE_ASSIGNED', 'ACTIVATED', 'RUNNING', 'ACTIVE', 'GRACE', 'SUSPENDED', 'REVOKED'];
    static TERMINAL_STATES = ['DELETED', 'PURGED'];

    public static isNameReserved(entityOrStatus: any): boolean {
        const entityStatus = typeof entityOrStatus === 'string' ? entityOrStatus : entityOrStatus?.status;
        if (!entityStatus) return false;
        if (this.TERMINAL_STATES.includes(entityStatus)) return false;
        return this.ACTIVE_STATES.includes(entityStatus);
    }
    
    public static canActivate(entityStatus: string): boolean {
        return ['PROVISIONED', 'LICENSE_ASSIGNED', 'SUSPENDED'].includes(entityStatus);
    }

    public static canDelete(entityStatus: string): boolean {
        return !this.TERMINAL_STATES.includes(entityStatus);
    }

    public static canSync(entityStatus: string): boolean {
        return ['ACTIVATED', 'RUNNING'].includes(entityStatus);
    }

    public static canRestore(entityStatus: string): boolean {
        return ['PROVISIONED', 'LICENSE_ASSIGNED', 'ACTIVATED', 'RUNNING', 'SUSPENDED', 'REVOKED'].includes(entityStatus);
    }

    public static canUpdate(entityStatus: string): boolean {
        return ['PROVISIONED', 'LICENSE_ASSIGNED', 'ACTIVATED', 'RUNNING'].includes(entityStatus);
    }
}
