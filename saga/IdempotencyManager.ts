import { IdempotencyRecord, SagaStep } from './types';

// In a real production system, this would be backed by Redis or PostgreSQL with TTL
export class IdempotencyManager {
    private static store: Map<string, IdempotencyRecord> = new Map();

    public static async registerOperation(operationId: string, correlationId: string, contextJson: string): Promise<boolean> {
        if (this.store.has(operationId)) {
            return false; // Already exists
        }
        this.store.set(operationId, {
            operationId,
            correlationId,
            status: 'IN_PROGRESS',
            lastCheckpoint: 'PREPARE_STARTED',
            timestamp: new Date(),
            context: contextJson
        });
        return true;
    }

    public static async getOperation(operationId: string): Promise<IdempotencyRecord | null> {
        return this.store.get(operationId) || null;
    }

    public static async updateCheckpoint(operationId: string, checkpoint: SagaStep, status?: 'IN_PROGRESS' | 'COMPLETED' | 'FAILED'): Promise<void> {
        const record = this.store.get(operationId);
        if (record) {
            record.lastCheckpoint = checkpoint;
            if (status) {
                record.status = status;
            }
            record.timestamp = new Date();
            this.store.set(operationId, record);
        }
    }

    public static async clearCompletedOperations(maxAgeMs: number = 7 * 24 * 60 * 60 * 1000): Promise<void> {
        const now = Date.now();
        for (const [operationId, record] of this.store.entries()) {
            if (record.status === 'COMPLETED' || record.status === 'FAILED') {
                if (now - record.timestamp.getTime() > maxAgeMs) {
                    this.store.delete(operationId);
                }
            }
        }
    }
}
