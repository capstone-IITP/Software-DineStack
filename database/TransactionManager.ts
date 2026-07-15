import { ITransactionManager } from "../core/interfaces";
import { PrismaClient } from "@prisma/client";
import { LifecycleError } from "../core/models";

const prisma = new PrismaClient();

export class TransactionManager implements ITransactionManager {
  /**
   * Executes the given operation within a Prisma transaction.
   * If the operation fails, the transaction is automatically rolled back.
   * 
   * @param operation The callback containing the transactional operations.
   */
  public async execute<T>(operation: (tx: any) => Promise<T>): Promise<T> {
    try {
      return await prisma.$transaction(async (tx) => {
        return await operation(tx);
      });
    } catch (error: any) {
      // We can implement retry policies here for transient failures in the future.
      console.error("[TransactionManager] Transaction failed:", error.message);
      throw new LifecycleError(`Transaction failed: ${error.message}`);
    }
  }

  // A method for repositories to get the base client for non-transactional reads
  public getClient(): PrismaClient {
    return prisma;
  }
}
