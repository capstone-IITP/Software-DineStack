import { IEntityRepository } from "../core/interfaces";
import { TransactionManager } from "../database/TransactionManager";

export class PrismaEntityRepository implements IEntityRepository {
  constructor(private transactionManager: TransactionManager) {}

  public async findById(id: string): Promise<any> {
    const prisma = this.transactionManager.getClient();
    return await prisma.restaurant.findUnique({
      where: { id },
      include: {
        activationCode: true,
        activationCodes: true
      }
    });
  }

  public async findByName(name: string): Promise<any> {
    const prisma = this.transactionManager.getClient();
    return await prisma.restaurant.findUnique({
      where: { name },
      include: {
        activationCode: true
      }
    });
  }

  public async save(entity: any): Promise<any> {
    const prisma = this.transactionManager.getClient();
    return await prisma.restaurant.create({
      data: entity
    });
  }

  public async update(id: string, data: any): Promise<any> {
    const prisma = this.transactionManager.getClient();
    return await prisma.restaurant.update({
      where: { id },
      data
    });
  }

  public async delete(id: string): Promise<void> {
    const prisma = this.transactionManager.getClient();
    await prisma.restaurant.delete({
      where: { id }
    });
  }
}
