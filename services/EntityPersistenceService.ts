import { IEntityPersistenceService, ITransactionManager } from "../core/interfaces";

export class EntityPersistenceService implements IEntityPersistenceService {
  constructor(private transactionManager: ITransactionManager) {}

  public async applyDeletionTransition(mutatedEntity: any): Promise<any> {
    return await this.transactionManager.execute(async (tx: any) => {
      await tx.session.deleteMany({ where: { restaurantId: mutatedEntity.id } });
      await tx.tableSession.deleteMany({ where: { restaurantId: mutatedEntity.id } });
      await tx.refreshToken.deleteMany({ where: { restaurantId: mutatedEntity.id } });
      
      const orders = await tx.order.findMany({ where: { restaurantId: mutatedEntity.id }, select: { id: true } });
      const orderIds = orders.map((o: any) => o.id);
      if (orderIds.length > 0) {
        await tx.orderItem.deleteMany({ where: { orderId: { in: orderIds } } });
      }
      await tx.order.deleteMany({ where: { restaurantId: mutatedEntity.id } });
      
      await tx.menuItemVariant.deleteMany({ where: { menuItem: { restaurantId: mutatedEntity.id } } });
      await tx.menuItem.deleteMany({ where: { restaurantId: mutatedEntity.id } });
      await tx.category.deleteMany({ where: { restaurantId: mutatedEntity.id } });
      await tx.device.deleteMany({ where: { restaurantId: mutatedEntity.id } });
      await tx.table.deleteMany({ where: { restaurantId: mutatedEntity.id } });
      await tx.customer.deleteMany({ where: { restaurantId: mutatedEntity.id } });
      await tx.coupon.deleteMany({ where: { restaurantId: mutatedEntity.id } });

      const updated = await tx.restaurant.update({
        where: { id: mutatedEntity.id },
        data: {
          name: mutatedEntity.name,
          status: mutatedEntity.status,
          isActive: mutatedEntity.isActive,
          deletedAt: mutatedEntity.deletedAt,
          lifecycleRevision: mutatedEntity.lifecycleRevision,
          entityVersion: mutatedEntity.entityVersion
        }
      });
      return updated;
    });
  }

  public async applyStateTransition(mutatedEntity: any): Promise<any> {
    return await this.transactionManager.execute(async (tx: any) => {
      return await tx.restaurant.update({
        where: { id: mutatedEntity.id },
        data: {
          status: mutatedEntity.status,
          isActive: mutatedEntity.isActive,
          lifecycleRevision: mutatedEntity.lifecycleRevision,
          entityVersion: mutatedEntity.entityVersion,
          deletedAt: mutatedEntity.deletedAt
        }
      });
    });
  }

  public async applyMetadataUpdate(mutatedEntity: any, metadata: any): Promise<any> {
    return await this.transactionManager.execute(async (tx: any) => {
      return await tx.restaurant.update({
        where: { id: mutatedEntity.id },
        data: {
          ...metadata,
          lifecycleRevision: mutatedEntity.lifecycleRevision,
          entityVersion: mutatedEntity.entityVersion,
          updatedAt: mutatedEntity.updatedAt
        }
      });
    });
  }

  public async purge(entityId: string): Promise<void> {
    await this.transactionManager.execute(async (tx: any) => {
      await tx.restaurant.delete({ where: { id: entityId } });
    });
  }

  public async createEntity(entity: any): Promise<any> {
    return await this.transactionManager.execute(async (tx: any) => {
      return await tx.restaurant.create({ data: entity });
    });
  }

  public async updateEntity(entity: any): Promise<any> {
    return await this.transactionManager.execute(async (tx: any) => {
      return await tx.restaurant.update({ where: { id: entity.id }, data: entity });
    });
  }

  public async transitionEntity(entity: any): Promise<any> {
    return this.applyStateTransition(entity);
  }

  public async deleteEntity(entityId: string): Promise<void> {
    await this.purge(entityId);
  }
}
