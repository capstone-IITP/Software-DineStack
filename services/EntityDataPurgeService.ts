import { IEntityPersistenceService, ITransactionManager } from "../core/interfaces";

export class EntityDataPurgeService implements IEntityPersistenceService {
  constructor(private transactionManager: ITransactionManager) {}

  public async purge(entityId: string): Promise<void> {
    await this.transactionManager.execute(async (tx) => {
      // Deletes relational data, activation artifacts, refresh tokens, sessions, etc.
      await tx.session.deleteMany({ where: { restaurantId: entityId } });
      await tx.tableSession.deleteMany({ where: { restaurantId: entityId } });
      await tx.refreshToken.deleteMany({ where: { restaurantId: entityId } });
      
      // Delete orders, menu items, categories, etc...
      await tx.orderItem.deleteMany({ where: { order: { restaurantId: entityId } } });
      await tx.order.deleteMany({ where: { restaurantId: entityId } });
      
      await tx.menuItemVariant.deleteMany({ where: { menuItem: { restaurantId: entityId } } });
      await tx.menuItem.deleteMany({ where: { restaurantId: entityId } });
      await tx.category.deleteMany({ where: { restaurantId: entityId } });

      await tx.device.deleteMany({ where: { restaurantId: entityId } });
      await tx.table.deleteMany({ where: { restaurantId: entityId } });
      await tx.customer.deleteMany({ where: { restaurantId: entityId } });
      await tx.coupon.deleteMany({ where: { restaurantId: entityId } });

      // Note: we don't necessarily delete the restaurant itself if it's just "purging relational data".
      // Usually "purge" means deleting it entirely. But "DELETED" keeps the record.
      // If purge means actual removal:
      await tx.restaurant.delete({ where: { id: entityId } });
    });
  }
}
