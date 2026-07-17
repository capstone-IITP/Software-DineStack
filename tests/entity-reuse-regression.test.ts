import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { EntityPolicy } from '../policies/EntityPolicy';
import { EntityLifecycleService } from '../services/EntityLifecycleService';
import { EntityPersistenceService } from '../services/EntityPersistenceService';

class MemoryTransactionManager {
  constructor(private tx: any) {}

  async execute<T>(operation: (tx: any) => Promise<T>): Promise<T> {
    return operation(this.tx);
  }
}

function createDeletionTx(seed: any) {
  const state = {
    restaurant: { ...seed.restaurant },
    activationCodes: [...seed.activationCodes],
    sessions: [...seed.sessions],
    tableSessions: [...seed.tableSessions],
    refreshTokens: [...seed.refreshTokens],
    orders: [...seed.orders],
    orderItems: [...seed.orderItems],
    menuItemVariants: [...seed.menuItemVariants],
    menuItems: [...seed.menuItems],
    categories: [...seed.categories],
    devices: [...seed.devices],
    tables: [...seed.tables],
    customers: [...seed.customers],
    coupons: [...seed.coupons],
    pairCodes: [...seed.pairCodes],
    recoveryCodes: [...seed.recoveryCodes],
    apiKeys: [...seed.apiKeys],
    subscriptions: [...seed.subscriptions],
    payments: [...seed.payments],
    auditLogs: [] as any[]
  };

  const clearByRestaurant = (collection: keyof typeof state) => async ({ where }: any) => {
    (state[collection] as any[]) = (state[collection] as any[]).filter((row) => row.restaurantId !== where.restaurantId);
  };

  return {
    state,
    tx: {
      activationCode: {
        updateMany: async ({ data }: any) => {
          state.activationCodes = state.activationCodes.map((code) => ({
            ...code,
            ...data
          }));
        }
      },
      session: { deleteMany: clearByRestaurant('sessions') },
      tableSession: { deleteMany: clearByRestaurant('tableSessions') },
      refreshToken: { deleteMany: clearByRestaurant('refreshTokens') },
      pairCode: { deleteMany: clearByRestaurant('pairCodes') },
      recoveryCode: { deleteMany: clearByRestaurant('recoveryCodes') },
      apiKey: { deleteMany: clearByRestaurant('apiKeys') },
      subscription: { deleteMany: clearByRestaurant('subscriptions') },
      payment: { deleteMany: clearByRestaurant('payments') },
      order: {
        findMany: async () => state.orders.map((order) => ({ id: order.id })),
        deleteMany: clearByRestaurant('orders')
      },
      orderItem: {
        deleteMany: async () => {
          state.orderItems = [];
        }
      },
      menuItemVariant: { deleteMany: async () => { state.menuItemVariants = []; } },
      menuItem: { deleteMany: clearByRestaurant('menuItems') },
      category: { deleteMany: clearByRestaurant('categories') },
      device: { deleteMany: clearByRestaurant('devices') },
      table: { deleteMany: clearByRestaurant('tables') },
      customer: { deleteMany: clearByRestaurant('customers') },
      coupon: { deleteMany: clearByRestaurant('coupons') },
      auditLog: {
        create: async ({ data }: any) => {
          state.auditLogs.push(data);
        }
      },
      restaurant: {
        update: async ({ data }: any) => {
          state.restaurant = { ...state.restaurant, ...data };
          return state.restaurant;
        }
      }
    }
  };
}

test('deleted restaurant names are reusable without visible name mutation or old runtime reuse', async () => {
  const oldRestaurantId = randomUUID();
  const oldActivationId = randomUUID();
  const displayName = "Anwar's Cafe";
  const deletedAt = '2026-07-15T00:00:00.000Z';

  const oldRestaurant = {
    id: oldRestaurantId,
    name: displayName,
    status: 'ACTIVE',
    isActive: true,
    activationCodeId: oldActivationId,
    entityVersion: 1,
    lifecycleRevision: 1,
    deletedAt: null
  };

  const { state, tx } = createDeletionTx({
    restaurant: oldRestaurant,
    activationCodes: [{ id: oldActivationId, restaurantId: oldRestaurantId, status: 'USED', isUsed: true }],
    sessions: [{ id: randomUUID(), restaurantId: oldRestaurantId }],
    tableSessions: [{ id: randomUUID(), restaurantId: oldRestaurantId }],
    refreshTokens: [{ id: randomUUID(), restaurantId: oldRestaurantId }],
    orders: [{ id: randomUUID(), restaurantId: oldRestaurantId }],
    orderItems: [{ id: randomUUID() }],
    menuItemVariants: [{ id: randomUUID() }],
    menuItems: [{ id: randomUUID(), restaurantId: oldRestaurantId }],
    categories: [{ id: randomUUID(), restaurantId: oldRestaurantId }],
    devices: [{ id: randomUUID(), restaurantId: oldRestaurantId }],
    tables: [{ id: randomUUID(), restaurantId: oldRestaurantId }],
    customers: [{ id: randomUUID(), restaurantId: oldRestaurantId }],
    coupons: [{ id: randomUUID(), restaurantId: oldRestaurantId }],
    pairCodes: [{ id: randomUUID(), restaurantId: oldRestaurantId }],
    recoveryCodes: [{ id: randomUUID(), restaurantId: oldRestaurantId }],
    apiKeys: [{ id: randomUUID(), restaurantId: oldRestaurantId }],
    subscriptions: [{ id: randomUUID(), restaurantId: oldRestaurantId }],
    payments: [{ id: randomUUID(), restaurantId: oldRestaurantId }]
  });

  const persistence = new EntityPersistenceService(new MemoryTransactionManager(tx));
  const lifecycle = new EntityLifecycleService(
    { findById: async () => oldRestaurant, findByName: async () => null, save: async () => null, delete: async () => undefined, update: async () => null },
    persistence,
    { now: () => Date.parse(deletedAt), utcNow: () => deletedAt }
  );

  const deletedRestaurant = await lifecycle.transitionToDeleted(oldRestaurant);

  assert.equal(deletedRestaurant.name, displayName);
  assert.equal(deletedRestaurant.status, 'DELETED');
  assert.equal(deletedRestaurant.isActive, false);
  assert.equal(deletedRestaurant.activationCodeId, null);
  assert.equal(EntityPolicy.isNameReserved(deletedRestaurant), false);
  assert.equal(state.auditLogs.length, 1);
  assert.equal(JSON.parse(state.auditLogs[0].details).archivedDisplayName, displayName);
  assert.ok(!deletedRestaurant.name.includes('DELETED-'));

  for (const collection of [
    state.sessions,
    state.tableSessions,
    state.refreshTokens,
    state.orders,
    state.orderItems,
    state.menuItemVariants,
    state.menuItems,
    state.categories,
    state.devices,
    state.tables,
    state.customers,
    state.coupons,
    state.pairCodes,
    state.recoveryCodes,
    state.apiKeys,
    state.subscriptions,
    state.payments
  ]) {
    assert.equal(collection.length, 0);
  }

  assert.equal(state.activationCodes[0].status, 'INVALIDATED');
  assert.equal(state.activationCodes[0].restaurantId, null);

  const recreatedRestaurant = {
    id: randomUUID(),
    name: displayName,
    status: 'ACTIVE',
    isActive: true,
    activationCodeId: randomUUID()
  };

  assert.notEqual(recreatedRestaurant.id, oldRestaurantId);
  assert.notEqual(recreatedRestaurant.activationCodeId, oldActivationId);
  assert.equal(recreatedRestaurant.name, displayName);
  assert.equal(EntityPolicy.isNameReserved(recreatedRestaurant), true);
});
