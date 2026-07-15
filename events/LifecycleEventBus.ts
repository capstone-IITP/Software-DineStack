import { ILifecycleEventBus } from "../core/interfaces";
import { LifecycleEvent } from "./types";

export class LifecycleEventBus implements ILifecycleEventBus {
  private handlers: Map<string, Array<(event: any) => Promise<void>>> = new Map();

  public subscribe(eventType: string, handler: (event: any) => Promise<void>): void {
    const existing = this.handlers.get(eventType) || [];
    existing.push(handler);
    this.handlers.set(eventType, existing);
  }

  public async publish(event: LifecycleEvent): Promise<void> {
    const handlers = this.handlers.get(event.type) || [];
    
    // We do not wait for all handlers sequentially unless necessary.
    // However, robust error handling requires we at least catch errors so the bus doesn't crash.
    const promises = handlers.map(async (handler) => {
      try {
        await handler(event);
      } catch (err: any) {
        console.error(`[LifecycleEventBus] Error handling event ${event.type}:`, err.message);
      }
    });

    await Promise.all(promises);
  }
}

// Global instance for legacy areas not using DI yet
export const systemEventBus = new LifecycleEventBus();
