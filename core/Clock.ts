import { IClock } from "./interfaces";

export class Clock implements IClock {
  public now(): number {
    return Date.now();
  }

  public utcNow(): string {
    return new Date().toISOString();
  }
}

// A singleton instance for simple usage where DI is not strictly enforced yet.
// However, according to the rules, DI should be used for this.
export const systemClock = new Clock();
