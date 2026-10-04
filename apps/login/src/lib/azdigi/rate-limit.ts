/**
 * In-memory sliding-window limiters for the OTP server action. One login instance in M1; a shared store (Redis)
 * is a recorded debt. Buckets live on globalThis so dev hot reloads do not reset them.
 */
export type LimitResult = { allowed: boolean; remaining: number; retryAfterMs: number };

export class SlidingWindowLimiter {
  private readonly hits = new Map<string, number[]>();
  private lastPrune = 0;

  constructor(
    readonly limit: number,
    readonly windowMs: number,
    private readonly maxKeys = 50_000,
  ) {}

  /** Records one hit for the key and reports whether it stays within the limit. */
  hit(key: string, now = Date.now()): LimitResult {
    this.prune(now);
    const stamps = (this.hits.get(key) ?? []).filter((t) => now - t < this.windowMs);
    if (stamps.length >= this.limit) {
      this.hits.set(key, stamps);
      return { allowed: false, remaining: 0, retryAfterMs: stamps[0] + this.windowMs - now };
    }
    stamps.push(now);
    this.hits.set(key, stamps);
    return { allowed: true, remaining: this.limit - stamps.length, retryAfterMs: 0 };
  }

  /** Reports the state without recording a hit. */
  peek(key: string, now = Date.now()): LimitResult {
    const stamps = (this.hits.get(key) ?? []).filter((t) => now - t < this.windowMs);
    if (stamps.length >= this.limit) {
      return { allowed: false, remaining: 0, retryAfterMs: stamps[0] + this.windowMs - now };
    }
    return { allowed: true, remaining: this.limit - stamps.length, retryAfterMs: 0 };
  }

  clear(key: string) {
    this.hits.delete(key);
  }

  reset() {
    this.hits.clear();
  }

  private prune(now: number) {
    if (now - this.lastPrune < this.windowMs && this.hits.size < this.maxKeys) {
      return;
    }
    this.lastPrune = now;
    for (const [key, stamps] of Array.from(this.hits.entries())) {
      const live = stamps.filter((t) => now - t < this.windowMs);
      if (live.length === 0) {
        this.hits.delete(key);
      } else {
        this.hits.set(key, live);
      }
    }
    if (this.hits.size >= this.maxKeys) {
      // drop the oldest keys; being generous here only loosens the limit briefly
      for (const key of Array.from(this.hits.keys()).slice(0, this.hits.size - this.maxKeys + 1)) {
        this.hits.delete(key);
      }
    }
  }
}

const TEN_MINUTES = 10 * 60 * 1000;

type Limiters = {
  otpSendPerLogin: SlidingWindowLimiter;
  otpSendPerIp: SlidingWindowLimiter;
  otpVerifyPerUser: SlidingWindowLimiter;
};

const store = globalThis as typeof globalThis & { __azdigiLimiters?: Limiters };

function limitFromEnv(name: string, fallback: number): number {
  const value = Number(process.env[name]);
  return Number.isFinite(value) && value > 0 ? value : fallback;
}

export const limiters: Limiters = (store.__azdigiLimiters ??= {
  // code sends: 3 per login name and 20 per client IP in 10 minutes (AZDIGI_OTP_SEND_PER_LOGIN / _PER_IP override)
  otpSendPerLogin: new SlidingWindowLimiter(limitFromEnv("AZDIGI_OTP_SEND_PER_LOGIN", 3), TEN_MINUTES),
  otpSendPerIp: new SlidingWindowLimiter(limitFromEnv("AZDIGI_OTP_SEND_PER_IP", 20), TEN_MINUTES),
  // code attempts: 2 per user in 10 minutes — Zitadel v4.11 locks the user on the 3rd wrong code (observed 04/10/2026
  // with maxOtpAttempts=5) and never unlocks by itself, so the soft limit must sit below that
  otpVerifyPerUser: new SlidingWindowLimiter(limitFromEnv("AZDIGI_OTP_VERIFY_PER_USER", 2), TEN_MINUTES),
});

export function resetLimiters() {
  limiters.otpSendPerLogin.reset();
  limiters.otpSendPerIp.reset();
  limiters.otpVerifyPerUser.reset();
}
