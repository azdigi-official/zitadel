import { describe, expect, test } from "vitest";
import { claimVerifyPageSend, resetLimiters, SlidingWindowLimiter } from "./rate-limit";

describe("claimVerifyPageSend", () => {
  test("one automatic send per user and kind per minute", () => {
    resetLimiters();
    expect(claimVerifyPageSend("u1", "invite", 0)).toBe(true);
    expect(claimVerifyPageSend("u1", "invite", 500)).toBe(false);
    expect(claimVerifyPageSend("u1", "email", 500)).toBe(true);
    expect(claimVerifyPageSend("u2", "invite", 500)).toBe(true);
    expect(claimVerifyPageSend("u1", "invite", 60_000)).toBe(true);
  });
});

describe("SlidingWindowLimiter", () => {
  test("allows up to the limit inside the window and refuses afterwards with a retry hint", () => {
    const l = new SlidingWindowLimiter(3, 600_000);
    const t0 = 1_000_000;
    expect(l.hit("k", t0).allowed).toBe(true);
    expect(l.hit("k", t0 + 1).allowed).toBe(true);
    expect(l.hit("k", t0 + 2)).toEqual({ allowed: true, remaining: 0, retryAfterMs: 0 });
    const refused = l.hit("k", t0 + 3);
    expect(refused.allowed).toBe(false);
    expect(refused.retryAfterMs).toBe(600_000 - 3);
  });

  test("hits fall out of the window and keys are independent", () => {
    const l = new SlidingWindowLimiter(1, 1000);
    expect(l.hit("a", 0).allowed).toBe(true);
    expect(l.hit("a", 500).allowed).toBe(false);
    expect(l.hit("b", 500).allowed).toBe(true);
    expect(l.hit("a", 1000).allowed).toBe(true);
  });

  test("peek does not count, clear resets one key", () => {
    const l = new SlidingWindowLimiter(2, 1000);
    l.hit("k", 0);
    expect(l.peek("k", 1).remaining).toBe(1);
    expect(l.peek("k", 1).remaining).toBe(1);
    l.clear("k");
    expect(l.peek("k", 2).remaining).toBe(2);
  });
});
