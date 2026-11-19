import { describe, expect, test } from "vitest";
import { estimateUnlockAt, isLockedMessage, orgKindFromSettings, unlockWindowMinutes } from "./lockout";

describe("lockout helpers", () => {
  test("recognises Zitadel's locked messages", () => {
    expect(isLockedMessage("User is locked (COMMAND-S6h4R)")).toBe(true);
    expect(isLockedMessage("Errors.User.NotActive (SESSION-Gj4ko)")).toBe(true);
    expect(isLockedMessage("Code is invalid (CODE-woT0xc)")).toBe(false);
    expect(isLockedMessage(undefined)).toBe(false);
  });

  test("windows default to 30/15 minutes and can be overridden", () => {
    expect(unlockWindowMinutes("customers", {} as any)).toBe(30);
    expect(unlockWindowMinutes("internal", {} as any)).toBe(15);
    expect(unlockWindowMinutes("customers", { AZDIGI_UNLOCK_MINUTES_CUSTOMERS: "45" } as any)).toBe(45);
    expect(unlockWindowMinutes("internal", { AZDIGI_UNLOCK_MINUTES_INTERNAL: "x" } as any)).toBe(15);
    expect(orgKindFromSettings({ forceMfa: true })).toBe("internal");
    expect(orgKindFromSettings(undefined)).toBe("customers");
  });

  test("ETA only while the worker flag is on, in the future, with a known lock time", () => {
    const locked = new Date("2026-10-04T06:00:00Z");
    const now = new Date("2026-10-04T06:10:00Z");
    expect(estimateUnlockAt(locked, "customers", now, {} as any)).toBeUndefined();
    const on = { AZDIGI_UNLOCK_ETA_ENABLED: "true" } as any;
    expect(estimateUnlockAt(locked, "customers", now, on)?.toISOString()).toBe("2026-10-04T06:30:00.000Z");
    expect(estimateUnlockAt(locked, "internal", now, on)?.toISOString()).toBe("2026-10-04T06:15:00.000Z");
    expect(estimateUnlockAt(locked, "internal", new Date("2026-10-04T06:20:00Z"), on)).toBeUndefined();
    expect(estimateUnlockAt(undefined, "internal", now, on)).toBeUndefined();
  });
});
