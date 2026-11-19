import { describe, expect, test } from "vitest";
import { clientIpFromHeaders } from "./client-ip";

const h = (o: Record<string, string>) => ({ get: (n: string) => o[n.toLowerCase()] ?? null });

describe("clientIpFromHeaders", () => {
  test("prefers CF-Connecting-IP, then the first X-Forwarded-For entry, then X-Real-IP", () => {
    expect(clientIpFromHeaders(h({ "cf-connecting-ip": "1.1.1.1", "x-forwarded-for": "2.2.2.2, 3.3.3.3" }))).toBe("1.1.1.1");
    expect(clientIpFromHeaders(h({ "x-forwarded-for": " 2.2.2.2 , 3.3.3.3" }))).toBe("2.2.2.2");
    expect(clientIpFromHeaders(h({ "x-real-ip": "4.4.4.4" }))).toBe("4.4.4.4");
    expect(clientIpFromHeaders(h({}))).toBeUndefined();
  });
});
