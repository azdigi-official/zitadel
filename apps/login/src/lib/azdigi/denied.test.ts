import { describe, expect, test } from "vitest";
import { DENIED_REASONS, deniedReason } from "./denied";

describe("deniedReason", () => {
  test("known codes pass, with or without the token-endpoint prefix; anything else is the generic reason", () => {
    expect(deniedReason("client_banned")).toBe("client_banned");
    expect(deniedReason("azdigi_ineligible:client_user_invite_acceptance_required")).toBe("client_user_invite_acceptance_required");
    expect(deniedReason("<script>alert(1)</script>")).toBe("not_eligible");
    expect(deniedReason(undefined)).toBe("not_eligible");
    expect(deniedReason(["client_banned"])).toBe("not_eligible");
    expect(DENIED_REASONS).toContain("eligibility_unavailable");
  });
});
