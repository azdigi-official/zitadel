// AZDIGI: the code screen (resend clears old errors, alternatives wait for the code request in flight).
import { updateOrCreateSession } from "@/lib/actions/session";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { LoginOTP } from "./login-otp";

const push = vi.hoisted(() => vi.fn());
vi.mock("next/navigation", () => ({ useRouter: () => ({ push }) }));
vi.mock("next-intl", () => ({ useTranslations: () => (key: string) => key }));
vi.mock("@/lib/actions/session", () => ({ updateOrCreateSession: vi.fn() }));
vi.mock("@/lib/actions/password", () => ({ resetPassword: vi.fn() }));
vi.mock("@/lib/client-utils", () => ({ handleServerActionResponse: vi.fn() }));
vi.mock("@/lib/actions/flow", () => ({ completeFlowOrGetUrl: vi.fn() }));
vi.mock("./azdigi/otp-channel-picker", () => ({ OtpChannelPicker: () => null }));

afterEach(cleanup);
beforeEach(() => vi.resetAllMocks());

test.each(["email", "sms"])(
  "resending %s clears the previous rate-limit error while pending and after success",
  async (method) => {
    let finish!: (value: any) => void;
    vi.mocked(updateOrCreateSession)
      .mockResolvedValueOnce({ error: "Too many requests" })
      .mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            finish = resolve;
          }),
      );
    render(<LoginOTP loginName="customer@example.test" method={method} />);
    expect(await screen.findByTestId("error")).toHaveTextContent("Too many requests");
    await waitFor(() => expect(screen.getByTestId("resend-button")).toBeEnabled());
    fireEvent.click(screen.getByTestId("resend-button"));
    expect(screen.queryByTestId("error")).not.toBeInTheDocument();
    expect(screen.getByTestId("resend-button")).toBeDisabled();
    await act(async () => finish({ sessionId: "s1" }));
    expect(screen.queryByTestId("error")).not.toBeInTheDocument();
    expect(screen.getByTestId("resend-button")).toBeEnabled();
  },
);

test("a failed resend displays the current error", async () => {
  vi.mocked(updateOrCreateSession)
    .mockResolvedValueOnce({ error: "Old error" })
    .mockResolvedValueOnce({ error: "Still rate limited" });
  render(<LoginOTP loginName="customer@example.test" method="email" />);
  expect(await screen.findByTestId("error")).toHaveTextContent("Old error");
  await waitFor(() => expect(screen.getByTestId("resend-button")).toBeEnabled());
  fireEvent.click(screen.getByTestId("resend-button"));
  await waitFor(() => expect(screen.getByTestId("error")).toHaveTextContent("Still rate limited"));
});

test.each([
  ["password-button", "/password"],
  ["passkey-button", "/passkey"],
])("%s waits for the code request in flight before leaving the screen", async (button, path) => {
  let finish!: (value: any) => void;
  vi.mocked(updateOrCreateSession).mockImplementationOnce(
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  render(<LoginOTP loginName="customer@example.test" method="email" altPassword altPasskey />);
  fireEvent.click(screen.getByTestId(button));
  await act(async () => {});
  expect(push).not.toHaveBeenCalled();
  await act(async () => finish({ sessionId: "s1" }));
  await waitFor(() => expect(push).toHaveBeenCalledWith(expect.stringContaining(path + "?")));
});

test("a verified code asked for by an enrolment page goes back to that page, rebuilt from the known path", async () => {
  const { completeFlowOrGetUrl } = await import("@/lib/actions/flow");
  vi.mocked(updateOrCreateSession).mockResolvedValue({
    sessionId: "s1",
    factors: { user: { loginName: "khach@example.vn", organizationId: "customers" } },
  } as any);
  render(
    <LoginOTP loginName="khach@example.vn" method="time-based" requestId="oidc_1" returnTo="/passkey/set?prompt=true" />,
  );
  fireEvent.change(screen.getByTestId("code-text-input"), { target: { value: "123456" } });
  await waitFor(() => expect(screen.getByTestId("submit-button")).toBeEnabled());
  fireEvent.click(screen.getByTestId("submit-button"));
  await waitFor(
    () =>
      expect(push).toHaveBeenCalledWith(
        "/passkey/set?prompt=true&loginName=khach%40example.vn&organization=customers&requestId=oidc_1",
      ),
    { timeout: 5_000 },
  );
  expect(completeFlowOrGetUrl).not.toHaveBeenCalled();
});

test("a way back that is not a known enrolment page is ignored: the flow continues as usual", async () => {
  const { completeFlowOrGetUrl } = await import("@/lib/actions/flow");
  vi.mocked(updateOrCreateSession).mockResolvedValue({
    sessionId: "s1",
    factors: { user: { loginName: "khach@example.vn", organizationId: "customers" } },
  } as any);
  vi.mocked(completeFlowOrGetUrl).mockResolvedValue({ redirect: "/account" } as any);
  render(<LoginOTP loginName="khach@example.vn" method="time-based" returnTo="https://evil.example/passkey/set" />);
  fireEvent.change(screen.getByTestId("code-text-input"), { target: { value: "123456" } });
  await waitFor(() => expect(screen.getByTestId("submit-button")).toBeEnabled());
  fireEvent.click(screen.getByTestId("submit-button"));
  await waitFor(() => expect(completeFlowOrGetUrl).toHaveBeenCalled(), { timeout: 5_000 });
  expect(push).not.toHaveBeenCalledWith(expect.stringContaining("evil"));
});
