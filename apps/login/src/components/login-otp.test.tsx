import { updateOrCreateSession } from "@/lib/server/session";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { LoginOTP } from "./login-otp";

const push = vi.hoisted(() => vi.fn());
vi.mock("next/navigation", () => ({ useRouter: () => ({ push }) }));
vi.mock("next-intl", () => ({ useTranslations: () => (key: string) => key }));
vi.mock("@/lib/server/session", () => ({ updateOrCreateSession: vi.fn() }));
vi.mock("@/lib/server/password", () => ({ resetPassword: vi.fn() }));
vi.mock("@/lib/client", () => ({ handleServerActionResponse: vi.fn(), completeFlowOrGetUrl: vi.fn() }));
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
    render(<LoginOTP host="login.example.test" loginName="customer@example.test" method={method} />);
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
  render(<LoginOTP host="login.example.test" loginName="customer@example.test" method="email" />);
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
  render(<LoginOTP host="login.example.test" loginName="customer@example.test" method="email" altPassword altPasskey />);
  fireEvent.click(screen.getByTestId(button));
  await act(async () => {});
  expect(push).not.toHaveBeenCalled();
  await act(async () => finish({ sessionId: "s1" }));
  await waitFor(() => expect(push).toHaveBeenCalledWith(expect.stringContaining(path + "?")));
});
