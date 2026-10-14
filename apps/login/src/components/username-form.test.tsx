import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { sendLoginname } from "@/lib/server/loginname";
import { UsernameForm } from "./username-form";

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));
vi.mock("next-intl", () => ({
  useTranslations: () => (key: string) => key,
}));
vi.mock("@/lib/server/loginname", () => ({ sendLoginname: vi.fn() }));
vi.mock("@/lib/client", () => ({ handleServerActionResponse: vi.fn() }));

describe("UsernameForm whitespace validation", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(sendLoginname).mockResolvedValue({ error: "Search stopped" });
  });
  afterEach(cleanup);

  function renderForm(loginName?: string, submit = false) {
    render(
      <UsernameForm
        loginName={loginName}
        requestId={undefined}
        loginSettings={undefined}
        submit={submit}
        allowRegister={false}
      />,
    );
  }

  test("trims pasted outer whitespace before submitting", async () => {
    renderForm();
    fireEvent.change(screen.getByTestId("username-text-input"), { target: { value: " a@b.com " } });
    await waitFor(() => expect(screen.getByTestId("submit-button")).toBeEnabled());
    fireEvent.click(screen.getByTestId("submit-button"));
    await waitFor(() => expect(sendLoginname).toHaveBeenCalledWith(expect.objectContaining({ loginName: "a@b.com" })));
  });

  test.each(["a @b.com", "a\tb.com", "a\u00a0@b.com"])("rejects inner whitespace: %j", async (loginName) => {
    renderForm();
    fireEvent.change(screen.getByTestId("username-text-input"), { target: { value: loginName } });
    expect(await screen.findByText("errors.whitespace")).toBeInTheDocument();
    expect(screen.getByTestId("submit-button")).toBeDisabled();
    expect(sendLoginname).not.toHaveBeenCalled();
  });

  test("keeps whitespace-only input required", async () => {
    renderForm();
    fireEvent.change(screen.getByTestId("username-text-input"), { target: { value: "   " } });
    expect(await screen.findByText("required.loginName")).toBeInTheDocument();
    expect(screen.getByTestId("submit-button")).toBeDisabled();
    expect(sendLoginname).not.toHaveBeenCalled();
  });

  test("trims prefilled auto-submit values", async () => {
    renderForm(" a@b.com ", true);
    await waitFor(() => expect(sendLoginname).toHaveBeenCalledWith(expect.objectContaining({ loginName: "a@b.com" })));
  });
});
