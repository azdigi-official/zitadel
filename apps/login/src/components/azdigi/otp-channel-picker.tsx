"use client";

import { OtpChannel } from "@/lib/azdigi/otp-channel";
import { setOtpChannel } from "@/lib/server/azdigi/otp-channel";
import clsx from "clsx";
import { useTranslations } from "next-intl";
import { useRouter } from "next/navigation";
import { useState } from "react";

type Props = {
  current: OtpChannel;
  phoneMasked: string;
  available: OtpChannel[];
  loginName?: string;
  organization?: string;
  requestId?: string;
  altPassword?: boolean;
  onError: (message: string) => void;
};

/** "Receive the code via: Email · Zalo · SMS" above the code field; shown only with a verified phone and SMS enabled. */
export function OtpChannelPicker({ current, phoneMasked, available, loginName, organization, requestId, altPassword, onError }: Props) {
  const t = useTranslations("otp.channel");
  const router = useRouter();
  const [busy, setBusy] = useState<OtpChannel | null>(null);

  const all: { channel: OtpChannel; label: string }[] = [
    { channel: "email", label: t("email") },
    { channel: "zalo", label: t("zalo", { phone: phoneMasked }) },
    { channel: "sms", label: t("sms", { phone: phoneMasked }) },
  ];
  const choices = all.filter((choice) => available.includes(choice.channel));

  async function choose(channel: OtpChannel) {
    if (channel === current || busy) {
      return;
    }
    setBusy(channel);
    const result = await setOtpChannel({ channel, loginName, organization, requestId, altPassword }).catch(() => ({
      error: t("errors.couldNotStore"),
    }));
    setBusy(null);
    if ("redirect" in result) {
      router.push(result.redirect);
    } else {
      onError(result.error);
    }
  }

  return (
    <fieldset className="mb-2" data-testid="otp-channel-picker">
      <legend className="ztdl-p mb-2">{t("title")}</legend>
      <div className="flex flex-wrap gap-2">
        {choices.map((choice) => (
          <button
            key={choice.channel}
            type="button"
            disabled={busy !== null}
            aria-pressed={choice.channel === current}
            onClick={() => choose(choice.channel)}
            data-testid={`otp-channel-${choice.channel}`}
            className={clsx(
              "rounded-md border px-3 py-1.5 text-sm",
              choice.channel === current
                ? "border-primary-light-500 text-primary-light-500 dark:border-primary-dark-500 dark:text-primary-dark-500"
                : "border-black/10 text-black dark:border-white/10 dark:text-white",
              "disabled:opacity-60",
            )}
          >
            {choice.label}
          </button>
        ))}
      </div>
    </fieldset>
  );
}
