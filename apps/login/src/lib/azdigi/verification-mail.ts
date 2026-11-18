// AZDIGI: sending the verification / invitation mail when the verify page is opened with `send=true`.
//
// Plain server module, NOT server actions: the link template is an argument, and published as actions (they lived in
// lib/server/verify.ts) anyone could have had the login mail a link of their choosing to any user.
import { createInviteCode, sendEmailCode as zitadelSendEmailCode } from "@/lib/zitadel";
import { headers } from "next/headers";
import { getServiceConfig } from "../service-url";

type SendEmailCommand = {
  userId: string;
  urlTemplate: string;
};

export async function sendEmailCode(command: SendEmailCommand) {
  const _headers = await headers();
  const { serviceConfig } = getServiceConfig(_headers);

  return zitadelSendEmailCode({ serviceConfig, userId: command.userId, urlTemplate: command.urlTemplate });
}

export async function sendInviteEmailCode(command: SendEmailCommand) {
  const _headers = await headers();
  const { serviceConfig } = getServiceConfig(_headers);

  return createInviteCode({ serviceConfig, userId: command.userId, urlTemplate: command.urlTemplate });
}
