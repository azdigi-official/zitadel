// AZDIGI: mailing the verification / invitation code when an AZDIGI step sends the user to /verify (the OTP-first
// customer who still has to set up, the email-code registration).
//
// Upstream's /verify page no longer sends on render; the step that redirects sends first and passes codeSent=true.
// Every new code voids the one before, so a repeated step (double submit, back and forth) sends at most one code per
// user and kind per minute (rate-limit.ts claimVerifyPageSend). The user is always resolved on the server.
import { trySendVerification } from "@/lib/server/verification-email";
import { claimVerifyPageSend } from "./rate-limit";

export async function sendVerificationOnce(command: {
  userId: string;
  isInvite: boolean;
  requestId?: string;
}): Promise<boolean> {
  if (!claimVerifyPageSend(command.userId, command.isInvite ? "invite" : "email")) {
    return false;
  }
  return trySendVerification(command);
}
