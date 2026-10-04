"use server";

import { guardedDeviceAuthorization } from "@/lib/azdigi/issue";
import { headers } from "next/headers";
import { getServiceConfig } from "../service-url";

export async function completeDeviceAuthorization(
  deviceAuthorizationId: string,
  session?: { sessionId: string; sessionToken: string },
) {
  const _headers = await headers();
  const { serviceConfig } = getServiceConfig(_headers);

  // without the session, device auth request is denied; with one, the AZDIGI policy is checked first
  return guardedDeviceAuthorization({ serviceConfig, deviceAuthorizationId, session });
}
