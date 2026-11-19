"use server";

import { clientIpFromHeaders } from "@/lib/azdigi/client-ip";
import { decoyOtpRedirect, withMinimumDuration } from "@/lib/azdigi/decoy";
import { estimateUnlockAt, orgKindFromSettings } from "@/lib/azdigi/lockout";
import { isOtpFirstOrg } from "@/lib/azdigi/org-lookup";
import { decideOtpFirst, otpFirstAlternatives, otpFirstParams } from "@/lib/azdigi/otp-first";
import { limiters } from "@/lib/azdigi/rate-limit";
import { sendVerificationOnce } from "@/lib/azdigi/verification-mail";
import { idpTypeToIdentityProviderType, idpTypeToSlug } from "@/lib/idp";
import { equalsIgnoreCase } from "@/lib/server/auth-utils";
import { addIdpFlowProof } from "@/lib/server/fingerprint";
import { isClassifiedError } from "@/lib/server/grpc/interceptors/error-classification";
import { createLogger } from "@/lib/server/logger";
import { create, timestampDate } from "@zitadel/client";
import { ChecksSchema } from "@zitadel/proto/zitadel/session/v2/session_service_pb";
import { AuthenticationMethodType } from "@zitadel/proto/zitadel/user/v2/user_service_pb";
import { getTranslations } from "next-intl/server";
import { headers } from "next/headers";

import { getPublicHost } from "@/lib/server/host";
import { getServiceConfig } from "@/lib/server/service-url";
import { createSessionAndUpdateCookie } from "@/lib/server/session-cookie";
import {
  getActiveIdentityProviders,
  getIDPByID,
  getLoginSettings,
  getOrgsByDomain,
  listAuthenticationMethodTypes,
  listIDPLinks,
  searchUsers,
  SearchUsersCommand,
  startIdentityProviderFlow,
} from "@/lib/server/zitadel";
import { PasskeysType } from "@zitadel/proto/zitadel/settings/v2/login_settings_pb";
import { IDPLink } from "@zitadel/proto/zitadel/user/v2/idp_pb";
import { UserState } from "@zitadel/proto/zitadel/user/v2/user_pb";

const logger = createLogger("loginname");

export type SendLoginnameCommand = {
  loginName: string;
  requestId?: string;
  organization?: string;
  defaultOrganization?: string;
  suffix?: string;
};

const ORG_SUFFIX_REGEX = /(?<=@)(.+)/;

/** AZDIGI: answers take a minimum time (decoy.ts) so a fast "unknown" or "known" answer does not stand out. */
export async function sendLoginname(command: SendLoginnameCommand) {
  return withMinimumDuration(() => sendLoginnameNow(command));
}

async function sendLoginnameNow(command: SendLoginnameCommand) {
  const t = await getTranslations("loginname");

  // AZDIGI: reject whitespace before the lookup so invalid input cannot enter the registration or decoy paths
  if (typeof command.loginName !== "string") {
    return { error: t("errors.couldNotSearchUsers") };
  }
  command = { ...command, loginName: command.loginName.trim() };
  if (/\s/.test(command.loginName)) {
    return { error: t("errors.whitespace") };
  }

  const _headers = await headers();
  const { serviceConfig } = getServiceConfig(_headers);

  const loginSettingsByContext = await getLoginSettings({ serviceConfig, organization: command.organization });

  if (!loginSettingsByContext) {
    return { error: t("errors.couldNotGetLoginSettings") };
  }

  // Single source of truth for enumeration protection, derived server-side from the
  // request-context login settings (sendLoginname is a public server action, so a
  // client-supplied flag must not be trusted). It gates session creation and the
  // loginName exposed in redirect URLs, keeping known and unknown users
  // indistinguishable while protection applies.
  const ignoreUnknownUsernames = !!loginSettingsByContext.ignoreUnknownUsernames;

  let searchUsersRequest: SearchUsersCommand = {
    serviceConfig,
    searchValue: command.loginName,
    organizationId: command.organization,
    loginSettings: loginSettingsByContext,
    suffix: command.suffix,
  };

  const searchResult = await searchUsers(searchUsersRequest);

  // Safety check: ensure searchResult is defined
  if (!searchResult) {
    logger.error("searchUsers returned undefined or null");
    return { error: t("errors.couldNotSearchUsers") };
  }

  if ("error" in searchResult && searchResult.error) {
    logger.debug("searchUsers returned error, returning early", { error: searchResult.error });
    return searchResult;
  }

  if (!("result" in searchResult)) {
    logger.debug("searchUsers has no result field");
    return { error: t("errors.couldNotSearchUsers") };
  }

  const { result: potentialUsers } = searchResult;

  // Additional safety check: treat undefined result as empty array
  const users = potentialUsers ?? [];

  if (users.length === 0) {
    logger.debug("No users found, will proceed with org discovery");
  }

  const preventUserEnumeration = async (organization: string | undefined) => {
    // AZDIGI: a customer (or context-free) entry never says "user not found": the decoy email-code page looks like a
    // real customer account. It comes first because the context-free settings are the default organisation's.
    const decoy = await decoyOtpRedirect(serviceConfig, {
      loginName: command.loginName,
      contextOrg: organization,
      requestId: command.requestId,
    });
    if (decoy) {
      return decoy;
    }
    if (ignoreUnknownUsernames) {
      logger.debug("ignoreUnknownUsernames is true, redirecting to password");
      const paramsPasswordDefault = new URLSearchParams({
        loginName: command.loginName,
      });

      if (command.requestId) {
        paramsPasswordDefault.append("requestId", command.requestId);
      }

      if (organization) {
        paramsPasswordDefault.append("organization", organization);
      }

      return { redirect: "/password?" + paramsPasswordDefault };
    }

    return { error: t("errors.userNotFound") };
  };

  // With an org domain suffix the user types only the local part, so put the
  // login name back together for the checks below and for the IdP login hint.
  const concatLoginname = command.suffix ? `${command.loginName}@${command.suffix}` : command.loginName;

  const redirectUserToIDP = async (userId?: string, organization?: string) => {
    // If userId is provided, check for user-specific IDP links first
    let identityProviders: IDPLink[] = [];
    if (userId) {
      identityProviders = await listIDPLinks({ serviceConfig, userId }).then((resp) => {
        return resp.result;
      });
    }

    // If no IDP links exist for the user (or no userId provided), try to get active IDPs from the organization
    if (identityProviders.length === 0) {
      const activeIdps = await getActiveIdentityProviders({ serviceConfig, orgId: organization }).then((resp) => {
        return resp.identityProviders.filter((idp) => idp.options?.isAutoCreation || idp.options?.isCreationAllowed);
      });

      // If exactly one active IDP exists in the organization, redirect to it
      if (activeIdps.length === 1) {
        const _headers = await headers();
        const { serviceConfig } = getServiceConfig(_headers);
        const host = getPublicHost(_headers);

        const identityProviderType = activeIdps[0].type;
        const provider = idpTypeToSlug(identityProviderType);

        const params = new URLSearchParams();

        if (userId) {
          params.set("userId", userId);
        }

        if (command.requestId) {
          params.set("requestId", command.requestId);
        }

        if (organization) {
          params.set("organization", organization);
        }

        await addIdpFlowProof(params);

        const basePath = process.env.NEXT_PUBLIC_BASE_PATH ?? "";

        const response = await startIdentityProviderFlow({
          serviceConfig,
          idpId: activeIdps[0].id,
          urls: {
            successUrl:
              `${host.includes("localhost") ? "http://" : "https://"}${host}${basePath}/idp/${provider}/process?` +
              new URLSearchParams(params),
            failureUrl:
              `${host.includes("localhost") ? "http://" : "https://"}${host}${basePath}/idp/${provider}/failure?` +
              new URLSearchParams(params),
            loginHint: concatLoginname,
          },
        });

        if (!response || !response.url) {
          return { error: t("errors.couldNotStartIDPFlow") };
        }

        if (response.fields) {
          return { samlData: { url: response.url, fields: response.fields } };
        }

        return { redirect: response.url };
      }
    }

    if (identityProviders.length === 1) {
      const _headers = await headers();
      const { serviceConfig } = getServiceConfig(_headers);
      const host = getPublicHost(_headers);

      const identityProviderId = identityProviders[0].idpId;

      const idp = await getIDPByID({ serviceConfig, id: identityProviderId });

      const idpType = idp?.type;

      if (!idp || !idpType) {
        throw new Error(t("errors.couldNotFindIdentityProvider"));
      }

      const identityProviderType = idpTypeToIdentityProviderType(idpType);
      const provider = idpTypeToSlug(identityProviderType);

      const params = new URLSearchParams();

      if (userId) {
        params.set("userId", userId);
      }

      if (command.requestId) {
        params.set("requestId", command.requestId);
      }

      if (organization) {
        params.set("organization", organization);
      }

      await addIdpFlowProof(params);

      const basePath = process.env.NEXT_PUBLIC_BASE_PATH ?? "";

      const response = await startIdentityProviderFlow({
        serviceConfig,
        idpId: idp.id,
        urls: {
          successUrl:
            `${host.includes("localhost") ? "http://" : "https://"}${host}${basePath}/idp/${provider}/process?` +
            new URLSearchParams(params),
          failureUrl:
            `${host.includes("localhost") ? "http://" : "https://"}${host}${basePath}/idp/${provider}/failure?` +
            new URLSearchParams(params),
          // The user is already linked to this IdP, so prefer the username the
          // IdP knows the user by over the ZITADEL login name (same as Login V1).
          loginHint: identityProviders[0].userName || concatLoginname,
        },
      });

      if (!response || !response.url) {
        return { error: t("errors.couldNotStartIDPFlow") };
      }

      if (response.fields) {
        return { samlData: { url: response.url, fields: response.fields } };
      }

      return { redirect: response.url };
    }
  };

  // Used when the user has more than one identity provider and none can be picked automatically.
  const redirectToIDPSelection = (organization?: string) => {
    const params = new URLSearchParams();

    if (command.requestId) {
      params.set("requestId", command.requestId);
    }

    if (organization) {
      params.set("organization", organization);
    }

    return { redirect: "/idp?" + params };
  };

  if (users.length > 1) {
    logger.debug("multiple users found, returning error");
    if (ignoreUnknownUsernames) {
      return preventUserEnumeration(command.organization);
    }
    return { error: t("errors.moreThanOneUserFound") };
  } else if (users.length == 1 && users[0].userId) {
    const user = users[0];
    const userId = users[0].userId;

    // AZDIGI: fresh, this decides the first factor
    const userLoginSettings = await getLoginSettings({
      serviceConfig,
      organization: user.details?.resourceOwner,
      fresh: true,
    });

    const humanUser = users[0].type.case === "human" ? users[0].type.value : undefined;

    // recheck login settings after user discovery, as the search might have been done without org scope
    if (userLoginSettings?.disableLoginWithEmail && userLoginSettings?.disableLoginWithPhone) {
      if (!equalsIgnoreCase(user.preferredLoginName, concatLoginname)) {
        return preventUserEnumeration(command.organization);
      }
    } else if (userLoginSettings?.disableLoginWithEmail) {
      if (
        !equalsIgnoreCase(user.preferredLoginName, concatLoginname) &&
        !equalsIgnoreCase(humanUser?.phone?.phone, command.loginName)
      ) {
        return preventUserEnumeration(command.organization);
      }
    } else if (userLoginSettings?.disableLoginWithPhone) {
      if (
        !equalsIgnoreCase(user.preferredLoginName, concatLoginname) &&
        !equalsIgnoreCase(humanUser?.email?.email, command.loginName)
      ) {
        return preventUserEnumeration(command.organization);
      }
    }

    // AZDIGI: a locked user gets the lockout message on this screen (no session, no code); the expected unlock time
    // only while the unlock worker is on. With enumeration protection the account is not revealed.
    if (user.state === UserState.LOCKED) {
      if (ignoreUnknownUsernames || userLoginSettings?.ignoreUnknownUsernames) {
        return preventUserEnumeration(command.organization);
      }
      const unlockAt = estimateUnlockAt(
        user.details?.changeDate ? timestampDate(user.details.changeDate) : undefined,
        orgKindFromSettings(userLoginSettings),
      );
      return {
        error: unlockAt ? t("errors.userLockedUntil", { time: unlockAt }) : t("errors.userLocked"),
        locked: true,
      };
    }

    // Only create a session (and its cookie) when enumeration protection does not
    // apply: with protection on, known and unknown users must be indistinguishable,
    // and the /password page must not be able to tell the difference either.
    let session;
    if (!ignoreUnknownUsernames) {
      const checks = create(ChecksSchema, {
        user: { search: { case: "userId", value: userId } },
      });

      const sessionOrError = await createSessionAndUpdateCookie({
        checks,
        requestId: command.requestId,
      }).catch((error) => {
        if (isClassifiedError(error) && error.message?.includes("Errors.User.NotActive")) {
          return { error: t("errors.userNotActive") };
        }
        throw error;
      });

      if ("error" in sessionOrError) {
        return sessionOrError;
      }

      session = sessionOrError.session;
    }

    if (session && !session.factors?.user?.id) {
      return { error: t("errors.couldNotCreateSession") };
    }

    // LoginName to expose in redirect URLs: while enumeration protection applies,
    // echo the raw input so known and unknown users stay indistinguishable; otherwise
    // use the session's loginName so the next page can match the session cookie
    // (falling back to the user's preferred login name).
    const redirectLoginName = ignoreUnknownUsernames
      ? command.loginName
      : (session?.factors?.user?.loginName ?? user.preferredLoginName);

    // TODO: check if handling of userstate INITIAL is needed
    if (user.state === UserState.INITIAL) {
      if (ignoreUnknownUsernames) {
        return preventUserEnumeration(command.organization);
      }
      return { error: t("errors.initialUserNotSupported") };
    }

    // Resolve organization from command or session
    let organization = command.organization ?? session?.factors?.user?.organizationId ?? user.details?.resourceOwner;

    if (ignoreUnknownUsernames) {
      organization = command.organization;
      if (!organization && ORG_SUFFIX_REGEX.test(command.loginName)) {
        const matched = ORG_SUFFIX_REGEX.exec(command.loginName);
        const suffix = matched?.[1] ?? "";
        const orgs = await getOrgsByDomain({ serviceConfig, domain: suffix });

        if (orgs.result && orgs.result.length === 1) {
          const orgToCheckForDiscovery = orgs.result[0].id;
          const orgLoginSettings = await getLoginSettings({ serviceConfig, organization: orgToCheckForDiscovery });

          if (orgLoginSettings?.allowDomainDiscovery) {
            organization = orgToCheckForDiscovery;
          }
        }
      }
    }

    const methods = await listAuthenticationMethodTypes({
      serviceConfig,
      userId: session?.factors?.user?.id ?? userId,
    });

    // AZDIGI: email code as the first factor for eligible users (allow-listed organisation whose fresh policy does not
    // force MFA, OTP_EMAIL method, verified email, active user); everyone else takes the stock path. This must come
    // before the "no primary method" check below: an OTP-first customer has no password, passkey or IdP.
    const otpFirst = decideOtpFirst({
      otpFirstOrg: await isOtpFirstOrg(serviceConfig, user.details?.resourceOwner ?? organization),
      loginSettings: userLoginSettings,
      authMethods: methods.authMethodTypes,
      emailVerified: !!humanUser?.email?.isVerified,
      userState: user.state,
    });

    if (otpFirst.eligible) {
      return {
        redirect:
          "/otp/email?" +
          otpFirstParams({
            // the account's own login name: the email-code page finds its session cookie by it, and the decoy for
            // unknown names shows the same normalised form
            loginName: session?.factors?.user?.loginName ?? user.preferredLoginName ?? command.loginName,
            organization,
            requestId: command.requestId,
            ...otpFirstAlternatives(userLoginSettings),
          }),
      };
    }

    const hasPrimaryMethod =
      methods.authMethodTypes?.some(
        (m: AuthenticationMethodType) =>
          m === AuthenticationMethodType.PASSWORD ||
          m === AuthenticationMethodType.PASSKEY ||
          m === AuthenticationMethodType.IDP,
      ) ?? false;

    // always resend invite or setup email if user has no primary auth method set
    if (!hasPrimaryMethod) {
      logger.debug("humanUser.email?.isVerified", {
        isVerified: humanUser?.email?.isVerified,
      });

      // AZDIGI: mail the invitation whether or not the email is verified, as the fork always did. Upstream only sends
      // for a verified email, assuming an unverified one already holds a code from its creation; a customer provisioned
      // from WHMCS (foundation customer-provision) was created without any mail and would never get one. The once a
      // minute rule (sendVerificationOnce) keeps a repeated step, or every typed login name, from mailing a new code that
      // voids the one just sent. One client is also held to its code budget across accounts (the per-IP limit of code
      // requests; the IP comes only from the proxy's trusted header): typing a list of addresses must not mail them all.
      // Over the budget nothing is sent and the page offers "resend", which answers with the rate-limit message.
      const ip = clientIpFromHeaders(_headers);
      const withinIpBudget = ip ? limiters.otpSendPerIp.hit(`ip:${ip}`).allowed : true;
      const codeSent = withinIpBudget
        ? await sendVerificationOnce({
            userId: session?.factors?.user?.id ?? user.userId,
            isInvite: true,
            requestId: command.requestId,
          })
        : false;

      const params = new URLSearchParams({
        loginName: (session?.factors?.user?.loginName ?? user.preferredLoginName) as string,
        invite: "true", // always send invite code if user has no primary auth method
      });

      if (codeSent) {
        params.append("codeSent", "true");
      }

      if (command.requestId) {
        params.append("requestId", command.requestId);
      }

      if (organization) {
        params.append("organization", organization);
      }

      return { redirect: `/verify?` + params };
    }

    if (methods.authMethodTypes.length == 1) {
      const method = methods.authMethodTypes[0];
      switch (method) {
        case AuthenticationMethodType.PASSWORD: // user has only password as auth method
          if (!userLoginSettings?.allowLocalAuthentication) {
            // Check if user has IDPs available as alternative, that could eventually be used to register/link.
            const idpResp = await redirectUserToIDP(userId, organization);
            if (idpResp?.redirect) {
              return idpResp;
            }

            if (ignoreUnknownUsernames) {
              return preventUserEnumeration(command.organization);
            }

            return {
              error: t("errors.localAuthenticationNotAllowed"),
            };
          }

          {
            const paramsPassword = new URLSearchParams({
              loginName: redirectLoginName,
            });

            if (organization) {
              paramsPassword.append("organization", organization);
            }

            if (command.requestId) {
              paramsPassword.append("requestId", command.requestId);
            }

            return {
              redirect: "/password?" + paramsPassword,
            };
          }

        case AuthenticationMethodType.PASSKEY: // AuthenticationMethodType.AUTHENTICATION_METHOD_TYPE_PASSKEY
          if (userLoginSettings?.passkeysType === PasskeysType.NOT_ALLOWED || !userLoginSettings?.allowLocalAuthentication) {
            if (ignoreUnknownUsernames) {
              return preventUserEnumeration(command.organization);
            }
            return {
              error: t("errors.passkeysNotAllowed"),
            };
          }

          {
            const paramsPasskey = new URLSearchParams({
              loginName: redirectLoginName,
            });
            if (command.requestId) {
              paramsPasskey.append("requestId", command.requestId);
            }

            if (organization) {
              paramsPasskey.append("organization", organization);
            }

            return { redirect: "/passkey?" + paramsPasskey };
          }

        case AuthenticationMethodType.IDP: {
          const resp = await redirectUserToIDP(userId, organization);

          if (resp?.error) {
            return { error: resp.error };
          }

          // no single identity provider could be resolved, let the user choose one
          return resp ?? redirectToIDPSelection(organization);
        }

        default:
          // AZDIGI: a lone second factor (TOTP, SMS/email code, U2F) cannot start a sign-in outside OTP-first
          if (ignoreUnknownUsernames) {
            return preventUserEnumeration(command.organization);
          }
          return { error: t("errors.noUsableAuthMethod") };
      }
    } else {
      // prefer passkey in favor of other methods
      if (
        methods.authMethodTypes.includes(AuthenticationMethodType.PASSKEY) &&
        userLoginSettings?.passkeysType !== PasskeysType.NOT_ALLOWED &&
        userLoginSettings?.allowLocalAuthentication
      ) {
        const passkeyParams = new URLSearchParams({
          loginName: redirectLoginName,
          altPassword: `${methods.authMethodTypes.includes(AuthenticationMethodType.PASSWORD) && userLoginSettings?.allowLocalAuthentication}`, // show alternative password option only if allowed
        });

        if (command.requestId) {
          passkeyParams.append("requestId", command.requestId);
        }

        if (organization) {
          passkeyParams.append("organization", organization);
        }

        return { redirect: "/passkey?" + passkeyParams };
      }

      if (methods.authMethodTypes.includes(AuthenticationMethodType.IDP)) {
        const resp = await redirectUserToIDP(userId, organization);
        if (resp) {
          return resp;
        }
        // no single identity provider could be resolved, continue with the remaining methods
      }

      if (
        methods.authMethodTypes.includes(AuthenticationMethodType.PASSWORD) &&
        userLoginSettings?.allowLocalAuthentication
      ) {
        // user has no passkey setup and login settings allow passwords
        const paramsPasswordDefault = new URLSearchParams({
          loginName: redirectLoginName,
        });

        if (command.requestId) {
          paramsPasswordDefault.append("requestId", command.requestId);
        }

        if (organization) {
          paramsPasswordDefault.append("organization", organization);
        }

        return {
          redirect: "/password?" + paramsPasswordDefault,
        };
      }

      if (methods.authMethodTypes.includes(AuthenticationMethodType.IDP)) {
        return redirectToIDPSelection(organization);
      }

      if (methods.authMethodTypes.includes(AuthenticationMethodType.PASSWORD)) {
        // password authentication is not allowed
        if (ignoreUnknownUsernames) {
          return preventUserEnumeration(command.organization);
        }
        return {
          error: t("errors.localAuthenticationNotAllowed"),
        };
      }

      // AZDIGI: only second factors on the user: nothing can start a sign-in outside OTP-first
      if (ignoreUnknownUsernames) {
        return preventUserEnumeration(command.organization);
      }
      return { error: t("errors.noUsableAuthMethod") };
    }
  }

  logger.debug("User not found (0 potential users), checking registration options");

  // user not found, perform organization discovery if no org context provided
  let discoveredOrganization = command.organization;
  let effectiveLoginSettings = loginSettingsByContext;

  if (!command.organization && command.defaultOrganization) {
    const defaultLoginSettings = await getLoginSettings({ serviceConfig, organization: command.defaultOrganization });
    if (defaultLoginSettings) {
      effectiveLoginSettings = defaultLoginSettings;
    }
  }

  if (!discoveredOrganization && command.loginName && ORG_SUFFIX_REGEX.test(command.loginName)) {
    const matched = ORG_SUFFIX_REGEX.exec(command.loginName);
    const suffix = matched?.[1] ?? "";

    // this just returns orgs where the suffix is set as the Organization Domain
    const orgs = await getOrgsByDomain({ serviceConfig, domain: suffix });

    const orgToCheckForDiscovery = orgs.result && orgs.result.length === 1 ? orgs.result[0].id : undefined;

    if (orgToCheckForDiscovery) {
      const orgLoginSettings = await getLoginSettings({ serviceConfig, organization: orgToCheckForDiscovery });

      if (orgLoginSettings?.allowDomainDiscovery) {
        logger.debug("Org discovery successful", { organization: orgToCheckForDiscovery });
        discoveredOrganization = orgToCheckForDiscovery;
        // Use the discovered organization's login settings for subsequent checks
        effectiveLoginSettings = orgLoginSettings;
      } else {
        logger.debug("Org does not allow domain discovery");
      }
    } else {
      logger.debug("No single org found for discovery");
    }
  }

  // When a user is not found, try to redirect to an external IdP if:
  // - local authentication is disabled, OR
  // - domain discovery resolved an organization (regardless of allowRegister)
  // Registration policy (allowRegister) controls local account creation only
  // and must not prevent authentication via an external IdP.
  // Fixes: https://github.com/zitadel/zitadel/issues/12021
  // Fixes: https://github.com/zitadel/zitadel/issues/12023
  //
  // Enumeration protection (ignoreUnknownUsernames) must NOT gate the redirect
  // when local authentication is disabled: in an IdP-only org, known users are
  // auto-redirected to the IdP, so sending unknown usernames to the very same
  // IdP is what keeps them indistinguishable. Diverting unknown users to the
  // decoy password screen instead would both break silent SSO for first-time
  // users (the IdP is meant to create the account on first login) and act as an
  // enumeration oracle (redirect = user exists, password screen = unknown).
  // Conversely, when local authentication is enabled, the decoy password screen
  // is what known (password) users see, so enumeration protection keeps gating
  // the discovery-based redirect there.

  if (!effectiveLoginSettings?.allowLocalAuthentication || (discoveredOrganization && !ignoreUnknownUsernames)) {
    const resp = await redirectUserToIDP(undefined, discoveredOrganization);
    if (resp) {
      logger.debug("Redirecting to IDP", { organization: discoveredOrganization });
      return resp;
    }

    // If local auth is disabled, there is no fallback — return error
    if (!effectiveLoginSettings?.allowLocalAuthentication) {
      logger.debug("IDP redirect failed and local auth not allowed, returning user not found");
      return preventUserEnumeration(discoveredOrganization);
    }
  }

  // AZDIGI: no "register with this email?" for an unknown name in a customer context: that page would tell the name is
  // free; the decoy email-code page looks like a real account instead (registration stays reachable from the login page)
  const decoy = await decoyOtpRedirect(serviceConfig, {
    loginName: command.loginName,
    contextOrg: discoveredOrganization,
    requestId: command.requestId,
  });
  if (decoy) {
    return decoy;
  }

  if (effectiveLoginSettings?.allowRegister && effectiveLoginSettings?.allowLocalAuthentication) {
    logger.debug("register and password both allowed");
    // do not register user if ignoreUnknownUsernames is set
    if (discoveredOrganization && !effectiveLoginSettings?.ignoreUnknownUsernames) {
      logger.debug("Redirecting to registration page", { organization: discoveredOrganization });
      const params = new URLSearchParams({ organization: discoveredOrganization });

      if (command.requestId) {
        params.set("requestId", command.requestId);
      }

      if (command.loginName) {
        params.set("email", command.loginName);
      }

      return { redirect: "/register?" + params };
    } else {
      logger.debug("Not redirecting to register", {
        hasDiscoveredOrg: !!discoveredOrganization,
        ignoreUnknownUsernames: effectiveLoginSettings?.ignoreUnknownUsernames,
      });
    }
  }

  return preventUserEnumeration(discoveredOrganization);
}
