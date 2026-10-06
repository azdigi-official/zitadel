"use server";

import { create } from "@zitadel/client";
import { ChecksSchema } from "@zitadel/proto/zitadel/session/v2/session_service_pb";
import { AuthenticationMethodType } from "@zitadel/proto/zitadel/user/v2/user_service_pb";
import { getTranslations } from "next-intl/server";
import { headers } from "next/headers";
import { idpTypeToIdentityProviderType, idpTypeToSlug } from "../idp";

import { timestampDate } from "@zitadel/client";
import { PasskeysType } from "@zitadel/proto/zitadel/settings/v2/login_settings_pb";
import { IDPLink } from "@zitadel/proto/zitadel/user/v2/idp_pb";
import { UserState } from "@zitadel/proto/zitadel/user/v2/user_pb";
import { estimateUnlockAt, orgKindFromSettings } from "../azdigi/lockout";
import { decoyOtpRedirect, withMinimumDuration } from "../azdigi/decoy";
import { isOtpFirstOrg } from "../azdigi/org-lookup";
import { decideOtpFirst, otpFirstAlternatives, otpFirstParams } from "../azdigi/otp-first";
import { getServiceConfig } from "../service-url";
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
} from "../zitadel";
import { createSessionAndUpdateCookie } from "./cookie";
import { getPublicHost } from "./host";

export type SendLoginnameCommand = {
  loginName: string;
  requestId?: string;
  organization?: string;
  defaultOrganization?: string;
  suffix?: string;
  ignoreUnknownUsernames?: boolean;
};

const ORG_SUFFIX_REGEX = /(?<=@)(.+)/;

/** AZDIGI: answers take a minimum time (decoy.ts) so a fast "unknown" or "known" answer does not stand out. */
export async function sendLoginname(command: SendLoginnameCommand) {
  return withMinimumDuration(() => sendLoginnameNow(command));
}

async function sendLoginnameNow(command: SendLoginnameCommand) {
  const _headers = await headers();
  const { serviceConfig } = getServiceConfig(_headers);

  const t = await getTranslations("loginname");

  const loginSettingsByContext = await getLoginSettings({ serviceConfig, organization: command.organization });

  if (!loginSettingsByContext) {
    return { error: t("errors.couldNotGetLoginSettings") };
  }

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
    console.error("searchUsers returned undefined or null");
    return { error: t("errors.couldNotSearchUsers") };
  }

  if ("error" in searchResult && searchResult.error) {
    console.log("searchUsers returned error, returning early:", searchResult.error);
    return searchResult;
  }

  if (!("result" in searchResult)) {
    console.log("searchUsers has no result field");
    return { error: t("errors.couldNotSearchUsers") };
  }

  const { result: potentialUsers } = searchResult;

  // Additional safety check: treat undefined result as empty array
  const users = potentialUsers ?? [];

  if (users.length === 0) {
    console.log("No users found, will proceed with org discovery");
  }

  const preventUserEnumeration = async (organization: string | undefined) => {
    // AZDIGI: a customer (or context-free) entry never says "user not found" — the decoy email-code page looks like a real
    // customer account; it comes first because the context-free settings are the default organisation's (staff policy)
    const decoy = await decoyOtpRedirect(serviceConfig, {
      loginName: command.loginName,
      contextOrg: organization,
      requestId: command.requestId,
    });
    if (decoy) {
      return decoy;
    }
    if (command.ignoreUnknownUsernames) {
      console.log("ignoreUnknownUsernames is true, redirecting to password");
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
        return resp.identityProviders;
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

  if (users.length > 1) {
    console.log("multiple users found, returning error");
    if (loginSettingsByContext?.ignoreUnknownUsernames) {
      return preventUserEnumeration(command.organization);
    }
    return { error: t("errors.moreThanOneUserFound") };
  } else if (users.length == 1 && users[0].userId) {
    const user = users[0];
    const userId = users[0].userId;

    // fresh: this decides the first factor (AZDIGI)
    const userLoginSettings = await getLoginSettings({
      serviceConfig,
      organization: user.details?.resourceOwner,
      fresh: true,
    });

    // compare with the concatenated suffix when set
    const concatLoginname = command.suffix ? `${command.loginName}@${command.suffix}` : command.loginName;
    // AZDIGI: login names and emails compare case-insensitively (an email typed in capitals is the same account)
    const same = (a: string | undefined, b: string | undefined) => !!a && !!b && a.toLowerCase() === b.toLowerCase();

    const humanUser = users[0].type.case === "human" ? users[0].type.value : undefined;

    // recheck login settings after user discovery, as the search might have been done without org scope
    if (userLoginSettings?.disableLoginWithEmail && userLoginSettings?.disableLoginWithPhone) {
      if (!same(user.preferredLoginName, concatLoginname)) {
        return preventUserEnumeration(command.organization);
      }
    } else if (userLoginSettings?.disableLoginWithEmail) {
      // AZDIGI: the user name OR the phone may be typed (upstream demanded both, so a user whose name differs failed)
      if (!(same(user.preferredLoginName, concatLoginname) || humanUser?.phone?.phone === command.loginName)) {
        return preventUserEnumeration(command.organization);
      }
    } else if (userLoginSettings?.disableLoginWithPhone) {
      // AZDIGI: the user name OR the email may be typed (a customer whose email changed keeps the old user name)
      if (!(same(user.preferredLoginName, concatLoginname) || same(humanUser?.email?.email, command.loginName))) {
        return preventUserEnumeration(command.organization);
      }
    }

    // AZDIGI: a locked user gets the lockout message on this screen (no session, no code); the expected unlock time
    // only while the unlock worker (M2) is on. With ignoreUnknownUsernames the account is not revealed.
    if (user.state === UserState.LOCKED) {
      if (userLoginSettings?.ignoreUnknownUsernames || command.ignoreUnknownUsernames) {
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

    let session;
    if (!userLoginSettings?.ignoreUnknownUsernames) {
      const checks = create(ChecksSchema, {
        user: { search: { case: "userId", value: userId } },
      });

      const sessionOrError = await createSessionAndUpdateCookie({
        checks,
        requestId: command.requestId,
      }).catch((error) => {
        if (error?.rawMessage === "Errors.User.NotActive (SESSION-Gj4ko)") {
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

    // TODO: check if handling of userstate INITIAL is needed
    if (user.state === UserState.INITIAL) {
      if (userLoginSettings?.ignoreUnknownUsernames) {
        return preventUserEnumeration(command.organization);
      }
      return { error: t("errors.initialUserNotSupported") };
    }

    // Resolve organization from command or session
    let organization = command.organization ?? session?.factors?.user?.organizationId ?? user.details?.resourceOwner;

    if (userLoginSettings?.ignoreUnknownUsernames) {
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

    // always resend invite if user has no auth method set
    if (!methods.authMethodTypes || !methods.authMethodTypes.length) {
      console.log("humanUser.email?.isVerified", humanUser?.email?.isVerified);
      const params = new URLSearchParams({
        loginName: (session?.factors?.user?.loginName ?? user.preferredLoginName) as string,
        send: "true", // set this to true to request a new code immediately
        invite: humanUser?.email?.isVerified ? "false" : "true", // sendInviteEmailCode results in an error if user is already initialized
      });

      if (command.requestId) {
        params.append("requestId", command.requestId);
      }

      if (organization) {
        params.append("organization", organization);
      }

      return { redirect: `/verify?` + params };
    }

    // AZDIGI: email code as the first factor for eligible users (allow-listed organisation whose fresh policy does
    // not force MFA, OTP_EMAIL method, verified email, active user); everyone else takes the stock path
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
            // AZDIGI: always the account's own login name — the email-code page finds its session cookie by it, and the
            // decoy for unknown names shows the same normalised form (the context-free settings ignore unknown names)
            loginName: session?.factors?.user?.loginName ?? user.preferredLoginName ?? command.loginName,
            organization,
            requestId: command.requestId,
            ...otpFirstAlternatives(userLoginSettings),
          }),
      };
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

            if (command.ignoreUnknownUsernames) {
              return preventUserEnumeration(command.organization);
            }

            return {
              error: t("errors.localAuthenticationNotAllowed"),
            };
          }

          const paramsPassword = new URLSearchParams({
            loginName: command.ignoreUnknownUsernames
              ? command.loginName
              : (session?.factors?.user?.loginName ?? user.preferredLoginName),
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

        case AuthenticationMethodType.PASSKEY: // AuthenticationMethodType.AUTHENTICATION_METHOD_TYPE_PASSKEY
          if (
            userLoginSettings?.passkeysType === PasskeysType.NOT_ALLOWED ||
            !userLoginSettings?.allowLocalAuthentication
          ) {
            if (command.ignoreUnknownUsernames) {
              return preventUserEnumeration(command.organization);
            }
            return {
              error: t("errors.passkeysNotAllowed"),
            };
          }

          const paramsPasskey = new URLSearchParams({
            loginName: command.ignoreUnknownUsernames
              ? command.loginName
              : (session?.factors?.user?.loginName ?? user.preferredLoginName),
          });
          if (command.requestId) {
            paramsPasskey.append("requestId", command.requestId);
          }

          if (organization) {
            paramsPasskey.append("organization", organization);
          }

          return { redirect: "/passkey?" + paramsPasskey };

        case AuthenticationMethodType.IDP:
          const resp = await redirectUserToIDP(userId, organization);

          if (resp?.error) {
            return { error: resp.error };
          }

          return resp;

        default:
          // AZDIGI: a lone second factor (TOTP, SMS/email code, U2F) cannot start a login outside OTP-first
          if (command.ignoreUnknownUsernames) {
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
          loginName: command.ignoreUnknownUsernames
            ? command.loginName
            : (session?.factors?.user?.loginName ?? user.preferredLoginName),
          altPassword: `${methods.authMethodTypes.includes(AuthenticationMethodType.PASSWORD) && userLoginSettings?.allowLocalAuthentication}`, // show alternative password option only if allowed
        });

        if (command.requestId) {
          passkeyParams.append("requestId", command.requestId);
        }

        if (organization) {
          passkeyParams.append("organization", organization);
        }

        return { redirect: "/passkey?" + passkeyParams };
      } else if (methods.authMethodTypes.includes(AuthenticationMethodType.IDP)) {
        return redirectUserToIDP(userId, organization);
      } else if (methods.authMethodTypes.includes(AuthenticationMethodType.PASSWORD)) {
        // Check if password authentication is allowed
        if (!userLoginSettings?.allowLocalAuthentication) {
          if (command.ignoreUnknownUsernames) {
            return preventUserEnumeration(command.organization);
          }
          return {
            error: t("errors.localAuthenticationNotAllowed"),
          };
        }

        // user has no passkey setup and login settings allow passwords
        const paramsPasswordDefault = new URLSearchParams({
          loginName: command.ignoreUnknownUsernames
            ? command.loginName
            : (session?.factors?.user?.loginName ?? user.preferredLoginName),
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
      } else {
        // AZDIGI: only second factors on the user — nothing can start a login outside OTP-first
        if (command.ignoreUnknownUsernames) {
          return preventUserEnumeration(command.organization);
        }
        return { error: t("errors.noUsableAuthMethod") };
      }
    }
  }

  console.log("user not found (0 potential users), checking registration options");

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

    // this just returns orgs where the suffix is set as primary domain
    const orgs = await getOrgsByDomain({ serviceConfig, domain: suffix });

    const orgToCheckForDiscovery = orgs.result && orgs.result.length === 1 ? orgs.result[0].id : undefined;

    if (orgToCheckForDiscovery) {
      const orgLoginSettings = await getLoginSettings({ serviceConfig, organization: orgToCheckForDiscovery });

      if (orgLoginSettings?.allowDomainDiscovery) {
        console.log("org discovery successful, using org:", orgToCheckForDiscovery);
        discoveredOrganization = orgToCheckForDiscovery;
        // Use the discovered organization's login settings for subsequent checks
        effectiveLoginSettings = orgLoginSettings;
      } else {
        console.log("org does not allow domain discovery");
      }
    } else {
      console.log("no single org found for discovery");
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

  // user not found, check if register is enabled on instance / organization context
  if (effectiveLoginSettings?.allowRegister && !effectiveLoginSettings?.allowLocalAuthentication) {
    console.log("redirecting to IDP (register allowed, password not allowed)");
    const resp = await redirectUserToIDP(undefined, discoveredOrganization);
    if (resp) {
      return resp;
    }
    console.log("IDP redirect failed, returning user not found");

    return preventUserEnumeration(discoveredOrganization);
  } else if (effectiveLoginSettings?.allowRegister && effectiveLoginSettings?.allowLocalAuthentication) {
    console.log("register and password both allowed");
    // do not register user if ignoreUnknownUsernames is set
    if (discoveredOrganization && !effectiveLoginSettings?.ignoreUnknownUsernames) {
      console.log("redirecting to registration page with org:", discoveredOrganization);
      const params = new URLSearchParams({ organization: discoveredOrganization });

      if (command.requestId) {
        params.set("requestId", command.requestId);
      }

      if (command.loginName) {
        params.set("email", command.loginName);
      }

      return { redirect: "/register?" + params };
    } else {
      console.log("not redirecting to register:", {
        hasDiscoveredOrg: !!discoveredOrganization,
        ignoreUnknownUsernames: effectiveLoginSettings?.ignoreUnknownUsernames,
      });
    }
  }

  return preventUserEnumeration(discoveredOrganization);
}
