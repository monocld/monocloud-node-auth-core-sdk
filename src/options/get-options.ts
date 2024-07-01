/* eslint-disable prefer-destructuring */
/* eslint-disable @typescript-eslint/no-non-null-assertion */
import { MonoCloudValidationError } from '../errors/monocloud-validation-error';
import {
  MonoCloudOptionsBase,
  SameSiteValues,
  SecurityAlgorithms,
  MonoCloudOptions,
} from '../types';
import { IdTokenClaims } from '../types/internal';
import { getBoolean, getNumber, removeTrailingSlash } from '../utils';
import { DefaultOptions } from './defaults';
import { optionsSchema } from './validation';

export const getOptions = (
  options?: MonoCloudOptions
): MonoCloudOptionsBase => {
  const MONOCLOUD_AUTH_CLIENT_ID = process.env.MONOCLOUD_AUTH_CLIENT_ID;
  const MONOCLOUD_AUTH_CLIENT_SECRET = process.env.MONOCLOUD_AUTH_CLIENT_SECRET;
  const MONOCLOUD_AUTH_ISSUER = process.env.MONOCLOUD_AUTH_ISSUER;
  const MONOCLOUD_AUTH_SCOPES = process.env.MONOCLOUD_AUTH_SCOPES;
  const MONOCLOUD_AUTH_COOKIE_SECRET = process.env.MONOCLOUD_AUTH_COOKIE_SECRET;
  const MONOCLOUD_AUTH_APP_URL = process.env.MONOCLOUD_AUTH_APP_URL;
  const MONOCLOUD_AUTH_CALLBACK_URL = process.env.MONOCLOUD_AUTH_CALLBACK_URL;
  const MONOCLOUD_AUTH_BACK_CHANNEL_LOGOUT_URL =
    process.env.MONOCLOUD_AUTH_BACK_CHANNEL_LOGOUT_URL;
  const MONOCLOUD_AUTH_SIGN_IN_URL = process.env.MONOCLOUD_AUTH_SIGN_IN_URL;
  const MONOCLOUD_AUTH_SIGN_OUT_URL = process.env.MONOCLOUD_AUTH_SIGN_OUT_URL;
  const MONOCLOUD_AUTH_USER_INFO_URL = process.env.MONOCLOUD_AUTH_USER_INFO_URL;
  const MONOCLOUD_AUTH_CLOCK_SKEW = process.env.MONOCLOUD_AUTH_CLOCK_SKEW;
  const MONOCLOUD_AUTH_RESPONSE_TIMEOUT =
    process.env.MONOCLOUD_AUTH_RESPONSE_TIMEOUT;
  const MONOCLOUD_AUTH_USE_PAR = process.env.MONOCLOUD_AUTH_USE_PAR;
  const MONOCLOUD_AUTH_POST_LOGOUT_REDIRECT_URI =
    process.env.MONOCLOUD_AUTH_POST_LOGOUT_REDIRECT_URI;
  const MONOCLOUD_AUTH_FEDERATED_LOGOUT =
    process.env.MONOCLOUD_AUTH_FEDERATED_LOGOUT;
  const MONOCLOUD_AUTH_USER_INFO = process.env.MONOCLOUD_AUTH_USER_INFO;
  const MONOCLOUD_AUTH_REFRESH_USER_INFO =
    process.env.MONOCLOUD_AUTH_REFRESH_USER_INFO;
  const MONOCLOUD_AUTH_SESSION_COOKIE_NAME =
    process.env.MONOCLOUD_AUTH_SESSION_COOKIE_NAME;
  const MONOCLOUD_AUTH_SESSION_COOKIE_PATH =
    process.env.MONOCLOUD_AUTH_SESSION_COOKIE_PATH;
  const MONOCLOUD_AUTH_SESSION_COOKIE_DOMAIN =
    process.env.MONOCLOUD_AUTH_SESSION_COOKIE_DOMAIN;
  const MONOCLOUD_AUTH_SESSION_COOKIE_HTTP_ONLY =
    process.env.MONOCLOUD_AUTH_SESSION_COOKIE_HTTP_ONLY;
  const MONOCLOUD_AUTH_SESSION_COOKIE_SECURE =
    process.env.MONOCLOUD_AUTH_SESSION_COOKIE_SECURE;
  const MONOCLOUD_AUTH_SESSION_COOKIE_SAME_SITE =
    process.env.MONOCLOUD_AUTH_SESSION_COOKIE_SAME_SITE;
  const MONOCLOUD_AUTH_SESSION_COOKIE_PERSISTENT =
    process.env.MONOCLOUD_AUTH_SESSION_COOKIE_PERSISTENT;
  const MONOCLOUD_AUTH_SESSION_SLIDING =
    process.env.MONOCLOUD_AUTH_SESSION_SLIDING;
  const MONOCLOUD_AUTH_SESSION_DURATION =
    process.env.MONOCLOUD_AUTH_SESSION_DURATION;
  const MONOCLOUD_AUTH_SESSION_MAX_DURATION =
    process.env.MONOCLOUD_AUTH_SESSION_MAX_DURATION;
  const MONOCLOUD_AUTH_STATE_COOKIE_NAME =
    process.env.MONOCLOUD_AUTH_STATE_COOKIE_NAME;
  const MONOCLOUD_AUTH_STATE_COOKIE_PATH =
    process.env.MONOCLOUD_AUTH_STATE_COOKIE_PATH;
  const MONOCLOUD_AUTH_STATE_COOKIE_DOMAIN =
    process.env.MONOCLOUD_AUTH_STATE_COOKIE_DOMAIN;
  const MONOCLOUD_AUTH_STATE_COOKIE_SECURE =
    process.env.MONOCLOUD_AUTH_STATE_COOKIE_SECURE;
  const MONOCLOUD_AUTH_STATE_COOKIE_SAME_SITE =
    process.env.MONOCLOUD_AUTH_STATE_COOKIE_SAME_SITE;
  const MONOCLOUD_AUTH_STATE_COOKIE_PERSISTENT =
    process.env.MONOCLOUD_AUTH_STATE_COOKIE_PERSISTENT;
  const MONOCLOUD_AUTH_ID_TOKEN_SIGNING_ALG =
    process.env.MONOCLOUD_AUTH_ID_TOKEN_SIGNING_ALG;
  const MONOCLOUD_AUTH_FILTERED_ID_TOKEN_CLAIMS =
    process.env.MONOCLOUD_AUTH_FILTERED_ID_TOKEN_CLAIMS;

  const appUrl = options?.appUrl || MONOCLOUD_AUTH_APP_URL!;

  const opt: MonoCloudOptionsBase = {
    clientId: options?.clientId || MONOCLOUD_AUTH_CLIENT_ID!,
    clientSecret: options?.clientSecret || MONOCLOUD_AUTH_CLIENT_SECRET,
    issuer: options?.issuer || MONOCLOUD_AUTH_ISSUER!,
    defaultAuthParams: {
      ...(options?.defaultAuthParams ?? {}),
      scope:
        options?.defaultAuthParams?.scope ||
        MONOCLOUD_AUTH_SCOPES ||
        DefaultOptions.defaultAuthParams.scope,
      response_type:
        options?.defaultAuthParams?.response_type ||
        DefaultOptions.defaultAuthParams.response_type,
    },
    cookieSecret: options?.cookieSecret || MONOCLOUD_AUTH_COOKIE_SECRET!,
    appUrl: removeTrailingSlash(appUrl),
    routes: {
      callback: removeTrailingSlash(
        options?.routes?.callback ||
          MONOCLOUD_AUTH_CALLBACK_URL ||
          DefaultOptions.routes.callback
      ),
      backChannelLogout: removeTrailingSlash(
        options?.routes?.backChannelLogout ||
          MONOCLOUD_AUTH_BACK_CHANNEL_LOGOUT_URL ||
          DefaultOptions.routes.backChannelLogout
      ),
      signIn: removeTrailingSlash(
        options?.routes?.signIn ||
          MONOCLOUD_AUTH_SIGN_IN_URL ||
          DefaultOptions.routes.signIn
      ),
      signOut: removeTrailingSlash(
        options?.routes?.signOut ||
          MONOCLOUD_AUTH_SIGN_OUT_URL ||
          DefaultOptions.routes.signOut
      ),
      userInfo: removeTrailingSlash(
        options?.routes?.userInfo ||
          MONOCLOUD_AUTH_USER_INFO_URL ||
          DefaultOptions.routes.userInfo
      ),
    },
    clockSkew:
      options?.clockSkew ??
      getNumber(MONOCLOUD_AUTH_CLOCK_SKEW) ??
      DefaultOptions.clockSkew,
    responseTimeout:
      options?.responseTimeout ??
      getNumber(MONOCLOUD_AUTH_RESPONSE_TIMEOUT) ??
      DefaultOptions.responseTimeout,
    usePar:
      options?.usePar ??
      getBoolean(MONOCLOUD_AUTH_USE_PAR) ??
      DefaultOptions.usePar,
    postLogoutRedirectUri:
      options?.postLogoutRedirectUri || MONOCLOUD_AUTH_POST_LOGOUT_REDIRECT_URI,
    federatedLogout:
      options?.federatedLogout ??
      getBoolean(MONOCLOUD_AUTH_FEDERATED_LOGOUT) ??
      DefaultOptions.federatedLogout,
    userInfo:
      options?.userInfo ??
      getBoolean(MONOCLOUD_AUTH_USER_INFO) ??
      DefaultOptions.userInfo,
    refreshUserInfo:
      options?.refreshUserInfo ??
      getBoolean(MONOCLOUD_AUTH_REFRESH_USER_INFO) ??
      DefaultOptions.refreshUserInfo,
    session: {
      cookie: {
        name:
          options?.session?.cookie?.name ||
          MONOCLOUD_AUTH_SESSION_COOKIE_NAME ||
          DefaultOptions.session.cookie.name,
        path:
          options?.session?.cookie?.path ||
          MONOCLOUD_AUTH_SESSION_COOKIE_PATH ||
          DefaultOptions.session.cookie.path,
        domain:
          options?.session?.cookie?.domain ||
          MONOCLOUD_AUTH_SESSION_COOKIE_DOMAIN,
        httpOnly:
          options?.session?.cookie?.httpOnly ??
          getBoolean(MONOCLOUD_AUTH_SESSION_COOKIE_HTTP_ONLY) ??
          DefaultOptions.session.cookie.httpOnly,
        secure:
          options?.session?.cookie?.secure ??
          getBoolean(MONOCLOUD_AUTH_SESSION_COOKIE_SECURE) ??
          appUrl?.startsWith('https:'),
        sameSite:
          options?.session?.cookie?.sameSite ||
          (MONOCLOUD_AUTH_SESSION_COOKIE_SAME_SITE as SameSiteValues) ||
          DefaultOptions.session.cookie.sameSite,
        persistent:
          options?.session?.cookie?.persistent ??
          getBoolean(MONOCLOUD_AUTH_SESSION_COOKIE_PERSISTENT) ??
          DefaultOptions.session.cookie.persistent,
      },
      sliding:
        options?.session?.sliding ??
        getBoolean(MONOCLOUD_AUTH_SESSION_SLIDING) ??
        DefaultOptions.session.sliding,
      duration:
        options?.session?.duration ??
        getNumber(MONOCLOUD_AUTH_SESSION_DURATION) ??
        DefaultOptions.session.duration,
      maximumDuration:
        options?.session?.maximumDuration ??
        getNumber(MONOCLOUD_AUTH_SESSION_MAX_DURATION) ??
        DefaultOptions.session.maximumDuration,
      store: options?.session?.store,
    },
    state: {
      cookie: {
        name:
          options?.state?.cookie?.name ||
          MONOCLOUD_AUTH_STATE_COOKIE_NAME ||
          DefaultOptions.state.cookie.name,
        path:
          options?.state?.cookie?.path ||
          MONOCLOUD_AUTH_STATE_COOKIE_PATH ||
          DefaultOptions.state.cookie.path,
        domain:
          options?.state?.cookie?.domain || MONOCLOUD_AUTH_STATE_COOKIE_DOMAIN,
        httpOnly: DefaultOptions.state.cookie.httpOnly,
        secure:
          options?.state?.cookie?.secure ??
          getBoolean(MONOCLOUD_AUTH_STATE_COOKIE_SECURE) ??
          appUrl?.startsWith('https:'),
        sameSite:
          options?.state?.cookie?.sameSite ||
          (MONOCLOUD_AUTH_STATE_COOKIE_SAME_SITE as SameSiteValues) ||
          DefaultOptions.state.cookie.sameSite,
        persistent:
          options?.state?.cookie?.persistent ??
          getBoolean(MONOCLOUD_AUTH_STATE_COOKIE_PERSISTENT) ??
          DefaultOptions.state.cookie.persistent,
      },
    },
    idTokenSigningAlg:
      options?.idTokenSigningAlg ??
      (MONOCLOUD_AUTH_ID_TOKEN_SIGNING_ALG as SecurityAlgorithms) ??
      DefaultOptions.idTokenSigningAlg,
    filteredIdTokenClaims:
      options?.filteredIdTokenClaims ??
      (MONOCLOUD_AUTH_FILTERED_ID_TOKEN_CLAIMS?.split(' ')
        .map(x => x.trim())
        .filter(
          x => x.length
        ) as unknown as (keyof Partial<IdTokenClaims>)[]) ??
      DefaultOptions.filteredIdTokenClaims,
    debugger: options?.debugger ?? DefaultOptions.debugger,
    userAgent: options?.userAgent ?? DefaultOptions.userAgent,
    onBackChannelLogout: options?.onBackChannelLogout,
    onSetApplicationState: options?.onSetApplicationState,
    onSessionCreating: options?.onSessionCreating,
  };

  const { value, error } = optionsSchema.validate(opt, { abortEarly: false });

  if (error) {
    throw new MonoCloudValidationError(error.details[0].message);
  }

  return value;
};
