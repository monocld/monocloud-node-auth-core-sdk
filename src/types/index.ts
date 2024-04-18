/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable import/no-cycle */
import type { Except, PartialDeep } from 'type-fest';
import {
  AuthorizationParameters,
  EndSessionParameters,
  IdTokenClaims,
  MonoCloudRequest,
  UserinfoResponse,
} from './internal';

/**
 * Possible values for the SameSite attribute in cookies.
 */
export type SameSiteValues = 'strict' | 'lax' | 'none';

/**
 * Possible values for the authenticators.
 */
export type Authenticators =
  | 'password'
  | 'email'
  | 'phone'
  | 'google'
  | 'apple'
  | 'facebook'
  | 'microsoft'
  | 'github'
  | 'gitlab'
  | 'discord'
  | 'twitter'
  | 'linkedin';

/**
 * Possible values for the Security Algorithms.
 */
export type SecurityAlgorithms =
  | 'RS256'
  | 'RS384'
  | 'RS512'
  | 'PS256'
  | 'PS384'
  | 'PS512'
  | 'ES256'
  | 'ES384'
  | 'ES512';

export type MonoCloudUser = Partial<IdTokenClaims>;

/**
 * Represents a session containing user information, tokens, and additional custom properties.
 */
export interface MonoCloudSession {
  /**
   * Information about the authenticated user, typically claims obtained from an ID token or the 'userinfo' endpoint.
   */
  user: MonoCloudUser;

  /**
   * Optional. The ID token associated with the session.
   */
  idToken?: string;

  /**
   * Optional. The access token associated with the session.
   */
  accessToken?: string;

  /**
   * Optional. The expiration timestamp of the access token (in epoch).
   */
  accessTokenExpiration?: number;

  /**
   * Optional. The scopes granted by the access token.
   */
  scopes?: string;

  /**
   * Optional. The refresh token associated with the session.
   */
  refreshToken?: string;

  /**
   * Additional custom properties that can be added to the session.
   */
  [key: string]: any;
}

/**
 * Represents the lifetime information of a session, including the creation time (c),
 * the last updated time (u), and optionally the expiration time (e).
 */
export interface SessionLifetime {
  /**
   * The time at which the session was created (in epoch).
   */
  c: number;

  /**
   * The time at which the session was last updated (in epoch).
   */
  u: number;

  /**
   * Optional. The expiration time of the session (in epoch).
   */
  e?: number;
}

/**
 * Represents the authentication state information including the state parameter,
 * nonce, custom application state, code verifier, maximum age of the session,
 * response type and optional return URL.
 */
export interface MonoCloudState {
  /**
   * A unique value used to maintain state between the sign-in request and the callback.
   */
  state: string;

  /**
   * A unique value used to prevent replay attacks in OAuth flows.
   */
  nonce: string;

  /**
   * Additional custom application specific state information.
   */
  appState: string;

  /**
   * Optional. A code verifier used in PKCE (Proof Key for Code Exchange) flow.
   */
  verifier?: string;

  /**
   * Optional. The maximum age (in seconds) of the session.
   */
  maxAge?: number;

  /**
   * Optional. The URL to which the user will be redirected after authentication.
   */
  returnUrl?: string;
}

/**
 * Represents a session store interface for managing session data.
 */
export interface MonoCloudSessionStore {
  /**
   * Retrieves a session from the store based on the provided key.
   * @param key - The key used to identify the session.
   * @returns A Promise that resolves with the session data, or undefined / null if not found.
   */
  get(key: string): Promise<MonoCloudSession | undefined | null>;

  /**
   * Stores a session in the store with the specified key.
   * @param key - The key used to identify the session.
   * @param data - The session data to be stored.
   * @param lifetime - The lifetime information of the session.
   * @returns A Promise that resolves when the session is successfully stored.
   */
  set(
    key: string,
    data: MonoCloudSession,
    lifetime: SessionLifetime
  ): Promise<void>;

  /**
   * Deletes a session from the store based on the provided key.
   * @param key - The key used to identify the session to be deleted.
   * @returns A Promise that resolves when the session is successfully deleted.
   */
  delete(key: string): Promise<void>;
}

/**
 * Options for cookies.
 */
interface MonoCloudCookieOptions {
  /**
   * The name of the cookie.
   * For session cookies, the default value is 'session'.
   * For state cookies, the default value is 'state'.
   */
  name: string;

  /**
   * The path for which the cookie is valid.
   * @defaultValue '/'
   */
  path: string;

  /**
   * Optional: The domain for which the cookie is valid.
   */
  domain?: string;

  /**
   * Determines whether the cookie is accessible only through HTTP requests.
   * This setting will be ignored for the state cookie and will always be true.
   * @defaultValue true
   */
  httpOnly: boolean;

  /**
   * Determines whether the cookie should only be sent over HTTPS connections.
   * If not provided, this settings will be auto-detected basis the scheme of the application url.
   */
  secure: boolean;

  /**
   * The SameSite attribute value for the cookie, ensuring cross-site request forgery protection.
   * @defaultValue 'lax'
   */
  sameSite: SameSiteValues;

  /**
   * Determines whether the cookie should persist beyond the current session.
   * For session cookies, the default value is true.
   * For state cookies, the default value is false.
   */
  persistent: boolean;
}

/**
 * Options for the authentication sessions.
 */
export interface MonoCloudSessionOptionsBase {
  /**
   * Configuration options for the authentication session cookie.
   */
  cookie: MonoCloudCookieOptions;

  /**
   * Determines whether the session should use sliding expiration.
   * @defaultValue false
   */
  sliding: boolean;

  /**
   * The duration of the session in seconds.
   * @defaultValue 86400 (1 Day)
   */
  duration: number;

  /**
   * The maximum duration for the session in seconds.
   * Will only be used when the session is set to 'sliding'.
   * @defaultValue 604800 (1 Week)
   */
  maximumDuration: number;

  /**
   * Optional: The session store to use for storing session data.
   */
  store?: MonoCloudSessionStore;
}

/**
 * Options for the authentication state.
 */
export interface MonoCloudStateOptions {
  /**
   * Configuration options for the authentication state cookie.
   */
  cookie: MonoCloudCookieOptions;
}

/**
 * Options for the MonoCloud Authentication route handlers.
 */
export interface MonoCloudRoutes {
  /**
   * The URL of the callback handler
   * @defaultValue '/api/auth/callback'
   */
  callback: string;

  /**
   * The URL of the back-channel logout handler
   * @defaultValue '/api/auth/backchannel-logout'
   */
  backChannelLogout: string;

  /**
   * The URL of the sign-in handler
   * @defaultValue '/api/auth/signin'
   */
  signIn: string;

  /**
   * The URL of the sign-out handler
   * @defaultValue '/api/auth/signout'
   */
  signOut: string;

  /**
   * The URL of the userinfo handler
   * @defaultValue '/api/auth/userinfo'
   */
  userInfo: string;
}

/**
 * Options for configuration MonoCloud Authentication.
 */
export interface MonoCloudOptionsBase {
  /**
   * The client ID of the authenticating application.
   */
  clientId: string;

  /**
   * Optional: The client secret of the authenticating application.
   */
  clientSecret?: string;

  /**
   * The issuer URL for the authentication service.
   */
  issuer: string;

  /**
   * A secret key that will be used for encrypting cookies.
   */
  cookieSecret: string;

  /**
   * The URL of the application.
   */
  appUrl: string;

  /**
   * Configuration options for the route handler URLs.
   */
  routes: MonoCloudRoutes;

  /**
   * The maximum allowed clock skew (in seconds) for token validation.
   * @defaultValue 60 (seconds)
   */
  clockSkew: number;

  /**
   * The timeout (in milliseconds) for receiving responses from the authentication service.
   * @defaultValue 10000 (10 seconds)
   */
  responseTimeout: number;

  /**
   * Determines whether to use PAR (Pushed Authorization Requests) for authorization requests.
   * @defaultValue false
   */
  usePar: boolean;

  /**
   * Optional: The URI to redirect to after the user logs out.
   */
  postLogoutRedirectUri?: string;

  /**
   * Determines whether the user will be logged out of the authentication service.
   * @defaultValue true
   */
  federatedLogout: boolean;

  /**
   * Determines whether to fetch the user information from the 'userinfo' endpoint during authentication.
   * @defaultValue true
   */
  userInfo: boolean;

  /**
   * Determines whether to refetch the user information from the authentication service on each request to the
   * application's userinfo endpoint.
   * @defaultValue false
   */
  refreshUserInfo: boolean;

  /**
   * Default authorization parameters to include in authentication requests.
   * @defaultValue {
   *   scope: 'openid email profile',
   *   response_type: 'code'
   * }
   */
  defaultAuthParams: AuthorizationParameters;

  /**
   * Configuration options for the user session.
   */
  session: MonoCloudSessionOptionsBase;

  /**
   * Configuration options for state management during authentication.
   */
  state: MonoCloudStateOptions;

  /**
   * The signing algorithm that is expected to be used for signing ID tokens.
   * @defaultValue 'RS256'
   */
  idTokenSigningAlg: SecurityAlgorithms;

  /**
   *  Array of strings representing the filtered ID token claims.
   */
  filteredIdTokenClaims: (keyof MonoCloudUser)[];

  /**
   * The name of the debugger instance.
   */
  debugger: string;

  /**
   * The name of the user agent.
   */
  userAgent: string;

  /**
   * Optional: A callback function invoked when a back-channel logout event is received.
   */
  onBackChannelLogout?: OnBackChannelLogout;

  /**
   * Optional: A callback function invoked when an authentication state is being set (before sign-in).
   */
  onSetApplicationState?: OnSetApplicationState;

  /**
   * Optional: A callback function invoked before creating or updating the user session.
   */
  onSessionCreating?: OnSessionCreating;
}

/**
 * Options for the authentication sessions.
 */
type MonoCloudSessionOptions = Except<
  PartialDeep<MonoCloudSessionOptionsBase>,
  'store'
> & {
  /**
   * Optional: The session store to use for storing session data.
   */
  store?: MonoCloudSessionStore;
};

/**
 * Options for configuration MonoCloud Authentication.
 */
export type MonoCloudOptions = Except<
  PartialDeep<MonoCloudOptionsBase>,
  'defaultAuthParams' | 'session'
> & {
  /**
   * Default authorization parameters to include in authentication requests.
   * @defaultValue {
   *   scope: 'openid email profile',
   *   response_type: 'code'
   * }
   */
  defaultAuthParams?: Partial<AuthorizationParameters>;

  /**
   * Configuration options for the user session.
   */
  session?: MonoCloudSessionOptions;
};

/**
 * The custom application state.
 */
export type ApplicationState = Record<string, any>;

/**
 * Defines a callback function to be invoked when a back-channel logout event is received.
 * This function receives an optional subject identifier (sub) of the user and an optional session identifier (sid).
 *
 * @param sub - Optional. The subject identifier (sub) of the user.
 * @param sid - Optional. The session identifier (sid) associated with the user's session.
 * @returns A Promise that resolves when the operation is completed, or void.
 */
export type OnBackChannelLogout = (
  /**
   * Optional. The subject identifier (sub) of the user.
   */
  sub?: string,
  /**
   * Optional. The session identifier (sid) associated with the user's session.
   */
  sid?: string
) => Promise<void> | void;

/**
 * Defines a callback function to be executed when an authentication state is being set.
 * This function receives the incoming request and should return or resolve with an ApplicationState object.
 *
 * @param req - The incoming request.
 * @returns A Promise that resolves with the ApplicationState object when the operation is completed, or the ApplicationState object directly.
 */
export type OnSetApplicationState = (
  /**
   * The incoming request.
   */
  req: MonoCloudRequest
) => Promise<ApplicationState> | ApplicationState;

/**
 * Defines a callback function to be executed when a new session is being created or updated.
 * This function receives parameters related to the session being created,
 * including the session object itself, optional ID token and user information claims,
 * and the application state.
 *
 * @param session - The Session object being created.
 * @param idToken - Optional. Claims from the ID token received during authentication.
 * @param userInfo - Optional. Claims from the user information received during authentication.
 * @param state - Optional. The application state associated with the session.
 * @returns A Promise that resolves when the operation is completed, or void.
 */
export type OnSessionCreating = (
  /**
   * The Session object being created.
   */
  session: MonoCloudSession,

  /**
   * Optional. Claims from the ID token received during authentication.
   */
  idToken?: Partial<IdTokenClaims>,

  /**
   * Optional. Claims from the user information received during authentication.
   */
  userInfo?: UserinfoResponse,

  /**
   * Optional. The application state associated with the session.
   */
  state?: ApplicationState
) => Promise<void> | void;

/**
 * Represents the tokens obtained during authentication that are available in the session.
 */
export interface MonoCloudTokens {
  /**
   * The access token obtained during authentication.
   */
  accessToken?: string;

  /**
   * The ID token obtained during authentication.
   */
  idToken?: string;

  /**
   * The refresh token obtained during authentication.
   */
  refreshToken?: string;

  /**
   * Specifies if the access token has expired.
   */
  isExpired: boolean;
}

/**
 * Represents options for the sign-in handler.
 */
export interface SignInOptions {
  /**
   * The application URL to which the user should be redirected after successful authentication.
   * Must be a relative Url.
   * Defaults to the appUrl.
   */
  returnUrl?: string;

  /**
   * The authenticator which will be used for authenticating the user.
   */
  authenticator?: Authenticators;

  /**
   * A hint to the authentication system indicating the user's preferred login identifier.
   */
  loginHint?: string;

  /**
   * Specifies whether to initiate a user registration process.
   */
  register?: boolean;

  /**
   * Additional authorization parameters to include in the authentication request.
   */
  authParams?: AuthorizationParameters;
}

/**
 * Represents options for the callback handler.
 */
export interface CallbackOptions {
  /**
   * Determines whether to fetch the user information from the 'userinfo' endpoint after processing the callback.
   */
  userInfo?: boolean;

  /**
   * Additional authorization parameters to include in the callback request.
   */
  authParams?: AuthorizationParameters;
}

/**
 * Represents options for the userinfo handler.
 */
export interface UserInfoOptions {
  /**
   * Determines whether to refetch the user information from the authentication service.
   */
  refresh?: boolean;
}

/**
 * Represents options for the sign-out handler.
 */
export interface SignOutOptions {
  /**
   * The application URL to which the user should be redirected after sign-out.
   * Defaults to the appUrl.
   */
  post_logout_url?: string;

  /**
   * Determines whether the user will be logged out of the authentication service.
   */
  federatedLogout?: boolean;

  /**
   * Additional parameters to include in the sign-out request.
   */
  signOutParams?: EndSessionParameters;
}

/**
 * Represents options for the GetTokens handler.
 */
export interface GetTokensOptions {
  /**
   * Specifies whether to force the refresh of the access token.
   */
  forceRefresh?: boolean;

  /**
   * Additional authorization parameters to include in the token refresh request.
   */
  refreshParams?: AuthorizationParameters;
}
