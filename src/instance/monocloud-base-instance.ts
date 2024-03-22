/* eslint-disable @typescript-eslint/no-dynamic-delete */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { MonoCloudSessionService } from '../session/monocloud-session-service';
import { MonoCloudStateService } from '../state/monocloud-state-service';
import { getOptions } from '../options/get-options';
import {
  ApplicationState,
  CallbackOptions,
  GetTokensOptions,
  SignInOptions,
  SignOutOptions,
  MonoCloudOptionsBase,
  MonoCloudSession,
  MonoCloudState,
  MonoCloudTokens,
  UserInfoOptions,
  MonoCloudOptions,
} from '../types';
import {
  AuthorizationParameters,
  IMonoCloudCookieRequest,
  IMonoCloudCookieResponse,
  IdTokenClaims,
  IssuerMetadata,
  MonoCloudRequest,
  MonoCloudResponse,
  Tokens,
  UserinfoResponse,
} from '../types/internal';
import {
  callbackOptionsSchema,
  getTokensOptionsSchema,
  signInOptionsSchema,
  signOutOptionsSchema,
  userInfoOptionsSchema,
} from '../options/validation';
import { MonoCloudValidationError } from '../errors/monocloud-validation-error';
import { debug, getAcrValues, isAbsoluteUrl, isSameHost, now } from '../utils';
import { OAuthClient } from '../openid-client/oauth-client';

export class MonoCloudBaseInstance {
  private readonly options: MonoCloudOptionsBase;

  private readonly stateService: MonoCloudStateService;

  private readonly sessionService: MonoCloudSessionService;

  private readonly client: OAuthClient;

  constructor(partialOptions?: MonoCloudOptions) {
    this.options = getOptions(partialOptions);
    this.client = new OAuthClient(this.options);
    this.stateService = new MonoCloudStateService(this.options);
    this.sessionService = new MonoCloudSessionService(this.options);
  }

  async signIn(
    request: MonoCloudRequest,
    response: MonoCloudResponse,
    signInOptions?: SignInOptions
  ): Promise<any> {
    debug('Starting sign-in handler');

    // Merge the sign-in options and the default options
    const opt: SignInOptions = {
      ...(signInOptions || {}),
      authParams: {
        ...this.options.defaultAuthParams,
        ...signInOptions?.authParams,
      },
    };

    let appState: ApplicationState = {};

    // Set the application state if the onSetApplicationState function is set
    if (this.options.onSetApplicationState) {
      appState = await this.options.onSetApplicationState(request);

      // Validate the custom sign-in state
      if (typeof appState !== 'object' || Array.isArray(appState)) {
        throw new MonoCloudValidationError(
          'Invalid Application State. Expected state to be an object'
        );
      }
    }

    // Set the return url if passed down
    const retUrl = request.getQuery('return_url') ?? opt.returnUrl;
    if (typeof retUrl === 'string' && retUrl) {
      opt.returnUrl = retUrl;
    }

    // Validate the options
    const { error } = signInOptionsSchema.validate(opt, { abortEarly: true });

    if (error) {
      throw new MonoCloudValidationError(error.details[0].message);
    }

    // Generate the state, nonce & code verifier
    const state = this.client.generateState();
    const nonce = this.client.generateNonce();
    const verifier = this.client.generateCodeVerifier();
    const codeChallenge = await this.client.codeChallenge(verifier);
    const maxAge =
      typeof opt.authParams?.max_age === 'number'
        ? opt.authParams.max_age
        : undefined;

    // Ensure that return to is present, if not then use the base url as the return to
    const returnUrl = encodeURIComponent(opt.returnUrl ?? this.options.appUrl);

    const redirectUrl = new URL(
      this.options.routes.callback,
      this.options.appUrl
    ).toString();

    // Generate the monocloud state
    const monoCloudState: MonoCloudState = {
      returnUrl,
      state,
      nonce,
      verifier,
      maxAge,
      appState: JSON.stringify(appState),
    };

    // Create the Authorization Parameters
    let params: AuthorizationParameters = {
      redirect_uri: redirectUrl,
      ...opt.authParams,
      nonce,
      state,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
    };

    // Set the Authenticator if passed down
    const authenticator =
      request.getQuery('authenticator') ?? opt.authenticator;
    if (typeof authenticator === 'string' && authenticator) {
      let acrValues = getAcrValues(params.acr_values);
      acrValues = acrValues.filter(x => x.startsWith('authenticator:'));
      acrValues.push(`authenticator:${authenticator}`);
      params.acr_values = acrValues.join(' ');
    }

    // Set the login hint if passed down
    const loginHint = request.getQuery('login_hint') ?? opt.loginHint;
    if (typeof loginHint === 'string' && loginHint) {
      params.login_hint = loginHint;
    }

    // Set the prompt to register if passed down
    const register = request.getQuery('register') ?? opt.register?.toString();
    if (typeof register === 'string' && register.toLowerCase() === 'true') {
      params.prompt = 'create';
    }

    // if options is set to use par or if the issuer requires par then use it
    const metadata = await this.client.getMetadata();
    if (this.options.usePar || metadata.require_pushed_authorization_requests) {
      // eslint-disable-next-line @typescript-eslint/naming-convention
      const { request_uri } =
        await this.client.pushedAuthorizationRequest(params);
      params = { request_uri, scope: undefined, response_type: undefined };
    }

    // Create the authorize url
    const authUrl = await this.client.authorizationUrl(params);

    // Set the state cookie
    await this.stateService.setState(
      response,
      monoCloudState,
      params.response_mode === 'form_post' ? 'none' : undefined
    );

    // Redirect to the authorize url
    response.redirect(authUrl);

    return response.done();
  }

  async callback(
    request: MonoCloudRequest,
    response: MonoCloudResponse,
    callbackOptions?: CallbackOptions
  ): Promise<any> {
    debug('Starting callback handler');

    // Validate the callback Options
    if (callbackOptions) {
      const { error } = callbackOptionsSchema.validate(callbackOptions, {
        abortEarly: true,
      });

      if (error) {
        throw new MonoCloudValidationError(error.details[0].message);
      }
    }

    // Get the state value
    const monoCloudState = await this.stateService.getState(request, response);

    // Handle invalid state
    if (!monoCloudState) {
      throw new MonoCloudValidationError('Invalid State');
    }

    const { method, url, body } = await request.getRawRequest();

    let fullUrl = url;

    // check if the url is a relative url
    if (!isAbsoluteUrl(url)) {
      fullUrl = new URL(url, this.options.appUrl).toString();
    }

    // Get the search parameters or the body
    const payload =
      method.toLowerCase() === 'post'
        ? new URLSearchParams(body)
        : new URL(fullUrl).searchParams;

    // Get the parameters returned from the server
    const callbackParams = await this.client.callbackParams(
      payload,
      monoCloudState.state
    );

    // Get the redirect Url to be validated
    const redirectUri =
      callbackOptions?.authParams?.redirect_uri ??
      new URL(this.options.routes.callback, this.options.appUrl).toString();

    // Get the tokens
    const tokens = await this.client.callback(
      redirectUri,
      callbackParams,
      monoCloudState.verifier as string,
      monoCloudState.nonce,
      monoCloudState.maxAge,
      callbackOptions?.authParams
    );

    // Parse the client state
    const appState: ApplicationState = JSON.parse(monoCloudState.appState);

    // Generate the user session
    const session = await this.getSessionFromCallback(
      tokens,
      appState,
      callbackOptions
    );

    // Set the user session
    await this.sessionService.setSession(request, response, session);

    // Return to base url if no return url was set
    if (!monoCloudState.returnUrl) {
      response.redirect(this.options.appUrl);
      return response.done();
    }

    // Return to a valid return to url
    try {
      const decodedUrl = decodeURIComponent(monoCloudState.returnUrl);

      if (!isAbsoluteUrl(decodedUrl)) {
        response.redirect(new URL(decodedUrl, this.options.appUrl).toString());
        return response.done();
      }

      if (isSameHost(this.options.appUrl, decodedUrl)) {
        response.redirect(decodedUrl);
        return response.done();
      }
    } catch (e) {
      // do nothing
    }

    response.redirect(this.options.appUrl);

    return response.done();
  }

  async userInfo(
    request: MonoCloudRequest,
    response: MonoCloudResponse,
    userinfoOptions?: UserInfoOptions
  ): Promise<any> {
    debug('Starting userinfo handler');

    // Validate the User Info options
    if (userinfoOptions) {
      const { error } = userInfoOptionsSchema.validate(userinfoOptions, {
        abortEarly: true,
      });

      if (error) {
        throw new MonoCloudValidationError(error.details[0].message);
      }
    }

    const refreshUserInfo =
      userinfoOptions?.refresh ?? this.options.refreshUserInfo;

    // Get the user session
    const session = await this.sessionService.getSession(
      request,
      response,
      !refreshUserInfo
    );

    // Handle no session
    if (!session) {
      response.setNoCache();
      response.noContent();
      return response.done();
    }

    // If refetch is false then return the session
    if (!refreshUserInfo || !session.accessToken) {
      response.sendJson(session.user);
      return response.done();
    }

    // Get the new data from the user info endpoint
    const uiClaims = await this.client.userinfo(session.accessToken);

    // Set the session userinfo claims
    session.user = { ...session.user, ...uiClaims };

    if (this.options.onSessionCreating) {
      await this.options.onSessionCreating(
        session,
        undefined,
        uiClaims,
        undefined
      );
    }

    // Update the session containing the new claims
    const updated = await this.sessionService.updateSession(
      request,
      response,
      session
    );

    // Handle session was not updated successfully
    if (!updated) {
      response.setNoCache();
      response.noContent();
      return response.done();
    }

    // Return the Claims
    response.sendJson(session.user);
    return response.done();
  }

  async signOut(
    request: MonoCloudRequest,
    response: MonoCloudResponse,
    signOutOptions?: SignOutOptions
  ): Promise<any> {
    debug('Starting sign-out handler');

    // Validate the sign-out options
    if (signOutOptions) {
      const { error } = signOutOptionsSchema.validate(signOutOptions, {
        abortEarly: true,
      });

      if (error) {
        throw new MonoCloudValidationError(error.details[0].message);
      }
    }

    // Build the return to url
    let returnUrl =
      signOutOptions?.post_logout_url ??
      this.options.postLogoutRedirectUri ??
      this.options.appUrl;

    // Set the return url if passed down
    const retUrl = request.getQuery('post_logout_url');
    if (typeof retUrl === 'string' && retUrl) {
      const { error } = signOutOptionsSchema.validate({
        post_logout_url: retUrl,
      });

      if (!error) {
        returnUrl = retUrl;
      }
    }

    // Ensure the return to is an absolute one
    if (!isAbsoluteUrl(returnUrl)) {
      returnUrl = new URL(returnUrl, this.options.appUrl).toString();
    }

    // Get the current session
    const session = await this.sessionService.getSession(
      request,
      response,
      false
    );

    // Redirect to return url if session doesnt exist
    if (!session) {
      response.redirect(returnUrl);
      return response.done();
    }

    await this.sessionService.removeSession(request, response);

    // Handle Federated Logout
    const isFederatedLogout =
      signOutOptions?.federatedLogout ?? this.options.federatedLogout;

    if (!isFederatedLogout) {
      response.redirect(returnUrl);
      return response.done();
    }

    // Build the end session Url
    const url = await this.client.endSessionUrl({
      ...(signOutOptions?.signOutParams ?? {}),
      id_token_hint: session.idToken,
      post_logout_redirect_uri: returnUrl,
    });

    // Redirect the user to the end session endpoint
    response.redirect(url);
    return response.done();
  }

  async backChannelLogout(
    request: MonoCloudRequest,
    response: MonoCloudResponse
  ): Promise<any> {
    debug('Starting back-channel logout handler');

    response.setNoCache();

    if (!this.options.onBackChannelLogout) {
      response.notFound();
      return response.done();
    }

    const { method, body } = await request.getRawRequest();

    if (method.toLowerCase() !== 'post') {
      response.methodNotAllowed();
      return response.done();
    }

    const params = new URLSearchParams(body);
    const logoutToken = params.get('logout_token');

    if (!logoutToken) {
      throw new MonoCloudValidationError('Missing Logout Token');
    }

    const { sid, sub } = await this.verifyLogoutToken(
      logoutToken,
      await this.client.getMetadata()
    );

    await this.options.onBackChannelLogout(sub, sid as any);

    response.noContent();
    return response.done();
  }

  async isAuthenticated(
    request: IMonoCloudCookieRequest,
    response: IMonoCloudCookieResponse
  ): Promise<boolean> {
    // Get the session
    const session = await this.sessionService.getSession(request, response);

    // Return true if the session exists
    return !!session?.user;
  }

  getSession(
    request: IMonoCloudCookieRequest,
    response: IMonoCloudCookieResponse
  ): Promise<MonoCloudSession | undefined> {
    return this.sessionService.getSession(request, response);
  }

  async updateSession(
    request: IMonoCloudCookieRequest,
    response: IMonoCloudCookieResponse,
    session: MonoCloudSession
  ): Promise<void> {
    await this.sessionService.updateSession(request, response, session);
  }

  getOptions(): MonoCloudOptionsBase {
    return { ...this.options };
  }

  destroySession(
    request: IMonoCloudCookieRequest,
    response: IMonoCloudCookieResponse
  ): Promise<void> {
    return this.sessionService.removeSession(request, response);
  }

  async getTokens(
    request: IMonoCloudCookieRequest,
    response: IMonoCloudCookieResponse,
    options?: GetTokensOptions
  ): Promise<MonoCloudTokens> {
    // Validate the get tokens options
    if (options) {
      const { error } = getTokensOptionsSchema.validate(options, {
        abortEarly: true,
      });

      if (error) {
        throw new MonoCloudValidationError(error.details[0].message);
      }
    }

    // Get the session
    const session = await this.sessionService.getSession(request, response);

    // Handle no access token
    if (!session?.accessToken) {
      return {
        accessToken: undefined,
        idToken: session?.idToken,
        refreshToken: undefined,
        isExpired: false,
      };
    }

    const { accessTokenExpiration, accessToken, refreshToken, idToken } =
      session;

    const tokens: MonoCloudTokens = {
      accessToken,
      idToken,
      refreshToken,
      isExpired: false,
    };

    // Handle no access token expiration
    if (!accessTokenExpiration) {
      return { ...tokens, isExpired: true };
    }

    // Handle access token expired and no refresh token
    if (!refreshToken && accessTokenExpiration * 1000 - 30000 < now()) {
      return { ...tokens, isExpired: true };
    }

    // Handle force refresh and no refresh token
    if (options?.forceRefresh && !refreshToken) {
      return { ...tokens, isExpired: false };
    }

    // Handle when access token is valid or does not need refresh
    if (
      !(
        refreshToken &&
        (accessTokenExpiration * 1000 - 30000 < now() || options?.forceRefresh)
      )
    ) {
      return { ...tokens, isExpired: false };
    }

    // Refresh the token
    const newTokens = await this.client.refresh(
      refreshToken,
      options?.refreshParams
    );

    const newSession = await this.getSessionFromRefresh(newTokens, session);

    await this.sessionService.updateSession(request, response, newSession);

    const isNewTokenExpired =
      !!newSession.accessToken &&
      (!newSession.accessTokenExpiration ||
        newSession.accessTokenExpiration * 1000 - 30000 < now());

    // Return the claims
    return {
      accessToken: newSession.accessToken,
      refreshToken: newSession.refreshToken,
      idToken: newSession.idToken,
      isExpired: isNewTokenExpired,
    };
  }

  private async getSessionFromCallback(
    tokens: Tokens,
    appState: ApplicationState,
    callbackOptions?: CallbackOptions
  ): Promise<MonoCloudSession> {
    let uiClaims;

    // Fetch the user info if set
    if (
      tokens.access_token &&
      (callbackOptions?.userInfo ?? this.options.userInfo)
    ) {
      uiClaims = await this.client.userinfo(tokens.access_token);
    }

    // Get the identity token claims
    const idTokenClaims = { ...(tokens.claims ?? {}) };

    // Delete the filtered claims
    this.options.filteredIdTokenClaims?.forEach(x => {
      delete idTokenClaims[x as any];
    });

    // Build the session
    const session: MonoCloudSession = {
      user: { ...idTokenClaims, ...uiClaims },
      accessToken: tokens.access_token,
      idToken: tokens.id_token,
      refreshToken: tokens.refresh_token,
      accessTokenExpiration: tokens.expires_at,
      scopes: tokens.scope,
    };

    // If a custom post callback function was provided then call it
    if (this.options?.onSessionCreating) {
      await this.options.onSessionCreating(
        session,
        tokens.claims,
        uiClaims,
        appState
      );
    }

    // return the session
    return session;
  }

  private async getSessionFromRefresh(
    tokens: Tokens,
    oldSession: MonoCloudSession
  ): Promise<MonoCloudSession> {
    let uiClaims;

    // Fetch the user info if set
    if (tokens.access_token && this.options.refreshUserInfo) {
      uiClaims = await this.client.userinfo(tokens.access_token);
    }

    // Get the identity token claims
    const idTokenClaims = { ...(tokens.claims ?? {}) };

    // Delete the filtered claims
    this.options.filteredIdTokenClaims?.forEach(x => {
      delete idTokenClaims[x as any];
    });

    // Build the session
    const session: MonoCloudSession = {
      user: { ...idTokenClaims, ...uiClaims },
      accessToken: tokens.access_token,
      idToken: tokens.id_token,
      refreshToken: tokens.refresh_token || oldSession.refreshToken,
      accessTokenExpiration: tokens.expires_at,
      scopes: tokens.scope,
    };

    Object.assign(oldSession, session, {
      user: { ...oldSession.user, ...session.user },
    });

    // If a custom post refresh function was provided then call it
    if (this.options.onSessionCreating) {
      await this.options.onSessionCreating(
        oldSession,
        tokens.claims as IdTokenClaims,
        uiClaims as UserinfoResponse,
        undefined
      );
    }

    // return the session
    return oldSession;
  }

  private async verifyLogoutToken(token: string, metadata: IssuerMetadata) {
    const jwks = createRemoteJWKSet(new URL(metadata.jwks_uri as string));

    const { payload } = await jwtVerify(token, jwks, {
      issuer: metadata.issuer,
      audience: this.options.clientId,
      algorithms: [this.options.idTokenSigningAlg],
      requiredClaims: ['iat'],
    });

    if (
      (!payload.sid && !payload.sub) ||
      payload.nonce ||
      !payload.events ||
      typeof payload.events !== 'object'
    ) {
      throw new MonoCloudValidationError('Invalid logout token');
    }

    const event = (payload.events as any)[
      'http://schemas.openid.net/event/backchannel-logout'
    ];

    if (!event || typeof event !== 'object') {
      throw new MonoCloudValidationError('Invalid logout token');
    }

    return payload;
  }
}
