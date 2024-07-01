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
  MonoCloudUser,
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
import dbug, { Debugger } from 'debug';
import {
  ensureLeadingSlash,
  getAcrValues,
  isAbsoluteUrl,
  isSameHost,
  now,
} from '../utils';
import { OAuthClient } from '../openid-client/oauth-client';

export class MonoCloudBaseInstance {
  private readonly options: MonoCloudOptionsBase;

  private readonly stateService: MonoCloudStateService;

  private readonly sessionService: MonoCloudSessionService;

  private readonly client: OAuthClient;

  private readonly debug: Debugger;

  constructor(partialOptions?: MonoCloudOptions) {
    this.options = getOptions(partialOptions);
    this.debug = dbug(this.options.debugger);
    this.client = new OAuthClient(this.options, this.debug);
    this.stateService = new MonoCloudStateService(this.options);
    this.sessionService = new MonoCloudSessionService(this.options);

    /* c8 ignore start */
    if (process.env.DEBUG && !this.debug.enabled) {
      dbug.enable(process.env.DEBUG);
    }
    /* c8 ignore end */

    this.debug('Debug logging enabled.');
  }

  async signIn(
    request: MonoCloudRequest,
    response: MonoCloudResponse,
    signInOptions?: SignInOptions
  ): Promise<any> {
    this.debug('Starting sign-in handler');

    try {
      const { method } = await request.getRawRequest();

      if (method.toLowerCase() !== 'get') {
        response.methodNotAllowed();
        return response.done();
      }

      // Merge the sign-in options and the default options
      const opt = {
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
        if (
          appState === null ||
          appState === undefined ||
          typeof appState !== 'object' ||
          Array.isArray(appState)
        ) {
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
        typeof opt.authParams.max_age === 'number'
          ? opt.authParams.max_age
          : undefined;

      // Ensure that return to is present, if not then use the base url as the return to
      const returnUrl = encodeURIComponent(
        opt.returnUrl ?? this.options.appUrl
      );

      const redirectUrl = `${this.options.appUrl}${ensureLeadingSlash(this.options.routes.callback)}`;

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
      if (
        this.options.usePar ||
        metadata.require_pushed_authorization_requests
      ) {
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
      response.redirect(authUrl, 302);
    } catch (error) {
      this.handleCatchAll(error, response);
    }

    return response.done();
  }

  async callback(
    request: MonoCloudRequest,
    response: MonoCloudResponse,
    callbackOptions?: CallbackOptions
  ): Promise<any> {
    this.debug('Starting callback handler');

    try {
      const { method, url, body } = await request.getRawRequest();

      if (method.toLowerCase() !== 'get' && method.toLowerCase() !== 'post') {
        response.methodNotAllowed();
        return response.done();
      }

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
      const monoCloudState = await this.stateService.getState(
        request,
        response
      );

      // Handle invalid state
      if (!monoCloudState) {
        throw new MonoCloudValidationError('Invalid State');
      }

      let fullUrl = url;

      // check if the url is a relative url
      if (!isAbsoluteUrl(url)) {
        fullUrl = `${this.options.appUrl}${ensureLeadingSlash(url)}`;
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
        `${this.options.appUrl}${ensureLeadingSlash(this.options.routes.callback)}`;

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
          response.redirect(
            `${this.options.appUrl}${ensureLeadingSlash(decodedUrl)}`
          );
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
    } catch (error) {
      this.handleCatchAll(error, response);
    }

    return response.done();
  }

  async userInfo(
    request: MonoCloudRequest,
    response: MonoCloudResponse,
    userinfoOptions?: UserInfoOptions
  ): Promise<any> {
    this.debug('Starting userinfo handler');

    try {
      const { method } = await request.getRawRequest();

      if (method.toLowerCase() !== 'get') {
        response.methodNotAllowed();
        return response.done();
      }

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
    } catch (error) {
      this.handleCatchAll(error, response);
    }

    return response.done();
  }

  async signOut(
    request: MonoCloudRequest,
    response: MonoCloudResponse,
    signOutOptions?: SignOutOptions
  ): Promise<any> {
    this.debug('Starting sign-out handler');

    try {
      const { method } = await request.getRawRequest();

      if (method.toLowerCase() !== 'get') {
        response.methodNotAllowed();
        return response.done();
      }

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
        returnUrl = `${this.options.appUrl}${ensureLeadingSlash(returnUrl)}`;
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
    } catch (error) {
      this.handleCatchAll(error, response);
    }

    return response.done();
  }

  async backChannelLogout(
    request: MonoCloudRequest,
    response: MonoCloudResponse
  ): Promise<any> {
    this.debug('Starting back-channel logout handler');

    try {
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
    } catch (error) {
      this.handleCatchAll(error, response);
    }

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
    if (!refreshToken && accessTokenExpiration - 30 < now()) {
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
      /* istanbul ignore next */
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

  public async getUserOrRedirect(
    request: MonoCloudRequest,
    response: MonoCloudResponse,
    returnUrl?: string
  ): Promise<MonoCloudUser> {
    const session = await this.getSession(request, response);

    if (!session) {
      const rawRequest = await request.getRawRequest();

      const url = `${this.options.appUrl}${ensureLeadingSlash(this.options.routes.signIn)}?return_url=${returnUrl?.trim().length ? returnUrl : rawRequest.url}`;

      response.redirect(url, 302);
      return response.done();
    }

    return session.user;
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
    /* istanbul ignore next */
    const idTokenClaims = { ...(tokens.claims ?? {}) };

    // Delete the filtered claims
    this.options.filteredIdTokenClaims.forEach(x => {
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
    if (this.options.onSessionCreating) {
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
    /* istanbul ignore next */
    const idTokenClaims = { ...(tokens.claims ?? {}) };

    // Delete the filtered claims
    this.options.filteredIdTokenClaims.forEach(x => {
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

  private handleCatchAll(error: Error, res: MonoCloudResponse) {
    console.error(error);
    res.internalServerError();
  }
}
