/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable class-methods-use-this */
import {
  discoveryRequest,
  processDiscoveryResponse,
  AuthorizationServer,
  clockTolerance,
  Client,
  generateRandomCodeVerifier,
  generateRandomState,
  generateRandomNonce,
  calculatePKCECodeChallenge,
  userInfoRequest,
  processUserInfoResponse,
  skipSubjectCheck,
  processPushedAuthorizationResponse,
  pushedAuthorizationRequest,
  validateAuthResponse,
  isOAuth2Error,
  authorizationCodeGrantRequest,
  processAuthorizationCodeOpenIDResponse,
  HttpRequestOptions,
  refreshTokenGrantRequest,
  processRefreshTokenResponse,
  OperationProcessingError,
} from './oauth4webapi';
import { MonoCloudOptionsBase } from '../types';
import {
  AuthorizationParameters,
  EndSessionParameters,
  IdTokenClaims,
  IssuerMetadata,
  Tokens,
  UserinfoResponse,
} from '../types/internal';
import { MonoCloudDiscoveryError } from '../errors/monocloud-discovery-error';
import { MonoCloudValidationError } from '../errors/monocloud-validation-error';
import { MonoCloudOPError } from '../errors/monocloud-op-error';
import { debug, isPresent, now } from '../utils';
import { MonoCloudError } from '../errors/monocloud-error';

export class OAuthClient {
  private client!: Client;

  private authServer!: AuthorizationServer;

  constructor(
    private readonly options: MonoCloudOptionsBase,
    public readonly userAgent?: string
  ) {}

  async getClient(): Promise<void> {
    if (this.client && this.authServer) {
      return;
    }

    if (
      this.options.defaultAuthParams.response_type &&
      this.options.defaultAuthParams.response_type !== 'code'
    ) {
      throw new MonoCloudValidationError(
        'The sdk only supports the authorization code flow. Please use the "code" response_type.'
      );
    }

    const url = new URL(this.options.issuer);

    let authServer: AuthorizationServer;

    debug(`Discovering metadata for ${this.options.issuer}`);

    try {
      const httpOptions = this.getHttpRequestOptions();
      const as = await discoveryRequest(url, {
        signal: httpOptions.signal,
        headers: httpOptions.headers,
      });
      authServer = await processDiscoveryResponse(url, as);
    } catch (error: any) {
      if (error instanceof OperationProcessingError) {
        throw new MonoCloudDiscoveryError(error.message);
      } else {
        throw new MonoCloudError(
          'An unknown error occurred while discovering the issuer.'
        );
      }
    }

    if (
      this.options.usePar &&
      !authServer.pushed_authorization_request_endpoint
    ) {
      throw new MonoCloudValidationError(
        'The issuer does not support pushed authorization requests.'
      );
    }

    const client: Client = {
      client_id: this.options.clientId,
      client_secret: this.options.clientSecret,
      id_token_signed_response_alg: this.options.idTokenSigningAlg,
      [clockTolerance]: this.options.clockSkew,
    };

    this.client = client;
    this.authServer = authServer;
  }

  getHttpRequestOptions(): HttpRequestOptions {
    const headers = new Headers();
    headers.set('User-Agent', this.userAgent ?? 'monocloud-node-auth-core-sdk');

    return {
      signal: AbortSignal.timeout(this.options.responseTimeout),
      headers,
    };
  }

  generateCodeVerifier(): string {
    return generateRandomCodeVerifier();
  }

  generateState(): string {
    return generateRandomState();
  }

  generateNonce(): string {
    return generateRandomNonce();
  }

  codeChallenge(codeVerifier: string): Promise<string> {
    return calculatePKCECodeChallenge(codeVerifier);
  }

  async getMetadata(): Promise<IssuerMetadata> {
    await this.getClient();
    return this.authServer;
  }

  async pushedAuthorizationRequest(params: AuthorizationParameters): Promise<{
    request_uri: string;
    expires_in: number;
  }> {
    await this.getClient();

    debug('Starting a pushed authorization request');

    const response = await pushedAuthorizationRequest(
      this.authServer,
      this.client,
      params as Record<string, any>
    );

    const result = await processPushedAuthorizationResponse(
      this.authServer,
      this.client,
      response
    );

    if (isOAuth2Error(result)) {
      throw new MonoCloudOPError(result.error, result.error_description);
    }

    return { request_uri: result.request_uri, expires_in: result.expires_in };
  }

  async authorizationUrl(parameters: AuthorizationParameters): Promise<string> {
    await this.getClient();

    if (!this.authServer.authorization_endpoint) {
      throw new MonoCloudValidationError(
        'Server has no authorization endpoint'
      );
    }

    const url = new URL(this.authServer.authorization_endpoint);

    url.searchParams.set('client_id', this.client.client_id);

    Object.entries(parameters as Record<string, string>)
      .filter(x => isPresent(x[1]))
      .forEach(([key, value]) => url.searchParams.set(key, value));

    debug(`Generated authorization url ${url.toString()}`);

    return url.toString();
  }

  async callbackParams(
    searchParams: URLSearchParams,
    expectedState: string
  ): Promise<URLSearchParams> {
    await this.getClient();

    debug('Extracting callback received from server');

    try {
      const result = validateAuthResponse(
        this.authServer,
        this.client,
        searchParams,
        expectedState
      );

      if (isOAuth2Error(result)) {
        throw new MonoCloudOPError(result.error, result.error_description);
      }

      return result;
    } catch (e: any) {
      throw new MonoCloudOPError(e.message, e.error_description);
    }
  }

  async callback(
    redirectUri: string,
    callbackParameters: URLSearchParams,
    codeVerifier: string,
    expectedNonce?: string,
    maxAge?: number,
    additionalParameters?: Record<string, any>
  ): Promise<Tokens> {
    await this.getClient();

    debug('Processing callback received from server');

    const httpOptions = this.getHttpRequestOptions();

    const response = await authorizationCodeGrantRequest(
      this.authServer,
      this.client,
      callbackParameters,
      redirectUri,
      codeVerifier,
      {
        additionalParameters,
        signal: httpOptions.signal,
        headers: httpOptions.headers,
      }
    );

    const result = await processAuthorizationCodeOpenIDResponse(
      this.authServer,
      this.client,
      response,
      expectedNonce,
      maxAge
    );

    if (isOAuth2Error(result)) {
      throw new MonoCloudOPError(result.error, result.error_description);
    }

    let claims: Partial<IdTokenClaims> = {};

    if (result.id_token) {
      claims = JSON.parse(
        Buffer.from(result.id_token.split('.')[1].trim(), 'base64').toString(
          'utf-8'
        )
      );
    }

    return {
      access_token: result.access_token,
      id_token: result.id_token,
      refresh_token: result.refresh_token,
      scope: result.scope,
      token_type: result.token_type,
      expires_in: result.expires_in,
      expires_at: result.expires_in ? now() + result.expires_in : undefined,
      claims,
    };
  }

  async userinfo(accessToken: string): Promise<UserinfoResponse> {
    await this.getClient();

    debug('Starting request to user info endpoint');

    const httpOptions = this.getHttpRequestOptions();

    try {
      const response = await userInfoRequest(
        this.authServer,
        this.client,
        accessToken,
        {
          signal: httpOptions.signal,
          headers: httpOptions.headers,
        }
      );

      return await processUserInfoResponse(
        this.authServer,
        this.client,
        skipSubjectCheck,
        response
      );
    } catch (e: any) {
      if (e instanceof OperationProcessingError) {
        throw new MonoCloudOPError(e.message);
      } else {
        throw new MonoCloudError(
          'An unknown error occurred while fetching the user info.'
        );
      }
    }
  }

  async endSessionUrl(parameters: EndSessionParameters): Promise<string> {
    await this.getClient();

    if (!this.authServer.end_session_endpoint) {
      throw new MonoCloudValidationError('Server has no end session endpoint');
    }

    const url = new URL(this.authServer.end_session_endpoint);

    url.searchParams.set('client_id', this.client.client_id);

    Object.entries(parameters as Record<string, string>)
      .filter(x => isPresent(x[1]))
      .forEach(([key, value]) => url.searchParams.set(key, value));

    debug(`Generating end session url ${url.toString()}`);

    return url.toString();
  }

  async refresh(
    refreshToken: string,
    additionalParameters?: Record<string, any>
  ): Promise<Tokens> {
    await this.getClient();

    debug('Starting token refresh');

    const httpOptions = this.getHttpRequestOptions();

    const response = await refreshTokenGrantRequest(
      this.authServer,
      this.client,
      refreshToken,
      {
        additionalParameters,
        headers: httpOptions.headers,
        signal: httpOptions.signal,
      }
    );

    const result = await processRefreshTokenResponse(
      this.authServer,
      this.client,
      response
    );

    if (isOAuth2Error(result)) {
      throw new MonoCloudOPError(result.error, result.error_description);
    }

    let claims: Partial<IdTokenClaims> = {};

    if (result.id_token) {
      claims = JSON.parse(
        Buffer.from(result.id_token.split('.')[1].trim(), 'base64').toString(
          'utf-8'
        )
      );
    }

    return {
      access_token: result.access_token,
      id_token: result.id_token,
      refresh_token: result.refresh_token,
      scope: result.scope,
      token_type: result.token_type,
      expires_in: result.expires_in,
      expires_at: result.expires_in ? now() + result.expires_in : undefined,
      claims,
    };
  }
}
