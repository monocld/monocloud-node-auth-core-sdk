/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable import/no-cycle */
import type { CookieSerializeOptions } from 'cookie';
import { MonoCloudSession, SessionLifetime } from '.';

type KnownKeys<T> = {
  [K in keyof T]: string extends K ? never : number extends K ? never : K;
} extends { [_ in keyof T]: infer U }
  ? object extends U
    ? never
    : U
  : never;

type UnknownObject = Record<string, unknown>;

type Override<T1, T2> = Omit<T1, keyof Omit<T2, keyof KnownKeys<T2>>> & T2;

type Address<ExtendedAddress extends object = UnknownObject> = Override<
  {
    formatted?: string;
    street_address?: string;
    locality?: string;
    region?: string;
    postal_code?: string;
    country?: string;
  },
  ExtendedAddress
>;

export type UserinfoResponse<
  UserInfo extends object = UnknownObject,
  ExtendedAddress extends object = UnknownObject,
> = Override<
  {
    sub: string;
    name?: string;
    given_name?: string;
    family_name?: string;
    middle_name?: string;
    nickname?: string;
    preferred_username?: string;
    profile?: string;
    picture?: string;
    website?: string;
    email?: string;
    email_verified?: boolean;
    gender?: string;
    birthdate?: string;
    zoneinfo?: string;
    locale?: string;
    phone_number?: string;
    updated_at?: number;
    address?: Address<ExtendedAddress>;
  },
  UserInfo
>;

export interface IdTokenClaims extends UserinfoResponse {
  acr?: string;
  amr?: string[];
  at_hash?: string;
  aud: string | string[];
  auth_time?: number;
  azp?: string;
  c_hash?: string;
  exp: number;
  iat: number;
  iss: string;
  nonce?: string;
  s_hash?: string;
  sub: string;
  [key: string]: unknown;
}

export interface AuthorizationParameters {
  acr_values?: string;
  client_id?: string;
  display?: string;
  id_token_hint?: string;
  login_hint?: string;
  max_age?: number;
  prompt?: string;
  redirect_uri?: string;
  request_uri?: string;
  request?: string;
  response_mode?: string;
  response_type?: string;
  scope?: string;
  ui_locales?: string;
  [key: string]: unknown;
}

export interface IssuerMetadata {
  issuer: string;
  authorization_endpoint?: string;
  token_endpoint?: string;
  jwks_uri?: string;
  userinfo_endpoint?: string;
  revocation_endpoint?: string;
  end_session_endpoint?: string;
  registration_endpoint?: string;
  token_endpoint_auth_methods_supported?: string[];
  token_endpoint_auth_signing_alg_values_supported?: string[];
  introspection_endpoint_auth_methods_supported?: string[];
  introspection_endpoint_auth_signing_alg_values_supported?: string[];
  revocation_endpoint_auth_methods_supported?: string[];
  revocation_endpoint_auth_signing_alg_values_supported?: string[];
  request_object_signing_alg_values_supported?: string[];
  mtls_endpoint_aliases?: MtlsEndpointAliases;
  [key: string]: unknown;
}

interface MtlsEndpointAliases {
  token_endpoint?: string;
  userinfo_endpoint?: string;
  revocation_endpoint?: string;
  introspection_endpoint?: string;
  device_authorization_endpoint?: string;
}

export interface EndSessionParameters {
  id_token_hint?: string;
  post_logout_redirect_uri?: string;
  state?: string;
  client_id?: string;
  logout_hint?: string;
  [key: string]: unknown;
}

export type CookieOptions = CookieSerializeOptions;

export interface IMonoCloudCookieRequest {
  getCookie(name: string): string | undefined;
  getAllCookies(): Map<string, string>;
}

export interface MonoCloudRequest extends IMonoCloudCookieRequest {
  getRoute(parameter: string): string | string[] | undefined;
  getQuery(parameter: string): string | string[] | undefined;
  getRawRequest(): Promise<{
    method: string;
    url: string;
    body: Record<string, string> | string;
  }>;
}

export interface IMonoCloudCookieResponse {
  setCookie(cookieName: string, value: string, options: CookieOptions): void;
}

export interface MonoCloudResponse extends IMonoCloudCookieResponse {
  redirect(url: string, statusCode?: number): void;
  sendJson(data: any, statusCode?: number): void;
  notFound(): void;
  noContent(): void;
  methodNotAllowed(): void;
  setNoCache(): void;
  done(): any;
}

export interface SessionCookieValue {
  key: string;
  lifetime: SessionLifetime;
  session?: MonoCloudSession;
}

export interface Tokens {
  access_token?: string;
  token_type?: string;
  id_token?: string;
  refresh_token?: string;
  scope?: string;
  expires_at?: number;
  expires_in?: number;
  claims?: Partial<IdTokenClaims>;
}
