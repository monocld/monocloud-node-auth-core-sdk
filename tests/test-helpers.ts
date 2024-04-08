/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @typescript-eslint/no-non-null-assertion */
/* eslint-disable @typescript-eslint/consistent-indexed-object-style */
/* eslint-disable @typescript-eslint/no-unused-vars */
// eslint-disable-next-line max-classes-per-file
import * as jose from 'jose';
import { CookieSerializeOptions } from 'cookie';
import { MonoCloudRequest, MonoCloudResponse } from '../src/types/internal';
import {
  MonoCloudSession,
  MonoCloudSessionStore,
  SessionLifetime,
} from '../src/types';
import { encryptData, now } from '../src/utils';

interface MockCookies {
  [key: string]: { value: string; options: CookieSerializeOptions };
}

interface MockQuery {
  [key: string]: string | string[] | undefined;
}

interface MockRequest {
  cookies?: MockCookies;
  query?: MockQuery;
  method?: 'GET' | 'POST';
  url?: string;
  body?: any;
}

interface MockResponse {
  cookies: MockCookies;
  redirectedUrl?: string;
  statusCode?: number;
  body?: any;
  done?: boolean;
  noCacheSet?: boolean;
}

export class TestRes implements MonoCloudResponse {
  public get cookies() {
    return this.res.cookies;
  }

  public readonly res: MockResponse;

  constructor(cookies?: MockCookies) {
    this.res = { cookies: cookies ?? {} };
  }

  internalServerError(): void {
    this.throwIfDone();
    this.res.statusCode = 500;
  }

  redirect(url: string, statusCode?: number | undefined): void {
    this.throwIfDone();
    this.res.redirectedUrl = url;
    this.res.statusCode = statusCode;
  }

  sendJson(data: any, statusCode?: number | undefined): void {
    this.throwIfDone();
    this.res.statusCode = statusCode;
    this.res.body = data;
  }

  notFound(): void {
    this.throwIfDone();
    this.res.statusCode = 404;
  }

  noContent(): void {
    this.throwIfDone();
    this.res.statusCode = 204;
  }

  methodNotAllowed(): void {
    this.throwIfDone();
    this.res.statusCode = 405;
  }

  setNoCache(): void {
    this.throwIfDone();
    this.res.noCacheSet = true;
  }

  done() {
    this.throwIfDone();
    this.res.done = true;
  }

  setCookie(
    cookieName: string,
    value: string,
    options: CookieSerializeOptions
  ): void {
    this.throwIfDone();
    this.cookies[cookieName] = { value, options };
  }

  private throwIfDone() {
    if (this.res.done) {
      throw new Error('ERR: Called done twice in TestRes');
    }
  }
}

export class TestReq implements MonoCloudRequest {
  public get cookies() {
    return this.req.cookies;
  }

  public readonly req: MockRequest;

  constructor(req?: Partial<MockRequest>) {
    this.req = {
      cookies: req?.cookies ?? {},
      query: req?.query ?? {},
      url: req?.url,
      body: req?.body,
      method: req?.method,
    };
  }

  getRoute(_parameter: string): string | string[] | undefined {
    throw new Error('Method not implemented.');
  }

  getQuery(parameter: string): string | string[] | undefined {
    if (this.req.url) {
      const url = new URL(this.req.url);
      return url.searchParams.get(parameter) ?? undefined;
    }
    return this.req.query?.[parameter];
  }

  getRawRequest(): Promise<{
    method: string;
    url: string;
    /* eslint-disable @typescript-eslint/no-non-null-assertion */
    /* eslint-disable @typescript-eslint/consistent-indexed-object-style */
    /* eslint-disable @typescript-eslint/no-unused-vars */
    // eslint-disable-next-line max-classes-per-file
    body: string | Record<string, string>;
  }> {
    return Promise.resolve({
      method: this.req.method!,
      body: this.req.body!,
      url: this.req.url!,
    });
  }

  getCookie(name: string): string | undefined {
    return this.cookies?.[name]?.value;
  }

  getAllCookies(): Map<string, string> {
    const map = new Map();
    Object.keys(this.cookies ?? {}).forEach(key =>
      map.set(key, this.cookies?.[key].value)
    );
    return map;
  }
}

export class TestStore implements MonoCloudSessionStore {
  private store = new Map<string, MonoCloudSession>();

  lifetimes = new Map<string, SessionLifetime>();

  get(key: string): Promise<MonoCloudSession | null | undefined> {
    return Promise.resolve(this.store.get(key));
  }

  set(
    key: string,
    data: MonoCloudSession,
    lifetime: SessionLifetime
  ): Promise<void> {
    this.store.set(key, JSON.parse(JSON.stringify(data)));
    this.lifetimes.set(key, JSON.parse(JSON.stringify(lifetime)));
    return Promise.resolve();
  }

  delete(key: string): Promise<void> {
    this.store.delete(key);
    this.lifetimes.delete(key);
    return Promise.resolve();
  }
}

export const defaultConfig = {
  cookieSecret: '__test_session_secret__',
  clientId: '__test_client_id__',
  clientSecret: '__test_client_secret__',
  issuer: 'https://op.example.com',
  appUrl: 'https://example.org',
  defaultAuthParams: {
    response_type: 'code',
    scope: 'openid profile read:customer',
    audience: 'https://api.acme.com',
  },
};

export const defaultStoreKeyForTest = 'key';

export const defaultSessionData = (): MonoCloudSession => ({
  user: {
    sub: 'randomid',
  },
  foo: 'bar',
  accessToken: 'at',
  accessTokenExpiration: 0,
  idToken: 'idt',
  refreshToken: 'rt',
  scopes: 'openid',
});

export const getSessionCookie = (params?: {
  session?: any;
  store?: MonoCloudSessionStore;
  key?: any;
  exp?: number;
}) => {
  const lifetime = { e: params?.exp ?? now() + 1, c: now(), u: now() };

  const cookieValue = {
    key: params?.key ?? defaultStoreKeyForTest,
    lifetime,
    session: !params?.store ? params?.session : undefined,
  };

  if (params?.store) {
    params.store.set(cookieValue.key, params?.session ?? {}, lifetime);
  }

  return encryptData(JSON.stringify(cookieValue), defaultConfig.cookieSecret!);
};

export const createTestIdToken = async (claims = {}) => {
  const kp = await jose.generateKeyPair('ES256', { extractable: true });
  const jwk = await jose.exportJWK(kp.publicKey);
  const sub = await jose.calculateJwkThumbprint(jwk);
  return {
    idToken: await new jose.SignJWT({
      sub_jwk: jwk,
      sub,
      ...claims,
    })
      .setIssuedAt()
      .setProtectedHeader({ alg: 'ES256' })
      .setIssuer('https://op.example.com')
      .setAudience('__test_client_id__')
      .setExpirationTime('1m')
      .sign(kp.privateKey),
    key: jwk,
    sub,
  };
};
