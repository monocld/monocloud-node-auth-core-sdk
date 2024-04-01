/* eslint-disable @typescript-eslint/no-non-null-assertion */
/* eslint-disable import/no-unresolved */
/* eslint-disable @typescript-eslint/no-explicit-any */

import nock from 'nock';
import * as jose from 'jose';
import { getOptions } from '../src/options/get-options';
import {
  MonoCloudOptions,
  MonoCloudSession,
  MonoCloudState,
  SessionLifetime,
} from '../src/types';
import { MonoCloudBaseInstance } from '../src/instance/monocloud-base-instance';
import {
  TestReq,
  TestRes,
  createTestIdToken,
  defaultConfig,
  defaultSessionData,
  defaultStoreKeyForTest,
  getSessionCookie,
} from './test-helpers';
import {
  AuthorizationServer,
  OperationProcessingError,
} from '../src/openid-client/oauth4webapi';
import { decryptData, encryptData, now } from '../src/utils';
import { MonoCloudValidationError } from '../src/errors/monocloud-validation-error';
import { JWK } from 'jose/dist/types/types';
import { freeze, reset, travel } from 'timekeeper';
import { MonoCloudOPError } from '../src/errors/monocloud-op-error';

const setupDiscovery = (discoveryDoc: Partial<AuthorizationServer> = {}) => {
  nock(defaultConfig.issuer)
    .get('/.well-known/openid-configuration')
    .reply(200, { issuer: defaultConfig.issuer, ...discoveryDoc });
};

const getConfiguredInstance = (
  options: Partial<MonoCloudOptions> = {}
): MonoCloudBaseInstance => {
  return new MonoCloudBaseInstance(
    getOptions({ ...defaultConfig, ...options })
  );
};

const setStateCookieValue = async (
  cookies: any,
  state?: Partial<MonoCloudState>,
  secret?: string,
  cookieName?: string
) => {
  state = {
    appState: '{}',
    nonce: '123',
    state: 'peace',
    verifier: 'a', // ypeBEsobvcr6wjGzmiPcTaeG7_gUfE5yuYB3ha_uSLs
    ...(state || {}),
  };
  cookies[cookieName ?? 'state'] = {
    value: await encryptData(
      JSON.stringify({ state }),
      secret ?? defaultConfig.cookieSecret
    ),
  };
};

const assertStateCookieValue = async (
  res: TestRes,
  valueCheck: Record<string, any> = {}
) => {
  const cookieValue = res.cookies.state.value;

  const cookie = JSON.parse(
    (await decryptData(cookieValue, defaultConfig.cookieSecret))!
  ).state;

  expect(cookie.verifier.length).toBeGreaterThan(0);

  for (const key of Object.keys(valueCheck)) {
    expect(cookie[key]).toEqual(valueCheck[key]);
  }
};

const setSessionCookieValue = async (
  cookies: any,
  value: {
    session?: Partial<MonoCloudSession>;
    lifetime?: Partial<SessionLifetime>;
  }
) => {
  cookies.session = {
    value: await encryptData(
      JSON.stringify({
        key: defaultStoreKeyForTest,
        session: value.session,
        lifetime: value.lifetime,
      }),
      defaultConfig.cookieSecret
    ),
  };
};

const assertSessionCookieValue = async (
  cookies: any,
  assert?: { session?: Record<string, any>; lifetime?: Record<string, any> },
  secret?: string
) => {
  let cookieValue;

  if (Object.keys(cookies).filter(x => x.startsWith('session')).length > 1) {
    cookieValue = Object.entries(cookies)
      .map(([key, value]) => ({
        key: parseInt(key.split('.').pop() || '0', 10),
        value,
      }))
      .sort((a, b) => a.key - b.key)
      .map(({ value }: any) => value.value)
      .join('');
  } else {
    cookieValue = cookies.session.value;
  }

  const cookie = JSON.parse(
    (await decryptData(cookieValue, secret ?? defaultConfig.cookieSecret))!
  );

  expect(cookie.key.length).toBeGreaterThan(0);

  if (assert?.lifetime) {
    expect(cookie.lifetime).toEqual(assert.lifetime);
  }

  if (assert?.session) {
    expect(cookie.session).toEqual(assert.session);
  }
};

describe('MonoCloud Base Instance', () => {
  afterEach(nock.cleanAll);

  describe('handlers', () => {
    describe('signin', () => {
      it('should redirect to authorize url', async () => {
        setupDiscovery({
          authorization_endpoint: 'https://op.example.com/authorize',
        });
        const instance = getConfiguredInstance();

        const cookies = {};
        const req = new TestReq({ cookies });
        const res = new TestRes(cookies);

        await instance.signIn(req, res);

        expect(res.res.statusCode).toBe(302);

        const url = new URL(res.res.redirectedUrl!);

        expect(`${url.protocol}//${url.host}${url.pathname}`).toBe(
          'https://op.example.com/authorize'
        );

        const search = Object.fromEntries(url.searchParams.entries());
        expect(Object.keys(search).length).toBe(9);
        expect(search.state.length).toBeGreaterThan(0);
        expect(search.code_challenge.length).toBeGreaterThan(0);
        expect(search.nonce.length).toBeGreaterThan(0);
        expect(search.code_challenge_method).toBe('S256');
        expect(search.client_id).toBe('__test_client_id__');
        expect(search.response_type).toBe('code');
        expect(search.scope).toBe('openid profile read:customer');
        expect(search.redirect_uri).toBe(
          'https://example.org/api/auth/callback'
        );
        expect(search.audience).toBe('https://api.acme.com');

        assertStateCookieValue(res, {
          nonce: search.nonce,
          state: search.state,
          returnUrl: encodeURIComponent(defaultConfig.appUrl),
          appState: '{}',
        });
      });

      it('should be able override auth params except nonce, state, code_challenge + method', async () => {
        setupDiscovery({
          authorization_endpoint: 'https://op.example.com/authorize',
        });
        const instance = getConfiguredInstance();

        const cookies = {};
        const req = new TestReq({ cookies });
        const res = new TestRes(cookies);

        await instance.signIn(req, res, {
          authParams: {
            state: 'cantchange',
            code_challenge: 'cannotchange',
            code_challenge_method: 'S384',
            nonce: 'changecant',
            client_id: 'testclient',
            scope: 'openid',
            redirect_uri: 'testredirect',
            audience: 'testaudience',
          },
        });

        expect(res.res.statusCode).toBe(302);

        const url = new URL(res.res.redirectedUrl!);

        expect(`${url.protocol}//${url.host}${url.pathname}`).toBe(
          'https://op.example.com/authorize'
        );

        const search = Object.fromEntries(url.searchParams.entries());
        expect(Object.keys(search).length).toBe(9);
        expect(search.state).not.toBe('cantchange');
        expect(search.code_challenge).not.toBe('cannotchange');
        expect(search.nonce).not.toBe('changecant');
        expect(search.code_challenge_method).toBe('S256');
        expect(search.client_id).toBe('testclient');
        expect(search.response_type).toBe('code');
        expect(search.scope).toBe('openid');
        expect(search.redirect_uri).toBe('testredirect');
        expect(search.audience).toBe('testaudience');

        assertStateCookieValue(res, {
          nonce: search.nonce,
          state: search.state,
          returnUrl: encodeURIComponent(defaultConfig.appUrl),
          appState: '{}',
        });
      });

      it('should be able to provide custom auth params', async () => {
        setupDiscovery({
          authorization_endpoint: 'https://op.example.com/authorize',
        });
        const instance = getConfiguredInstance();

        const cookies = {};
        const req = new TestReq({ cookies });
        const res = new TestRes(cookies);

        await instance.signIn(req, res, {
          authParams: {
            ui_locales: 'en',
            custom: 'param',
            max_age: 30,
          },
        });

        expect(res.res.statusCode).toBe(302);

        const url = new URL(res.res.redirectedUrl!);

        expect(`${url.protocol}//${url.host}${url.pathname}`).toBe(
          'https://op.example.com/authorize'
        );

        const search = Object.fromEntries(url.searchParams.entries());
        expect(Object.keys(search).length).toBe(12);
        expect(search.state.length).toBeGreaterThan(0);
        expect(search.code_challenge.length).toBeGreaterThan(0);
        expect(search.nonce.length).toBeGreaterThan(0);
        expect(search.code_challenge_method).toBe('S256');
        expect(search.ui_locales).toBe('en');
        expect(search.custom).toBe('param');
        expect(search.max_age).toBe('30');
        expect(search.client_id).toBe('__test_client_id__');
        expect(search.response_type).toBe('code');
        expect(search.scope).toBe('openid profile read:customer');
        expect(search.redirect_uri).toBe(
          'https://example.org/api/auth/callback'
        );
        expect(search.audience).toBe('https://api.acme.com');

        assertStateCookieValue(res, {
          nonce: search.nonce,
          state: search.state,
          returnUrl: encodeURIComponent(defaultConfig.appUrl),
          appState: '{}',
          maxAge: 30,
        });
      });

      it('should be able to set login_hint through options', async () => {
        setupDiscovery({
          authorization_endpoint: 'https://op.example.com/authorize',
        });
        const instance = getConfiguredInstance();

        const cookies = {};
        const req = new TestReq({ cookies });
        const res = new TestRes(cookies);

        await instance.signIn(req, res, {
          loginHint: 'usernaaaame',
        });

        expect(res.res.statusCode).toBe(302);

        const url = new URL(res.res.redirectedUrl!);

        expect(`${url.protocol}//${url.host}${url.pathname}`).toBe(
          'https://op.example.com/authorize'
        );

        const search = Object.fromEntries(url.searchParams.entries());
        expect(Object.keys(search).length).toBe(10);
        expect(search.state.length).toBeGreaterThan(0);
        expect(search.code_challenge.length).toBeGreaterThan(0);
        expect(search.nonce.length).toBeGreaterThan(0);
        expect(search.code_challenge_method).toBe('S256');
        expect(search.login_hint).toBe('usernaaaame');
        expect(search.client_id).toBe('__test_client_id__');
        expect(search.response_type).toBe('code');
        expect(search.scope).toBe('openid profile read:customer');
        expect(search.redirect_uri).toBe(
          'https://example.org/api/auth/callback'
        );
        expect(search.audience).toBe('https://api.acme.com');
      });

      it('should redirect with prompt=create when register is true', async () => {
        setupDiscovery({
          authorization_endpoint: 'https://op.example.com/authorize',
        });
        const instance = getConfiguredInstance();

        const cookies = {};
        const req = new TestReq({ cookies });
        const res = new TestRes(cookies);

        await instance.signIn(req, res, {
          register: true,
        });

        expect(res.res.statusCode).toBe(302);

        const url = new URL(res.res.redirectedUrl!);

        expect(`${url.protocol}//${url.host}${url.pathname}`).toBe(
          'https://op.example.com/authorize'
        );

        const search = Object.fromEntries(url.searchParams.entries());
        expect(Object.keys(search).length).toBe(10);
        expect(search.state.length).toBeGreaterThan(0);
        expect(search.code_challenge.length).toBeGreaterThan(0);
        expect(search.nonce.length).toBeGreaterThan(0);
        expect(search.code_challenge_method).toBe('S256');
        expect(search.prompt).toBe('create');
        expect(search.client_id).toBe('__test_client_id__');
        expect(search.response_type).toBe('code');
        expect(search.scope).toBe('openid profile read:customer');
        expect(search.redirect_uri).toBe(
          'https://example.org/api/auth/callback'
        );
        expect(search.audience).toBe('https://api.acme.com');
      });

      it('should redirect with acr_values when authenticator is set', async () => {
        setupDiscovery({
          authorization_endpoint: 'https://op.example.com/authorize',
        });
        const instance = getConfiguredInstance();

        const cookies = {};
        const req = new TestReq({ cookies });
        const res = new TestRes(cookies);

        await instance.signIn(req, res, {
          authenticator: 'apple',
        });

        expect(res.res.statusCode).toBe(302);

        const url = new URL(res.res.redirectedUrl!);

        expect(`${url.protocol}//${url.host}${url.pathname}`).toBe(
          'https://op.example.com/authorize'
        );

        const search = Object.fromEntries(url.searchParams.entries());
        expect(Object.keys(search).length).toBe(10);
        expect(search.state.length).toBeGreaterThan(0);
        expect(search.code_challenge.length).toBeGreaterThan(0);
        expect(search.nonce.length).toBeGreaterThan(0);
        expect(search.code_challenge_method).toBe('S256');
        expect(search.acr_values).toBe('authenticator:apple');
        expect(search.client_id).toBe('__test_client_id__');
        expect(search.response_type).toBe('code');
        expect(search.scope).toBe('openid profile read:customer');
        expect(search.redirect_uri).toBe(
          'https://example.org/api/auth/callback'
        );
        expect(search.audience).toBe('https://api.acme.com');
      });

      it('should pick up the authenticator from the request and auth params even if the authenticator is passed through options', async () => {
        setupDiscovery({
          authorization_endpoint: 'https://op.example.com/authorize',
        });
        const instance = getConfiguredInstance();

        const cookies = {};
        const req = new TestReq({
          cookies,
          query: { authenticator: 'gooooooogle' },
        });
        const res = new TestRes(cookies);

        await instance.signIn(req, res, {
          authenticator: 'apple',
          authParams: { acr_values: 'authenticator:test' },
        });

        expect(res.res.statusCode).toBe(302);

        const url = new URL(res.res.redirectedUrl!);

        expect(`${url.protocol}//${url.host}${url.pathname}`).toBe(
          'https://op.example.com/authorize'
        );

        const search = Object.fromEntries(url.searchParams.entries());
        expect(Object.keys(search).length).toBe(10);
        expect(search.state.length).toBeGreaterThan(0);
        expect(search.code_challenge.length).toBeGreaterThan(0);
        expect(search.nonce.length).toBeGreaterThan(0);
        expect(search.code_challenge_method).toBe('S256');
        expect(search.acr_values).toBe(
          'authenticator:test authenticator:gooooooogle'
        );
        expect(search.client_id).toBe('__test_client_id__');
        expect(search.response_type).toBe('code');
        expect(search.scope).toBe('openid profile read:customer');
        expect(search.redirect_uri).toBe(
          'https://example.org/api/auth/callback'
        );
        expect(search.audience).toBe('https://api.acme.com');
      });

      it('should pick up the login_hint from the request even if the loginHint is passed through options', async () => {
        setupDiscovery({
          authorization_endpoint: 'https://op.example.com/authorize',
        });
        const instance = getConfiguredInstance();

        const cookies = {};
        const req = new TestReq({
          cookies,
          query: { login_hint: 'oooosername' },
        });
        const res = new TestRes(cookies);

        await instance.signIn(req, res, {
          loginHint: 'username',
        });

        expect(res.res.statusCode).toBe(302);

        const url = new URL(res.res.redirectedUrl!);

        expect(`${url.protocol}//${url.host}${url.pathname}`).toBe(
          'https://op.example.com/authorize'
        );

        const search = Object.fromEntries(url.searchParams.entries());
        expect(Object.keys(search).length).toBe(10);
        expect(search.state.length).toBeGreaterThan(0);
        expect(search.code_challenge.length).toBeGreaterThan(0);
        expect(search.nonce.length).toBeGreaterThan(0);
        expect(search.code_challenge_method).toBe('S256');
        expect(search.login_hint).toBe('oooosername');
        expect(search.client_id).toBe('__test_client_id__');
        expect(search.response_type).toBe('code');
        expect(search.scope).toBe('openid profile read:customer');
        expect(search.redirect_uri).toBe(
          'https://example.org/api/auth/callback'
        );
        expect(search.audience).toBe('https://api.acme.com');
      });

      [
        [true, 'create', 10],
        [false, undefined, 9],
      ].forEach(([register, prompt, paramCount]) => {
        it(`should override register (${register}) with the value from the request`, async () => {
          setupDiscovery({
            authorization_endpoint: 'https://op.example.com/authorize',
          });
          const instance = getConfiguredInstance();

          const cookies = {};
          const req = new TestReq({
            cookies,
            query: { register: register?.toString() },
          });
          const res = new TestRes(cookies);
          await instance.signIn(req, res, {
            register: !register,
          });

          expect(res.res.statusCode).toBe(302);

          const url = new URL(res.res.redirectedUrl!);

          expect(`${url.protocol}//${url.host}${url.pathname}`).toBe(
            'https://op.example.com/authorize'
          );

          const search = Object.fromEntries(url.searchParams.entries());
          expect(Object.keys(search).length).toBe(paramCount);
          expect(search.state.length).toBeGreaterThan(0);
          expect(search.code_challenge.length).toBeGreaterThan(0);
          expect(search.nonce.length).toBeGreaterThan(0);
          expect(search.code_challenge_method).toBe('S256');
          expect(search.prompt).toBe(prompt);
          expect(search.client_id).toBe('__test_client_id__');
          expect(search.response_type).toBe('code');
          expect(search.scope).toBe('openid profile read:customer');
          expect(search.redirect_uri).toBe(
            'https://example.org/api/auth/callback'
          );
          expect(search.audience).toBe('https://api.acme.com');
        });
      });

      it(`should set custom app state in state cookie if onSetApplicationState callback is set to Object`, async () => {
        setupDiscovery({
          authorization_endpoint: 'https://op.example.com/authorize',
        });
        const instance = getConfiguredInstance({
          onSetApplicationState: () => ({
            customState: 'something',
          }),
        });

        const cookies = {};
        const req = new TestReq({ cookies });
        const res = new TestRes(cookies);

        await instance.signIn(req, res);

        assertStateCookieValue(res, {
          appState: '{"customState":"something"}',
        });
      });

      [1, null, undefined, Symbol('test'), true, []].forEach(x => {
        it(`should throw error if onSetApplicationState returns a non object (${Array.isArray(x) ? 'Array' : typeof x})`, async () => {
          setupDiscovery({
            authorization_endpoint: 'https://op.example.com/authorize',
          });
          const instance = getConfiguredInstance({
            onSetApplicationState: () => x as any,
          });

          const cookies = {};
          const req = new TestReq({ cookies });
          const res = new TestRes(cookies);

          try {
            await instance.signIn(req, res);
            throw new Error();
          } catch (error) {
            expect(error).toBeInstanceOf(MonoCloudValidationError);
            expect(error.message).toBe(
              'Invalid Application State. Expected state to be an object'
            );
          }
        });
      });

      ['code token', 'code id_token', 'code token id_token', 'token'].forEach(
        response_type => {
          it('should throw error if response type from options is unsupported', async () => {
            setupDiscovery({
              authorization_endpoint: 'https://op.example.com/authorize',
            });
            const instance = getConfiguredInstance();

            const cookies = {};
            const req = new TestReq({ cookies });
            const res = new TestRes(cookies);

            try {
              await instance.signIn(req, res, {
                authParams: { response_type },
              });
              throw new Error();
            } catch (error) {
              expect(error).toBeInstanceOf(MonoCloudValidationError);
              expect(error.message).toBe(
                '"authParams.response_type" must be [code]'
              );
            }
          });
        }
      );

      [true, false].forEach(usePar => {
        it('should use par endpoint if par is required', async () => {
          setupDiscovery({
            authorization_endpoint: 'https://op.example.com/authorize',
            pushed_authorization_request_endpoint: 'https://op.example.com/par',
            require_pushed_authorization_requests: true,
          });

          nock('https://op.example.com')
            .matchHeader(
              'authorization',
              'Basic X190ZXN0X2NsaWVudF9pZF9fOl9fdGVzdF9jbGllbnRfc2VjcmV0X18='
            )
            .post('/par', body => {
              expect(Object.keys(body).length).toBe(9);
              expect(body.state.length).toBeGreaterThan(0);
              expect(body.code_challenge.length).toBeGreaterThan(0);
              expect(body.nonce.length).toBeGreaterThan(0);
              expect(body.code_challenge_method).toBe('S256');
              expect(body.client_id).toBe('__test_client_id__');
              expect(body.response_type).toBe('code');
              expect(body.scope).toBe('openid profile read:customer');
              expect(body.redirect_uri).toBe(
                'https://example.org/api/auth/callback'
              );
              expect(body.audience).toBe('https://api.acme.com');
              return true;
            })
            .reply(201, {
              request_uri: 'urn:example:bwc4JK-ESC0w8acc191e-Y1LTC2',
              expires_in: 90,
            });

          const instance = getConfiguredInstance({ usePar });

          const cookies = {};
          const req = new TestReq({
            cookies,
          });
          const res = new TestRes(cookies);

          await instance.signIn(req, res);

          expect(res.res.statusCode).toBe(302);

          const url = new URL(res.res.redirectedUrl!);

          expect(`${url.protocol}//${url.host}${url.pathname}`).toBe(
            'https://op.example.com/authorize'
          );

          const search = Object.fromEntries(url.searchParams.entries());
          expect(Object.keys(search).length).toBe(2);
          expect(search.client_id).toBe('__test_client_id__');
          expect(search.request_uri).toBe(
            'urn:example:bwc4JK-ESC0w8acc191e-Y1LTC2'
          );
        });
      });

      it('can pass custom return_url for application redirects', async () => {
        setupDiscovery({
          authorization_endpoint: 'https://op.example.com/authorize',
        });
        const instance = getConfiguredInstance();

        const cookies = {};
        const req = new TestReq({
          cookies,
        });
        const res = new TestRes(cookies);

        await instance.signIn(req, res, {
          returnUrl: '/custom',
        });

        assertStateCookieValue(res, {
          returnUrl: encodeURIComponent('/custom'),
        });
      });

      it('can pass custom application return url through request query', async () => {
        setupDiscovery({
          authorization_endpoint: 'https://op.example.com/authorize',
        });
        const instance = getConfiguredInstance();

        const cookies = {};
        const req = new TestReq({
          cookies,
          query: { return_url: '/custom' },
        });
        const res = new TestRes(cookies);

        await instance.signIn(req, res);

        assertStateCookieValue(res, {
          returnUrl: encodeURIComponent('/custom'),
        });
      });

      it('should set same site to none if the response_mode is form_post', async () => {
        setupDiscovery({
          authorization_endpoint: 'https://op.example.com/authorize',
        });
        const instance = getConfiguredInstance({
          defaultAuthParams: { response_mode: 'form_post' },
        });

        const cookies = {} as any;
        const req = new TestReq({
          cookies,
        });
        const res = new TestRes(cookies);

        await instance.signIn(req, res);

        expect(cookies.state.options.sameSite).toBe('none');
      });
    });

    describe('callback', () => {
      let createdIdToken: {
        idToken: string;
        key: JWK;
        sub: string;
      };

      const frozenTimeMs = 1330688329321;

      beforeEach(async () => {
        freeze(frozenTimeMs);

        createdIdToken = await createTestIdToken({
          username: 'oooooooooosername',
          nonce: '123',
        });

        nock('https://op.example.com')
          .get('/jwks')
          .reply(200, { keys: [createdIdToken.key] });

        nock('https://op.example.com')
          .matchHeader('authorization', 'Bearer at')
          .get('/userinfo')
          .reply(200, {
            sub: createdIdToken.sub,
            username: 'oooooooooosername',
            test: '123',
          });
      });

      const setupTokenEndpoint = (
        requestBodyCheck: any = {
          code: 'code',
          code_verifier: 'a',
          grant_type: 'authorization_code',
          redirect_uri: 'https://example.org/api/auth/callback',
        },
        responseBody: any = {
          access_token: 'at',
          id_token: createdIdToken.idToken,
          refresh_token: 'rt',
          scope: 'something',
          token_type: 'Bearer',
          expires_in: 999,
        },
        discoveryDoc: any = {
          token_endpoint: 'https://op.example.com/token',
          jwks_uri: 'https://op.example.com/jwks',
          userinfo_endpoint: 'https://op.example.com/userinfo',
        }
      ) => {
        setupDiscovery(discoveryDoc);

        nock('https://op.example.com')
          .matchHeader(
            'authorization',
            'Basic X190ZXN0X2NsaWVudF9pZF9fOl9fdGVzdF9jbGllbnRfc2VjcmV0X18='
          )
          .post('/token', body => {
            expect(body).toEqual(requestBodyCheck);
            return true;
          })
          .reply(200, responseBody);
      };

      afterEach(() => {
        reset();
        createdIdToken = undefined as any;
      });

      [
        'https://op.example.com/auth/api/callback',
        '/auth/api/callback',
      ].forEach(url => {
        it('should perform a successful callback (Query)', async () => {
          setupTokenEndpoint();

          const cookies = {} as any;

          await setStateCookieValue(cookies);

          const instance = getConfiguredInstance({
            idTokenSigningAlg: 'ES256',
          });

          const req = new TestReq({
            cookies,
            url: `${url}?state=peace&code=code`,
            method: 'GET',
          });
          const res = new TestRes(cookies);

          await instance.callback(req, res);

          expect(res.res.redirectedUrl).toBe('https://example.org');
          expect(cookies.state).toEqual({
            value: '',
            options: {
              domain: undefined,
              expires: new Date(0),
              httpOnly: true,
              path: '/',
              sameSite: 'lax',
              secure: true,
            },
          });

          assertSessionCookieValue(cookies, {
            lifetime: { c: now(), u: now(), e: now() + 86400 },
            session: {
              accessToken: 'at',
              accessTokenExpiration: now() + 999,
              idToken: createdIdToken.idToken,
              refreshToken: 'rt',
              scopes: 'something',
              user: {
                sub_jwk: createdIdToken.key,
                sub: createdIdToken.sub,
                username: 'oooooooooosername',
                test: '123',
              },
            },
          });
        });

        it('should perform a successful callback (Body)', async () => {
          setupTokenEndpoint();

          const cookies = {} as any;

          await setStateCookieValue(cookies);

          const instance = getConfiguredInstance({
            idTokenSigningAlg: 'ES256',
          });

          const req = new TestReq({
            cookies,
            url,
            method: 'POST',
            body: { state: 'peace', code: 'code' },
          });
          const res = new TestRes(cookies);

          await instance.callback(req, res);

          expect(res.res.redirectedUrl).toBe('https://example.org');
          expect(cookies.state).toEqual({
            value: '',
            options: {
              domain: undefined,
              expires: new Date(0),
              httpOnly: true,
              path: '/',
              sameSite: 'lax',
              secure: true,
            },
          });

          assertSessionCookieValue(cookies, {
            lifetime: { c: now(), u: now(), e: now() + 86400 },
            session: {
              accessToken: 'at',
              accessTokenExpiration: now() + 999,
              idToken: createdIdToken.idToken,
              refreshToken: 'rt',
              scopes: 'something',
              user: {
                sub_jwk: createdIdToken.key,
                sub: createdIdToken.sub,
                username: 'oooooooooosername',
                test: '123',
              },
            },
          });
        });
      });

      it('should throw invalid state error if state is not found', async () => {
        const cookies = { state: { value: 'null' } } as any;

        const instance = getConfiguredInstance();

        const req = new TestReq({
          cookies,
        });
        const res = new TestRes(cookies);

        try {
          await instance.callback(req, res);
          throw new Error();
        } catch (error) {
          expect(error).toBeInstanceOf(MonoCloudValidationError);
          expect(error.message).toBe('Invalid State');
        }
      });

      [
        [
          {
            authParams: {
              scope: 'abc',
            },
          },
          'Scope must contain openid',
        ],
        [
          {
            authParams: {
              response_type: 'anything other than code',
            },
          },
          '"authParams.response_type" must be [code]',
        ],
        [
          {
            authParams: {
              response_mode: 'invalid',
            },
          },
          '"authParams.response_mode" must be one of [query, form_post]',
        ],
        [{ userinfo: null }, '"userinfo" is not allowed'],
      ].forEach(([opt, expectedMessage]) => {
        it('should throw validation error if wrong callback options are passed in', async () => {
          const instance = getConfiguredInstance();

          const req = new TestReq();
          const res = new TestRes();

          try {
            await instance.callback(req, res, opt as any);
            throw new Error();
          } catch (error) {
            expect(error).toBeInstanceOf(MonoCloudValidationError);
            expect(error.message).toBe(expectedMessage);
          }
        });
      });

      it('can pass in a custom redirect uri in options', async () => {
        setupTokenEndpoint({
          code: 'code',
          code_verifier: 'a',
          grant_type: 'authorization_code',
          redirect_uri: 'https://example.org/custom',
        });

        const cookies = {} as any;

        await setStateCookieValue(cookies);

        const instance = getConfiguredInstance({
          idTokenSigningAlg: 'ES256',
          routes: {
            callback: '/custom',
          },
        });

        const req = new TestReq({
          cookies,
          url: '/custom?state=peace&code=code',
          method: 'GET',
        });
        const res = new TestRes(cookies);

        await instance.callback(req, res);

        expect(res.res.redirectedUrl).toBe('https://example.org');
        expect(cookies.state).toEqual({
          value: '',
          options: {
            domain: undefined,
            expires: new Date(0),
            httpOnly: true,
            path: '/',
            sameSite: 'lax',
            secure: true,
          },
        });

        assertSessionCookieValue(cookies, {
          lifetime: { c: now(), u: now(), e: now() + 86400 },
          session: {
            accessToken: 'at',
            accessTokenExpiration: now() + 999,
            idToken: createdIdToken.idToken,
            refreshToken: 'rt',
            scopes: 'something',
            user: {
              sub_jwk: createdIdToken.key,
              sub: createdIdToken.sub,
              username: 'oooooooooosername',
              test: '123',
            },
          },
        });
      });

      it('can pass in a custom redirect uri in callback handler options, overriding the options', async () => {
        setupTokenEndpoint({
          code: 'code',
          code_verifier: 'a',
          grant_type: 'authorization_code',
          redirect_uri: 'https://example.org/custom/handler',
        });

        const cookies = {} as any;

        await setStateCookieValue(cookies);

        const instance = getConfiguredInstance({
          idTokenSigningAlg: 'ES256',
          routes: {
            callback: '/custom',
          },
        });

        const req = new TestReq({
          cookies,
          url: '/custom?state=peace&code=code',
          method: 'GET',
        });
        const res = new TestRes(cookies);

        await instance.callback(req, res, {
          authParams: { redirect_uri: 'https://example.org/custom/handler' },
        });

        expect(res.res.redirectedUrl).toBe('https://example.org');
        expect(cookies.state).toEqual({
          value: '',
          options: {
            domain: undefined,
            expires: new Date(0),
            httpOnly: true,
            path: '/',
            sameSite: 'lax',
            secure: true,
          },
        });

        assertSessionCookieValue(cookies, {
          lifetime: { c: now(), u: now(), e: now() + 86400 },
          session: {
            accessToken: 'at',
            accessTokenExpiration: now() + 999,
            idToken: createdIdToken.idToken,
            refreshToken: 'rt',
            scopes: 'something',
            user: {
              sub_jwk: createdIdToken.key,
              sub: createdIdToken.sub,
              username: 'oooooooooosername',
              test: '123',
            },
          },
        });
      });

      it('throws error if state parameter mismatches', async () => {
        setupDiscovery();

        const cookies = {} as any;

        await setStateCookieValue(cookies);

        const instance = getConfiguredInstance();

        const req = new TestReq({
          cookies,
          url: '/api/auth/callback?state=wrong&code=code',
          method: 'GET',
        });
        const res = new TestRes(cookies);

        try {
          await instance.callback(req, res);
          throw new Error();
        } catch (error) {
          expect(error).toBeInstanceOf(MonoCloudOPError);
          expect(error.message).toBe(
            'unexpected "state" response parameter value'
          );
        }
      });

      it('throws error if nonce parameter mismatches', async () => {
        setupTokenEndpoint();

        const cookies = {} as any;

        await setStateCookieValue(cookies, { nonce: 'wrong' });

        const instance = getConfiguredInstance({
          idTokenSigningAlg: 'ES256',
        });

        const req = new TestReq({
          cookies,
          url: '/custom?state=peace&code=code',
          method: 'GET',
        });
        const res = new TestRes(cookies);

        try {
          await instance.callback(req, res);
          throw new Error();
        } catch (error) {
          expect(error).toBeInstanceOf(OperationProcessingError);
          expect(error.message).toBe('unexpected ID Token "nonce" claim value');
        }
      });

      it('validates max age', async () => {
        createdIdToken = await createTestIdToken({
          username: 'oooooooooosername',
          nonce: '123',
          auth_time: now() - 10000,
        });

        setupTokenEndpoint(undefined, {
          access_token: 'at',
          id_token: createdIdToken.idToken,
          refresh_token: 'rt',
          scope: 'something',
          token_type: 'Bearer',
          expires_in: 999,
        });

        nock('https://op.example.com')
          .get('/jwks')
          .reply(200, { keys: [createdIdToken.key] });

        nock('https://op.example.com').get('/userinfo').reply(200, {
          sub: createdIdToken.sub,
          username: 'oooooooooosername',
        });

        const cookies = {} as any;

        await setStateCookieValue(cookies, { maxAge: 100 });

        const instance = getConfiguredInstance({
          idTokenSigningAlg: 'ES256',
        });

        const req = new TestReq({
          cookies,
          url: '/custom?state=peace&code=code',
          method: 'GET',
        });
        const res = new TestRes(cookies);

        try {
          await instance.callback(req, res);
          throw new Error();
        } catch (error) {
          expect(error).toBeInstanceOf(OperationProcessingError);
          expect(error.message).toBe(
            'too much time has elapsed since the last End-User authentication'
          );
        }
      });

      it('can add custom fields to session by passing in onSessionCreating', async () => {
        setupTokenEndpoint();

        const cookies = {} as any;

        await setStateCookieValue(cookies, { appState: '{"test":1}' });

        const instance = getConfiguredInstance({
          idTokenSigningAlg: 'ES256',
          // eslint-disable-next-line @typescript-eslint/no-unused-vars
          onSessionCreating: (session, idToken, userInfo, state) => {
            expect(state).toEqual({ test: 1 });
            expect(idToken).toBeDefined();
            expect(userInfo).toBeDefined();
            session.test = 1;
          },
        });

        const req = new TestReq({
          cookies,
          url: 'api/auth/callback?state=peace&code=code',
          method: 'GET',
        });
        const res = new TestRes(cookies);

        await instance.callback(req, res);

        expect(res.res.redirectedUrl).toBe('https://example.org');
        expect(cookies.state).toEqual({
          value: '',
          options: {
            domain: undefined,
            expires: new Date(0),
            httpOnly: true,
            path: '/',
            sameSite: 'lax',
            secure: true,
          },
        });

        assertSessionCookieValue(cookies, {
          lifetime: { c: now(), u: now(), e: now() + 86400 },
          session: {
            accessToken: 'at',
            accessTokenExpiration: now() + 999,
            idToken: createdIdToken.idToken,
            refreshToken: 'rt',
            scopes: 'something',
            user: {
              sub_jwk: createdIdToken.key,
              sub: createdIdToken.sub,
              username: 'oooooooooosername',
              test: '123',
            },
            test: 1,
          },
        });
      });

      it('should redirect to app url if state does not have a redirect url', async () => {
        setupTokenEndpoint();

        const cookies = {} as any;

        await setStateCookieValue(cookies, { returnUrl: undefined });

        const instance = getConfiguredInstance({
          idTokenSigningAlg: 'ES256',
        });

        const req = new TestReq({
          cookies,
          url: 'api/auth/callback?state=peace&code=code',
          method: 'GET',
        });
        const res = new TestRes(cookies);

        await instance.callback(req, res);

        expect(res.res.redirectedUrl).toBe('https://example.org');
      });

      ['/test', 'https://example.org/test'].forEach(url => {
        it(`should redirect to the return url from the state if the url is ${url.startsWith('/') ? 'Relative' : 'Absolute'}`, async () => {
          setupTokenEndpoint();

          const cookies = {} as any;

          await setStateCookieValue(cookies, { returnUrl: url });

          const instance = getConfiguredInstance({
            idTokenSigningAlg: 'ES256',
          });

          const req = new TestReq({
            cookies,
            url: 'api/auth/callback?state=peace&code=code',
            method: 'GET',
          });
          const res = new TestRes(cookies);

          await instance.callback(req, res);

          expect(res.res.redirectedUrl).toBe('https://example.org/test');
        });
      });

      it('should redirect to the app url if the returnUrl in the state is invalid', async () => {
        setupTokenEndpoint();

        const cookies = {} as any;

        await setStateCookieValue(cookies, {
          returnUrl: 'https://someoneelse.com/cb',
        });

        const instance = getConfiguredInstance({
          idTokenSigningAlg: 'ES256',
        });

        const req = new TestReq({
          cookies,
          url: 'api/auth/callback?state=peace&code=code',
          method: 'GET',
        });
        const res = new TestRes(cookies);

        await instance.callback(req, res);

        expect(res.res.redirectedUrl).toBe('https://example.org');
      });

      it('should not fetch from userinfo if options.userInfo explicitly to false', async () => {
        setupTokenEndpoint(undefined, undefined, {
          token_endpoint: 'https://op.example.com/token',
          jwks_uri: 'https://op.example.com/jwks',
        });

        const cookies = {} as any;

        await setStateCookieValue(cookies);

        const instance = getConfiguredInstance({
          idTokenSigningAlg: 'ES256',
        });

        const req = new TestReq({
          cookies,
          url: 'api/auth/callback?state=peace&code=code',
          method: 'GET',
        });
        const res = new TestRes(cookies);

        await instance.callback(req, res, { userInfo: false });

        expect(res.res.redirectedUrl).toBe('https://example.org');

        assertSessionCookieValue(cookies, {
          lifetime: { c: now(), u: now(), e: now() + 86400 },
          session: {
            accessToken: 'at',
            accessTokenExpiration: now() + 999,
            idToken: createdIdToken.idToken,
            refreshToken: 'rt',
            scopes: 'something',
            user: {
              sub_jwk: createdIdToken.key,
              sub: createdIdToken.sub,
              username: 'oooooooooosername',
            },
          },
        });
      });

      it('should filter out the configured claims', async () => {
        setupTokenEndpoint();

        const cookies = {} as any;

        await setStateCookieValue(cookies);

        const instance = getConfiguredInstance({
          idTokenSigningAlg: 'ES256',
          filteredIdTokenClaims: ['nonce', 'sub_jwk'],
        });

        const req = new TestReq({
          cookies,
          url: '/api/auth/callback?state=peace&code=code',
          method: 'GET',
        });
        const res = new TestRes(cookies);

        await instance.callback(req, res);

        assertSessionCookieValue(cookies, {
          lifetime: { c: now(), u: now(), e: now() + 86400 },
          session: {
            accessToken: 'at',
            accessTokenExpiration: now() + 999,
            idToken: createdIdToken.idToken,
            refreshToken: 'rt',
            scopes: 'something',
            user: {
              username: 'oooooooooosername',
              sub: createdIdToken.sub,
              iss: 'https://op.example.com',
              aud: '__test_client_id__',
              exp: 1330688389,
              iat: 1330688329,
              test: '123',
            },
          },
        });
      });
    });

    describe('userinfo', () => {
      const frozenTimeMs = 1330688329321;

      beforeEach(() => {
        freeze(frozenTimeMs);

        nock('https://op.example.com')
          .matchHeader('authorization', 'Bearer at')
          .get('/userinfo')
          .reply(200, {
            sub: 'id',
            username: 'username',
            test: 'updated',
            new: 'field',
          });
      });

      afterEach(reset);

      it('should perform a userinfo request when customized through options', async () => {
        setupDiscovery({
          userinfo_endpoint: 'https://op.example.com/userinfo',
        });

        const cookies = {} as any;

        const oldTime = now();

        await setSessionCookieValue(cookies, {
          session: {
            user: {
              sub: 'id',
              username: 'username',
              test: '123',
            },
            accessToken: 'at',
            idToken: 'a.b.c',
            refreshToken: 'rt',
            accessTokenExpiration: oldTime + 5,
            scopes: 'something',
          },
          lifetime: { c: oldTime, u: oldTime, e: oldTime + 86400 },
        });

        const newFrozenTime = frozenTimeMs + 2000;

        travel(newFrozenTime);

        const instance = getConfiguredInstance({ refreshUserInfo: true });

        const req = new TestReq({ cookies });
        const res = new TestRes(cookies);

        await instance.userInfo(req, res);

        await assertSessionCookieValue(cookies, {
          session: {
            user: {
              sub: 'id',
              username: 'username',
              test: 'updated',
              new: 'field',
            },
            accessToken: 'at',
            idToken: 'a.b.c',
            refreshToken: 'rt',
            accessTokenExpiration: oldTime + 5,
            scopes: 'something',
          },
          lifetime: { c: oldTime, u: now(), e: oldTime + 86400 },
        });
      });

      it('should perform a userinfo request when customized through handler options and will override options', async () => {
        setupDiscovery({
          userinfo_endpoint: 'https://op.example.com/userinfo',
        });

        const cookies = {} as any;

        const oldTime = now();

        await setSessionCookieValue(cookies, {
          session: {
            user: {
              sub: 'id',
              username: 'username',
              test: '123',
            },
            accessToken: 'at',
            idToken: 'a.b.c',
            refreshToken: 'rt',
            accessTokenExpiration: oldTime + 5,
            scopes: 'something',
          },
          lifetime: { c: oldTime, u: oldTime, e: oldTime + 86400 },
        });

        const newFrozenTime = frozenTimeMs + 2000;

        travel(newFrozenTime);

        const instance = getConfiguredInstance({ refreshUserInfo: false });

        const req = new TestReq({ cookies });
        const res = new TestRes(cookies);

        await instance.userInfo(req, res, { refresh: true });

        await assertSessionCookieValue(cookies, {
          session: {
            user: {
              sub: 'id',
              username: 'username',
              test: 'updated',
              new: 'field',
            },
            accessToken: 'at',
            idToken: 'a.b.c',
            refreshToken: 'rt',
            accessTokenExpiration: oldTime + 5,
            scopes: 'something',
          },
          lifetime: { c: oldTime, u: now(), e: oldTime + 86400 },
        });
      });

      it('should not perform a userinfo request when customized through handler options and will override options', async () => {
        setupDiscovery({
          userinfo_endpoint: 'https://op.example.com/userinfo',
        });

        const cookies = {} as any;

        const oldTime = now();

        await setSessionCookieValue(cookies, {
          session: {
            user: {
              sub: 'id',
              username: 'username',
              test: '123',
            },
            accessToken: 'at',
            idToken: 'a.b.c',
            refreshToken: 'rt',
            accessTokenExpiration: oldTime + 5,
            scopes: 'something',
          },
          lifetime: { c: oldTime, u: oldTime, e: oldTime + 86400 },
        });

        const newFrozenTime = frozenTimeMs + 2000;

        travel(newFrozenTime);

        const instance = getConfiguredInstance({ refreshUserInfo: true });

        const req = new TestReq({ cookies });
        const res = new TestRes(cookies);

        await instance.userInfo(req, res, { refresh: false });

        await assertSessionCookieValue(cookies, {
          session: {
            user: {
              sub: 'id',
              username: 'username',
              test: '123',
            },
            accessToken: 'at',
            idToken: 'a.b.c',
            refreshToken: 'rt',
            accessTokenExpiration: oldTime + 5,
            scopes: 'something',
          },
          lifetime: { c: oldTime, u: oldTime, e: oldTime + 86400 },
        });
      });

      it('should not perform a userinfo request when customized through options', async () => {
        setupDiscovery({
          userinfo_endpoint: 'https://op.example.com/userinfo',
        });

        const cookies = {} as any;

        const oldTime = now();

        await setSessionCookieValue(cookies, {
          session: {
            user: {
              sub: 'id',
              username: 'username',
              test: '123',
            },
            accessToken: 'at',
            idToken: 'a.b.c',
            refreshToken: 'rt',
            accessTokenExpiration: oldTime + 5,
            scopes: 'something',
          },
          lifetime: { c: oldTime, u: oldTime, e: oldTime + 86400 },
        });

        const newFrozenTime = frozenTimeMs + 2000;

        travel(newFrozenTime);

        const instance = getConfiguredInstance({ refreshUserInfo: false });

        const req = new TestReq({ cookies });
        const res = new TestRes(cookies);

        await instance.userInfo(req, res);

        await assertSessionCookieValue(cookies, {
          session: {
            user: {
              sub: 'id',
              username: 'username',
              test: '123',
            },
            accessToken: 'at',
            idToken: 'a.b.c',
            refreshToken: 'rt',
            accessTokenExpiration: oldTime + 5,
            scopes: 'something',
          },
          lifetime: { c: oldTime, u: oldTime, e: oldTime + 86400 },
        });
      });

      it('should return with no cache header and no content if session is not found', async () => {
        const cookies = {} as any;

        const instance = getConfiguredInstance();

        const req = new TestReq({ cookies });
        const res = new TestRes(cookies);

        await instance.userInfo(req, res);

        expect(res.res.noCacheSet).toBe(true);
        expect(res.res.statusCode).toBe(204);
      });

      [
        [{ refresh: 54 }, '"refresh" must be a boolean'],
        [[], '"value" must be of type object'],
      ].forEach(([opt, expectedMessage]) => {
        it('should throw a validation error if options is a wrong object', async () => {
          const cookies = {} as any;

          const instance = getConfiguredInstance();

          const req = new TestReq({ cookies });
          const res = new TestRes(cookies);

          try {
            await instance.userInfo(req, res, opt as any);
            throw new Error();
          } catch (error) {
            expect(error).toBeInstanceOf(MonoCloudValidationError);
            expect(error.message).toBe(expectedMessage);
          }
        });
      });

      it('can add custom fields to session by passing in onSessionCreating', async () => {
        setupDiscovery({
          userinfo_endpoint: 'https://op.example.com/userinfo',
        });

        const cookies = {} as any;

        const oldTime = now();

        await setSessionCookieValue(cookies, {
          session: {
            user: {
              sub: 'id',
              username: 'username',
              test: '123',
            },
            accessToken: 'at',
            idToken: 'a.b.c',
            refreshToken: 'rt',
            accessTokenExpiration: oldTime + 5,
            scopes: 'something',
          },
          lifetime: { c: oldTime, u: oldTime, e: oldTime + 86400 },
        });

        const newFrozenTime = frozenTimeMs + 2000;

        travel(newFrozenTime);

        const instance = getConfiguredInstance({
          refreshUserInfo: true,
          onSessionCreating: (session, idToken, userInfo, state) => {
            expect(state).toBeUndefined();
            expect(idToken).toBeUndefined();
            expect(userInfo).toBeDefined();
            session.test = 1;
          },
        });

        const req = new TestReq({ cookies });
        const res = new TestRes(cookies);

        await instance.userInfo(req, res);

        await assertSessionCookieValue(cookies, {
          session: {
            user: {
              sub: 'id',
              username: 'username',
              test: 'updated',
              new: 'field',
            },
            accessToken: 'at',
            idToken: 'a.b.c',
            refreshToken: 'rt',
            accessTokenExpiration: oldTime + 5,
            scopes: 'something',
            test: 1,
          },
          lifetime: { c: oldTime, u: now(), e: oldTime + 86400 },
        });
      });

      it('returns no cache and no content if the session was not updated', async () => {
        setupDiscovery({
          userinfo_endpoint: 'https://op.example.com/userinfo',
        });

        const cookies = {} as any;

        const oldTime = now();

        await setSessionCookieValue(cookies, {
          session: {
            user: {
              sub: 'id',
              username: 'username',
              test: '123',
            },
            accessToken: 'at',
            idToken: 'a.b.c',
            refreshToken: 'rt',
            accessTokenExpiration: oldTime + 5,
            scopes: 'something',
          },
          lifetime: { c: oldTime, u: oldTime, e: oldTime + 86400 },
        });

        const newFrozenTime = frozenTimeMs + 2000;

        travel(newFrozenTime);

        const instance = getConfiguredInstance({
          refreshUserInfo: true,
        });

        // Find a better way than this later.
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-expect-error
        instance.sessionService.updateSession = () => Promise.resolve(false);

        const req = new TestReq({ cookies });
        const res = new TestRes(cookies);

        await instance.userInfo(req, res);

        expect(res.res.noCacheSet).toBe(true);
        expect(res.res.statusCode).toBe(204);

        await assertSessionCookieValue(cookies, {
          session: {
            user: {
              sub: 'id',
              username: 'username',
              test: '123',
            },
            accessToken: 'at',
            idToken: 'a.b.c',
            refreshToken: 'rt',
            accessTokenExpiration: oldTime + 5,
            scopes: 'something',
          },
          lifetime: { c: oldTime, u: oldTime, e: oldTime + 86400 },
        });
      });
    });

    describe('signout', () => {
      it('should redirect to endSessionUrl', async () => {
        setupDiscovery({
          end_session_endpoint: 'https://op.example.com/endsession',
        });

        const cookies = {} as any;

        await setSessionCookieValue(cookies, {
          session: {},
          lifetime: { c: now(), e: now() + 86400, u: now() },
        });

        const instance = getConfiguredInstance();

        const req = new TestReq({
          cookies,
        });
        const res = new TestRes(cookies);

        await instance.signOut(req, res);

        expect(res.res.redirectedUrl).toBe(
          `https://op.example.com/endsession?client_id=__test_client_id__&post_logout_redirect_uri=${encodeURIComponent('https://example.org')}`
        );
        expect(cookies.session).toEqual({
          value: '',
          options: {
            domain: undefined,
            expires: new Date(0),
            httpOnly: true,
            path: '/',
            sameSite: 'lax',
            secure: true,
          },
        });
      });

      it('should redirect to endSessionUrl with post logout redirect uri and id token hint', async () => {
        setupDiscovery({
          end_session_endpoint: 'https://op.example.com/endsession',
        });

        const cookies = {} as any;

        await setSessionCookieValue(cookies, {
          session: {
            idToken: 'a.b.c',
          },
          lifetime: { c: now(), e: now() + 86400, u: now() },
        });

        const instance = getConfiguredInstance({
          postLogoutRedirectUri: '/test',
        });

        const req = new TestReq({
          cookies,
        });
        const res = new TestRes(cookies);

        await instance.signOut(req, res);

        expect(res.res.redirectedUrl).toBe(
          `https://op.example.com/endsession?client_id=__test_client_id__&id_token_hint=${encodeURIComponent('a.b.c')}&post_logout_redirect_uri=${encodeURIComponent('https://example.org/test')}`
        );

        expect(cookies.session).toEqual({
          value: '',
          options: {
            domain: undefined,
            expires: new Date(0),
            httpOnly: true,
            path: '/',
            sameSite: 'lax',
            secure: true,
          },
        });
      });

      it('should redirect to endSessionUrl with post logout configured through handler options', async () => {
        setupDiscovery({
          end_session_endpoint: 'https://op.example.com/endsession',
        });

        const cookies = {} as any;

        await setSessionCookieValue(cookies, {
          session: {},
          lifetime: { c: now(), e: now() + 86400, u: now() },
        });

        const instance = getConfiguredInstance();

        const req = new TestReq({
          cookies,
        });
        const res = new TestRes(cookies);

        await instance.signOut(req, res, { post_logout_url: '/test' });

        expect(res.res.redirectedUrl).toBe(
          `https://op.example.com/endsession?client_id=__test_client_id__&post_logout_redirect_uri=${encodeURIComponent('https://example.org/test')}`
        );

        expect(cookies.session).toEqual({
          value: '',
          options: {
            domain: undefined,
            expires: new Date(0),
            httpOnly: true,
            path: '/',
            sameSite: 'lax',
            secure: true,
          },
        });
      });

      it('can customize endsession url using sign out handler options', async () => {
        setupDiscovery({
          end_session_endpoint: 'https://op.example.com/endsession',
        });

        const cookies = {} as any;

        await setSessionCookieValue(cookies, {
          session: {},
          lifetime: { c: now(), e: now() + 86400, u: now() },
        });

        const instance = getConfiguredInstance();

        const req = new TestReq({
          cookies,
        });
        const res = new TestRes(cookies);

        await instance.signOut(req, res, {
          signOutParams: {
            client_id: 'clientid',
            logout_hint: 'logouthint',
            state: 'test',
            custom: 'param',
          },
        });

        expect(res.res.redirectedUrl).toBe(
          `https://op.example.com/endsession?client_id=clientid&logout_hint=logouthint&state=test&custom=param&post_logout_redirect_uri=${encodeURIComponent('https://example.org')}`
        );

        expect(cookies.session).toEqual({
          value: '',
          options: {
            domain: undefined,
            expires: new Date(0),
            httpOnly: true,
            path: '/',
            sameSite: 'lax',
            secure: true,
          },
        });
      });

      ['/from/query', 'https://example.org/from/query'].forEach(
        post_logout_url => {
          it('can pickup post_logout_url from query param', async () => {
            setupDiscovery({
              end_session_endpoint: 'https://op.example.com/endsession',
            });

            const cookies = {} as any;

            await setSessionCookieValue(cookies, {
              session: {},
              lifetime: { c: now(), e: now() + 86400, u: now() },
            });

            const instance = getConfiguredInstance();

            const req = new TestReq({
              cookies,
              query: { post_logout_url },
            });
            const res = new TestRes(cookies);

            await instance.signOut(req, res);

            expect(res.res.redirectedUrl).toBe(
              `https://op.example.com/endsession?client_id=__test_client_id__&post_logout_redirect_uri=${encodeURIComponent('https://example.org/from/query')}`
            );

            expect(cookies.session).toEqual({
              value: '',
              options: {
                domain: undefined,
                expires: new Date(0),
                httpOnly: true,
                path: '/',
                sameSite: 'lax',
                secure: true,
              },
            });
          });
        }
      );

      [
        [{ federatedLogout: 23 }, '"federatedLogout" must be a boolean'],
        [
          { post_logout_url: Symbol('test') },
          '"post_logout_url" must be a string',
        ],
        [{ signOutParams: [] }, '"signOutParams" must be of type object'],
      ].forEach(([opt, expectedMessage], i) => {
        it(`should throw validation error for invalid configuration options. ${i + 1} of 3`, async () => {
          setupDiscovery({
            end_session_endpoint: 'https://op.example.com/endsession',
          });

          const cookies = {} as any;

          await setSessionCookieValue(cookies, {
            session: {},
            lifetime: { c: now(), e: now() + 86400, u: now() },
          });

          const instance = getConfiguredInstance();

          const req = new TestReq({
            cookies,
          });
          const res = new TestRes(cookies);

          try {
            await instance.signOut(req, res, opt as any);
            throw new Error();
          } catch (error) {
            expect(error).toBeInstanceOf(MonoCloudValidationError);
            expect(error.message).toBe(expectedMessage);
          }
        });
      });

      it('should redirect to app url if there is no session', async () => {
        setupDiscovery({
          end_session_endpoint: 'https://op.example.com/endsession',
        });

        const cookies = {} as any;

        await setSessionCookieValue(cookies, {
          lifetime: { c: now(), e: now() + 86400, u: now() },
        });

        const instance = getConfiguredInstance();

        const req = new TestReq({
          cookies,
        });
        const res = new TestRes(cookies);

        await instance.signOut(req, res);

        expect(res.res.redirectedUrl).toBe('https://example.org');
      });

      [
        [{ federatedLogout: false }, {}],
        [{}, { federatedLogout: false }],
      ].forEach(([opt, handlerOpt], i) => {
        it(`should redirect to app url if federatedLogout is false ${i + 1} of 2`, async () => {
          setupDiscovery({
            end_session_endpoint: 'https://op.example.com/endsession',
          });

          const cookies = {} as any;

          await setSessionCookieValue(cookies, {
            session: {},
            lifetime: { c: now(), e: now() + 86400, u: now() },
          });

          const instance = getConfiguredInstance(opt as any);

          const req = new TestReq({
            cookies,
          });
          const res = new TestRes(cookies);

          await instance.signOut(req, res, handlerOpt);

          expect(res.res.redirectedUrl).toBe(`https://example.org`);

          expect(cookies.session).toEqual({
            value: '',
            options: {
              domain: undefined,
              expires: new Date(0),
              httpOnly: true,
              path: '/',
              sameSite: 'lax',
              secure: true,
            },
          });
        });
      });
    });

    describe('backchannelLogout', () => {
      const createBackchannelLogout = async (claims = {}) => {
        const kp = await jose.generateKeyPair('ES256', { extractable: true });
        const jwk = await jose.exportJWK(kp.publicKey);
        const sub = await jose.calculateJwkThumbprint(jwk);
        return {
          token: await new jose.SignJWT({
            sub_jwk: jwk,
            sub: sub,
            sid: 'sid',
            events: {
              'http://schemas.openid.net/event/backchannel-logout': {},
            },
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

      it('should return no cache and not found if no back channel handler is found', () => {
        const instance = getConfiguredInstance();
        const res = new TestRes();

        instance.backChannelLogout(new TestReq(), res);

        expect(res.res.noCacheSet).toBe(true);
        expect(res.res.statusCode).toBe(404);
      });

      it('should perform a backchannel logout', async () => {
        const backchannelLogoutToken = await createBackchannelLogout();
        nock('https://op.example.com')
          .get('/jwks')
          .reply(200, { keys: [backchannelLogoutToken.key] });

        setupDiscovery({ jwks_uri: 'https://op.example.com/jwks' });

        const instance = getConfiguredInstance({
          idTokenSigningAlg: 'ES256',
          onBackChannelLogout: (sub, sid) => {
            expect(sub).toBe(backchannelLogoutToken.sub);
            expect(sid).toBe('sid');
          },
        });

        const req = new TestReq({
          method: 'POST',
          body: { logout_token: backchannelLogoutToken.token },
        });
        const res = new TestRes();

        await instance.backChannelLogout(req, res);

        expect(res.res.statusCode).toBe(204);
      });

      it('should return a method not allowed if the request was not a post', async () => {
        const instance = getConfiguredInstance({
          onBackChannelLogout: () => {},
        });

        const req = new TestReq({
          method: 'GET',
          body: { logout_token: 'token' },
        });
        const res = new TestRes();

        await instance.backChannelLogout(req, res);

        expect(res.res.statusCode).toBe(405);
      });

      it('should throw an error if the logout token was not found in the body', async () => {
        const instance = getConfiguredInstance({
          onBackChannelLogout: () => {},
        });

        const req = new TestReq({
          method: 'POST',
          body: {},
        });
        const res = new TestRes();

        try {
          await instance.backChannelLogout(req, res);
        } catch (error) {
          expect(error).toBeInstanceOf(MonoCloudValidationError);
          expect(error.message).toBe('Missing Logout Token');
        }
      });

      it('should throw validation error if the event is not an object', async () => {
        const backchannelLogoutToken = await createBackchannelLogout({
          events: {
            'http://schemas.openid.net/event/backchannel-logout': null,
          },
        });
        nock('https://op.example.com')
          .get('/jwks')
          .reply(200, { keys: [backchannelLogoutToken.key] });

        setupDiscovery({ jwks_uri: 'https://op.example.com/jwks' });

        const instance = getConfiguredInstance({
          idTokenSigningAlg: 'ES256',
          onBackChannelLogout: (sub, sid) => {
            expect(sub).toBe(backchannelLogoutToken.sub);
            expect(sid).toBe('sid');
          },
        });

        const req = new TestReq({
          method: 'POST',
          body: { logout_token: backchannelLogoutToken.token },
        });
        const res = new TestRes();

        try {
          await instance.backChannelLogout(req, res);
          throw new Error();
        } catch (error) {
          expect(error).toBeInstanceOf(MonoCloudValidationError);
          expect(error.message).toBe('Invalid logout token');
        }
      });

      [
        { sid: undefined, sub: undefined },
        { nonce: 'test' },
        { events: undefined },
        { events: 1 },
      ].forEach((x, i) => {
        it(`should throw validation error if the logout token is invalid ${i + 1} of 4`, async () => {
          const backchannelLogoutToken = await createBackchannelLogout(x);
          nock('https://op.example.com')
            .get('/jwks')
            .reply(200, { keys: [backchannelLogoutToken.key] });

          setupDiscovery({ jwks_uri: 'https://op.example.com/jwks' });

          const instance = getConfiguredInstance({
            idTokenSigningAlg: 'ES256',
            onBackChannelLogout: (sub, sid) => {
              expect(sub).toBe(backchannelLogoutToken.sub);
              expect(sid).toBe('sid');
            },
          });

          const req = new TestReq({
            method: 'POST',
            body: { logout_token: backchannelLogoutToken.token },
          });
          const res = new TestRes();

          try {
            await instance.backChannelLogout(req, res);
            throw new Error();
          } catch (error) {
            expect(error).toBeInstanceOf(MonoCloudValidationError);
            expect(error.message).toBe('Invalid logout token');
          }
        });
      });
    });
  });

  describe('instance helpers', () => {
    it('should return options configured by the client when instance.getOptions() is called', () => {
      const instance = new MonoCloudBaseInstance(defaultConfig);

      expect(instance.getOptions()).toEqual(getOptions(defaultConfig));
    });

    it('should destroy session', async () => {
      const instance = getConfiguredInstance({
        session: { cookie: { name: 'destroysessioncookie' } },
      });

      const cookies: any = {
        destroysessioncookie: {
          value: await getSessionCookie({ session: defaultSessionData() }),
        },
      };

      await instance.destroySession(
        new TestReq({ cookies }),
        new TestRes(cookies)
      );

      expect(cookies.destroysessioncookie).toEqual({
        value: '',
        options: {
          domain: undefined,
          expires: new Date(0),
          httpOnly: true,
          path: '/',
          sameSite: 'lax',
          secure: true,
        },
      });
    });

    it('isAuthenticated should return true if the request is authenticated and has a session', async () => {
      const cookies = {};

      await setSessionCookieValue(cookies, {
        session: { user: { sub: 'id' } },
        lifetime: { u: now(), e: now() + 4, c: now() },
      });

      const req = new TestReq({ cookies });
      const res = new TestRes();

      const instance = getConfiguredInstance();

      expect(await instance.isAuthenticated(req, res)).toBe(true);
    });

    it('isAuthenticated should return false if the request is not authenticated', async () => {
      const cookies = {};

      const req = new TestReq({ cookies });
      const res = new TestRes();

      const instance = getConfiguredInstance();
      expect(await instance.isAuthenticated(req, res)).toBe(false);
    });

    it('getSession should return the session', async () => {
      const cookies = {};

      await setSessionCookieValue(cookies, {
        session: {
          user: { sub: 'id' },
          scopes: 'abc',
          accessToken: 'at',
          accessTokenExpiration: 8,
          idToken: 'idtoken',
          refreshToken: 'rt',
        },
        lifetime: { u: now(), e: now() + 4, c: now() },
      });

      const req = new TestReq({ cookies });
      const res = new TestRes();

      const instance = getConfiguredInstance();

      const session = await instance.getSession(req, res);

      expect(session).toEqual({
        user: { sub: 'id' },
        scopes: 'abc',
        accessToken: 'at',
        accessTokenExpiration: 8,
        idToken: 'idtoken',
        refreshToken: 'rt',
      });
    });

    it('updateSession should update the session', async () => {
      const frozenTimeMs = 1330688329321;

      freeze(frozenTimeMs);

      const cookies = {};

      const timeOld = now();
      await setSessionCookieValue(cookies, {
        session: {
          user: { sub: 'id' },
          scopes: 'abc',
          accessToken: 'at',
          accessTokenExpiration: 8,
          idToken: 'idtoken',
          refreshToken: 'rt',
        },
        lifetime: { u: timeOld, e: timeOld + 86400, c: timeOld },
      });

      const req = new TestReq({ cookies });
      const res = new TestRes(cookies);

      const instance = getConfiguredInstance();

      travel(frozenTimeMs + 2000);

      await instance.updateSession(req, res, {
        test: 1,
        user: {},
      });

      assertSessionCookieValue(cookies, {
        session: {
          user: {},
          test: 1,
        },
        lifetime: { u: now(), e: timeOld + 86400, c: timeOld },
      });

      reset();
    });

    describe('getTokens()', () => {
      it('should return the tokens', async () => {
        const cookies = {};

        await setSessionCookieValue(cookies, {
          session: {
            user: {},
            scopes: 'abc',
            accessToken: 'at',
            accessTokenExpiration: now() + 100,
            idToken: 'idtoken',
            refreshToken: 'rt',
          },
          lifetime: { u: now(), e: now() + 86400, c: now() },
        });

        const req = new TestReq({ cookies });
        const res = new TestRes(cookies);

        const instance = getConfiguredInstance();

        const tokens = await instance.getTokens(req, res);

        expect(tokens).toEqual({
          accessToken: 'at',
          idToken: 'idtoken',
          refreshToken: 'rt',
          isExpired: false,
        });
      });

      [
        [{ forceRefresh: Symbol() }, '"forceRefresh" must be a boolean'],
        [{ refreshParams: { scope: 'abc' } }, 'Scope must contain openid'],
        [
          { refreshParams: { response_type: 'abc' } },
          '"refreshParams.response_type" must be [code]',
        ],
        [
          { refreshParams: { response_mode: 'abc' } },
          '"refreshParams.response_mode" must be one of [query, form_post]',
        ],
      ].forEach(([opt, expectedMessage], i) => {
        it(`getTokens should throw an error if options are invalid ${i + 1} of 4`, async () => {
          const cookies = {};

          const req = new TestReq({ cookies });
          const res = new TestRes(cookies);

          const instance = getConfiguredInstance();

          try {
            await instance.getTokens(req, res, opt as any);
          } catch (error) {
            expect(error).toBeInstanceOf(MonoCloudValidationError);
            expect(error.message).toBe(expectedMessage);
          }
        });
      });

      it('should refresh the tokens if specified', async () => {
        const frozenTimeMs = 1330688329321;
        freeze(frozenTimeMs);

        setupDiscovery({
          token_endpoint: 'https://op.example.com/token',
          jwks_uri: 'https://op.example.com/token',
        });

        const createdIdToken = await createTestIdToken({
          username: 'oooooooooosername',
        });

        nock('https://op.example.com')
          .matchHeader(
            'authorization',
            'Basic X190ZXN0X2NsaWVudF9pZF9fOl9fdGVzdF9jbGllbnRfc2VjcmV0X18='
          )
          .post('/token', body => {
            expect(body).toEqual({
              grant_type: 'refresh_token',
              refresh_token: 'rt',
            });
            return true;
          })
          .reply(200, {
            access_token: 'at1',
            id_token: createdIdToken.idToken,
            refresh_token: 'rt1',
            scope: 'something',
            token_type: 'Bearer',
            expires_in: 999,
          });

        nock('https://op.example.com')
          .get('/jwks')
          .reply(200, { keys: [createdIdToken.key] });

        const cookies = {};

        const oldTime = now();

        await setSessionCookieValue(cookies, {
          session: {
            user: { sub: createdIdToken.sub },
            scopes: 'abc',
            accessToken: 'at',
            accessTokenExpiration: oldTime + 100,
            idToken: 'idtoken',
            refreshToken: 'rt',
          },
          lifetime: { u: oldTime, e: oldTime + 86400, c: oldTime },
        });

        const req = new TestReq({ cookies });
        const res = new TestRes(cookies);

        const instance = getConfiguredInstance({ idTokenSigningAlg: 'ES256' });

        const newFrozenTime = frozenTimeMs + 2000;
        travel(newFrozenTime);

        const tokens = await instance.getTokens(req, res, {
          forceRefresh: true,
        });

        expect(tokens).toEqual({
          accessToken: 'at1',
          idToken: createdIdToken.idToken,
          refreshToken: 'rt1',
          isExpired: false,
        });

        await assertSessionCookieValue(cookies, {
          session: {
            user: {
              sub_jwk: createdIdToken.key,
              sub: createdIdToken.sub,
              username: 'oooooooooosername',
            },
            scopes: 'something',
            accessToken: 'at1',
            accessTokenExpiration: now() + 999,
            idToken: createdIdToken.idToken,
            refreshToken: 'rt1',
          },
          lifetime: { c: oldTime, e: oldTime + 86400, u: now() },
        });
      });

      it('should return only identity token if the access token is not found', async () => {
        const cookies = {};

        await setSessionCookieValue(cookies, {
          session: {
            user: {},
            scopes: 'abc',
            idToken: 'idtoken',
            refreshToken: 'rt',
          },
          lifetime: { u: now(), e: now() + 86400, c: now() },
        });

        const req = new TestReq({ cookies });
        const res = new TestRes(cookies);

        const instance = getConfiguredInstance();

        const tokens = await instance.getTokens(req, res);

        expect(tokens).toEqual({
          idToken: 'idtoken',
          isExpired: false,
        });
      });

      it('should return isExpired true if the access token expiration is not found', async () => {
        const cookies = {};

        await setSessionCookieValue(cookies, {
          session: {
            user: {},
            scopes: 'abc',
            accessToken: 'at',
            idToken: 'idtoken',
            refreshToken: 'rt',
          },
          lifetime: { u: now(), e: now() + 86400, c: now() },
        });

        const req = new TestReq({ cookies });
        const res = new TestRes(cookies);

        const instance = getConfiguredInstance();

        const tokens = await instance.getTokens(req, res);

        expect(tokens).toEqual({
          idToken: 'idtoken',
          accessToken: 'at',
          refreshToken: 'rt',
          isExpired: true,
        });
      });

      it('should return isExpired true if the access token is expired and no refresh token is found', async () => {
        const cookies = {};

        await setSessionCookieValue(cookies, {
          session: {
            user: {},
            scopes: 'abc',
            accessToken: 'at',
            accessTokenExpiration: now() - 10000,
            idToken: 'idtoken',
          },
          lifetime: { u: now(), e: now() + 86400, c: now() },
        });

        const req = new TestReq({ cookies });
        const res = new TestRes(cookies);

        const instance = getConfiguredInstance();

        const tokens = await instance.getTokens(req, res);

        expect(tokens).toEqual({
          idToken: 'idtoken',
          accessToken: 'at',
          isExpired: true,
          refreshToken: undefined,
        });
      });

      it('should not refresh tokens if force refresh is true and no refresh token is found', async () => {
        const cookies = {};

        await setSessionCookieValue(cookies, {
          session: {
            user: {},
            scopes: 'abc',
            accessToken: 'at',
            accessTokenExpiration: now() + 100,
            idToken: 'idtoken',
          },
          lifetime: { u: now(), e: now() + 86400, c: now() },
        });

        const req = new TestReq({ cookies });
        const res = new TestRes(cookies);

        const instance = getConfiguredInstance();

        const tokens = await instance.getTokens(req, res, {
          forceRefresh: true,
        });

        expect(tokens).toEqual({
          idToken: 'idtoken',
          accessToken: 'at',
          isExpired: false,
          refreshToken: undefined,
        });

        await assertSessionCookieValue(cookies, {
          session: {
            user: {},
            scopes: 'abc',
            accessToken: 'at',
            accessTokenExpiration: now() + 100,
            idToken: 'idtoken',
          },
        });
      });

      it('should refresh the tokens and fetch from userinfo using the new access token if specified', async () => {
        const frozenTimeMs = 1330688329321;
        freeze(frozenTimeMs);

        setupDiscovery({
          token_endpoint: 'https://op.example.com/token',
          jwks_uri: 'https://op.example.com/token',
          userinfo_endpoint: 'https://op.example.com/userinfo',
        });

        const createdIdToken = await createTestIdToken({
          username: 'oooooooooosername',
        });

        nock('https://op.example.com')
          .matchHeader(
            'authorization',
            'Basic X190ZXN0X2NsaWVudF9pZF9fOl9fdGVzdF9jbGllbnRfc2VjcmV0X18='
          )
          .post('/token', body => {
            expect(body).toEqual({
              grant_type: 'refresh_token',
              refresh_token: 'rt',
            });
            return true;
          })
          .reply(200, {
            access_token: 'at1',
            id_token: createdIdToken.idToken,
            refresh_token: 'rt1',
            scope: 'something',
            token_type: 'Bearer',
            expires_in: 999,
          });

        nock('https://op.example.com')
          .matchHeader('authorization', 'Bearer at1')
          .get('/userinfo')
          .reply(200, {
            sub: createdIdToken.sub,
            username: 'oooooooooosername',
            test: '123',
            test2: '1234',
          });

        nock('https://op.example.com')
          .get('/jwks')
          .reply(200, { keys: [createdIdToken.key] });

        const cookies = {};

        const oldTime = now();
        await setSessionCookieValue(cookies, {
          session: {
            user: { sub: createdIdToken.sub },
            scopes: 'abc',
            accessToken: 'at',
            accessTokenExpiration: oldTime + 100,
            idToken: 'idtoken',
            refreshToken: 'rt',
          },
          lifetime: { u: oldTime, e: oldTime + 86400, c: oldTime },
        });

        const req = new TestReq({ cookies });
        const res = new TestRes(cookies);

        const instance = getConfiguredInstance({
          idTokenSigningAlg: 'ES256',
          refreshUserInfo: true,
        });

        const newFrozenTime = frozenTimeMs + 2000;
        travel(newFrozenTime);

        const tokens = await instance.getTokens(req, res, {
          forceRefresh: true,
        });

        expect(tokens).toEqual({
          accessToken: 'at1',
          idToken: createdIdToken.idToken,
          refreshToken: 'rt1',
          isExpired: false,
        });

        await assertSessionCookieValue(cookies, {
          session: {
            user: {
              sub_jwk: createdIdToken.key,
              sub: createdIdToken.sub,
              username: 'oooooooooosername',
              test: '123',
              test2: '1234',
            },
            scopes: 'something',
            accessToken: 'at1',
            accessTokenExpiration: now() + 999,
            idToken: createdIdToken.idToken,
            refreshToken: 'rt1',
          },
          lifetime: { c: oldTime, e: oldTime + 86400, u: now() },
        });
      });

      it('should save with the old refresh token if the updated token response does not have one', async () => {
        const frozenTimeMs = 1330688329321;
        freeze(frozenTimeMs);

        setupDiscovery({
          token_endpoint: 'https://op.example.com/token',
          jwks_uri: 'https://op.example.com/token',
        });

        const createdIdToken = await createTestIdToken({
          username: 'oooooooooosername',
        });

        nock('https://op.example.com')
          .matchHeader(
            'authorization',
            'Basic X190ZXN0X2NsaWVudF9pZF9fOl9fdGVzdF9jbGllbnRfc2VjcmV0X18='
          )
          .post('/token', body => {
            expect(body).toEqual({
              grant_type: 'refresh_token',
              refresh_token: 'rt',
            });
            return true;
          })
          .reply(200, {
            access_token: 'at1',
            id_token: createdIdToken.idToken,
            scope: 'something',
            token_type: 'Bearer',
            expires_in: 999,
          });

        nock('https://op.example.com')
          .get('/jwks')
          .reply(200, { keys: [createdIdToken.key] });

        const cookies = {};

        const oldTime = now();
        await setSessionCookieValue(cookies, {
          session: {
            user: { sub: createdIdToken.sub },
            scopes: 'abc',
            accessToken: 'at',
            accessTokenExpiration: oldTime + 100,
            idToken: 'idtoken',
            refreshToken: 'rt',
          },
          lifetime: { u: oldTime, e: oldTime + 86400, c: oldTime },
        });

        const req = new TestReq({ cookies });
        const res = new TestRes(cookies);

        const instance = getConfiguredInstance({
          idTokenSigningAlg: 'ES256',
        });

        const newFrozenTime = frozenTimeMs + 2000;
        travel(newFrozenTime);

        const tokens = await instance.getTokens(req, res, {
          forceRefresh: true,
        });

        expect(tokens).toEqual({
          accessToken: 'at1',
          idToken: createdIdToken.idToken,
          refreshToken: 'rt',
          isExpired: false,
        });

        await assertSessionCookieValue(cookies, {
          session: {
            user: {
              sub_jwk: createdIdToken.key,
              sub: createdIdToken.sub,
              username: 'oooooooooosername',
            },
            scopes: 'something',
            accessToken: 'at1',
            accessTokenExpiration: now() + 999,
            idToken: createdIdToken.idToken,
            refreshToken: 'rt',
          },
          lifetime: { c: oldTime, e: oldTime + 86400, u: now() },
        });
      });

      it('should be able to customize if the session using onSessionCreating', async () => {
        const frozenTimeMs = 1330688329321;
        freeze(frozenTimeMs);

        setupDiscovery({
          token_endpoint: 'https://op.example.com/token',
          jwks_uri: 'https://op.example.com/token',
        });

        const createdIdToken = await createTestIdToken({
          username: 'oooooooooosername',
        });

        nock('https://op.example.com')
          .matchHeader(
            'authorization',
            'Basic X190ZXN0X2NsaWVudF9pZF9fOl9fdGVzdF9jbGllbnRfc2VjcmV0X18='
          )
          .post('/token', body => {
            expect(body).toEqual({
              grant_type: 'refresh_token',
              refresh_token: 'rt',
            });
            return true;
          })
          .reply(200, {
            access_token: 'at1',
            refresh_token: 'rt1',
            id_token: createdIdToken.idToken,
            scope: 'something',
            token_type: 'Bearer',
            expires_in: 999,
          });

        nock('https://op.example.com')
          .get('/jwks')
          .reply(200, { keys: [createdIdToken.key] });

        const cookies = {};

        const oldTime = now();
        await setSessionCookieValue(cookies, {
          session: {
            user: { sub: createdIdToken.sub },
            scopes: 'abc',
            accessToken: 'at',
            accessTokenExpiration: oldTime + 100,
            idToken: 'idtoken',
            refreshToken: 'rt',
          },
          lifetime: { u: oldTime, e: oldTime + 86400, c: oldTime },
        });

        const req = new TestReq({ cookies });
        const res = new TestRes(cookies);

        const instance = getConfiguredInstance({
          onSessionCreating: (session, idtoken, userinfo, appState) => {
            expect(appState).toBeUndefined();
            expect(userinfo).toBeUndefined();
            expect(idtoken).toBeDefined();
            session.custom = 1;
          },
          idTokenSigningAlg: 'ES256',
        });

        const newFrozenTime = frozenTimeMs + 2000;
        travel(newFrozenTime);

        const tokens = await instance.getTokens(req, res, {
          forceRefresh: true,
        });

        expect(tokens).toEqual({
          accessToken: 'at1',
          idToken: createdIdToken.idToken,
          refreshToken: 'rt1',
          isExpired: false,
        });

        await assertSessionCookieValue(cookies, {
          session: {
            user: {
              sub_jwk: createdIdToken.key,
              sub: createdIdToken.sub,
              username: 'oooooooooosername',
            },
            scopes: 'something',
            accessToken: 'at1',
            accessTokenExpiration: now() + 999,
            idToken: createdIdToken.idToken,
            refreshToken: 'rt1',
            custom: 1,
          },
          lifetime: { c: oldTime, e: oldTime + 86400, u: now() },
        });
      });

      it('should return isExpired false if session is not found', async () => {
        const cookies = {};

        await setSessionCookieValue(cookies, {
          lifetime: { u: now(), e: now() + 86400, c: now() },
        });

        const req = new TestReq({ cookies });
        const res = new TestRes(cookies);

        const instance = getConfiguredInstance();

        const tokens = await instance.getTokens(req, res);

        expect(tokens).toEqual({
          idToken: undefined,
          accessToken: undefined,
          refreshToken: undefined,
          isExpired: false,
        });
      });
    });
  });
});
