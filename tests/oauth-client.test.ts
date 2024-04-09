/* eslint-disable @typescript-eslint/no-explicit-any */
import nock from 'nock';
import { MonoCloudValidationError } from '../src/errors/monocloud-validation-error';
import { OAuthClient } from '../src/openid-client/oauth-client';
import { getOptions } from '../src/options/get-options';
import { MonoCloudOptionsBase } from '../src/types';
import { AuthorizationServer } from '@monocloud/oauth4webapi';
import { MonoCloudOPError } from '../src/errors/monocloud-op-error';
import { freeze, reset } from 'timekeeper';
import { createTestIdToken, defaultConfig } from './test-helpers';
import { MonoCloudDiscoveryError } from '../src/errors/monocloud-discovery-error';

const getConfiguredClient = async (
  options: Partial<MonoCloudOptionsBase> = {},
  discoveryDoc: Partial<AuthorizationServer> = {}
): Promise<OAuthClient> => {
  nock(defaultConfig.issuer)
    .get('/.well-known/openid-configuration')
    .reply(200, { ...discoveryDoc });

  const client = new OAuthClient(getOptions({ ...defaultConfig, ...options }));

  await client.getClient();

  return client;
};

describe('OAuth Client', () => {
  afterEach(nock.cleanAll);
  describe('client.getClient()', () => {
    it('should throw validation error for unsupported response types', async () => {
      const options = getOptions({ ...defaultConfig });
      options.defaultAuthParams.response_type = 'token';

      const client = new OAuthClient(options);

      try {
        await client.getClient();
        throw new Error();
      } catch (err) {
        expect(err).toBeInstanceOf(MonoCloudValidationError);
        expect(err.message).toBe(
          'The sdk only supports the authorization code flow. Please use the "code" response_type.'
        );
      }
    });

    it('should throw op error if there were OP errors while discovering', async () => {
      try {
        await getConfiguredClient(undefined, {});
        throw new Error();
      } catch (err) {
        expect(err).toBeInstanceOf(MonoCloudDiscoveryError);
        expect(err.message).toBe(
          '"response" body "issuer" property must be a non-empty string'
        );
      }
    });

    it('should throw monocloud error if there were other errors while discovering', async () => {
      try {
        await getConfiguredClient({ issuer: 'ftp://abc' }, {});
        throw new Error();
      } catch (err) {
        expect(err).toBeInstanceOf(MonoCloudValidationError);
        expect(err.message).toBe(
          '"issuer.protocol" must be "https:" or "http:"'
        );
      }
    });

    it('should throw validation error if use par is enabled and par endpoint is not present', async () => {
      try {
        await getConfiguredClient(
          { usePar: true },
          { issuer: 'https://op.example.com' }
        );
        throw new Error();
      } catch (err) {
        expect(err).toBeInstanceOf(MonoCloudValidationError);
        expect(err.message).toBe(
          'The issuer does not support pushed authorization requests.'
        );
      }
    });
  });

  describe('client.pushedAuthorizationRequest()', () => {
    it('should throw op error if pushed authorization server returned error', async () => {
      nock('https://op.example.com').post('/par').reply(400, {
        error: 'server_error',
        error_description: 'bad things are happening',
      });

      try {
        const client = await getConfiguredClient(
          { usePar: true },
          {
            issuer: 'https://op.example.com',
            pushed_authorization_request_endpoint: 'https://op.example.com/par',
          }
        );

        await client.pushedAuthorizationRequest({});
        throw new Error();
      } catch (err) {
        expect(err).toBeInstanceOf(MonoCloudOPError);
        expect(err.message).toBe('server_error');
        expect(err.error_description).toBe('bad things are happening');
      }
    });

    it('should return request_uri and expires_in after a successful par', async () => {
      nock('https://op.example.com')
        .post('/par', body => {
          expect(body).toEqual({ client_id: '__test_client_id__' });
          return true;
        })
        .reply(201, {
          request_uri: 'requri',
          expires_in: 69420,
        });

      const client = await getConfiguredClient(
        { usePar: true },
        {
          issuer: 'https://op.example.com',
          pushed_authorization_request_endpoint: 'https://op.example.com/par',
        }
      );

      const parResponse = await client.pushedAuthorizationRequest({});

      expect(parResponse).toEqual({
        request_uri: 'requri',
        expires_in: 69420,
      });
    });

    it('should be able to send custom params to par endpoint', async () => {
      nock('https://op.example.com')
        .post('/par', body => {
          expect(body).toEqual({
            client_id: '__test_client_id__',
            redirect_uri: 'customredirect',
            hello: 'hi',
          });
          return true;
        })
        .reply(201, {
          request_uri: 'requri',
          expires_in: 69420,
        });

      const client = await getConfiguredClient(
        { usePar: true },
        {
          issuer: 'https://op.example.com',
          pushed_authorization_request_endpoint: 'https://op.example.com/par',
        }
      );

      const parResponse = await client.pushedAuthorizationRequest({
        redirect_uri: 'customredirect',
        hello: 'hi',
      });

      expect(parResponse).toEqual({
        request_uri: 'requri',
        expires_in: 69420,
      });
    });
  });

  describe('client.authorizationUrl()', () => {
    it('should throw op error if there is no authorization endpoint', async () => {
      try {
        const client = await getConfiguredClient(undefined, {
          issuer: 'https://op.example.com',
        });

        await client.authorizationUrl({});
        throw new Error();
      } catch (err) {
        expect(err).toBeInstanceOf(MonoCloudOPError);
        expect(err.message).toBe('Server has no authorization endpoint');
      }
    });

    it('should return a valid authorization url', async () => {
      const client = await getConfiguredClient(undefined, {
        issuer: 'https://op.example.com',
        authorization_endpoint: 'https://op.example.com/authorize',
      });

      const authUrl = await client.authorizationUrl({
        acr_values: 'hi there',
        redirect_uri: 'hello',
        scope: 'chat',
      });

      expect(authUrl).toBe(
        'https://op.example.com/authorize?client_id=__test_client_id__&acr_values=hi+there&redirect_uri=hello&scope=chat'
      );
    });

    it('should return url with custom parameters', async () => {
      const client = await getConfiguredClient(undefined, {
        issuer: 'https://op.example.com',
        authorization_endpoint: 'https://op.example.com/authorize',
      });

      const authUrl = await client.authorizationUrl({
        custom: 'parameter',
      });

      expect(authUrl).toBe(
        'https://op.example.com/authorize?client_id=__test_client_id__&custom=parameter'
      );
    });
  });

  describe('client.callbackParams()', () => {
    it('should throw op error if callback params responded with error', async () => {
      try {
        const client = await getConfiguredClient(undefined, {
          issuer: 'https://op.example.com',
        });

        const authResponse = new URLSearchParams();
        authResponse.append('state', 'state');
        authResponse.append('error', 'server_error');
        authResponse.append('error_description', 'bad things are happening');

        await client.callbackParams(authResponse, 'state');
        throw new Error();
      } catch (err) {
        expect(err).toBeInstanceOf(MonoCloudOPError);
        expect(err.message).toBe('server_error');
        expect(err.error_description).toBe('bad things are happening');
      }
    });

    it('should throw monocloud error if callback params has type error', async () => {
      try {
        const client = await getConfiguredClient(undefined, {
          issuer: 'https://op.example.com',
        });

        await client.callbackParams(undefined as any, 'state');
        throw new Error();
      } catch (err) {
        expect(err).toBeInstanceOf(MonoCloudValidationError);
        expect(err.message).toBe(
          '"parameters" must be an instance of URLSearchParams, or URL'
        );
      }
    });
  });

  describe('client.callback()', () => {
    it('should throw op error if token endpoint responded with error', async () => {
      nock('https://op.example.com').post('/token').reply(400, {
        error: 'server_error',
        error_description: 'bad things are happening',
      });

      try {
        const client = await getConfiguredClient(undefined, {
          issuer: 'https://op.example.com',
          token_endpoint: 'https://op.example.com/token',
        });

        let authResponse = new URLSearchParams();
        authResponse.append('state', 'state');
        authResponse.append('code', 'thecode');

        authResponse = await client.callbackParams(authResponse, 'state');

        await client.callback('redir', authResponse, 'verifier');
        throw new Error();
      } catch (err) {
        expect(err).toBeInstanceOf(MonoCloudOPError);
        expect(err.message).toBe('server_error');
        expect(err.error_description).toBe('bad things are happening');
      }
    });

    it('should throw monocloud error if callback endpoint has type error', async () => {
      try {
        const client = await getConfiguredClient(undefined, {
          issuer: 'https://op.example.com',
          token_endpoint: 'https://op.example.com/token',
        });

        await client.callback('redir', undefined as any, 'verifier');
        throw new Error();
      } catch (err) {
        expect(err).toBeInstanceOf(MonoCloudValidationError);
        expect(err.message).toBe(
          '"callbackParameters" must be an instance of URLSearchParams obtained from "validateAuthResponse()", or "validateJwtAuthResponse()'
        );
      }
    });

    [
      [
        999,
        {
          expires_at: 1330688329 + 999,
          expires_in: 999,
        },
      ],
      [undefined, {}],
    ].forEach(([serverExpiryReply, tokenExpiresAssertion]) => {
      it('should return tokens if the exchange was sucessful', async () => {
        const frozenTimeMs = 1330688329321;
        freeze(frozenTimeMs);

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
              code: 'thecode',
              code_verifier: 'verifier',
              grant_type: 'authorization_code',
              redirect_uri: 'redir',
              extra: 'param',
            });
            return true;
          })
          .reply(200, {
            access_token: 'at1',
            id_token: createdIdToken.idToken,
            refresh_token: 'rt1',
            scope: 'something',
            token_type: 'Bearer',
            expires_in: serverExpiryReply,
          });

        nock('https://op.example.com')
          .get('/jwks')
          .reply(200, { keys: [createdIdToken.key] });

        const client = await getConfiguredClient(
          { idTokenSigningAlg: 'ES256' },
          {
            issuer: 'https://op.example.com',
            token_endpoint: 'https://op.example.com/token',
            jwks_uri: 'https://op.example.com/token',
          }
        );

        let authResponse = new URLSearchParams();
        authResponse.append('state', 'state');
        authResponse.append('code', 'thecode');

        authResponse = await client.callbackParams(authResponse, 'state');

        const tokens = await client.callback(
          'redir',
          authResponse,
          'verifier',
          undefined,
          undefined,
          { extra: 'param' }
        );

        expect(tokens).toEqual({
          access_token: 'at1',
          id_token: createdIdToken.idToken,
          token_type: 'bearer',
          refresh_token: 'rt1',
          scope: 'something',
          claims: {
            sub_jwk: createdIdToken.key,
            sub: createdIdToken.sub,
            username: 'oooooooooosername',
            iat: 1330688329,
            iss: 'https://op.example.com',
            aud: '__test_client_id__',
            exp: 1330688389,
          },
          ...(tokenExpiresAssertion as any),
        });

        reset();
      });
    });
  });

  describe('client.userinfo()', () => {
    it('should throw op error if userinfo endpoint responded with error', async () => {
      nock('https://op.example.com')
        .get('/userinfo')
        .reply(401, 'Unauthorized');

      try {
        const client = await getConfiguredClient(undefined, {
          issuer: 'https://op.example.com',
          userinfo_endpoint: 'https://op.example.com/userinfo',
        });

        await client.userinfo('at');
        throw new Error();
      } catch (err) {
        expect(err).toBeInstanceOf(MonoCloudOPError);
        expect(err.message).toBe(
          '"response" is not a conform UserInfo Endpoint response'
        );
      }
    });

    it('should throw op error if userinfo endpoint responded without user id', async () => {
      nock('https://op.example.com').get('/userinfo').reply(200, {});

      try {
        const client = await getConfiguredClient(undefined, {
          issuer: 'https://op.example.com',
          userinfo_endpoint: 'https://op.example.com/userinfo',
        });

        await client.userinfo('at');
        throw new Error();
      } catch (err) {
        expect(err).toBeInstanceOf(MonoCloudOPError);
        expect(err.message).toBe(
          '"response" body "sub" property must be a non-empty string'
        );
      }
    });

    it('should get send access token to the server', async () => {
      nock('https://op.example.com')
        .get('/userinfo')
        .matchHeader('authorization', 'Bearer at')
        .reply(200, { sub: 'id' });

      const client = await getConfiguredClient(undefined, {
        issuer: 'https://op.example.com',
        userinfo_endpoint: 'https://op.example.com/userinfo',
      });

      await client.userinfo('at');
    });

    it('should throw monocloud error if there were other errors', async () => {
      try {
        const client = await getConfiguredClient(undefined, {
          issuer: 'https://op.example.com',
        });

        await client.userinfo('');
        throw new Error();
      } catch (err) {
        expect(err).toBeInstanceOf(MonoCloudValidationError);
        expect(err.message).toBe('"as.userinfo_endpoint" must be a string');
      }
    });
  });

  describe('client.endSessionUrl()', () => {
    it('should throw op error end_session_endpoint is not configured', async () => {
      try {
        const client = await getConfiguredClient(undefined, {
          issuer: 'https://op.example.com',
        });

        await client.endSessionUrl({});
        throw new Error();
      } catch (err) {
        expect(err).toBeInstanceOf(MonoCloudOPError);
        expect(err.message).toBe('Server has no end session endpoint');
      }
    });

    it('should return a valid endsession url', async () => {
      const client = await getConfiguredClient(undefined, {
        issuer: 'https://op.example.com',
        end_session_endpoint: 'https://op.example.com/endsession',
      });

      const endsessionUrl = await client.endSessionUrl({
        state: 'xyz',
        client_id: 'client',
        id_token_hint: 'idtoken',
        logout_hint: 'hi',
        post_logout_redirect_uri: 'uri',
        custom: 'param',
      });

      expect(endsessionUrl).toBe(
        'https://op.example.com/endsession?client_id=client&state=xyz&id_token_hint=idtoken&logout_hint=hi&post_logout_redirect_uri=uri&custom=param'
      );
    });
  });

  describe('client.refresh()', () => {
    it('should throw op error if refresh token endpoint responded with error', async () => {
      nock('https://op.example.com').post('/token').reply(400, {
        error: 'server_error',
        error_description: 'bad things are happening',
      });

      try {
        const client = await getConfiguredClient(undefined, {
          issuer: 'https://op.example.com',
          token_endpoint: 'https://op.example.com/token',
        });

        await client.refresh('rt');
        throw new Error();
      } catch (err) {
        expect(err).toBeInstanceOf(MonoCloudOPError);
        expect(err.message).toBe('server_error');
        expect(err.error_description).toBe('bad things are happening');
      }
    });

    [
      [
        999,
        {
          expires_at: 1330688329 + 999,
          expires_in: 999,
        },
      ],
      [undefined, {}],
    ].forEach(([serverExpiryReply, tokenExpiresAssertion]) => {
      it('should return tokens if the refresh was sucessful', async () => {
        const frozenTimeMs = 1330688329321;
        freeze(frozenTimeMs);

        const createdIdToken = await createTestIdToken({
          username: 'oooooooooosername',
        });

        nock('https://op.example.com')
          .post('/token', body => {
            expect(body).toEqual({
              grant_type: 'refresh_token',
              refresh_token: 'rt',
              extra: 'param',
            });
            return true;
          })
          .reply(200, {
            access_token: 'at1',
            id_token: createdIdToken.idToken,
            refresh_token: 'rt1',
            scope: 'something',
            token_type: 'Bearer',
            expires_in: serverExpiryReply,
          });

        nock('https://op.example.com')
          .get('/jwks')
          .reply(200, { keys: [createdIdToken.key] });

        const client = await getConfiguredClient(
          { idTokenSigningAlg: 'ES256' },
          {
            issuer: 'https://op.example.com',
            token_endpoint: 'https://op.example.com/token',
            jwks_uri: 'https://op.example.com/token',
          }
        );

        const tokens = await client.refresh('rt', { extra: 'param' });

        expect(tokens).toEqual({
          access_token: 'at1',
          id_token: createdIdToken.idToken,
          token_type: 'bearer',
          refresh_token: 'rt1',
          scope: 'something',
          claims: {
            sub_jwk: createdIdToken.key,
            sub: createdIdToken.sub,
            username: 'oooooooooosername',
            iat: 1330688329,
            iss: 'https://op.example.com',
            aud: '__test_client_id__',
            exp: 1330688389,
          },
          ...(tokenExpiresAssertion as any),
        });

        reset();
      });
    });
  });

  describe('client helper', () => {
    it('client.generateCodeVerifier() should generate non empty string', async () => {
      const client = await getConfiguredClient(undefined, {
        issuer: 'https://op.example.com',
      });

      expect(client.generateCodeVerifier().length).toBeGreaterThan(0);
    });

    it('client.generateNonce() should generate non empty string', async () => {
      const client = await getConfiguredClient(undefined, {
        issuer: 'https://op.example.com',
      });

      expect(client.generateNonce().length).toBeGreaterThan(0);
    });

    it('client.generateState() should generate non empty string', async () => {
      const client = await getConfiguredClient(undefined, {
        issuer: 'https://op.example.com',
      });

      expect(client.generateState().length).toBeGreaterThan(0);
    });

    it('client.codeChallenge() should generate non empty string', async () => {
      const client = await getConfiguredClient(undefined, {
        issuer: 'https://op.example.com',
      });

      const challenge = await client.codeChallenge('test');

      expect(challenge.length).toBeGreaterThan(0);
    });

    it('client.getMetadata() should return the issuer discovery document', async () => {
      const client = await getConfiguredClient(undefined, {
        issuer: 'https://op.example.com',
        something_else: 'hi',
      });

      const metadata = await client.getMetadata();

      expect(metadata).toEqual({
        issuer: 'https://op.example.com',
        something_else: 'hi',
      });
    });

    it('can set cusom user agent', async () => {
      nock(defaultConfig.issuer)
        .get('/.well-known/openid-configuration')
        .matchHeader('User-Agent', 'TEST AGENT')
        .reply(200, { issuer: 'https://op.example.com' });

      const client = new OAuthClient(
        getOptions({ ...defaultConfig, userAgent: 'TEST AGENT' })
      );

      await client.getClient();

      nock.isDone();
    });
  });
});
