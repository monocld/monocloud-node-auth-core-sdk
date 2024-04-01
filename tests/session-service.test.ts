/* eslint-disable @typescript-eslint/no-non-null-assertion */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { freeze, reset, travel } from 'timekeeper';
import { randomBytes } from 'crypto';
import { getOptions } from '../src/options/get-options';
import { decryptData, encryptData, now } from '../src/utils';
import { SessionCookieValue } from '../src/types/internal';
import {
  SameSiteValues,
  MonoCloudOptions,
  MonoCloudSession,
} from '../src/types';
import { MonoCloudSessionService } from '../src/session/monocloud-session-service';
import {
  TestReq,
  TestRes,
  TestStore,
  defaultConfig,
  defaultStoreKeyForTest,
  defaultSessionData,
  getSessionCookie,
} from './test-helpers';

const frozenTimeMs = 1330688329321;
const frozenTimeSec = 1330688329;

const getService = (
  params: MonoCloudOptions = {}
): Promise<MonoCloudSessionService> => {
  return Promise.resolve(
    new MonoCloudSessionService(getOptions({ ...defaultConfig, ...params }))
  );
};

describe('Session Service', () => {
  beforeEach(() => {
    freeze(frozenTimeMs);
  });

  afterEach(() => {
    reset();
  });

  describe('Default Store', () => {
    it('should set the session cookie with configured options', async () => {
      const cookieOptions = {
        domain: 'cookie_domain',
        httpOnly: true,
        name: 'cookie_name',
        path: 'cookie_path',
        persistent: true,
        sameSite: 'lax' as SameSiteValues,
        secure: true,
      };

      const service = await getService({
        session: { cookie: cookieOptions },
      });

      const session = defaultSessionData();

      const res = new TestRes();

      const key = await service.setSession(new TestReq(), res, session);

      const sessionCookieValue: SessionCookieValue = JSON.parse(
        (await decryptData(
          res.cookies.cookie_name.value,
          defaultConfig.cookieSecret!
        )) as string
      );

      expect(key.length).toBeGreaterThan(1);
      expect(sessionCookieValue.key.length).toBeGreaterThan(0);
      expect(sessionCookieValue.session).toEqual(session);
      expect(sessionCookieValue.lifetime.c).toEqual(frozenTimeSec);
      expect(sessionCookieValue.lifetime.c).toEqual(
        sessionCookieValue.lifetime.u
      );
      expect(sessionCookieValue.lifetime.e).toEqual(frozenTimeSec + 86400);

      expect(res.cookies.cookie_name.options).toEqual({
        domain: cookieOptions.domain,
        httpOnly: cookieOptions.httpOnly,
        sameSite: cookieOptions.sameSite,
        secure: cookieOptions.secure,
        path: cookieOptions.path,
        expires: new Date((frozenTimeSec + 86400) * 1000),
      });
    });

    it('should be able to get the session from cookies with configured options', async () => {
      const service = await getService({
        session: { cookie: { name: 'cookie_name' } },
      });

      const session = defaultSessionData();

      const cookies = {
        cookie_name: { value: await getSessionCookie({ session }) },
      } as any;

      const sessionValue = await service.getSession(
        new TestReq({ cookies }),
        new TestRes()
      );

      expect(sessionValue).toEqual(session);
    });

    it('should be able to update the session from cookies with configured options ', async () => {
      const cookieOptions = {
        domain: 'cookie_domain',
        httpOnly: true,
        name: 'cookie_name',
        path: 'cookie_path',
        persistent: true,
        sameSite: 'lax' as SameSiteValues,
        secure: true,
      };

      const service = await getService({
        session: { cookie: cookieOptions },
      });

      const session = defaultSessionData();

      const cookies = {
        cookie_name: { value: await getSessionCookie({ session }) },
      } as any;

      const newSession = { ...session, newValue: 'yoohoo' };

      const updateResult = await service.updateSession(
        new TestReq({ cookies }),
        new TestRes(cookies),
        newSession
      );

      expect(updateResult).toBe(true);

      const sessionValue = (await service.getSession(
        new TestReq({ cookies }),
        new TestRes(cookies)
      ))!;

      expect(sessionValue).toEqual(newSession);

      const sessionCookieValue: SessionCookieValue = JSON.parse(
        (await decryptData(
          cookies.cookie_name.value,
          defaultConfig.cookieSecret!
        )) as string
      );

      expect(sessionCookieValue.key.length).toBeGreaterThan(0);
      expect(sessionCookieValue.session).toEqual(newSession);
      expect(sessionCookieValue.lifetime.c).toEqual(frozenTimeSec);
      expect(sessionCookieValue.lifetime.c).toEqual(
        sessionCookieValue.lifetime.u
      );
      expect(sessionCookieValue.lifetime.e).toEqual(frozenTimeSec + 86400);
    });

    it('should remove the session cookie with configured options', async () => {
      const cookieOptions = {
        name: 'cookie_name',
      };

      const service = await getService({
        session: { cookie: cookieOptions },
      });

      const cookies = {
        other: { value: 'abc' },
        cookie_name: { value: await getSessionCookie() },
      } as any;

      await service.removeSession(
        new TestReq({ cookies }),
        new TestRes(cookies)
      );

      expect(Object.entries(cookies).length).toBe(2);
      expect(cookies.cookie_name.options.expires).toEqual(new Date(0));
      expect(cookies.cookie_name.value).toBe('');
      expect(cookies.other.value).toBe('abc');
    });

    it('should return undefined when getting an expired session', async () => {
      const service = await getService({
        session: { duration: 5 },
      });

      const cookies = {
        session: {
          value: await getSessionCookie({ session: defaultSessionData() }),
        },
      } as any;

      // Travel 6 seconds

      const newFrozenTimeMs = frozenTimeMs + 6 * 1000;

      travel(newFrozenTimeMs);

      const sessionValue = await service.getSession(
        new TestReq({ cookies }),
        new TestRes(cookies)
      );

      expect(sessionValue).toBeUndefined();
      expect(Object.entries(cookies).length).toBe(1);
      expect(cookies.session.options.expires).toEqual(new Date(0));
      expect(cookies.session.value).toBe('');
    });

    it('should return undefined when getting there is no session cookie in the request', async () => {
      const service = await getService();

      const cookies = {};

      const sessionValue = await service.getSession(
        new TestReq({ cookies }),
        new TestRes(cookies)
      );

      expect(sessionValue).toBeUndefined();
      expect(Object.entries(cookies).length).toBe(0);
    });

    it('should return undefined when getting an invalid session cookie', async () => {
      const service = await getService();

      const cookies: any = { session: { value: 'invalid' } };

      const sessionValue = await service.getSession(
        new TestReq({ cookies }),
        new TestRes(cookies)
      );

      expect(sessionValue).toBeUndefined();
      expect(Object.entries(cookies).length).toBe(1);
      expect(cookies.session.options.expires).toEqual(new Date(0));
      expect(cookies.session.value).toBe('');
    });

    it('should return undefined when getting a session cookie with no sesson data', async () => {
      const service = await getService();

      const cookies = { session: { value: await getSessionCookie() } } as any;

      const session = await service.getSession(
        new TestReq({ cookies }),
        new TestRes()
      );

      expect(session).toBeUndefined();
    });

    it('should not set expiration for non persistent sessions', async () => {
      const service = await getService({
        session: { cookie: { persistent: false } },
      });

      const session = defaultSessionData();

      const cookies = {} as any;

      await service.setSession(new TestReq(), new TestRes(cookies), session);

      const sessionValue: SessionCookieValue = JSON.parse(
        (await decryptData(
          cookies.session.value,
          defaultConfig.cookieSecret!
        )) as string
      );

      expect(sessionValue.key.length).toBeGreaterThan(0);
      expect(sessionValue.session).toEqual(session);
      expect(sessionValue.lifetime.c).toEqual(frozenTimeSec);
      expect(sessionValue.lifetime.c).toEqual(sessionValue.lifetime.u);
      expect(sessionValue.lifetime.e).toBeUndefined();

      expect(cookies.session.options).toEqual({
        domain: undefined,
        expires: undefined,
        httpOnly: true,
        path: '/',
        sameSite: 'lax',
        secure: true,
      });
    });

    it('should not update an invalid session', async () => {
      const service = await getService();

      const cookies: any = { session: { value: 'invalid' } };

      const updated = await service.updateSession(
        new TestReq({ cookies }),
        new TestRes(cookies),
        { user: { sub: 'yooohoo' } }
      );

      expect(updated).toBe(false);
      expect(Object.entries(cookies).length).toBe(1);
      expect((cookies as any).session.options.expires).toEqual(new Date(0));
      expect((cookies as any).session.value).toBe('');
    });

    it('should not update an expired session', async () => {
      const service = await getService({ session: { duration: 5 } });

      const session = { user: { sub: 'yooohoo' } };

      const cookies = {
        session: { value: await getSessionCookie({ session, exp: now() - 6 }) },
      } as any;

      const updated = await service.updateSession(
        new TestReq({ cookies }),
        new TestRes(cookies),
        { user: { sub: 'yooohoo' }, accessToken: 'at' }
      );

      expect(updated).toBe(false);
    });

    it('should remove invalid session', async () => {
      const service = await getService();

      const cookies = {
        other: { value: 'abc' },
        session: { value: 'invalid' },
      } as any;

      await service.removeSession(
        new TestReq({ cookies }),
        new TestRes(cookies)
      );

      expect(Object.entries(cookies).length).toBe(2);
      expect(cookies.session.options.expires).toEqual(new Date(0));
      expect(cookies.session.value).toBe('');
      expect(cookies.other.value).toBe('abc');
    });

    it('should save to chunked cookies if the session is too long', async () => {
      const cookieOptions = {
        domain: 'cookie_domain',
        httpOnly: true,
        name: 'cookie_name',
        path: 'cookie_path',
        persistent: true,
        sameSite: 'lax' as SameSiteValues,
        secure: true,
      };

      const service = await getService({
        session: { cookie: cookieOptions },
      });

      const session: MonoCloudSession = {
        user: {
          sub: 'randomid',
        },
        foo: 'bar',
        accessToken: 'at',
        accessTokenExpiration: 0,
        idToken: 'idt',
        refreshToken: 'rt',
        scopes: 'openid',
        unnecessarilyLongValue: randomBytes(2000).toString('hex'),
      };

      const res = new TestRes();
      await service.setSession(new TestReq(), res, session);

      const sessionValue: SessionCookieValue = JSON.parse(
        (await decryptData(
          res.cookies['cookie_name.0'].value +
            res.cookies['cookie_name.1'].value,
          defaultConfig.cookieSecret!
        )) as string
      );

      expect(sessionValue.key.length).toBeGreaterThan(0);
      expect(sessionValue.session).toEqual(session);
      expect(sessionValue.lifetime.c).toEqual(frozenTimeSec);
      expect(sessionValue.lifetime.c).toEqual(sessionValue.lifetime.u);
      expect(sessionValue.lifetime.e).toEqual(frozenTimeSec + 86400);

      Object.values(res.cookies).forEach(cookie => {
        expect(cookie.options).toEqual({
          domain: cookieOptions.domain,
          httpOnly: cookieOptions.httpOnly,
          sameSite: cookieOptions.sameSite,
          secure: cookieOptions.secure,
          path: cookieOptions.path,
          expires: new Date((frozenTimeSec + 86400) * 1000),
        });
      });
    });

    it('should be able to get from chunked cookies', async () => {
      const service = await getService();

      const session: MonoCloudSession = {
        user: {
          sub: 'randomid',
        },
        foo: 'bar',
        accessToken: 'at',
        accessTokenExpiration: 0,
        idToken: 'idt',
        refreshToken: 'rt',
        scopes: 'openid',
        unnecessarilyLongValue: randomBytes(2000).toString('hex'),
      };

      const res = new TestRes();
      await service.setSession(new TestReq(), res, session);

      const sessionValue = await service.getSession(
        new TestReq({ cookies: res.cookies }),
        new TestRes()
      );
      expect(sessionValue).toEqual(session);
    });

    it('should be able to update chunked cookies', async () => {
      const cookieOptions = {
        domain: 'cookie_domain',
        httpOnly: true,
        name: 'cookie_name',
        path: 'cookie_path',
        persistent: true,
        sameSite: 'lax' as SameSiteValues,
        secure: true,
      };

      const service = await getService({ session: { cookie: cookieOptions } });

      let session: MonoCloudSession = {
        user: {
          sub: 'randomid',
        },
        unnecessarilyLongValue: randomBytes(2000).toString('hex'),
      };

      const cookies = {} as any;

      await service.setSession(new TestReq(), new TestRes(cookies), session);

      expect(Object.keys(cookies).length).toBe(2);

      session = {
        ...session,
        anotherLongValue: randomBytes(2000).toString('hex'),
      };

      const updated = await service.updateSession(
        new TestReq({ cookies }),
        new TestRes(cookies),
        session
      );

      const sessionValue: SessionCookieValue = JSON.parse(
        (await decryptData(
          cookies['cookie_name.0'].value +
            cookies['cookie_name.1'].value +
            cookies['cookie_name.2'].value,
          defaultConfig.cookieSecret!
        )) as string
      );

      expect(updated).toBe(true);
      expect(Object.keys(cookies).length).toBe(3);
      expect(sessionValue.session).toEqual(session);
      Object.values(cookies).forEach((cookie: any) => {
        expect(cookie.options).toEqual({
          domain: cookieOptions.domain,
          httpOnly: cookieOptions.httpOnly,
          sameSite: cookieOptions.sameSite,
          secure: cookieOptions.secure,
          path: cookieOptions.path,
          expires: new Date((frozenTimeSec + 86400) * 1000),
        });
      });
    });

    it('should delete unwanted chunked cookies if updated session data is smaller than before', async () => {
      const cookieOptions = {
        domain: 'cookie_domain',
        httpOnly: true,
        name: 'cookie_name',
        path: 'cookie_path',
        persistent: true,
        sameSite: 'lax' as SameSiteValues,
        secure: true,
      };

      const service = await getService({ session: { cookie: cookieOptions } });

      let session: MonoCloudSession = {
        user: {
          sub: 'randomid',
        },
        unnecessarilyLongValue: randomBytes(5000).toString('hex'),
      };

      const cookies = {} as any;

      await service.setSession(new TestReq(), new TestRes(cookies), session);

      expect(Object.keys(cookies).length).toBe(4);

      session = {
        user: {
          sub: 'randomid',
        },
        unnecessarilyLongValue: randomBytes(2000).toString('hex'),
      };

      const updated = await service.updateSession(
        new TestReq({ cookies }),
        new TestRes(cookies),
        session
      );

      const sessionValue: SessionCookieValue = JSON.parse(
        (await decryptData(
          cookies['cookie_name.0'].value + cookies['cookie_name.1'].value,
          defaultConfig.cookieSecret!
        )) as string
      );

      expect(updated).toBe(true);
      expect(sessionValue.session).toEqual(session);

      const cookieValues = Object.values(cookies);

      [cookieValues[0], cookieValues[1]].forEach((cookie: any) => {
        expect(cookie.options).toEqual({
          domain: cookieOptions.domain,
          httpOnly: cookieOptions.httpOnly,
          sameSite: cookieOptions.sameSite,
          secure: cookieOptions.secure,
          path: cookieOptions.path,
          expires: new Date((frozenTimeSec + 86400) * 1000),
        });
      });

      [cookieValues[2], cookieValues[3]].forEach((cookie: any) => {
        expect(cookie.value).toBe('');
        expect(cookie.options.expires).toEqual(new Date(0));
      });
    });

    it('should not be able to get invalid chunked cookies', async () => {
      const service = await getService();

      const cookies = { 'session.': 'anyvalue' } as any;
      const session = await service.getSession(
        new TestReq({ cookies }),
        new TestRes()
      );

      expect(session).toBeUndefined();
    });

    describe('Sliding Session', () => {
      it('should slide the set duration with sliding expiration', async () => {
        const cookieOptions = {
          domain: 'cookie_domain',
          httpOnly: true,
          name: 'cookie_name',
          path: 'cookie_path',
          persistent: true,
          sameSite: 'lax' as SameSiteValues,
          secure: true,
        };

        const service = await getService({
          session: {
            cookie: cookieOptions,
            sliding: true,
            duration: 10,
            maximumDuration: 100,
          },
        });

        const req = new TestReq();
        const res = new TestRes();

        const session: MonoCloudSession = { user: {} };

        await service.setSession(req, res, session);

        let sessionValue: SessionCookieValue = JSON.parse(
          (await decryptData(
            res.cookies.cookie_name.value,
            defaultConfig.cookieSecret!
          )) as string
        );

        expect(sessionValue.lifetime.c).toEqual(frozenTimeSec);
        expect(sessionValue.lifetime.c).toEqual(sessionValue.lifetime.u);
        expect(sessionValue.lifetime.e).toEqual(frozenTimeSec + 10);

        expect(res.cookies.cookie_name.options).toEqual({
          domain: cookieOptions.domain,
          httpOnly: cookieOptions.httpOnly,
          sameSite: cookieOptions.sameSite,
          secure: cookieOptions.secure,
          path: cookieOptions.path,
          expires: new Date((frozenTimeSec + 10) * 1000),
        });

        // Travel 9 seconds and check the expiry

        const newFrozenTimeMs = frozenTimeMs + 9 * 1000;
        const newFrozenTimeSec = Math.floor(newFrozenTimeMs / 1000);

        travel(newFrozenTimeMs);

        const updateResult = await service.updateSession(
          new TestReq({ cookies: res.cookies }),
          res,
          session
        );

        expect(updateResult).toBe(true);

        sessionValue = JSON.parse(
          (await decryptData(
            res.cookies.cookie_name.value,
            defaultConfig.cookieSecret!
          )) as string
        );

        expect(sessionValue.lifetime.c).toEqual(frozenTimeSec);
        expect(sessionValue.lifetime.u).toEqual(newFrozenTimeSec);
        expect(sessionValue.lifetime.e).toEqual(newFrozenTimeSec + 10);

        expect(res.cookies.cookie_name.options).toEqual({
          domain: cookieOptions.domain,
          httpOnly: cookieOptions.httpOnly,
          sameSite: cookieOptions.sameSite,
          secure: cookieOptions.secure,
          path: cookieOptions.path,
          expires: new Date((newFrozenTimeSec + 10) * 1000),
        });
      });

      it('should not exceed max duration while the expiration is sliding', async () => {
        const cookieOptions = {
          domain: 'cookie_domain',
          httpOnly: true,
          name: 'cookie_name',
          path: 'cookie_path',
          persistent: true,
          sameSite: 'lax' as SameSiteValues,
          secure: true,
        };

        const service = await getService({
          session: {
            cookie: cookieOptions,
            sliding: true,
            duration: 7,
            maximumDuration: 10,
          },
        });

        const req = new TestReq();
        const res = new TestRes();

        const session: MonoCloudSession = { user: {} };

        await service.setSession(req, res, session);

        let sessionValue: SessionCookieValue = JSON.parse(
          (await decryptData(
            res.cookies.cookie_name.value,
            defaultConfig.cookieSecret!
          )) as string
        );

        expect(sessionValue.lifetime.c).toEqual(frozenTimeSec);
        expect(sessionValue.lifetime.c).toEqual(sessionValue.lifetime.u);
        expect(sessionValue.lifetime.e).toEqual(frozenTimeSec + 7);

        expect(res.cookies.cookie_name.options).toEqual({
          domain: cookieOptions.domain,
          httpOnly: cookieOptions.httpOnly,
          sameSite: cookieOptions.sameSite,
          secure: cookieOptions.secure,
          path: cookieOptions.path,
          expires: new Date((frozenTimeSec + 7) * 1000),
        });

        // Travel 5 seconds and check the expiry

        const newFrozenTimeMs = frozenTimeMs + 5 * 1000;
        const newFrozenTimeSec = Math.floor(newFrozenTimeMs / 1000);

        travel(newFrozenTimeMs);

        const updateResult = await service.updateSession(
          new TestReq({ cookies: res.cookies }),
          res,
          session
        );

        expect(updateResult).toBe(true);

        sessionValue = JSON.parse(
          (await decryptData(
            res.cookies.cookie_name.value,
            defaultConfig.cookieSecret!
          )) as string
        );

        expect(sessionValue.lifetime.c).toEqual(frozenTimeSec);
        expect(sessionValue.lifetime.u).toEqual(newFrozenTimeSec);
        expect(sessionValue.lifetime.e).toEqual(frozenTimeSec + 10);

        expect(res.cookies.cookie_name.options).toEqual({
          domain: cookieOptions.domain,
          httpOnly: cookieOptions.httpOnly,
          sameSite: cookieOptions.sameSite,
          secure: cookieOptions.secure,
          path: cookieOptions.path,
          expires: new Date((frozenTimeSec + 10) * 1000),
        });
      });

      it('should be able to get the session from the cookies and resave it', async () => {
        const service = await getService({ session: { sliding: true } });

        let res = new TestRes();

        const session: MonoCloudSession = {
          user: {
            sub: 'randomid',
          },
          foo: 'bar',
          accessToken: 'at',
          accessTokenExpiration: 0,
          idToken: 'idt',
          refreshToken: 'rt',
          scopes: 'openid',
        };

        await service.setSession(new TestReq(), res, session);

        let sessionCookieValue: SessionCookieValue = JSON.parse(
          (await decryptData(
            res.cookies.session.value,
            defaultConfig.cookieSecret!
          )) as string
        );

        expect(sessionCookieValue.lifetime.c).toEqual(frozenTimeSec);
        expect(sessionCookieValue.lifetime.c).toEqual(
          sessionCookieValue.lifetime.u
        );
        expect(sessionCookieValue.lifetime.e).toEqual(frozenTimeSec + 86400);

        // Travel 1 second

        const newFrozenTimeMs = frozenTimeMs + 1 * 1000;
        const newFrozenTimeSec = Math.floor(newFrozenTimeMs / 1000);

        travel(newFrozenTimeMs);

        // eslint-disable-next-line prefer-destructuring
        const cookies = res.cookies;

        res = new TestRes();
        const sessionValue = (await service.getSession(
          new TestReq({ cookies }),
          res,
          true
        ))!;

        expect(sessionValue).toEqual(session);

        sessionCookieValue = JSON.parse(
          (await decryptData(
            res.cookies.session.value,
            defaultConfig.cookieSecret!
          )) as string
        );

        expect(sessionCookieValue.lifetime.c).toEqual(frozenTimeSec);
        expect(sessionCookieValue.lifetime.u).toEqual(newFrozenTimeSec);
        expect(sessionCookieValue.lifetime.e).toEqual(newFrozenTimeSec + 86400);
      });

      it('should be able to get the session from the cookies without resaving it', async () => {
        const service = await getService({ session: { sliding: true } });

        const res = new TestRes();

        const session: MonoCloudSession = {
          user: {
            sub: 'randomid',
          },
          foo: 'bar',
          accessToken: 'at',
          accessTokenExpiration: 0,
          idToken: 'idt',
          refreshToken: 'rt',
          scopes: 'openid',
        };

        await service.setSession(new TestReq(), res, session);

        let sessionCookieValue: SessionCookieValue = JSON.parse(
          (await decryptData(
            res.cookies.session.value,
            defaultConfig.cookieSecret!
          )) as string
        );

        expect(sessionCookieValue.lifetime.c).toEqual(frozenTimeSec);
        expect(sessionCookieValue.lifetime.c).toEqual(
          sessionCookieValue.lifetime.u
        );
        expect(sessionCookieValue.lifetime.e).toEqual(frozenTimeSec + 86400);

        // Travel 1 second

        const newFrozenTimeMs = frozenTimeMs + 1 * 1000;

        travel(newFrozenTimeMs);

        const sessionValue = (await service.getSession(
          new TestReq({ cookies: res.cookies }),
          new TestRes(),
          false
        ))!;

        expect(sessionValue).toEqual(session);

        sessionCookieValue = JSON.parse(
          (await decryptData(
            res.cookies.session.value,
            defaultConfig.cookieSecret!
          )) as string
        );

        expect(sessionCookieValue.lifetime.c).toEqual(frozenTimeSec);
        expect(sessionCookieValue.lifetime.c).toEqual(
          sessionCookieValue.lifetime.u
        );
        expect(sessionCookieValue.lifetime.e).toEqual(frozenTimeSec + 86400);
      });

      it('should return undefined when getting an expired session beyond the duration', async () => {
        const service = await getService({
          session: { duration: 5, sliding: true },
        });

        const session: MonoCloudSession = {
          user: {
            sub: 'randomid',
          },
        };

        const cookies = {};

        await service.setSession(new TestReq(), new TestRes(cookies), session);

        // Travel 2 seconds

        const newFrozenTimeMs = frozenTimeMs + 2 * 1000;

        travel(newFrozenTimeMs);

        await service.updateSession(
          new TestReq({ cookies }),
          new TestRes(cookies),
          session
        );

        // Travel 6 seconds

        const newNewFrozenTimeMs = newFrozenTimeMs + 6 * 1000;

        travel(newNewFrozenTimeMs);

        const sessionValue = await service.getSession(
          new TestReq({ cookies }),
          new TestRes(cookies)
        );

        expect(sessionValue).toBeUndefined();
        expect(Object.entries(cookies).length).toBe(1);
        expect((cookies as any).session.options.expires).toEqual(new Date(0));
        expect((cookies as any).session.value).toBe('');
      });

      it('should return undefined when getting an expired session beyond the maximum duration', async () => {
        const service = await getService({
          session: { duration: 5, maximumDuration: 10, sliding: true },
        });

        const session: MonoCloudSession = {
          user: {
            sub: 'randomid',
          },
        };

        const cookies = {};

        await service.setSession(new TestReq(), new TestRes(cookies), session);

        // Travel 11 seconds

        const newFrozenTimeMs = frozenTimeMs + 11 * 1000;

        travel(newFrozenTimeMs);

        const sessionValue = await service.getSession(
          new TestReq({ cookies }),
          new TestRes(cookies)
        );

        expect(sessionValue).toBeUndefined();
        expect(Object.entries(cookies).length).toBe(1);
        expect((cookies as any).session.options.expires).toEqual(new Date(0));
        expect((cookies as any).session.value).toBe('');
      });
    });

    describe('Absolute Expiration', () => {
      it('should not exceed the configured session duration after updating the session', async () => {
        const cookieOptions = {
          domain: 'cookie_domain',
          httpOnly: true,
          name: 'cookie_name',
          path: 'cookie_path',
          persistent: true,
          sameSite: 'lax' as SameSiteValues,
          secure: true,
        };

        const service = await getService({
          session: {
            cookie: cookieOptions,
            duration: 10,
          },
        });

        const req = new TestReq();
        const res = new TestRes();

        const session: MonoCloudSession = { user: {} };

        await service.setSession(req, res, session);

        let sessionValue: SessionCookieValue = JSON.parse(
          (await decryptData(
            res.cookies.cookie_name.value,
            defaultConfig.cookieSecret!
          )) as string
        );

        expect(sessionValue.lifetime.c).toEqual(frozenTimeSec);
        expect(sessionValue.lifetime.c).toEqual(sessionValue.lifetime.u);
        expect(sessionValue.lifetime.e).toEqual(frozenTimeSec + 10);

        expect(res.cookies.cookie_name.options).toEqual({
          domain: cookieOptions.domain,
          httpOnly: cookieOptions.httpOnly,
          sameSite: cookieOptions.sameSite,
          secure: cookieOptions.secure,
          path: cookieOptions.path,
          expires: new Date((frozenTimeSec + 10) * 1000),
        });

        // Travel 9 seconds and check the expiry

        const newFrozenTimeMs = frozenTimeMs + 9 * 1000;
        const newFrozenTimeSec = Math.floor(newFrozenTimeMs / 1000);

        travel(newFrozenTimeMs);

        const updateResult = await service.updateSession(
          new TestReq({ cookies: res.cookies }),
          res,
          session
        );

        expect(updateResult).toBe(true);

        sessionValue = JSON.parse(
          (await decryptData(
            res.cookies.cookie_name.value,
            defaultConfig.cookieSecret!
          )) as string
        );

        expect(sessionValue.lifetime.c).toEqual(frozenTimeSec);
        expect(sessionValue.lifetime.u).toEqual(newFrozenTimeSec);
        expect(sessionValue.lifetime.e).toEqual(frozenTimeSec + 10);

        expect(res.cookies.cookie_name.options).toEqual({
          domain: cookieOptions.domain,
          httpOnly: cookieOptions.httpOnly,
          sameSite: cookieOptions.sameSite,
          secure: cookieOptions.secure,
          path: cookieOptions.path,
          expires: new Date((frozenTimeSec + 10) * 1000),
        });
      });
    });
  });

  describe('Custom Store', () => {
    it('should set the session cookie with configured options', async () => {
      const cookieOptions = {
        domain: 'cookie_domain',
        httpOnly: true,
        name: 'cookie_name',
        path: 'cookie_path',
        persistent: true,
        sameSite: 'lax' as SameSiteValues,
        secure: true,
      };

      const store = new TestStore();

      const service = await getService({
        session: { cookie: cookieOptions, store },
      });

      const session = defaultSessionData();

      const res = new TestRes();
      const key = await service.setSession(new TestReq(), res, session);

      const sessionCookieValue: SessionCookieValue = JSON.parse(
        (await decryptData(
          res.cookies.cookie_name.value,
          defaultConfig.cookieSecret!
        )) as string
      );

      expect(key.length).toBeGreaterThan(1);
      expect(sessionCookieValue.key.length).toBeGreaterThan(0);
      expect(sessionCookieValue.session).toBeUndefined();
      expect(sessionCookieValue.lifetime.c).toEqual(frozenTimeSec);
      expect(sessionCookieValue.lifetime.c).toEqual(
        sessionCookieValue.lifetime.u
      );
      expect(sessionCookieValue.lifetime.e).toEqual(frozenTimeSec + 86400);
      expect(await store.get(key)).toEqual(session);

      expect(res.cookies.cookie_name.options).toEqual({
        domain: cookieOptions.domain,
        httpOnly: cookieOptions.httpOnly,
        sameSite: cookieOptions.sameSite,
        secure: cookieOptions.secure,
        path: cookieOptions.path,
        expires: new Date((frozenTimeSec + 86400) * 1000),
      });
    });

    it('should be able to get the session with configured options', async () => {
      const store = new TestStore();

      const service = await getService({
        session: { cookie: { name: 'cookie_name' }, store },
      });

      const session = defaultSessionData();

      const cookies = {
        cookie_name: { value: await getSessionCookie({ session, store }) },
      } as any;

      const sessionValue = (await service.getSession(
        new TestReq({ cookies }),
        new TestRes(cookies)
      ))!;

      expect(sessionValue).toEqual(session);
      expect(await store.get(defaultStoreKeyForTest)).toEqual(session);
    });

    it('should be able to update the session with configured options', async () => {
      const cookieOptions = {
        domain: 'cookie_domain',
        httpOnly: true,
        name: 'cookie_name',
        path: 'cookie_path',
        persistent: true,
        sameSite: 'lax' as SameSiteValues,
        secure: true,
      };

      const store = new TestStore();

      const service = await getService({
        session: { cookie: cookieOptions, store },
      });

      const session = defaultSessionData();

      const cookies = {
        cookie_name: {
          value: await getSessionCookie({
            session,
            store,
          }),
        },
      } as any;

      const newSession = { ...session, newValue: 'yoohoo' };

      const updateResult = await service.updateSession(
        new TestReq({ cookies }),
        new TestRes(cookies),
        newSession
      );

      expect(updateResult).toBe(true);

      const sessionValue = (await service.getSession(
        new TestReq({ cookies }),
        new TestRes(cookies)
      ))!;

      expect(sessionValue).toEqual(newSession);
      expect(await store.get(defaultStoreKeyForTest)).toEqual(newSession);

      const sessionCookieValue: SessionCookieValue = JSON.parse(
        (await decryptData(
          cookies.cookie_name.value,
          defaultConfig.cookieSecret!
        )) as string
      );

      expect(sessionCookieValue.key.length).toBeGreaterThan(0);
      expect(sessionCookieValue.session).toBeUndefined();
      expect(sessionCookieValue.lifetime.c).toEqual(frozenTimeSec);
      expect(sessionCookieValue.lifetime.c).toEqual(
        sessionCookieValue.lifetime.u
      );
      expect(sessionCookieValue.lifetime.e).toEqual(frozenTimeSec + 86400);
    });

    it('should remove the session cookie with configured options', async () => {
      const store = new TestStore();

      const cookieOptions = {
        name: 'cookie_name',
      };

      const service = await getService({
        session: { cookie: cookieOptions, store },
      });

      const cookies = {
        other: { value: 'abc' },
        cookie_name: { value: await getSessionCookie({ store }) },
      } as any;

      await service.removeSession(
        new TestReq({ cookies }),
        new TestRes(cookies)
      );

      expect(await store.get(defaultStoreKeyForTest)).toBeUndefined();
      expect(Object.entries(cookies).length).toBe(2);
      expect(cookies.cookie_name.options.expires).toEqual(new Date(0));
      expect(cookies.cookie_name.value).toBe('');
      expect(cookies.other.value).toBe('abc');
    });

    it('should return undefined when getting an expired session', async () => {
      const store = new TestStore();

      const service = await getService({
        session: { duration: 5, store },
      });

      const cookies = {
        session: {
          value: await getSessionCookie({
            session: defaultSessionData(),
            store,
          }),
        },
      } as any;

      // Travel 6 seconds

      const newFrozenTimeMs = frozenTimeMs + 6 * 1000;

      travel(newFrozenTimeMs);

      const sessionValue = await service.getSession(
        new TestReq({ cookies }),
        new TestRes(cookies)
      );

      expect(sessionValue).toBeUndefined();
      expect(Object.entries(cookies).length).toBe(1);
      expect(cookies.session.options.expires).toEqual(new Date(0));
      expect(cookies.session.value).toBe('');
      expect(await store.get(defaultStoreKeyForTest)).toBeUndefined();
    });

    it('should return undefined when getting a session thats not present in the store', async () => {
      const store = new TestStore();

      const service = await getService({ session: { store } });

      const encryptedData = await encryptData(
        JSON.stringify({
          key: defaultStoreKeyForTest,
          lifetime: { e: now() + 1 },
        }),
        defaultConfig.cookieSecret!
      );
      const cookies = { session: { value: encryptedData } } as any;

      const session = await service.getSession(
        new TestReq({ cookies }),
        new TestRes()
      );

      expect(session).toBeUndefined();
    });

    describe('Sliding Session', () => {
      it('should slide the set duration with sliding expiration', async () => {
        const cookieOptions = {
          domain: 'cookie_domain',
          httpOnly: true,
          name: 'cookie_name',
          path: 'cookie_path',
          persistent: true,
          sameSite: 'lax' as SameSiteValues,
          secure: true,
        };

        const store = new TestStore();

        const service = await getService({
          session: {
            cookie: cookieOptions,
            sliding: true,
            duration: 10,
            maximumDuration: 100,
            store,
          },
        });

        const req = new TestReq();
        const res = new TestRes();

        const session: MonoCloudSession = { user: {} };

        const key = await service.setSession(req, res, session);

        let sessionValue: SessionCookieValue = JSON.parse(
          (await decryptData(
            res.cookies.cookie_name.value,
            defaultConfig.cookieSecret!
          )) as string
        );

        expect(sessionValue.lifetime.c).toEqual(frozenTimeSec);
        expect(sessionValue.lifetime.c).toEqual(sessionValue.lifetime.u);
        expect(sessionValue.lifetime.e).toEqual(frozenTimeSec + 10);

        let storeLifeTime = store.lifetimes.get(key)!;

        expect(storeLifeTime.c).toEqual(frozenTimeSec);
        expect(storeLifeTime.c).toEqual(storeLifeTime.u);
        expect(storeLifeTime.e).toEqual(frozenTimeSec + 10);

        expect(res.cookies.cookie_name.options).toEqual({
          domain: cookieOptions.domain,
          httpOnly: cookieOptions.httpOnly,
          sameSite: cookieOptions.sameSite,
          secure: cookieOptions.secure,
          path: cookieOptions.path,
          expires: new Date((frozenTimeSec + 10) * 1000),
        });

        // Travel 9 seconds and check the expiry

        const newFrozenTimeMs = frozenTimeMs + 9 * 1000;
        const newFrozenTimeSec = Math.floor(newFrozenTimeMs / 1000);

        travel(newFrozenTimeMs);

        const updateResult = await service.updateSession(
          new TestReq({ cookies: res.cookies }),
          res,
          session
        );

        expect(updateResult).toBe(true);

        sessionValue = JSON.parse(
          (await decryptData(
            res.cookies.cookie_name.value,
            defaultConfig.cookieSecret!
          )) as string
        );

        expect(sessionValue.lifetime.c).toEqual(frozenTimeSec);
        expect(sessionValue.lifetime.u).toEqual(newFrozenTimeSec);
        expect(sessionValue.lifetime.e).toEqual(newFrozenTimeSec + 10);

        storeLifeTime = store.lifetimes.get(key)!;

        expect(storeLifeTime.c).toEqual(frozenTimeSec);
        expect(storeLifeTime.u).toEqual(newFrozenTimeSec);
        expect(storeLifeTime.e).toEqual(newFrozenTimeSec + 10);

        expect(res.cookies.cookie_name.options).toEqual({
          domain: cookieOptions.domain,
          httpOnly: cookieOptions.httpOnly,
          sameSite: cookieOptions.sameSite,
          secure: cookieOptions.secure,
          path: cookieOptions.path,
          expires: new Date((newFrozenTimeSec + 10) * 1000),
        });
      });

      it('should not exceed max duration while the expiration is sliding', async () => {
        const cookieOptions = {
          domain: 'cookie_domain',
          httpOnly: true,
          name: 'cookie_name',
          path: 'cookie_path',
          persistent: true,
          sameSite: 'lax' as SameSiteValues,
          secure: true,
        };

        const store = new TestStore();

        const service = await getService({
          session: {
            cookie: cookieOptions,
            sliding: true,
            duration: 7,
            maximumDuration: 10,
            store,
          },
        });

        const req = new TestReq();
        const res = new TestRes();

        const session: MonoCloudSession = { user: {} };

        const key = await service.setSession(req, res, session);

        let sessionValue: SessionCookieValue = JSON.parse(
          (await decryptData(
            res.cookies.cookie_name.value,
            defaultConfig.cookieSecret!
          )) as string
        );

        expect(sessionValue.lifetime.c).toEqual(frozenTimeSec);
        expect(sessionValue.lifetime.c).toEqual(sessionValue.lifetime.u);
        expect(sessionValue.lifetime.e).toEqual(frozenTimeSec + 7);

        let storeLifeTime = store.lifetimes.get(key)!;

        expect(storeLifeTime.c).toEqual(frozenTimeSec);
        expect(storeLifeTime.c).toEqual(storeLifeTime.u);
        expect(storeLifeTime.e).toEqual(frozenTimeSec + 7);

        expect(res.cookies.cookie_name.options).toEqual({
          domain: cookieOptions.domain,
          httpOnly: cookieOptions.httpOnly,
          sameSite: cookieOptions.sameSite,
          secure: cookieOptions.secure,
          path: cookieOptions.path,
          expires: new Date((frozenTimeSec + 7) * 1000),
        });

        // Travel 5 seconds and check the expiry

        const newFrozenTimeMs = frozenTimeMs + 5 * 1000;
        const newFrozenTimeSec = Math.floor(newFrozenTimeMs / 1000);

        travel(newFrozenTimeMs);

        const updateResult = await service.updateSession(
          new TestReq({ cookies: res.cookies }),
          res,
          session
        );

        expect(updateResult).toBe(true);

        sessionValue = JSON.parse(
          (await decryptData(
            res.cookies.cookie_name.value,
            defaultConfig.cookieSecret!
          )) as string
        );

        expect(sessionValue.lifetime.c).toEqual(frozenTimeSec);
        expect(sessionValue.lifetime.u).toEqual(newFrozenTimeSec);
        expect(sessionValue.lifetime.e).toEqual(frozenTimeSec + 10);

        storeLifeTime = store.lifetimes.get(key)!;

        expect(storeLifeTime.c).toEqual(frozenTimeSec);
        expect(storeLifeTime.u).toEqual(newFrozenTimeSec);
        expect(storeLifeTime.e).toEqual(frozenTimeSec + 10);

        expect(res.cookies.cookie_name.options).toEqual({
          domain: cookieOptions.domain,
          httpOnly: cookieOptions.httpOnly,
          sameSite: cookieOptions.sameSite,
          secure: cookieOptions.secure,
          path: cookieOptions.path,
          expires: new Date((frozenTimeSec + 10) * 1000),
        });
      });

      it('should be able to get the session from the cookies and resave it', async () => {
        const store = new TestStore();

        const service = await getService({ session: { sliding: true, store } });

        let res = new TestRes();

        const session: MonoCloudSession = {
          user: {
            sub: 'randomid',
          },
          foo: 'bar',
          accessToken: 'at',
          accessTokenExpiration: 0,
          idToken: 'idt',
          refreshToken: 'rt',
          scopes: 'openid',
        };

        const key = await service.setSession(new TestReq(), res, session);

        let sessionCookieValue: SessionCookieValue = JSON.parse(
          (await decryptData(
            res.cookies.session.value,
            defaultConfig.cookieSecret!
          )) as string
        );

        expect(sessionCookieValue.lifetime.c).toEqual(frozenTimeSec);
        expect(sessionCookieValue.lifetime.c).toEqual(
          sessionCookieValue.lifetime.u
        );
        expect(sessionCookieValue.lifetime.e).toEqual(frozenTimeSec + 86400);

        let storeLifeTime = store.lifetimes.get(key)!;

        expect(storeLifeTime.c).toEqual(frozenTimeSec);
        expect(storeLifeTime.u).toEqual(storeLifeTime.c);
        expect(storeLifeTime.e).toEqual(frozenTimeSec + 86400);

        // Travel 1 second

        const newFrozenTimeMs = frozenTimeMs + 1 * 1000;
        const newFrozenTimeSec = Math.floor(newFrozenTimeMs / 1000);

        travel(newFrozenTimeMs);

        // eslint-disable-next-line prefer-destructuring
        const cookies = res.cookies;

        res = new TestRes();
        const sessionValue = (await service.getSession(
          new TestReq({ cookies }),
          res,
          true
        ))!;

        expect(sessionValue).toEqual(session);

        sessionCookieValue = JSON.parse(
          (await decryptData(
            res.cookies.session.value,
            defaultConfig.cookieSecret!
          )) as string
        );

        expect(sessionCookieValue.lifetime.c).toEqual(frozenTimeSec);
        expect(sessionCookieValue.lifetime.u).toEqual(newFrozenTimeSec);
        expect(sessionCookieValue.lifetime.e).toEqual(newFrozenTimeSec + 86400);

        storeLifeTime = store.lifetimes.get(key)!;

        expect(storeLifeTime.c).toEqual(frozenTimeSec);
        expect(storeLifeTime.u).toEqual(newFrozenTimeSec);
        expect(storeLifeTime.e).toEqual(newFrozenTimeSec + 86400);
      });

      it('should be able to get the session from the cookies without resaving it', async () => {
        const store = new TestStore();
        const service = await getService({ session: { sliding: true, store } });

        const res = new TestRes();

        const session: MonoCloudSession = {
          user: {
            sub: 'randomid',
          },
          foo: 'bar',
          accessToken: 'at',
          accessTokenExpiration: 0,
          idToken: 'idt',
          refreshToken: 'rt',
          scopes: 'openid',
        };

        const key = await service.setSession(new TestReq(), res, session);

        let sessionCookieValue: SessionCookieValue = JSON.parse(
          (await decryptData(
            res.cookies.session.value,
            defaultConfig.cookieSecret!
          )) as string
        );

        expect(sessionCookieValue.lifetime.c).toEqual(frozenTimeSec);
        expect(sessionCookieValue.lifetime.u).toEqual(
          sessionCookieValue.lifetime.c
        );
        expect(sessionCookieValue.lifetime.e).toEqual(frozenTimeSec + 86400);

        let storeLifetime = store.lifetimes.get(key)!;

        expect(storeLifetime.c).toEqual(frozenTimeSec);
        expect(storeLifetime.u).toEqual(storeLifetime.c);
        expect(storeLifetime.e).toEqual(frozenTimeSec + 86400);

        // Travel 1 second

        const newFrozenTimeMs = frozenTimeMs + 1 * 1000;

        travel(newFrozenTimeMs);

        const sessionValue = (await service.getSession(
          new TestReq({ cookies: res.cookies }),
          new TestRes(),
          false
        ))!;

        expect(sessionValue).toEqual(session);

        sessionCookieValue = JSON.parse(
          (await decryptData(
            res.cookies.session.value,
            defaultConfig.cookieSecret!
          )) as string
        );

        expect(sessionCookieValue.lifetime.c).toEqual(frozenTimeSec);
        expect(sessionCookieValue.lifetime.c).toEqual(
          sessionCookieValue.lifetime.u
        );
        expect(sessionCookieValue.lifetime.e).toEqual(frozenTimeSec + 86400);

        storeLifetime = store.lifetimes.get(key)!;

        expect(storeLifetime.c).toEqual(frozenTimeSec);
        expect(storeLifetime.u).toEqual(storeLifetime.c);
        expect(storeLifetime.e).toEqual(frozenTimeSec + 86400);
      });

      it('should return undefined when getting an expired session beyond the duration', async () => {
        const store = new TestStore();

        const service = await getService({
          session: { duration: 5, sliding: true, store },
        });

        const session: MonoCloudSession = {
          user: {
            sub: 'randomid',
          },
        };

        const cookies = {};

        const key = await service.setSession(
          new TestReq(),
          new TestRes(cookies),
          session
        );

        // Travel 2 seconds

        const newFrozenTimeMs = frozenTimeMs + 2 * 1000;

        travel(newFrozenTimeMs);

        await service.updateSession(
          new TestReq({ cookies }),
          new TestRes(cookies),
          session
        );

        // Travel 6 seconds

        const newNewFrozenTimeMs = newFrozenTimeMs + 6 * 1000;

        travel(newNewFrozenTimeMs);

        const sessionValue = await service.getSession(
          new TestReq({ cookies }),
          new TestRes(cookies)
        );

        expect(sessionValue).toBeUndefined();
        expect(Object.entries(cookies).length).toBe(1);
        expect((cookies as any).session.options.expires).toEqual(new Date(0));
        expect((cookies as any).session.value).toBe('');
        expect(await store.get(key)).toBeUndefined();
      });

      it('should return undefined when getting an expired session beyond the maximum duration', async () => {
        const store = new TestStore();

        const service = await getService({
          session: { duration: 5, maximumDuration: 10, sliding: true },
        });

        const session: MonoCloudSession = {
          user: {
            sub: 'randomid',
          },
        };

        const cookies = {};

        const key = await service.setSession(
          new TestReq(),
          new TestRes(cookies),
          session
        );

        // Travel 11 seconds
        const newFrozenTimeMs = frozenTimeMs + 11 * 1000;

        travel(newFrozenTimeMs);

        const sessionValue = await service.getSession(
          new TestReq({ cookies }),
          new TestRes(cookies)
        );

        expect(sessionValue).toBeUndefined();
        expect(Object.entries(cookies).length).toBe(1);
        expect((cookies as any).session.options.expires).toEqual(new Date(0));
        expect((cookies as any).session.value).toBe('');
        expect(await store.get(key)).toBeUndefined();
      });
    });

    describe('Absolute Expiration', () => {
      it('should not exceed the configured session duration after updating the session', async () => {
        const cookieOptions = {
          domain: 'cookie_domain',
          httpOnly: true,
          name: 'cookie_name',
          path: 'cookie_path',
          persistent: true,
          sameSite: 'lax' as SameSiteValues,
          secure: true,
        };

        const store = new TestStore();

        const service = await getService({
          session: {
            cookie: cookieOptions,
            duration: 10,
            store,
          },
        });

        const req = new TestReq();
        const res = new TestRes();

        const session: MonoCloudSession = { user: {} };

        const key = await service.setSession(req, res, session);

        let sessionValue: SessionCookieValue = JSON.parse(
          (await decryptData(
            res.cookies.cookie_name.value,
            defaultConfig.cookieSecret!
          )) as string
        );

        expect(sessionValue.lifetime.c).toEqual(frozenTimeSec);
        expect(sessionValue.lifetime.u).toEqual(sessionValue.lifetime.c);
        expect(sessionValue.lifetime.e).toEqual(frozenTimeSec + 10);

        const storeLifeTime = store.lifetimes.get(key)!;

        expect(storeLifeTime.c).toEqual(frozenTimeSec);
        expect(storeLifeTime.u).toEqual(storeLifeTime.c);
        expect(storeLifeTime.e).toEqual(frozenTimeSec + 10);

        expect(res.cookies.cookie_name.options).toEqual({
          domain: cookieOptions.domain,
          httpOnly: cookieOptions.httpOnly,
          sameSite: cookieOptions.sameSite,
          secure: cookieOptions.secure,
          path: cookieOptions.path,
          expires: new Date((frozenTimeSec + 10) * 1000),
        });

        // Travel 9 seconds and check the expiry

        const newFrozenTimeMs = frozenTimeMs + 9 * 1000;
        const newFrozenTimeSec = Math.floor(newFrozenTimeMs / 1000);

        travel(newFrozenTimeMs);

        const updateResult = await service.updateSession(
          new TestReq({ cookies: res.cookies }),
          res,
          session
        );

        expect(updateResult).toBe(true);

        sessionValue = JSON.parse(
          (await decryptData(
            res.cookies.cookie_name.value,
            defaultConfig.cookieSecret!
          )) as string
        );

        expect(sessionValue.lifetime.c).toEqual(frozenTimeSec);
        expect(sessionValue.lifetime.u).toEqual(newFrozenTimeSec);
        expect(sessionValue.lifetime.e).toEqual(frozenTimeSec + 10);

        expect(res.cookies.cookie_name.options).toEqual({
          domain: cookieOptions.domain,
          httpOnly: cookieOptions.httpOnly,
          sameSite: cookieOptions.sameSite,
          secure: cookieOptions.secure,
          path: cookieOptions.path,
          expires: new Date((frozenTimeSec + 10) * 1000),
        });
      });
    });
  });
});
