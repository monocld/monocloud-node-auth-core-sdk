/* eslint-disable no-param-reassign */
import { v4 as uuid } from 'uuid';
import { serialize } from 'cookie';
import { MonoCloudOptionsBase, MonoCloudSession } from '../types';
import { decryptData, encryptData, now } from '../utils';
import {
  CookieOptions,
  IMonoCloudCookieRequest,
  IMonoCloudCookieResponse,
  SessionCookieValue,
} from '../types/internal';

const CHUNK_BYTE_SIZE = 4090;

export class MonoCloudSessionService {
  constructor(private readonly options: MonoCloudOptionsBase) {}

  async setSession(
    req: IMonoCloudCookieRequest,
    res: IMonoCloudCookieResponse,
    session: MonoCloudSession
  ): Promise<string> {
    // Generate a session Id
    const key = uuid();

    // Set the issued and updated time
    const iat = now();
    const uat = iat;

    // Calculate the lifetime of the cookie
    const exp = this.getExpiry(iat, uat);

    // Set the Cookie Value
    const cookieValue: SessionCookieValue = {
      key,
      lifetime: { c: iat, u: uat, e: exp },
    };

    // Save the Session
    await this.saveSession(req, res, cookieValue, session);

    // Return the session Id
    return key;
  }

  async getSession(
    req: IMonoCloudCookieRequest,
    res: IMonoCloudCookieResponse,
    shouldResave = true
  ): Promise<MonoCloudSession | undefined> {
    // Get the current cookie value
    const cookieValue = await this.getCookieData(req);

    // Handle no cookie value
    if (!cookieValue) {
      this.deleteAllCookies(req, res);
      return undefined;
    }

    // Ensure that the session is valid
    const isValid = await this.validateSession(req, res, cookieValue);

    // Handle an invalid session
    if (!isValid) {
      return undefined;
    }

    // Get the new expiry for the cookie
    const uat = now();
    const exp = this.getExpiry(cookieValue.lifetime.c, uat);

    // if there is no session store
    if (!this.options.session.store) {
      const session: MonoCloudSession = { user: {} };

      // ensure that the cookie has a session
      if (!cookieValue.session) {
        return undefined;
      }

      // create a session object
      Object.assign(session, JSON.parse(JSON.stringify(cookieValue.session)));

      // Resave the session if the new expiry is different from the old one
      if (shouldResave && exp !== cookieValue.lifetime.e) {
        await this.saveSession(
          req,
          res,
          {
            ...cookieValue,
            lifetime: { c: cookieValue.lifetime.c, u: uat, e: exp },
          },
          session
        );
      }

      // return the sesison
      return session;
    }

    // Get the session from the store
    const sessionObj = await this.options.session.store.get(cookieValue.key);

    // if there is no session in the store then delete the cookie
    if (!sessionObj) {
      this.deleteAllCookies(req, res);
      return undefined;
    }

    // Get the instance of the session
    const session: MonoCloudSession = { user: {} };
    Object.assign(session, JSON.parse(JSON.stringify(sessionObj)));

    // Resave the session if the new expiry is different from the old one
    if (shouldResave && exp !== cookieValue.lifetime.e) {
      await this.saveSession(
        req,
        res,
        {
          ...cookieValue,
          lifetime: { c: cookieValue.lifetime.c, u: uat, e: exp },
        },
        session
      );
    }

    // return the sesison
    return session;
  }

  async updateSession(
    req: IMonoCloudCookieRequest,
    res: IMonoCloudCookieResponse,
    session: MonoCloudSession
  ): Promise<boolean> {
    // Get the current cookie value
    const cookieValue = await this.getCookieData(req);

    // Handle no cookie value
    if (!cookieValue) {
      this.deleteAllCookies(req, res);
      return false;
    }

    // Ensure that the session is valid
    const isValid = await this.validateSession(req, res, cookieValue);

    // Handle an invalid session
    if (!isValid) {
      return false;
    }

    // Get the new expiry for the cookie
    const uat = now();
    const exp = this.getExpiry(cookieValue.lifetime.c, uat);

    // Save the session
    await this.saveSession(
      req,
      res,
      {
        ...cookieValue,
        lifetime: { c: cookieValue.lifetime.c, u: uat, e: exp },
      },
      session
    );

    return true;
  }

  async removeSession(
    req: IMonoCloudCookieRequest,
    res: IMonoCloudCookieResponse
  ): Promise<void> {
    // Get the current cookie value
    const cookieValue = await this.getCookieData(req);

    // Handle no cookie value
    if (!cookieValue) {
      this.deleteAllCookies(req, res);
      return;
    }

    // If session store is present
    if (this.options.session.store) {
      // Delete the current session from the store
      if (cookieValue.key) {
        await this.options.session.store.delete(cookieValue.key);
      }
    }

    this.deleteAllCookies(req, res);
  }

  private async validateSession(
    req: IMonoCloudCookieRequest,
    res: IMonoCloudCookieResponse,
    cookieValue: SessionCookieValue
  ): Promise<boolean> {
    // Get the current time
    const nowTime = now();

    let isValid = true;

    // Ensure that the expiration has not passed
    if (cookieValue.lifetime.e && cookieValue.lifetime.e < nowTime) {
      isValid = false;
    }

    // If the session is sliding then ensure that the session has not expired based on the last updated time
    if (
      this.options.session.sliding &&
      cookieValue.lifetime.u + this.options.session.duration < nowTime
    ) {
      isValid = false;
    }

    // If the session is sliding then ensure that the session has not crossed the maximum duration allowed
    if (
      cookieValue.lifetime.c + this.options.session.maximumDuration <
      nowTime
    ) {
      isValid = false;
    }

    // return Is Valid if all ok
    if (isValid) {
      return true;
    }

    // If there is a session store then delete the session from the store
    if (this.options.session.store) {
      await this.options.session.store.delete(cookieValue.key);
    }

    this.deleteAllCookies(req, res);

    return false;
  }

  private async saveSession(
    req: IMonoCloudCookieRequest,
    res: IMonoCloudCookieResponse,
    cookieValue: SessionCookieValue,
    session: MonoCloudSession
  ) {
    const cookies = new Set(this.getRequestCookie(req)?.keys ?? []);

    // If no session store is present
    if (!this.options.session.store) {
      // Set the cookie session Value
      cookieValue.session = session;
    }

    // If session store is present
    if (this.options.session.store) {
      // Get the cookie containing the session Id
      const cookieData = await this.getCookieData(req);

      // Delete the current session from the store
      if (cookieData?.key) {
        await this.options.session.store.delete(cookieData.key);
      }

      // Ensure there is no session in the cookie value
      cookieValue.session = undefined;

      // Set the new session in the store
      await this.options.session.store.set(
        cookieValue.key,
        session,
        cookieValue.lifetime
      );
    }

    // Encrypt the cookie value
    const encryptedData = await encryptData(
      JSON.stringify(cookieValue),
      this.options.cookieSecret
    );

    const cookieExpiry = cookieValue.lifetime.e
      ? new Date(cookieValue.lifetime.e * 1000)
      : undefined;

    const cookieOptions = this.getCookieOptions(cookieExpiry);
    const chunkSize =
      CHUNK_BYTE_SIZE -
      serialize(`${this.options.session.cookie.name}.0`, '', cookieOptions)
        .length;

    // Calculate the number of cookie chunks
    const chunks = Math.ceil(encryptedData.length / chunkSize);

    for (let i = 0; i < chunks; i += 1) {
      const encryptedChunk = encryptedData.slice(
        i * chunkSize,
        (i + 1) * chunkSize
      );

      const cookieName =
        chunks === 1
          ? this.options.session.cookie.name
          : `${this.options.session.cookie.name}.${i}`;

      res.setCookie(
        cookieName,
        encryptedChunk,
        this.getCookieOptions(cookieExpiry)
      );

      cookies.delete(cookieName);
    }

    // Delete all cookies which are not required anymore
    cookies.forEach(key => {
      res.setCookie(key, '', this.getCookieOptions(new Date(0)));
    });
  }

  private async getCookieData(
    req: IMonoCloudCookieRequest
  ): Promise<SessionCookieValue | undefined> {
    // Get all the cookies
    const cookieData = this.getRequestCookie(req);

    // Handle no cookies
    if (!cookieData?.value) {
      return undefined;
    }

    // Decrypt the cookie
    const data = await decryptData(cookieData.value, this.options.cookieSecret);

    // Handle no data
    if (!data) {
      return undefined;
    }

    // Return the parsed session cookie value
    return JSON.parse(data);
  }

  private getRequestCookie(
    req: IMonoCloudCookieRequest
  ): { keys: string[]; value: string } | undefined {
    // Get all the cookies
    const cookies = req.getAllCookies();

    // Handle no cookies
    if (!cookies.size) {
      return undefined;
    }

    // If a cookie exists without chunks then return it
    const val = cookies.get(this.options.session.cookie.name);

    if (val) {
      return { keys: [this.options.session.cookie.name], value: val };
    }

    // Filter out the cookies and only keep the relevant ones
    const cookieValues = Array.from(cookies.entries())
      .filter(([cookie]) =>
        cookie.startsWith(`${this.options.session.cookie.name}.`)
      )
      .map(([cookie, value]) => ({
        key: parseInt(cookie.split('.').pop() || '0', 10),
        value,
      }))
      .sort((a, b) => a.key - b.key);

    // Sort the cookies by chunk numbers
    const cookieValue = cookieValues.map(({ value }) => value).join('');

    // Handle empty cookie value
    if (!cookieValue) {
      return undefined;
    }

    // Return the cookie names and values
    return {
      keys: cookieValues.map(
        ({ key }) => `${this.options.session.cookie.name}.${key}`
      ),
      value: cookieValue,
    };
  }

  private getExpiry(iat: number, uat: number): number | undefined {
    // Return null if session is not persistent
    if (!this.options.session.cookie.persistent) {
      return undefined;
    }

    // If session is not sliding the return the absolute expiration
    if (!this.options.session.sliding) {
      return Math.floor(iat + this.options.session.duration);
    }

    // If session is sliding then return the lesser of the next extended time or the maximum duration
    return Math.floor(
      Math.min(
        uat + this.options.session.duration,
        iat + this.options.session.maximumDuration
      )
    );
  }

  private getCookieOptions(exp?: Date): CookieOptions {
    return {
      domain: this.options.session.cookie.domain,
      httpOnly: this.options.session.cookie.httpOnly,
      sameSite: this.options.session.cookie.sameSite,
      secure: this.options.session.cookie.secure,
      path: this.options.session.cookie.path,
      expires: exp,
    };
  }

  private deleteAllCookies(
    req: IMonoCloudCookieRequest,
    res: IMonoCloudCookieResponse
  ) {
    this.getRequestCookie(req)
      ?.keys.filter(x => x.startsWith(this.options.session.cookie.name))
      .forEach(key => {
        res.setCookie(key, '', this.getCookieOptions(new Date(0)));
      });
  }
}
