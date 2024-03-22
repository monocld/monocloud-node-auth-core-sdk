import { CookieSerializeOptions } from 'cookie';
import {
  IMonoCloudCookieRequest,
  IMonoCloudCookieResponse,
} from '../src/types/internal';
import {
  MonoCloudSession,
  MonoCloudSessionStore,
  SessionLifetime,
} from '../src/types';

export class TestRes implements IMonoCloudCookieResponse {
  public readonly cookies: Record<
    string,
    { value: string; options: CookieSerializeOptions }
  >;

  constructor(
    cookies?: Record<string, { value: string; options: CookieSerializeOptions }>
  ) {
    this.cookies = cookies ?? {};
  }

  setCookie(
    cookieName: string,
    value: string,
    options: CookieSerializeOptions
  ): void {
    this.cookies[cookieName] = { value, options };
  }
}

export class TestReq implements IMonoCloudCookieRequest {
  public readonly cookies: Record<
    string,
    { value: string; options: CookieSerializeOptions }
  >;

  constructor(
    cookies?: Record<string, { value: string; options: CookieSerializeOptions }>
  ) {
    this.cookies = cookies ?? {};
  }

  getCookie(name: string): string | undefined {
    return this.cookies[name]?.value;
  }

  getAllCookies(): Map<string, string> {
    const map = new Map();
    Object.keys(this.cookies).forEach(key =>
      map.set(key, this.cookies[key].value)
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
