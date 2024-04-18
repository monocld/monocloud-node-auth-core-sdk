import { MonoCloudOptionsBase, MonoCloudState, SameSiteValues } from '../types';
import {
  CookieOptions,
  IMonoCloudCookieRequest,
  IMonoCloudCookieResponse,
} from '../types/internal';
import { decryptData, encryptData } from '../utils';

interface StateCookieValue {
  state?: MonoCloudState;
}

export class MonoCloudStateService {
  constructor(private readonly options: MonoCloudOptionsBase) {}

  async setState(
    res: IMonoCloudCookieResponse,
    state: MonoCloudState,
    overrideSameSite?: SameSiteValues
  ): Promise<void> {
    // Initialize the cookie value
    const cookieValue: StateCookieValue = { state };

    // Encrypt the data
    const encrypted = await encryptData(
      JSON.stringify(cookieValue),
      this.options.cookieSecret
    );

    // Set the cookie
    res.setCookie(
      this.options.state.cookie.name,
      encrypted,
      this.getCookieOptions(overrideSameSite)
    );

    return undefined;
  }

  async getState(
    req: IMonoCloudCookieRequest,
    res: IMonoCloudCookieResponse
  ): Promise<MonoCloudState | undefined> {
    // Get the cookie
    const cookie = req.getCookie(this.options.state.cookie.name);

    // Handle no cookie
    if (!cookie) {
      return undefined;
    }

    // Decrypt the cookie value
    const decrypted = await decryptData(cookie, this.options.cookieSecret);

    // Handle no data
    if (!decrypted) {
      return undefined;
    }

    // Parse the cookie
    const stateCookieValue: StateCookieValue = JSON.parse(decrypted);

    // Remove the cookie
    res.setCookie(this.options.state.cookie.name, '', {
      ...this.getCookieOptions(),
      expires: new Date(0),
    });

    // return the state
    return stateCookieValue.state;
  }

  private getCookieOptions(sameSite?: SameSiteValues): CookieOptions {
    return {
      domain: this.options.state.cookie.domain,
      httpOnly: this.options.state.cookie.httpOnly,
      sameSite: sameSite ?? this.options.state.cookie.sameSite,
      secure: this.options.state.cookie.secure,
      path: this.options.state.cookie.path,
    };
  }
}
