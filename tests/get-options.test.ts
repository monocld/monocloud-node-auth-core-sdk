/* eslint-disable @typescript-eslint/no-dynamic-delete */
import { MonoCloudValidationError } from '../src/errors/monocloud-validation-error';
import { getOptions } from '../src/options/get-options';

describe('Configuration Options', () => {
  const addedEnvs = new Map<string, string>();

  const addEnv = (env: string, value: string) => {
    addedEnvs.set(env, value);
    process.env[env] = value;
  };

  const setRequiredEnv = () => {
    addEnv('MONOCLOUD_AUTH_APP_URL', 'https://example.com');
    addEnv('MONOCLOUD_AUTH_CLIENT_ID', 'client_id');
    addEnv('MONOCLOUD_AUTH_ISSUER', 'https://issuer.monocloud.com');
    addEnv('MONOCLOUD_AUTH_COOKIE_SECRET', 'htmlisnotaprogramminglanguage!!!');
  };

  const clearEnvs = () => {
    addedEnvs.forEach(k => {
      // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
      delete process.env[k];
    });

    addedEnvs.clear();
  };

  afterEach(() => {
    clearEnvs();
  });

  it('should throw if the required properties are not set up', () => {
    expect(() => getOptions()).toThrow(MonoCloudValidationError);
  });

  it('should be able to configure id token claims filter', () => {
    setRequiredEnv();
    addEnv('MONOCLOUD_AUTH_FILTERED_ID_TOKEN_CLAIMS', 'c_hash at_hash');

    const options = getOptions();

    expect(options).toBeDefined();
  });
});
