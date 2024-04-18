/* eslint-disable @typescript-eslint/no-explicit-any */
import {
  decryptData,
  encryptData,
  ensureLeadingSlash,
  fromB64Url,
  getAcrValues,
  getBoolean,
  getNumber,
  isAbsoluteUrl,
  isPresent,
  isSameHost,
  now,
  removeTrailingSlash,
  toB64Url,
} from '../src/utils';

describe('getBoolean', () => {
  it('should return true when value is "true"', () => {
    const result = getBoolean('true');
    expect(result).toBe(true);
  });

  it('should return false when value is "false"', () => {
    const result = getBoolean('false');
    expect(result).toBe(false);
  });

  it('should return undefined when value is undefined', () => {
    const result = getBoolean(undefined);
    expect(result).toBeUndefined();
  });

  it('should return undefined when value is not "true" or "false"', () => {
    const result = getBoolean('foo');
    expect(result).toBeUndefined();
  });

  it('should ignore leading and trailing whitespace', () => {
    const result = getBoolean('  true  ');
    expect(result).toBe(true);
  });

  it('should ignore case sensitivity', () => {
    const result = getBoolean('TrUe');
    expect(result).toBe(true);
  });
});

describe('getNumber', () => {
  it('should return the parsed number when value is a valid number string', () => {
    const result = getNumber('123');
    expect(result).toBe(123);
  });

  it('should return undefined when value is an empty string', () => {
    const result = getNumber('');
    expect(result).toBeUndefined();
  });

  it('should return undefined when value is undefined', () => {
    const result = getNumber(undefined);
    expect(result).toBeUndefined();
  });

  it('should return undefined when value is not a valid number string', () => {
    const result = getNumber('foo');
    expect(result).toBeUndefined();
  });

  it('should ignore leading and trailing whitespace', () => {
    const result = getNumber('  456  ');
    expect(result).toBe(456);
  });
});

describe('encryptData and decryptData', () => {
  const data = 'data';
  const secret = 'secretsecretsecr';

  it('should encrypt and decrypt data', async () => {
    const encrypted = await encryptData(data, secret);
    const decrypted = await decryptData(encrypted, secret);
    expect(decrypted).toBe(data);
  });

  it('encrypt should not produce same result everytim', async () => {
    const encrypted1 = await encryptData(data, secret);
    const encrypted2 = await encryptData(data, secret);
    expect(encrypted1).not.toBe(encrypted2);
  });

  it('incorrect secret should not decrypt', async () => {
    const encrypted = await encryptData(data, secret);
    const decrypted = await decryptData(encrypted, `${secret}1`);
    expect(decrypted).toBe(undefined);
  });

  it('should return undefined if incorrect decrypt data', async () => {
    const encrypted = await encryptData(data, secret);
    const decrypted = await decryptData(`${encrypted}1`, secret);
    expect(decrypted).toBe(undefined);
  });
});

describe('toB64Url and fromB64Url', () => {
  it('should convert to base64url', () => {
    const input = 'U1qNPT6g+hJcksD4BaQ7bg==';
    const enc = toB64Url(input);
    const dec = fromB64Url(enc);
    expect(enc).toBe('U1qNPT6g-hJcksD4BaQ7bg');
    expect(dec).toBe(input);
  });
});

describe('getAcrValues', () => {
  it('should return an empty array when value is whitespace', () => {
    const result = getAcrValues('        ');
    expect(result).toEqual([]);
  });

  it('should return an empty array when value is undefined', () => {
    const result = getAcrValues(undefined);
    expect(result).toEqual([]);
  });

  it('should return an empty array when value is not a string', () => {
    const result = getAcrValues(123 as any);
    expect(result).toEqual([]);
  });

  it('should return an empty array when value is an empty string', () => {
    const result = getAcrValues('');
    expect(result).toEqual([]);
  });

  it('should return an array of trimmed non-empty strings when value is a string with multiple values', () => {
    const result = getAcrValues(' value1  value2  value3 ');
    expect(result).toEqual(['value1', 'value2', 'value3']);
  });

  it('should ignore leading and trailing whitespace for each value', () => {
    const result = getAcrValues('  value1   value2   value3  ');
    expect(result).toEqual(['value1', 'value2', 'value3']);
  });

  it('should filter out empty strings', () => {
    const result = getAcrValues(' value1   value2   value3  ');
    expect(result).toEqual(['value1', 'value2', 'value3']);
  });
});

describe('ensureLeadingSlash', () => {
  it('should return the input string with a leading slash if it does not have one', () => {
    const result = ensureLeadingSlash('path');
    expect(result).toBe('/path');
  });

  it('should return the input string as is if it already has a leading slash', () => {
    const result = ensureLeadingSlash('/path');
    expect(result).toBe('/path');
  });

  it('should return an empty string if the input is undefined', () => {
    const result = ensureLeadingSlash(undefined);
    expect(result).toBe(undefined);
  });

  it('should return an empty string if the input is an empty string', () => {
    const result = ensureLeadingSlash('');
    expect(result).toBe('');
  });

  it('should trim leading and trailing whitespace before adding a leading slash', () => {
    const result = ensureLeadingSlash('  path  ');
    expect(result).toBe('/path');
  });
});

describe('removeTrailingSlash', () => {
  it('should remove the trailing slash if present', () => {
    const result = removeTrailingSlash('path/');
    expect(result).toBe('path');
  });

  it('should return the input string as is if it does not have a trailing slash', () => {
    const result = removeTrailingSlash('path');
    expect(result).toBe('path');
  });

  it('should return an empty string if the input is undefined', () => {
    const result = removeTrailingSlash(undefined);
    expect(result).toBe(undefined);
  });

  it('should return an empty string if the input is an empty string', () => {
    const result = removeTrailingSlash('');
    expect(result).toBe('');
  });

  it('should trim leading and trailing whitespace before removing the trailing slash', () => {
    const result = removeTrailingSlash('  path/  ');
    expect(result).toBe('path');
  });
});

describe('isPresent', () => {
  it('should return true when value is a non-empty string', () => {
    const result = isPresent('value');
    expect(result).toBe(true);
  });

  it('should return false when value is an empty string', () => {
    const result = isPresent('');
    expect(result).toBe(false);
  });

  it('should return false when value is undefined', () => {
    const result = isPresent(undefined);
    expect(result).toBe(false);
  });

  it('should return false when value is null', () => {
    const result = isPresent(null as any);
    expect(result).toBe(false);
  });

  it('should return false when value is a string with only whitespace', () => {
    const result = isPresent('   ');
    expect(result).toBe(false);
  });
});

describe('now', () => {
  it('should return the current timestamp in seconds', () => {
    const result = now();
    const currentTimestamp = Math.floor(Date.now() / 1000);
    expect(result).toBeCloseTo(currentTimestamp);
  });
});

describe('isAbsoluteUrl', () => {
  it('should return true for absolute URLs starting with "http:"', () => {
    const result = isAbsoluteUrl('http://example.com');
    expect(result).toBe(true);
  });

  it('should return true for absolute URLs starting with "https:"', () => {
    const result = isAbsoluteUrl('https://example.com');
    expect(result).toBe(true);
  });

  it('should return false for relative URLs', () => {
    const result = isAbsoluteUrl('/path');
    expect(result).toBe(false);
  });

  it('should return false for undefined URLs', () => {
    const result = isAbsoluteUrl(undefined as any);
    expect(result).toBe(false);
  });

  it('should return false for empty URLs', () => {
    const result = isAbsoluteUrl('');
    expect(result).toBe(false);
  });

  it('should return false for URLs starting with "http:" but not followed by "//"', () => {
    const result = isAbsoluteUrl('http:path');
    expect(result).toBe(false);
  });

  it('should return false for URLs starting with "https:" but not followed by "//"', () => {
    const result = isAbsoluteUrl('https:path');
    expect(result).toBe(false);
  });
});

describe('isSameHost', () => {
  it('should return true when the origins of the URLs are the same', () => {
    const url = 'https://example.com/path';
    const urlToCheck = 'https://example.com/other-path';
    const result = isSameHost(url, urlToCheck);
    expect(result).toBe(true);
  });

  it('should return false when the origins of the URLs are different', () => {
    const url = 'https://example.com/path';
    const urlToCheck = 'https://example.org/other-path';
    const result = isSameHost(url, urlToCheck);
    expect(result).toBe(false);
  });

  it('should return false when the URLs are not valid', () => {
    const url = 'invalid-url';
    const urlToCheck = 'https://example.com/other-path';
    const result = isSameHost(url, urlToCheck);
    expect(result).toBe(false);
  });
});
