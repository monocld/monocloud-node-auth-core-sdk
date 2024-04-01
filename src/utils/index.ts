import dbug from 'debug';

export const toB64Url = (input: string) =>
  input.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

export const fromB64Url = (input: string) => {
  let str = input;
  if (str.length % 4 !== 0) {
    str += '==='.slice(0, 4 - (str.length % 4));
  }

  str = str.replace(/-/g, '+').replace(/_/g, '/');

  return str;
};

const stringToArrayBuffer = (str: string) => {
  const encoder = new TextEncoder();
  return encoder.encode(str);
};

const arrayBufferToString = (buffer: ArrayBuffer) => {
  const decoder = new TextDecoder();
  return decoder.decode(buffer);
};

const arrayBufferToBase64 = (buffer: Uint8Array) => {
  const bytes = new Uint8Array(buffer);
  const binary = bytes.reduce(
    (acc, byte) => acc + String.fromCharCode(byte),
    ''
  );
  return toB64Url(btoa(binary));
};

export const getBoolean = (value?: string): boolean | undefined => {
  const v = value?.toLowerCase()?.trim();

  if (v === 'true') {
    return true;
  }

  if (v === 'false') {
    return false;
  }

  return undefined;
};

export const getNumber = (value?: string): number | undefined => {
  const v = value?.trim();

  if (v === undefined || v.length === 0) {
    return undefined;
  }

  const p = parseInt(v, 10);

  return Number.isNaN(p) ? undefined : p;
};

export const debug = dbug('monocloud-node-auth-core-sdk');

export const encryptData = async (
  data: string,
  secretKey: string
): Promise<string> => {
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const plaintextBuffer = stringToArrayBuffer(data);
  const keyBuffer = await crypto.subtle.digest(
    'SHA-256',
    stringToArrayBuffer(secretKey)
  );
  const key = await crypto.subtle.importKey(
    'raw',
    keyBuffer,
    { name: 'AES-CBC' },
    false,
    ['encrypt']
  );

  const ciphertext = await crypto.subtle.encrypt(
    {
      name: 'AES-CBC',
      iv: iv,
    },
    key,
    plaintextBuffer
  );

  // Concatenate IV and ciphertext into single buffer
  const resultBuffer = new Uint8Array(iv.byteLength + ciphertext.byteLength);
  resultBuffer.set(iv, 0);
  resultBuffer.set(new Uint8Array(ciphertext), iv.byteLength);

  // Convert the result to a Base64-encoded string
  return arrayBufferToBase64(resultBuffer);
};

export const decryptData = async (data: string, secretKey: string) => {
  try {
    const ciphertextBuffer = Uint8Array.from(atob(fromB64Url(data)), c =>
      c.charCodeAt(0)
    );
    const keyBuffer = await crypto.subtle.digest(
      'SHA-256',
      stringToArrayBuffer(secretKey)
    );
    const key = await crypto.subtle.importKey(
      'raw',
      keyBuffer,
      { name: 'AES-CBC' },
      false,
      ['decrypt']
    );
    const iv = ciphertextBuffer.slice(0, 16);
    const decryptedBuffer = await crypto.subtle.decrypt(
      {
        name: 'AES-CBC',
        iv: iv,
      },
      key,
      ciphertextBuffer.slice(16)
    );
    const decryptedText = arrayBufferToString(decryptedBuffer);
    return decryptedText;
  } catch {
    return undefined;
  }
};

export const getAcrValues = (value?: string): string[] => {
  if (typeof value !== 'string' || !value.trim()) {
    return [];
  }

  return value
    .trim()
    .split(' ')
    .map(x => x.trim())
    .filter(x => x.length);
};

export const ensureLeadingSlash = (val?: string): string => {
  const v = val?.trim();

  if (!v) {
    return v as string;
  }

  return v.startsWith('/') ? v : `/${v}`;
};

export const removeTrailingSlash = (val?: string): string => {
  const v = val?.trim();

  if (!v) {
    return v as string;
  }

  return v.endsWith('/') ? v.substring(0, v.length - 1) : v;
};

export const isPresent = (value?: string | number | boolean): boolean => {
  if (typeof value === 'boolean' || typeof value === 'number') {
    return true;
  }
  const v = value?.trim();
  return v !== undefined && v !== null && v.length > 0;
};

export const now = () => Math.floor(Date.now() / 1000);

export const isAbsoluteUrl = (url: string) =>
  (url?.startsWith('http://') || url?.startsWith('https://')) ?? false;

export const isSameHost = (url: string, urlToCheck: string) => {
  try {
    const u = new URL(url);
    const u2 = new URL(urlToCheck);

    return u.origin === u2.origin;
  } catch {
    return false;
  }
};
