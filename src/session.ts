const encoder = new TextEncoder();

const base64UrlEncode = (data: ArrayBuffer | Uint8Array) => {
  const bytes = data instanceof ArrayBuffer ? new Uint8Array(data) : data;
  let binary = '';
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
};

const base64UrlDecode = (input: string) => {
  let str = input.replace(/-/g, '+').replace(/_/g, '/');
  const pad = str.length % 4;
  if (pad) {
    str += '='.repeat(4 - pad);
  }
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
};

const importKey = async (secret: string) => {
  return crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
};

const sign = async (secret: string, payload: string) => {
  const key = await importKey(secret);
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(payload));
  return base64UrlEncode(signature);
};

const verifySignature = async (secret: string, payload: string, sig: string) => {
  try {
    const key = await importKey(secret);
    return crypto.subtle.verify('HMAC', key, base64UrlDecode(sig), encoder.encode(payload));
  } catch {
    return false;
  }
};

export type SessionPayload = {
  userId: string;
  exp: number;
};

const sessionName = 'keybin_session';
const sessionLifetimeMs = 1000 * 60 * 60 * 24 * 7; // 7 days

export const createSessionCookie = async (userId: string, secret: string) => {
  const payload: SessionPayload = { userId, exp: Date.now() + sessionLifetimeMs };
  const json = JSON.stringify(payload);
  const encoded = base64UrlEncode(encoder.encode(json));
  const sig = await sign(secret, encoded);
  return `${sessionName}=${encoded}.${sig}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(
    sessionLifetimeMs / 1000
  )}`;
};

export const clearSessionCookie = () =>
  `${sessionName}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT`;

export const readSessionCookie = async (cookieHeader: string | null | undefined, secret: string) => {
  if (!cookieHeader) return null;
  const cookies = cookieHeader.split(/;\s*/);
  const sessionValue = cookies.find((cookie) => cookie.startsWith(`${sessionName}=`));
  if (!sessionValue) return null;
  const value = sessionValue.split('=')[1];
  if (!value) return null;
  const [encoded, sig] = value.split('.');
  if (!encoded || !sig) return null;
  const valid = await verifySignature(secret, encoded, sig);
  if (!valid) return null;
  try {
    const payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(encoded))) as SessionPayload;
    if (typeof payload.exp !== 'number' || payload.exp < Date.now()) {
      return null;
    }
    return payload;
  } catch {
    return null;
  }
};
