import { createCipheriv, createDecipheriv, createHash, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';

export const random = () => randomBytes(32).toString('base64url');
export const hash = value => createHash('sha256').update(value).digest('hex');
export function equal(a, b) {
  const left = Buffer.from(String(a)); const right = Buffer.from(String(b));
  return left.length === right.length && timingSafeEqual(left, right);
}
export function passwordMatches(candidate, expected) {
  const salt = 'step-ca-ui-master-v1';
  return timingSafeEqual(scryptSync(candidate, salt, 32), scryptSync(expected, salt, 32));
}
export function encryption(key) {
  const bytes = Buffer.from(key || '', 'base64');
  if (bytes.length !== 32 || bytes.toString('base64') !== key) throw new Error('ENCRYPTION_KEY must be exactly 32 random bytes in standard base64');
  return {
    seal(value) {
      const iv = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', bytes, iv);
      const ciphertext = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
      return Buffer.concat([iv, cipher.getAuthTag(), ciphertext]).toString('base64');
    },
    open(value) {
      const data = Buffer.from(value, 'base64');
      if (data.length < 28) throw new Error('Invalid encrypted data');
      const cipher = createDecipheriv('aes-256-gcm', bytes, data.subarray(0, 12));
      cipher.setAuthTag(data.subarray(12, 28));
      return Buffer.concat([cipher.update(data.subarray(28)), cipher.final()]).toString('utf8');
    }
  };
}
