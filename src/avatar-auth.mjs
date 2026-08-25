import { createHash, generateKeyPairSync, randomBytes, sign as cryptoSign } from 'node:crypto';

const curve25519Prime = (1n << 255n) - 19n;

function mod(value) {
  const result = value % curve25519Prime;
  return result >= 0n ? result : result + curve25519Prime;
}

function modPow(base, exponent) {
  let result = 1n;
  let factor = mod(base);
  let power = exponent;
  while (power > 0n) {
    if ((power & 1n) === 1n) {
      result = mod(result * factor);
    }
    factor = mod(factor * factor);
    power >>= 1n;
  }
  return result;
}

function littleEndianBytesToBigInt(bytes) {
  let result = 0n;
  for (let index = bytes.length - 1; index >= 0; index -= 1) {
    result = (result << 8n) + BigInt(bytes[index]);
  }
  return result;
}

function bigIntToLittleEndianBytes(value, length) {
  const bytes = Buffer.alloc(length);
  let remaining = mod(value);
  for (let index = 0; index < length; index += 1) {
    bytes[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return bytes;
}

function ed25519PublicKeyToX25519(publicKeyBytes) {
  const yBytes = Buffer.from(publicKeyBytes);
  yBytes[31] &= 0x7f;
  const y = littleEndianBytesToBigInt(yBytes);
  const u = mod((1n + y) * modPow(1n - y, curve25519Prime - 2n));
  return bigIntToLittleEndianBytes(u, 32);
}

export function createAvatarSigningIdentity() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const publicKeyDer = publicKey.export({ type: 'spki', format: 'der' });
  const ed25519PublicKey = Buffer.from(publicKeyDer.subarray(-32));
  const pubkeyEd25519 = ed25519PublicKey.toString('hex');
  const sessionId = `05${ed25519PublicKeyToX25519(ed25519PublicKey).toString('hex')}`;

  return {
    sessionId,
    authorizationHeaders(requestPath, content) {
      const timestamp = Date.now();
      const nonce = randomBytes(16).toString('hex');
      const contentSha256 = createHash('sha256').update(content).digest('hex');
      const signingPayload = Buffer.from([
        'deep-avatar-upload-v1',
        'PUT',
        requestPath,
        sessionId,
        pubkeyEd25519,
        String(timestamp),
        nonce,
        contentSha256
      ].join('\n'), 'utf8');

      return {
        'x-deep-session-id': sessionId,
        'x-deep-ed25519': pubkeyEd25519,
        'x-deep-timestamp': String(timestamp),
        'x-deep-nonce': nonce,
        'x-deep-content-sha256': contentSha256,
        'x-deep-signature': cryptoSign(null, signingPayload, privateKey).toString('base64')
      };
    }
  };
}
