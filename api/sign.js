import { SignJWT } from 'jose';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { privateKey, data } = req.body;

  if (!privateKey || !data) {
    return res.status(400).json({ error: 'Missing privateKey or data' });
  }

  try {
    const alg = 'RS256';
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'pkcs8',
      str2ab(privateKey),
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['sign']
    );

    const jwt = await new SignJWT({})
      .setProtectedHeader({ alg })
      .setIssuedAt()
      .setExpirationTime('1h')
      .sign(key);

    return res.status(200).json({ jwt });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
}

// Helper to convert PEM to ArrayBuffer
function str2ab(pem) {
  const b64 = pem
    .replace(/-----BEGIN PRIVATE KEY-----/, '')
    .replace(/-----END PRIVATE KEY-----/, '')
    .replace(/\s/g, '');
  const binary = atob(b64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}
