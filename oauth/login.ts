import axios from 'axios';

/**
 * Exchanges an OAuth code for tokens.
 * Designed for Cloudflare Workers, Node.js, and remote-first fintech.
 */
export async function login(
  code: string,
  redirectUri: string,
  {
    clientId,
    clientSecret,
    tokenUrl,
  }: { clientId: string; clientSecret: string; tokenUrl: string }
): Promise<{ access_token: string; refresh_token: string }> {
  const res = await axios.post(tokenUrl, {
    code,
    redirect_uri: redirectUri,
    client_id: clientId,
    client_secret: clientSecret,
    grant_type: 'authorization_code',
  });
  return res.data;
}