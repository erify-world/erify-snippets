import axios from 'axios';

/**
 * Refreshes an OAuth access token using a refresh token.
 * Secure for Cloudflare Workers & Node.js deployments.
 */
export async function refreshToken(
  refreshToken: string,
  {
    clientId,
    clientSecret,
    tokenUrl,
  }: { clientId: string; clientSecret: string; tokenUrl: string }
): Promise<{ access_token: string; refresh_token: string }> {
  const res = await axios.post(tokenUrl, {
    refresh_token: refreshToken,
    client_id: clientId,
    client_secret: clientSecret,
    grant_type: 'refresh_token',
  });
  return res.data;
}