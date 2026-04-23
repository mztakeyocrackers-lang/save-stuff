const crypto = require('crypto');
const { STATE_COOKIE, getConfig, redirect, serializeCookie } = require('./_lib');

module.exports = async function handler(req, res) {
  const { clientId, redirectUri, sessionSecret } = getConfig();
  if (!clientId || !redirectUri || !sessionSecret) {
    res.statusCode = 500;
    res.end('Discord portal authentication is not configured yet.');
    return;
  }

  const state = crypto.randomBytes(24).toString('hex');
  const url = new URL('https://discord.com/oauth2/authorize');
  url.searchParams.set('client_id', clientId);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('redirect_uri', redirectUri);
  url.searchParams.set('scope', 'identify guilds.members.read');
  url.searchParams.set('prompt', 'consent');
  url.searchParams.set('state', state);

  redirect(res, url.toString(), [
    serializeCookie(STATE_COOKIE, state, { maxAge: 900 })
  ]);
};
