const crypto = require('crypto');
const { RETURN_COOKIE, STATE_COOKIE, getConfig, redirect, sanitizeReturnTarget, serializeCookie } = require('./_lib');

module.exports = async function handler(req, res) {
  const { clientId, redirectUri, sessionSecret } = getConfig();
  const returnTo = sanitizeReturnTarget(req.query.return_to);
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
    serializeCookie(STATE_COOKIE, state, { maxAge: 900 }),
    serializeCookie(RETURN_COOKIE, returnTo, { maxAge: 900, httpOnly: true }),
  ]);
};
