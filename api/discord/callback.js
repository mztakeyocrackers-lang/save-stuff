const {
  SESSION_COOKIE,
  STATE_COOKIE,
  buildSessionPayload,
  encodeSession,
  fetchDiscordMember,
  fetchDiscordUser,
  fetchPersonnelByDiscordId,
  getConfig,
  parseCookies,
  redirect,
  serializeCookie
} = require('./_lib');

module.exports = async function handler(req, res) {
  const { clientId, clientSecret, guildId, verifiedRoleId, redirectUri, siteUrl, sessionSecret } = getConfig();
  const fallbackUrl = siteUrl || '/';
  const cookies = parseCookies(req);
  const code = req.query.code;
  const state = req.query.state;

  if (!code) {
    redirect(res, `${fallbackUrl}?auth_error=missing_code`, [
      serializeCookie(STATE_COOKIE, '', { maxAge: 0 }),
      serializeCookie(SESSION_COOKIE, '', { maxAge: 0 })
    ]);
    return;
  }

  if (!state || state !== cookies[STATE_COOKIE]) {
    redirect(res, `${fallbackUrl}?auth_error=oauth_failed`, [
      serializeCookie(STATE_COOKIE, '', { maxAge: 0 }),
      serializeCookie(SESSION_COOKIE, '', { maxAge: 0 })
    ]);
    return;
  }

  try {
    const tokenResponse = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        client_id: clientId,
        client_secret: clientSecret,
        grant_type: 'authorization_code',
        code: String(code),
        redirect_uri: redirectUri
      }).toString()
    });

    const tokenData = await tokenResponse.json();
    if (!tokenResponse.ok || !tokenData.access_token) {
      throw new Error(tokenData?.error_description || tokenData?.error || 'Token exchange failed.');
    }

    const user = await fetchDiscordUser(tokenData.access_token);
    let member;
    try {
      member = await fetchDiscordMember(tokenData.access_token, guildId);
    } catch (error) {
      const reason = error?.status === 404 ? 'not_in_guild' : 'oauth_failed';
      redirect(res, `${fallbackUrl}?auth_error=${reason}`, [
        serializeCookie(STATE_COOKIE, '', { maxAge: 0 }),
        serializeCookie(SESSION_COOKIE, '', { maxAge: 0 })
      ]);
      return;
    }

    const roles = Array.isArray(member?.roles) ? member.roles.map(String) : [];
    if (!roles.includes(String(verifiedRoleId))) {
      redirect(res, `${fallbackUrl}?auth_error=missing_role`, [
        serializeCookie(STATE_COOKIE, '', { maxAge: 0 }),
        serializeCookie(SESSION_COOKIE, '', { maxAge: 0 })
      ]);
      return;
    }

    const personnel = await fetchPersonnelByDiscordId(String(user.id));
    if (!personnel) {
      redirect(res, `${fallbackUrl}?auth_error=not_whitelisted`, [
        serializeCookie(STATE_COOKIE, '', { maxAge: 0 }),
        serializeCookie(SESSION_COOKIE, '', { maxAge: 0 })
      ]);
      return;
    }

    const payload = buildSessionPayload({
      user,
      personnel,
      accessToken: tokenData.access_token,
      expiresIn: tokenData.expires_in
    });

    redirect(res, `${fallbackUrl}?auth=1`, [
      serializeCookie(STATE_COOKIE, '', { maxAge: 0 }),
      serializeCookie(SESSION_COOKIE, encodeSession(payload, sessionSecret), {
        maxAge: Math.max(300, Math.min(Number(tokenData.expires_in || 3600), 43200))
      })
    ]);
  } catch {
    redirect(res, `${fallbackUrl}?auth_error=oauth_failed`, [
      serializeCookie(STATE_COOKIE, '', { maxAge: 0 }),
      serializeCookie(SESSION_COOKIE, '', { maxAge: 0 })
    ]);
  }
};
