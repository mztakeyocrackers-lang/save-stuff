const {
  SESSION_COOKIE,
  fetchDiscordMember,
  fetchPersonnelByDiscordId,
  getConfig,
  getSession,
  sendJson,
  serializeCookie
} = require('./_lib');

module.exports = async function handler(req, res) {
  const { guildId, verifiedRoleId } = getConfig();
  const session = getSession(req);

  if (!session?.accessToken || !session?.user?.id) {
    res.setHeader('Set-Cookie', serializeCookie(SESSION_COOKIE, '', { maxAge: 0 }));
    sendJson(res, 401, { error: 'session_expired' });
    return;
  }

  try {
    const member = await fetchDiscordMember(session.accessToken, guildId);
    const roles = Array.isArray(member?.roles) ? member.roles.map(String) : [];
    if (!roles.includes(String(verifiedRoleId))) {
      res.setHeader('Set-Cookie', serializeCookie(SESSION_COOKIE, '', { maxAge: 0 }));
      sendJson(res, 403, { error: 'missing_role' });
      return;
    }

    const personnel = await fetchPersonnelByDiscordId(String(session.user.id));
    if (!personnel) {
      res.setHeader('Set-Cookie', serializeCookie(SESSION_COOKIE, '', { maxAge: 0 }));
      sendJson(res, 403, { error: 'not_whitelisted' });
      return;
    }

    sendJson(res, 200, {
      verified: true,
      user: session.user,
      personnel
    });
  } catch (error) {
    const status = error?.status === 404 ? 403 : 401;
    const code = error?.status === 404 ? 'not_in_guild' : 'session_expired';
    res.setHeader('Set-Cookie', serializeCookie(SESSION_COOKIE, '', { maxAge: 0 }));
    sendJson(res, status, { error: code });
  }
};
