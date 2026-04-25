const { RETURN_COOKIE, SESSION_COOKIE, STATE_COOKIE, sendJson, serializeCookie } = require('./_lib');

module.exports = async function handler(req, res) {
  res.setHeader('Set-Cookie', [
    serializeCookie(SESSION_COOKIE, '', { maxAge: 0 }),
    serializeCookie(STATE_COOKIE, '', { maxAge: 0 }),
    serializeCookie(RETURN_COOKIE, '', { maxAge: 0 })
  ]);
  sendJson(res, 200, { ok: true });
};
