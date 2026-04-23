const crypto = require('crypto');

const SESSION_COOKIE = 'save_discord_session';
const STATE_COOKIE = 'save_discord_oauth_state';
const SUPABASE_URL = process.env.SUPABASE_URL || 'https://xnqjdgixcocekzehsote.supabase.co';
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InhucWpkZ2l4Y29jZWt6ZWhzb3RlIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzY2NTI4OTIsImV4cCI6MjA5MjIyODg5Mn0.U0zMSMRZE91RYnToZgooIel0VHDyLlxKK-Cr-Oh9ves';

function getConfig() {
  return {
    clientId: process.env.DISCORD_CLIENT_ID || '',
    clientSecret: process.env.DISCORD_CLIENT_SECRET || '',
    guildId: process.env.DISCORD_GUILD_ID || '',
    verifiedRoleId: process.env.DISCORD_VERIFIED_ROLE_ID || '',
    redirectUri: process.env.DISCORD_REDIRECT_URI || '',
    siteUrl: process.env.SITE_URL || '',
    sessionSecret: process.env.SESSION_SECRET || ''
  };
}

function parseCookies(req) {
  const raw = req.headers.cookie || '';
  return raw.split(';').reduce((acc, part) => {
    const [key, ...valueParts] = part.trim().split('=');
    if (!key) return acc;
    acc[key] = decodeURIComponent(valueParts.join('=') || '');
    return acc;
  }, {});
}

function serializeCookie(name, value, options = {}) {
  const bits = [`${name}=${encodeURIComponent(value)}`];
  bits.push(`Path=${options.path || '/'}`);
  if (typeof options.maxAge === 'number') bits.push(`Max-Age=${options.maxAge}`);
  if (options.httpOnly !== false) bits.push('HttpOnly');
  bits.push(`SameSite=${options.sameSite || 'Lax'}`);
  if (options.secure !== false) bits.push('Secure');
  return bits.join('; ');
}

function safeEqual(a, b) {
  const left = Buffer.from(String(a || ''));
  const right = Buffer.from(String(b || ''));
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}

function signValue(value, secret) {
  return crypto.createHmac('sha256', secret).update(value).digest('base64url');
}

function encodeSession(payload, secret) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return `${body}.${signValue(body, secret)}`;
}

function decodeSession(token, secret) {
  if (!token || !secret) return null;
  const [body, sig] = String(token).split('.');
  if (!body || !sig) return null;
  if (!safeEqual(sig, signValue(body, secret))) return null;
  try {
    const parsed = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (!parsed || typeof parsed !== 'object') return null;
    if (parsed.expiresAt && Date.now() > Number(parsed.expiresAt)) return null;
    return parsed;
  } catch {
    return null;
  }
}

function buildSessionPayload({ user, personnel, accessToken, expiresIn }) {
  const lifetimeMs = Math.max(300, Math.min(Number(expiresIn || 3600), 43200)) * 1000;
  return {
    user: {
      id: String(user.id || ''),
      username: String(user.username || ''),
      globalName: String(user.global_name || ''),
      avatar: String(user.avatar || '')
    },
    personnel: {
      id: String(personnel.id || ''),
      callsign: String(personnel.callsign || ''),
      rank: String(personnel.rank || ''),
      roblox_username: String(personnel.roblox_username || ''),
      roblox_id: String(personnel.roblox_id || ''),
      discord: String(personnel.discord || ''),
      discord_id: String(personnel.discord_id || ''),
      status: String(personnel.status || ''),
      category: String(personnel.category || '')
    },
    accessToken: String(accessToken || ''),
    expiresAt: Date.now() + lifetimeMs
  };
}

async function fetchJson(url, options = {}) {
  const response = await fetch(url, options);
  const text = await response.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }
  return { response, data };
}

async function fetchDiscordUser(accessToken) {
  const { response, data } = await fetchJson('https://discord.com/api/users/@me', {
    headers: {
      Authorization: `Bearer ${accessToken}`
    }
  });
  if (!response.ok) throw new Error(data?.message || 'Failed to fetch Discord user.');
  return data;
}

async function fetchDiscordMember(accessToken, guildId) {
  const { response, data } = await fetchJson(`https://discord.com/api/users/@me/guilds/${guildId}/member`, {
    headers: {
      Authorization: `Bearer ${accessToken}`
    }
  });
  if (!response.ok) {
    const error = new Error(data?.message || 'Failed to fetch guild membership.');
    error.status = response.status;
    throw error;
  }
  return data;
}

async function fetchPersonnelByDiscordId(discordId) {
  const url = new URL(`${SUPABASE_URL}/rest/v1/personnel`);
  url.searchParams.set('select', 'id,callsign,rank,roblox_username,roblox_id,discord,discord_id,status,category');
  url.searchParams.set('discord_id', `eq.${discordId}`);
  url.searchParams.set('limit', '1');

  const { response, data } = await fetchJson(url.toString(), {
    headers: {
      apikey: SUPABASE_ANON_KEY,
      Authorization: `Bearer ${SUPABASE_ANON_KEY}`,
      Accept: 'application/json'
    }
  });

  if (!response.ok) {
    throw new Error(data?.message || 'Failed to query linked personnel record.');
  }

  return Array.isArray(data) ? data[0] || null : null;
}

function sendJson(res, statusCode, payload) {
  res.statusCode = statusCode;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.end(JSON.stringify(payload));
}

function redirect(res, location, cookies = []) {
  if (cookies.length) res.setHeader('Set-Cookie', cookies);
  res.statusCode = 302;
  res.setHeader('Location', location);
  res.end();
}

function getSession(req) {
  const { sessionSecret } = getConfig();
  const cookies = parseCookies(req);
  return decodeSession(cookies[SESSION_COOKIE], sessionSecret);
}

module.exports = {
  SESSION_COOKIE,
  STATE_COOKIE,
  buildSessionPayload,
  decodeSession,
  encodeSession,
  fetchDiscordMember,
  fetchDiscordUser,
  fetchPersonnelByDiscordId,
  getConfig,
  getSession,
  parseCookies,
  redirect,
  sendJson,
  serializeCookie
};
