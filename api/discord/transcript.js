const {
  SESSION_COOKIE,
  fetchDiscordMember,
  fetchPersonnelByDiscordId,
  fetchSupabaseJson,
  getConfig,
  getSession,
  getTranscriptServiceKeyReady,
  sendJson,
  serializeCookie,
} = require('./_lib');

module.exports = async function handler(req, res) {
  const token = String(req.query.t || '').trim();
  if (!token) {
    sendJson(res, 400, { error: 'missing_token' });
    return;
  }

  if (!getTranscriptServiceKeyReady()) {
    sendJson(res, 500, { error: 'transcript_service_unconfigured' });
    return;
  }

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

    const transcriptUrl = new URL(`${process.env.SUPABASE_URL || 'https://xnqjdgixcocekzehsote.supabase.co'}/rest/v1/ticket_transcripts`);
    transcriptUrl.search = `?${new URLSearchParams({
      select: 'id,public_token,guild_id,channel_id,channel_name,ticket_system_id,ticket_type_label,opener_discord_id,opener_tag,closer_discord_id,closer_tag,close_reason,transcript_message_count,opened_at,closed_at,created_at',
      public_token: `eq.${token}`,
      limit: '1',
    }).toString()}`;

    const transcriptData = await fetchSupabaseJson(transcriptUrl.toString(), { serviceRole: true });
    const transcript = Array.isArray(transcriptData) ? transcriptData[0] || null : null;

    if (!transcript) {
      sendJson(res, 404, { error: 'not_found' });
      return;
    }

    const messagesUrl = new URL(`${process.env.SUPABASE_URL || 'https://xnqjdgixcocekzehsote.supabase.co'}/rest/v1/ticket_transcript_messages`);
    messagesUrl.search = `?${new URLSearchParams({
      select: 'message_id,author_discord_id,author_tag,author_name,content,attachments,embeds,created_at,edited_at,sequence_no',
      transcript_id: `eq.${transcript.id}`,
      order: 'sequence_no.asc,created_at.asc',
    }).toString()}`;

    const messages = await fetchSupabaseJson(messagesUrl.toString(), { serviceRole: true });

    sendJson(res, 200, {
      ok: true,
      viewer: {
        user: session.user,
        personnel,
      },
      transcript,
      messages: Array.isArray(messages) ? messages : [],
    });
  } catch (error) {
    console.error('Transcript fetch failed:', error);
    if (error?.status === 404) {
      res.setHeader('Set-Cookie', serializeCookie(SESSION_COOKIE, '', { maxAge: 0 }));
      sendJson(res, 403, { error: 'not_in_guild' });
      return;
    }

    if (error?.status === 401 || error?.status === 403 || String(error?.message || '').toLowerCase().includes('session')) {
      res.setHeader('Set-Cookie', serializeCookie(SESSION_COOKIE, '', { maxAge: 0 }));
      sendJson(res, 401, { error: 'session_expired' });
      return;
    }

    sendJson(res, 500, { error: 'transcript_fetch_failed' });
  }
};
