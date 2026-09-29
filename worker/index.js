// Teleskopskinnen arkiv — tar imot videoer fra /last-opp og lagrer dem i R2.
// Opplasting (/multipart/*) er åpen. Arkivet (/login, /list, /delete) krever
// headeren X-Arkiv-Passord. /fil bruker signerte lenker fra /list, så <video>
// og nedlasting fungerer uten header.

const LINK_TTL_SECONDS = 6 * 60 * 60; // signerte lenker varer 6 timer
const MAX_PARTS = 100; // 100 × 50 MB = maks 5 GB per video

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-Arkiv-Passord',
  'Access-Control-Expose-Headers': 'ETag, Content-Range, Content-Length',
};

const json = (obj, status = 200) => new Response(JSON.stringify(obj), {
  status,
  headers: { ...corsHeaders, 'Content-Type': 'application/json' },
});

const enc = new TextEncoder();

function safeEqual(a, b) {
  const x = enc.encode(a || '');
  const y = enc.encode(b || '');
  if (x.length !== y.length) return false;
  return crypto.subtle.timingSafeEqual(x, y);
}

async function sign(secret, message) {
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(message));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function signedUrl(origin, secret, key) {
  const exp = Math.floor(Date.now() / 1000) + LINK_TTL_SECONDS;
  const sig = await sign(secret, `${key}:${exp}`);
  return `${origin}/fil?key=${encodeURIComponent(key)}&exp=${exp}&sig=${sig}`;
}

function cleanName(s) {
  return (s || '').normalize('NFC').replace(/[^\p{L}\p{N}._ -]/gu, '').trim().slice(0, 120) || 'video';
}

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    const url = new URL(request.url);
    const path = url.pathname;
    const secret = env.ARKIV_PASSORD;
    if (!secret) return json({ error: 'ARKIV_PASSORD er ikke satt' }, 500);

    // ─── Signert fil (se/last ned) ──────────────────────────────
    if (request.method === 'GET' && path === '/fil') {
      const key = url.searchParams.get('key');
      const exp = parseInt(url.searchParams.get('exp'), 10);
      const sig = url.searchParams.get('sig');
      if (!key || !exp || !sig || exp < Date.now() / 1000) {
        return new Response('Lenken er utløpt', { status: 403, headers: corsHeaders });
      }
      if (!safeEqual(sig, await sign(secret, `${key}:${exp}`))) {
        return new Response('Ugyldig lenke', { status: 403, headers: corsHeaders });
      }

      const obj = await env.BUCKET.get(key, { range: request.headers });
      if (!obj) return new Response('Finnes ikke', { status: 404, headers: corsHeaders });

      const headers = new Headers(corsHeaders);
      obj.writeHttpMetadata(headers);
      headers.set('ETag', obj.httpEtag);
      headers.set('Accept-Ranges', 'bytes');
      if (url.searchParams.get('dl')) {
        const filename = obj.customMetadata?.originalName || key.split('/').pop();
        headers.set('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(filename)}`);
      }

      if (request.headers.has('Range') && obj.range) {
        const offset = 'suffix' in obj.range ? obj.size - obj.range.suffix : (obj.range.offset ?? 0);
        const length = 'suffix' in obj.range ? obj.range.suffix : (obj.range.length ?? obj.size - offset);
        headers.set('Content-Range', `bytes ${offset}-${offset + length - 1}/${obj.size}`);
        return new Response(obj.body, { status: 206, headers });
      }
      return new Response(obj.body, { headers });
    }

    // ─── Opplasting er åpen (ingen passord) ─────────────────────

    // ─── Multipart: start ───────────────────────────────────────
    if (request.method === 'POST' && path === '/multipart/create') {
      const original = cleanName(url.searchParams.get('filename'));
      const uploader = cleanName(url.searchParams.get('uploader')).slice(0, 40);
      const contentType = url.searchParams.get('contentType') || 'video/mp4';
      if (!contentType.startsWith('video/')) return json({ error: 'Bare video' }, 400);
      const date = new Date().toISOString().slice(0, 10);
      const key = `${date}/${Date.now()}-${original}`;
      const mpu = await env.BUCKET.createMultipartUpload(key, {
        httpMetadata: { contentType },
        customMetadata: { uploader, originalName: original },
      });
      return json({ key: mpu.key, uploadId: mpu.uploadId });
    }

    // ─── Multipart: én del ──────────────────────────────────────
    if (request.method === 'PUT' && path === '/multipart/part') {
      const key = url.searchParams.get('key');
      const uploadId = url.searchParams.get('uploadId');
      const partNumber = parseInt(url.searchParams.get('partNumber'), 10);
      if (!key || !uploadId || !partNumber) {
        return json({ error: 'key, uploadId, partNumber mangler' }, 400);
      }
      if (partNumber > MAX_PARTS) return json({ error: 'Filen er for stor' }, 413);
      const mpu = env.BUCKET.resumeMultipartUpload(key, uploadId);
      const part = await mpu.uploadPart(partNumber, request.body);
      return json({ partNumber: part.partNumber, etag: part.etag });
    }

    // ─── Multipart: fullfør ─────────────────────────────────────
    if (request.method === 'POST' && path === '/multipart/complete') {
      const { key, uploadId, parts } = await request.json();
      if (!key || !uploadId || !Array.isArray(parts)) {
        return json({ error: 'key, uploadId, parts mangler' }, 400);
      }
      const mpu = env.BUCKET.resumeMultipartUpload(key, uploadId);
      await mpu.complete(parts);
      return json({ ok: true });
    }

    // ─── Multipart: avbryt ──────────────────────────────────────
    if (request.method === 'POST' && path === '/multipart/abort') {
      const { key, uploadId } = await request.json();
      if (!key || !uploadId) return json({ error: 'key, uploadId mangler' }, 400);
      await env.BUCKET.resumeMultipartUpload(key, uploadId).abort();
      return json({ ok: true });
    }

    // Alt under her (arkivet) krever passord
    if (!safeEqual(request.headers.get('X-Arkiv-Passord'), secret)) {
      return json({ error: 'Feil passord' }, 401);
    }

    // ─── Sjekk passord ──────────────────────────────────────────
    if (request.method === 'POST' && path === '/login') {
      return json({ ok: true });
    }

    // ─── Liste ──────────────────────────────────────────────────
    if (request.method === 'GET' && path === '/list') {
      const objects = [];
      let cursor;
      do {
        const page = await env.BUCKET.list({ cursor, include: ['customMetadata'] });
        objects.push(...page.objects);
        cursor = page.truncated ? page.cursor : undefined;
      } while (cursor);

      const files = await Promise.all(objects.map(async o => ({
        key: o.key,
        name: o.customMetadata?.originalName || o.key.split('/').pop(),
        uploader: o.customMetadata?.uploader || '',
        size: o.size,
        uploaded: o.uploaded,
        url: await signedUrl(url.origin, secret, o.key),
      })));
      files.sort((a, b) => new Date(b.uploaded) - new Date(a.uploaded));
      return json(files);
    }

    // ─── Slett ──────────────────────────────────────────────────
    if (request.method === 'DELETE' && path === '/delete') {
      const key = url.searchParams.get('key');
      if (!key) return json({ error: 'key mangler' }, 400);
      await env.BUCKET.delete(key);
      return json({ ok: true });
    }

    return json({ error: 'Finnes ikke' }, 404);
  },
};
