const crypto = require('crypto');

const Q = 'footscan:scan:queue';
const P = 'footscan:scan:job:';
const TTL = Number(process.env.SCAN_JOB_TTL_SECONDS || 86400);

function env(n) {
  if (!process.env[n]) throw new Error('Missing env ' + n);
  return process.env[n];
}

async function redis(cmd) {
  const r = await fetch(env('UPSTASH_REDIS_REST_URL'), {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${env('UPSTASH_REDIS_REST_TOKEN')}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(cmd),
  });

  const j = await r.json();

  if (!r.ok || j.error) {
    throw new Error(j.error || `Upstash ${r.status}`);
  }

  return j.result;
}

async function body(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  if (typeof req.body === 'string') return JSON.parse(req.body || '{}');

  return await new Promise((ok, ko) => {
    let s = '';

    req.on('data', (c) => (s += c));
    req.on('end', () => {
      try {
        ok(s ? JSON.parse(s) : {});
      } catch (e) {
        ko(e);
      }
    });
    req.on('error', ko);
  });
}

function id(x) {
  x = String(x || '').trim();
  if (/^\d+$/.test(x)) return x;

  const m =
    x.match(/#id:(\d+)/) ||
    x.match(/\/event\/(\d+)/) ||
    x.match(/\/(\d+)(?:[/?#]|$)/);

  return m ? m[1] : x;
}

function rank(x) {
  if (x === undefined || x === null || x === '') return null;

  x = Number(String(x).replace(',', '.'));
  return Number.isFinite(x) && x > 0 ? x : null;
}

function skip(x) {
  x = Number(x || 0);
  return Number.isFinite(x) ? Math.max(0, Math.min(5, Math.floor(x))) : 0;
}

function numeric(x, fallback, min, max) {
  if (x === undefined || x === null || x === '') return fallback;
  const n = Number(String(x).replace(',', '.'));
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, n));
}

function bool(x) {
  return x === true || x === 'true' || x === 1 || x === '1';
}

module.exports = async function (req, res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Type', 'application/json; charset=utf-8');

  try {
    if (req.method === 'GET') {
      const jobId = req.query.jobId;

      if (!jobId) {
        res.statusCode = 400;
        return res.end(JSON.stringify({ error: 'jobId manquant' }));
      }

      const raw = await redis(['GET', P + jobId]);

      if (!raw) {
        res.statusCode = 404;
        return res.end(JSON.stringify({ error: 'Job introuvable ou expiré' }));
      }

      return res.end(raw);
    }

    if (req.method !== 'POST') {
      res.statusCode = 405;
      return res.end(JSON.stringify({ error: 'Méthode non autorisée' }));
    }

    const b = await body(req);
    const matchId = id(b.matchId || b.url || b.match);
    const rank1 = rank(b.rank1);
    const rank2 = rank(b.rank2);
    const simultaneousMode = bool(b.simultaneousMode);
    const rankEventStep = numeric(b.rankEventStep, 1, 0.0001, 5);
    const rankEventMode = b.rankEventMode === 'performance' ? 'performance' : 'fixed';
    const winnerMode = b.winnerMode === 'evolution' ? 'evolution' : 'dominance';

    if (!/^\d+$/.test(matchId)) {
      res.statusCode = 400;
      return res.end(JSON.stringify({ error: 'Match ID ou URL WEB invalide' }));
    }

    if (!rank1) {
      res.statusCode = 400;
      return res.end(JSON.stringify({ error: 'Rang 1 invalide' }));
    }

    if (b.rank2 !== undefined && b.rank2 !== '' && !rank2) {
      res.statusCode = 400;
      return res.end(JSON.stringify({ error: 'Rang 2 invalide' }));
    }

    const jid = crypto.randomBytes(12).toString('hex');
    const now = Math.floor(Date.now() / 1000);

    const job = {
      id: jid,
      status: 'queued',
      message: 'Scan ajouté à la file.',
      progress: 0,
      createdAt: now,
      updatedAt: now,
      params: {
        matchId,
        rank1,
        rank2,
        skipHome: skip(b.skipHome),
        skipAway: skip(b.skipAway),
        simultaneousMode,
        rankEventStep,
        rankEventMode,
        winnerMode,
      },
    };

    await redis(['SET', P + jid, JSON.stringify(job), 'EX', String(TTL)]);
    await redis(['LPUSH', Q, jid]);

    return res.end(JSON.stringify(job));
  } catch (e) {
    res.statusCode = 500;
    return res.end(JSON.stringify({ error: e.message || String(e) }));
  }
};
