const crypto = require("crypto");

const SCAN_QUEUE_KEY = "footscan:scan:queue";
const SCAN_JOB_PREFIX = "footscan:scan:job:";
const JOB_TTL_SECONDS = Number(process.env.SCAN_JOB_TTL_SECONDS || 86400);

function getEnv(name) {
  const value = process.env[name];

  if (!value) {
    throw new Error(`Missing environment variable: ${name}`);
  }

  return value;
}

async function redisCommand(command) {
  const url = getEnv("UPSTASH_REDIS_REST_URL");
  const token = getEnv("UPSTASH_REDIS_REST_TOKEN");

  const response = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(command),
  });

  const data = await response.json();

  if (!response.ok || data.error) {
    throw new Error(data.error || `Upstash HTTP ${response.status}`);
  }

  return data.result;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let raw = "";

    req.on("data", (chunk) => {
      raw += chunk;
    });

    req.on("end", () => {
      if (!raw) {
        resolve({});
        return;
      }

      try {
        resolve(JSON.parse(raw));
      } catch (error) {
        reject(new Error("JSON body invalide"));
      }
    });

    req.on("error", reject);
  });
}

function normalizeRank(value) {
  if (value === null || value === undefined || value === "") return null;

  const number = Number(String(value).replace(",", "."));

  if (!Number.isFinite(number) || number < 1) {
    return null;
  }

  return number;
}

function normalizeSkip(value) {
  const number = Number(value || 0);

  if (!Number.isFinite(number) || number < 0) return 0;

  return Math.min(5, Math.floor(number));
}

function extractMatchId(input) {
  const value = String(input || "").trim();

  if (/^\d+$/.test(value)) return value;

  const found =
    value.match(/#id:(\d+)/) ||
    value.match(/\/event\/(\d+)/) ||
    value.match(/\/(\d+)(?:[/?#]|$)/);

  return found ? found[1] : value;
}

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Content-Type", "application/json; charset=utf-8");

  try {
    if (req.method === "GET") {
      const jobId = req.query.jobId;

      if (!jobId) {
        res.statusCode = 400;
        res.end(JSON.stringify({ error: "jobId manquant" }));
        return;
      }

      const raw = await redisCommand(["GET", `${SCAN_JOB_PREFIX}${jobId}`]);

      if (!raw) {
        res.statusCode = 404;
        res.end(JSON.stringify({ error: "Job introuvable ou expiré" }));
        return;
      }

      res.statusCode = 200;
      res.end(raw);
      return;
    }

    if (req.method !== "POST") {
      res.statusCode = 405;
      res.end(JSON.stringify({ error: "Méthode non autorisée" }));
      return;
    }

    const body = await readBody(req);

    const matchId = extractMatchId(body.matchId || body.url || body.match || "");
    const rank1 = normalizeRank(body.rank1);
    const rank2 = normalizeRank(body.rank2);
    const skipHome = normalizeSkip(body.skipHome);
    const skipAway = normalizeSkip(body.skipAway);

    if (!matchId || !/^\d+$/.test(matchId)) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "Match ID ou URL SofaScore invalide" }));
      return;
    }

    if (!rank1) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "Rang 1 invalide" }));
      return;
    }

    if (body.rank2 !== undefined && body.rank2 !== "" && !rank2) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: "Rang 2 invalide" }));
      return;
    }

    const jobId = crypto.randomBytes(12).toString("hex");
    const now = Math.floor(Date.now() / 1000);

    const job = {
      id: jobId,
      status: "queued",
      message: "Scan ajouté à la file d’attente.",
      progress: 0,
      createdAt: now,
      updatedAt: now,
      params: {
        matchId,
        rank1,
        rank2,
        skipHome,
        skipAway,
      },
    };

    await redisCommand([
      "SET",
      `${SCAN_JOB_PREFIX}${jobId}`,
      JSON.stringify(job),
      "EX",
      String(JOB_TTL_SECONDS),
    ]);

    await redisCommand(["LPUSH", SCAN_QUEUE_KEY, jobId]);

    res.statusCode = 200;
    res.end(JSON.stringify(job));
  } catch (error) {
    res.statusCode = 500;
    res.end(JSON.stringify({ error: error.message || String(error) }));
  }
};
