const QUEUE_KEY = "sofa:queue";
const CACHE_PREFIX = "sofa:cache:";
const ERROR_PREFIX = "sofa:error:";
const REQUEST_PREFIX = "sofa:req:";
const LOCK_PREFIX = "sofa:lock:";

const CACHE_TTL_SECONDS = Number(process.env.SOFA_CACHE_TTL_SECONDS || 86400);
const REQUEST_TTL_SECONDS = 300;
const LOCK_TTL_SECONDS = 30;

function getEnv(name) {
  const value = process.env[name];

  if (!value) {
    throw new Error(`Variable d'environnement manquante: ${name}`);
  }

  return value;
}

function makeRequestId(path) {
  return Buffer.from(path).toString("base64url");
}

async function redisCmd(...cmd) {
  const url = getEnv("UPSTASH_REDIS_REST_URL");
  const token = getEnv("UPSTASH_REDIS_REST_TOKEN");

  const response = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(cmd),
  });

  const text = await response.text();

  if (!response.ok) {
    throw new Error(`Upstash HTTP ${response.status}: ${text}`);
  }

  const data = JSON.parse(text);

  if (data.error) {
    throw new Error(`Upstash error: ${data.error}`);
  }

  return data.result;
}

export default async function handler(req, res) {
  try {
    const { path } = req.query;

    if (!path || typeof path !== "string") {
      return res.status(400).json({
        error: 'Paramètre "path" manquant',
      });
    }

    const cleanPath = path.replace(/^\/+/, "").trim();

    if (!cleanPath || cleanPath.startsWith("http")) {
      return res.status(400).json({
        error: "Path SofaScore invalide",
      });
    }

    const requestId = makeRequestId(cleanPath);
    const cacheKey = `${CACHE_PREFIX}${cleanPath}`;
    const errorKey = `${ERROR_PREFIX}${cleanPath}`;
    const requestKey = `${REQUEST_PREFIX}${requestId}`;
    const lockKey = `${LOCK_PREFIX}${requestId}`;

    const cached = await redisCmd("GET", cacheKey);

    if (cached) {
      res.setHeader("Content-Type", "application/json");
      res.setHeader("Cache-Control", "no-store");
      res.setHeader("X-Foot-Scan-Cache", "HIT");
      return res.status(200).send(cached);
    }

    const cachedError = await redisCmd("GET", errorKey);

    if (cachedError) {
      let payload;

      try {
        payload = JSON.parse(cachedError);
      } catch {
        payload = { error: cachedError };
      }

      return res.status(502).json(payload);
    }

    await redisCmd(
      "SET",
      requestKey,
      JSON.stringify({
        id: requestId,
        path: cleanPath,
        createdAt: Date.now(),
      }),
      "EX",
      String(REQUEST_TTL_SECONDS)
    );

    const lockResult = await redisCmd(
      "SET",
      lockKey,
      "1",
      "EX",
      String(LOCK_TTL_SECONDS),
      "NX"
    );

    if (lockResult === "OK") {
      await redisCmd("LPUSH", QUEUE_KEY, requestId);
    }

    return res.status(202).json({
      status: "queued",
      id: requestId,
      path: cleanPath,
      retryAfter: 1000,
      message: "Requête envoyée au worker local",
    });
  } catch (error) {
    return res.status(500).json({
      error: error.message || String(error),
    });
  }
}
