const SOFA_HEADERS = {
  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  'Accept': 'application/json, text/plain, */*',
  'Accept-Language': 'fr-FR,fr;q=0.9,en;q=0.8',
  'Referer': 'https://www.sofascore.com/',
  'Origin': 'https://www.sofascore.com',
  'sec-ch-ua': '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
  'sec-ch-ua-mobile': '?0',
  'sec-ch-ua-platform': '"Windows"',
  'sec-fetch-dest': 'empty',
  'sec-fetch-mode': 'cors',
  'sec-fetch-site': 'same-site',
};

function isBlocked(text) {
  if (!text) return true;
  const t = text.trim();
  if (t.startsWith('<')) return true;
  try {
    const j = JSON.parse(t);
    if (j.error && (j.error.code === 403 || j.error.reason === 'challenge')) return true;
  } catch {}
  return false;
}

export default async function handler(req, res) {
  const { path } = req.query;
  if (!path || typeof path !== 'string') {
    return res.status(400).json({ error: 'paramètre "path" manquant' });
  }
  const cleanPath = path.replace(/^\/+/, '');

  const urls = [
    `https://api.sofascore.com/api/v1/${cleanPath}`,
    `https://www.sofascore.com/api/v1/${cleanPath}`,
  ];

  const errors = [];
  for (let i = 0; i < urls.length; i++) {
    try {
      const upstream = await fetch(urls[i], { headers: SOFA_HEADERS });
      const text = await upstream.text();
      if (!upstream.ok) { errors.push(`#${i+1}: HTTP ${upstream.status}`); continue; }
      if (isBlocked(text)) { errors.push(`#${i+1}: challenge détecté`); continue; }
      res.setHeader('Cache-Control', 's-maxage=60, stale-while-revalidate');
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('X-Strategy-Used', String(i + 1));
      return res.status(200).send(text);
    } catch (e) {
      errors.push(`#${i+1}: ${e.message}`);
    }
  }
  return res.status(502).json({
    error: 'Sofascore bloque depuis Vercel. Passer au plan B (GitHub Actions).',
    details: errors,
  });
}
