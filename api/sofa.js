const STRATEGIES = [
  // 1) Direct vers api.sofascore.com (échoue souvent depuis Vercel)
  (path) => ({
    url: `https://api.sofascore.com/api/v1/${path}`,
    headers: {
      'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
      'Accept': 'application/json',
      'Accept-Language': 'fr-FR,fr;q=0.9',
      'Referer': 'https://www.sofascore.com/',
      'Origin': 'https://www.sofascore.com',
    },
  }),
  // 2) Via le sous-domaine www (parfois moins protégé)
  (path) => ({
    url: `https://www.sofascore.com/api/v1/${path}`,
    headers: {
      'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15',
      'Accept': 'application/json',
      'Referer': 'https://www.sofascore.com/',
    },
  }),
  // 3) Via proxy CORS public corsproxy.io
  (path) => ({
    url: `https://corsproxy.io/?url=${encodeURIComponent(`https://api.sofascore.com/api/v1/${path}`)}`,
    headers: { 'Accept': 'application/json' },
  }),
  // 4) Via proxy allorigins
  (path) => ({
    url: `https://api.allorigins.win/raw?url=${encodeURIComponent(`https://api.sofascore.com/api/v1/${path}`)}`,
    headers: { 'Accept': 'application/json' },
  }),
  // 5) Via codetabs
  (path) => ({
    url: `https://api.codetabs.com/v1/proxy?quest=${encodeURIComponent(`https://api.sofascore.com/api/v1/${path}`)}`,
    headers: { 'Accept': 'application/json' },
  }),
];

export default async function handler(req, res) {
  const { path } = req.query;
  if (!path || typeof path !== 'string') {
    return res.status(400).json({ error: 'paramètre "path" manquant' });
  }
  const cleanPath = path.replace(/^\/+/, '');

  const errors = [];
  for (let i = 0; i < STRATEGIES.length; i++) {
    try {
      const { url, headers } = STRATEGIES[i](cleanPath);
      const upstream = await fetch(url, { headers });
      if (!upstream.ok) {
        errors.push(`#${i + 1}: HTTP ${upstream.status}`);
        continue;
      }
      const text = await upstream.text();
      if (!text || text.trim().startsWith('<')) {
        errors.push(`#${i + 1}: réponse HTML`);
        continue;
      }
      res.setHeader('Cache-Control', 's-maxage=60, stale-while-revalidate');
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('X-Strategy-Used', String(i + 1));
      return res.status(200).send(text);
    } catch (e) {
      errors.push(`#${i + 1}: ${e.message}`);
    }
  }
  return res.status(502).json({ error: 'Toutes les stratégies ont échoué', details: errors });
}
