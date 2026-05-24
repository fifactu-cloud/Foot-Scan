export default async function handler(req, res) {
  const { path } = req.query;
  if (!path || typeof path !== 'string') {
    return res.status(400).json({ error: 'paramètre "path" manquant' });
  }
  const url = `https://api.sofascore.com/api/v1/${path.replace(/^\/+/, '')}`;
  try {
    const upstream = await fetch(url, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'application/json',
        'Accept-Language': 'en-US,en;q=0.9',
      },
    });
    const text = await upstream.text();
    res.setHeader('Cache-Control', 's-maxage=60, stale-while-revalidate');
    res.setHeader('Content-Type', 'application/json');
    return res.status(upstream.status).send(text);
  } catch (e) {
    return res.status(502).json({ error: e.message });
  }
}
