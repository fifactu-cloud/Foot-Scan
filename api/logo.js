const BROWSER_HEADERS = {
  'User-Agent':
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ' +
    'AppleWebKit/537.36 (KHTML, like Gecko) ' +
    'Chrome/131.0.0.0 Safari/537.36',
  Accept: 'image/avif,image/webp,image/png,image/*,*/*;q=0.8',
  'Accept-Language': 'fr-FR,fr;q=0.9,en;q=0.8',
  Referer: 'https://www.sofascore.com/',
  Origin: 'https://www.sofascore.com',
};

// L'app mobile n'envoie ni Referer ni Origin : on l'imite sur l'hôte .app.
const APP_HEADERS = {
  'User-Agent': 'okhttp/4.12.0',
  Accept: 'image/*,*/*;q=0.8',
  'Accept-Language': 'fr-FR,fr;q=0.9',
};

module.exports = async function (req, res) {
  try {
    const raw = (req.query && req.query.teamId) || '';
    const teamId = String(raw).replace(/[^0-9]/g, '');

    if (!teamId) {
      res.statusCode = 400;
      res.setHeader('Content-Type', 'application/json');
      return res.end(JSON.stringify({ error: 'teamId requis' }));
    }

    const targets = [
      [`https://api.sofascore.app/api/v1/team/${teamId}/image`, APP_HEADERS],
      [`https://img.sofascore.com/api/v1/team/${teamId}/image`, BROWSER_HEADERS],
      [`https://www.sofascore.com/api/v1/team/${teamId}/image`, BROWSER_HEADERS],
    ];

    for (const [url, headers] of targets) {
      try {
        const r = await fetch(url, { headers, redirect: 'follow' });
        if (!r.ok) continue;

        const ct = r.headers.get('content-type') || 'image/png';
        if (!ct.toLowerCase().startsWith('image/')) continue;

        const buf = Buffer.from(await r.arrayBuffer());
        if (buf.length < 120) continue;

        res.statusCode = 200;
        res.setHeader('Content-Type', ct);
        res.setHeader(
          'Cache-Control',
          'public, max-age=86400, s-maxage=604800, stale-while-revalidate=86400'
        );
        return res.end(buf);
      } catch (e) {
        // essaie l'URL suivante
      }
    }

    res.statusCode = 404;
    res.setHeader('Content-Type', 'application/json');
    return res.end(JSON.stringify({ error: 'logo introuvable' }));
  } catch (e) {
    res.statusCode = 500;
    res.setHeader('Content-Type', 'application/json');
    return res.end(JSON.stringify({ error: e.message || String(e) }));
  }
};
