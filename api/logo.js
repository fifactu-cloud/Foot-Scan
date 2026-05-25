function svgFallback() {
  return `
    <svg xmlns="http://www.w3.org/2000/svg" width="96" height="96" viewBox="0 0 96 96">
      <defs>
        <linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stop-color="#ef4444"/>
          <stop offset="1" stop-color="#7f1d1d"/>
        </linearGradient>
      </defs>
      <rect width="96" height="96" rx="30" fill="#171717"/>
      <circle cx="48" cy="48" r="30" fill="url(#g)" opacity="0.85"/>
      <text x="48" y="56" text-anchor="middle" font-family="Arial, sans-serif" font-size="26" font-weight="900" fill="white">FC</text>
    </svg>
  `;
}

module.exports = async function handler(req, res) {
  const teamId = String(req.query.teamId || "").trim();

  res.setHeader("Cache-Control", "public, max-age=604800, immutable");

  if (!/^\d+$/.test(teamId)) {
    res.setHeader("Content-Type", "image/svg+xml; charset=utf-8");
    res.statusCode = 200;
    res.end(svgFallback());
    return;
  }

  try {
    const response = await fetch(`https://img.sofascore.com/api/v1/team/${teamId}/image`, {
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131 Safari/537.36",
        "Accept": "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
        "Referer": "https://www.sofascore.com/",
      },
    });

    if (!response.ok) {
      throw new Error(`Logo HTTP ${response.status}`);
    }

    const contentType = response.headers.get("content-type") || "image/png";
    const buffer = Buffer.from(await response.arrayBuffer());

    res.setHeader("Content-Type", contentType);
    res.statusCode = 200;
    res.end(buffer);
  } catch (error) {
    res.setHeader("Content-Type", "image/svg+xml; charset=utf-8");
    res.statusCode = 200;
    res.end(svgFallback());
  }
};
