# 🦅 CloneHawk — Clone & Customize Any Website

Paste a URL to clone any website, or upload a ZIP — then customize it visually in your browser.

Change text, swap images, update colors, links, and SEO. Export as a ready-to-deploy ZIP.

## Features

- **🌐 Clone by URL** — Paste any URL and CloneHawk clones it server-side with httrack. Friendly progress UX while you wait.
- **📦 Upload ZIP** — Already have an HTTrack mirror? Upload the ZIP directly.
- **📝 Text Editor** — Click any heading, paragraph, or link text to edit inline. Global replace across all pages.
- **🖼️ Image Swapper** — Visual grid of all images. Click to upload a replacement.
- **🎨 Color Picker** — Extracted color palette with one-click replacement across CSS + HTML.
- **🔗 Link Manager** — All URLs in one table. Edit booking links, socials, contact info.
- **🏷️ SEO Editor** — Per-page title and meta description editing (syncs OG tags).
- **🔎 Find & Replace** — Bulk text replacement + quick fields for business name, phone, address, email.
- **👁️ Live Preview** — Preview your changes in an iframe before exporting.
- **📦 Export ZIP** — Download your customized site ready to deploy.

## Quick Start

```bash
npm install
node server.js
# Open http://localhost:3456
```

## Deploy

### Docker
```bash
docker build -t clonehawk .
docker run -p 3456:3456 -v clonehawk-data:/app/.workspaces clonehawk
```

### Railway / Render / Fly.io
Just connect the repo. It auto-detects the `Dockerfile` or `npm start`.

### VPS (nginx proxy)
```bash
npm install --production
PORT=3456 node server.js

# nginx config:
# server {
#   server_name clonehawk.yourdomain.com;
#   client_max_body_size 200M;
#   location / { proxy_pass http://127.0.0.1:3456; proxy_set_header Host $host; }
# }
```

## Configuration

All via environment variables (see `.env.example`):

| Variable | Default | Description |
|---|---|---|
| `PORT` | `3456` | Server port |
| `HOST` | `0.0.0.0` | Bind address |
| `WORKSPACE_ROOT` | `./.workspaces` | Where user sessions are stored |
| `UPLOAD_MAX_MB` | `200` | Max ZIP upload size in MB |
| `SESSION_TTL_HOURS` | `24` | How long sessions live before cleanup |
| `CLEANUP_INTERVAL_MIN` | `30` | How often to check for expired sessions |
| `MAX_SESSIONS` | `50` | Max concurrent sessions |
| `BASE_URL` | (empty) | Public URL (for future features) |
| `NODE_ENV` | `development` | Set to `production` for secure cookies |

## How It Works

1. **Clone or Upload** — Paste a URL to clone via httrack, or upload a ZIP of an existing mirror
2. **Extract** — Server processes into a sandboxed session workspace
3. **Scan** — Cheerio parses all HTML/CSS to extract text, images, colors, links, and meta tags
4. **Edit** — User makes changes via the web UI, which writes directly to the extracted files
5. **Export** — User downloads the modified site as a ZIP

Sessions auto-expire after the configured TTL. Each user gets an isolated workspace.

## Tech Stack

- **Node.js + Express** — API server
- **httrack** — Website cloning engine
- **Cheerio** — HTML parsing and manipulation
- **Multer** — File upload handling
- **Vanilla JS** — Zero-framework frontend (fast, no build step)
- **Inter font** — Clean, modern typography

## Best For

- Find a site you like → clone it → make it yours
- Brochure / business websites
- Salon, restaurant, church, studio sites
- Quick rebranding of template sites

## License

MIT
