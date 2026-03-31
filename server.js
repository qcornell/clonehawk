require('dotenv').config();
const express = require('express');
const compression = require('compression');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const cheerio = require('cheerio');
const multer = require('multer');
const mime = require('mime-types');
const { execSync, spawn } = require('child_process');
const archiver = require('archiver');

// ─── Config (env vars with sane defaults) ────────────────────
const PORT = parseInt(process.env.PORT || '3456');
const HOST = process.env.HOST || '0.0.0.0';
const WORKSPACE_ROOT = process.env.WORKSPACE_ROOT || path.join(__dirname, '.workspaces');
const UPLOAD_MAX_MB = parseInt(process.env.UPLOAD_MAX_MB || '200');
const SESSION_TTL_HOURS = parseFloat(process.env.SESSION_TTL_HOURS || '24');
const CLEANUP_INTERVAL_MIN = parseInt(process.env.CLEANUP_INTERVAL_MIN || '30');
const BASE_URL = process.env.BASE_URL || '';  // e.g. https://clonehawk.dappily.io
const MAX_SESSIONS = parseInt(process.env.MAX_SESSIONS || '50');

// ─── Express setup ───────────────────────────────────────────
const app = express();
app.use(compression()); // gzip all responses
app.use(express.json({ limit: '50mb' }));

// Trust proxy for Railway/nginx
app.set('trust proxy', 1);

// Ensure workspace root exists
if (!fs.existsSync(WORKSPACE_ROOT)) fs.mkdirSync(WORKSPACE_ROOT, { recursive: true });

// ─── Session management ──────────────────────────────────────
// Simple cookie-based sessions. Each session gets a workspace dir.
const sessions = new Map(); // sessionId -> { path, createdAt, lastAccess }

function getSessionId(req, res) {
  let sid = req.cookies?.sf_session;
  if (!sid || !sessions.has(sid)) {
    sid = crypto.randomBytes(16).toString('hex');
    res.cookie('sf_session', sid, {
      httpOnly: true,
      sameSite: 'lax',
      maxAge: SESSION_TTL_HOURS * 60 * 60 * 1000,
      secure: process.env.NODE_ENV === 'production'
    });
  }
  return sid;
}

function getSession(req, res) {
  const sid = getSessionId(req, res);
  const session = sessions.get(sid);
  if (session) session.lastAccess = Date.now();
  return session || null;
}

function createSession(sid) {
  const wsPath = path.join(WORKSPACE_ROOT, sid);
  if (!fs.existsSync(wsPath)) fs.mkdirSync(wsPath, { recursive: true });
  const session = { path: wsPath, createdAt: Date.now(), lastAccess: Date.now(), projectPath: null, scanCache: null, undoStack: [], redoStack: [] };
  sessions.set(sid, session);
  return session;
}

function requireSession(req, res) {
  const session = getSession(req, res);
  if (!session || !session.projectPath) {
    res.status(400).json({ error: 'No project loaded. Upload a site ZIP first.' });
    return null;
  }
  return session;
}

// Cookie parser (minimal, no dependency)
app.use((req, res, next) => {
  req.cookies = {};
  const cookieHeader = req.headers.cookie;
  if (cookieHeader) {
    cookieHeader.split(';').forEach(c => {
      const [k, ...v] = c.trim().split('=');
      if (k) req.cookies[k.trim()] = v.join('=').trim();
    });
  }
  next();
});

// Serve static UI
app.use(express.static(path.join(__dirname, 'public'), { maxAge: 0, etag: false }));

// Serve moveable.min.js from node_modules (for iframe injection)
app.get('/api/lib/moveable.min.js', (req, res) => {
  const fp = path.join(__dirname, 'node_modules', 'moveable', 'dist', 'moveable.min.js');
  if (fs.existsSync(fp)) {
    res.setHeader('Content-Type', 'application/javascript');
    res.setHeader('Cache-Control', 'public, max-age=86400');
    fs.createReadStream(fp).pipe(res);
  } else {
    res.status(404).send('// moveable not found');
  }
});

// Serve selecto.min.js from node_modules (for iframe injection)
app.get('/api/lib/selecto.min.js', (req, res) => {
  const fp = path.join(__dirname, 'node_modules', 'selecto', 'dist', 'selecto.min.js');
  if (fs.existsSync(fp)) {
    res.setHeader('Content-Type', 'application/javascript');
    res.setHeader('Cache-Control', 'public, max-age=86400');
    fs.createReadStream(fp).pipe(res);
  } else {
    res.status(404).send('// selecto not found');
  }
});

// ─── Cleanup expired sessions ────────────────────────────────
function cleanupSessions() {
  const now = Date.now();
  const ttlMs = SESSION_TTL_HOURS * 60 * 60 * 1000;

  for (const [sid, session] of sessions) {
    if (now - session.lastAccess > ttlMs) {
      try {
        if (fs.existsSync(session.path)) {
          fs.rmSync(session.path, { recursive: true, force: true });
        }
      } catch (e) { /* ignore cleanup errors */ }
      sessions.delete(sid);
    }
  }
}

setInterval(cleanupSessions, CLEANUP_INTERVAL_MIN * 60 * 1000);

// ─── Helpers ─────────────────────────────────────────────────

// Directories that wget mirrors but aren't real site content
const SKIP_DIRS = ['hts-cache', 'hts-log', 'connect.facebook.net', 'www.googletagmanager.com', '__MACOSX', '.git'];

// Path segments and filenames that indicate non-HTML content (RSS, feeds, sitemaps, etc.)
// wget --adjust-extension saves these as .html but they're actually XML/RSS
const JUNK_PATH_SEGMENTS = ['/feed/', '/feeds/', '/rss/', '/atom/', '/sitemap', '/wp-json/', '/xmlrpc', '/trackback/', '/wp-cron', '/wp-login', '/wp-admin'];
const JUNK_FILENAMES = ['feed', 'rss', 'atom', 'sitemap', 'sitemap_index', 'robots.txt', 'xmlrpc'];

function isJunkHtmlFile(relPath) {
  const lower = relPath.toLowerCase().replace(/\\/g, '/');
  // Check path segments
  for (const seg of JUNK_PATH_SEGMENTS) {
    if (lower.includes(seg)) return true;
  }
  // Check filename (without extension)
  const name = path.basename(lower, path.extname(lower));
  if (JUNK_FILENAMES.includes(name)) return true;
  // Sitemaps with variations (sitemap-1, sitemap-posts, etc.)
  if (name.startsWith('sitemap')) return true;
  return false;
}

// Sniff first bytes of file to detect XML/RSS masquerading as HTML
function isXmlContent(filePath) {
  try {
    const fd = fs.openSync(filePath, 'r');
    const buf = Buffer.alloc(512);
    fs.readSync(fd, buf, 0, 512, 0);
    fs.closeSync(fd);
    const head = buf.toString('utf-8').trim().toLowerCase();
    return head.startsWith('<?xml') || head.startsWith('<rss') || head.startsWith('<feed') || head.startsWith('<urlset') || head.startsWith('<sitemapindex');
  } catch (e) { return false; }
}

function findHtmlFiles(dir, base = dir) {
  let results = [];
  try {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (SKIP_DIRS.includes(entry.name)) continue;
        // Skip feed/rss/sitemap directories entirely
        if (['feed', 'feeds', 'rss', 'atom'].includes(entry.name.toLowerCase())) continue;
        results = results.concat(findHtmlFiles(full, base));
      } else if (entry.name.endsWith('.html') || entry.name.endsWith('.htm')) {
        const rel = path.relative(base, full);
        // Skip known junk paths
        if (isJunkHtmlFile(rel)) continue;
        // Sniff content — skip XML/RSS saved as .html
        if (isXmlContent(full)) continue;
        results.push(rel);
      }
    }
  } catch (e) { /* skip permission errors */ }
  return results;
}

function findImageFiles(dir, base = dir) {
  const exts = ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg', '.ico'];
  let results = [];
  try {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name === 'hts-cache') continue;
        results = results.concat(findImageFiles(full, base));
      } else if (exts.includes(path.extname(entry.name).toLowerCase())) {
        const rel = path.relative(base, full);
        const stat = fs.statSync(full);
        results.push({ path: rel, size: stat.size, name: path.basename(full) });
      }
    }
  } catch (e) { /* skip */ }
  return results;
}

function findCssFiles(dir, base = dir) {
  let results = [];
  try {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name === 'hts-cache') continue;
        results = results.concat(findCssFiles(full, base));
      } else if (entry.name.endsWith('.css')) {
        results.push(path.relative(base, full));
      }
    }
  } catch (e) { /* skip */ }
  return results;
}

// Junk text patterns — HTTrack artifacts, Cloudflare, wget wrappers, etc.
const JUNK_TEXT_PATTERNS = [
  /^httrack/i,
  /httrack website copier/i,
  /open source offline browser/i,
  /local index.*httrack/i,
  /index of locally available sites/i,
  /mirrored from/i,
  /^\s*web site copier/i,
  /cloudflare.*email protection/i,
  /email address is being protected from spambots/i,
  /you need javascript enabled to view it/i,
  /please enable javascript to view/i,
  /this email address is being protected/i,
  /^\[email[\s\u00a0]*protected\]$/i,
  /^please turn javascript on/i,
  /^checking your browser/i,
  /^ray id:/i,
  /^performance.*security by cloudflare/i,
  /^powered by wordpress\.?$/i,
  /^skip to content\.?$/i,
  /^toggle navigation\.?$/i,
  /^menu$/i,
  /^close$/i,
  /^loading\.{0,3}$/i,
  /^search\.{0,3}$/i,
];

// Entire pages to skip based on <title> or body content
const JUNK_PAGE_TITLES = [
  /httrack/i,
  /local index/i,
  /email protection/i,
  /cloudflare/i,
  /just a moment/i,
  /attention required/i,
  /access denied/i,
  /403 forbidden/i,
  /404 not found/i,
  /error \d{3}/i,
];

function isJunkText(text) {
  if (!text) return true;
  const t = text.trim();
  if (t.length < 2) return true;
  for (const pattern of JUNK_TEXT_PATTERNS) {
    if (pattern.test(t)) return true;
  }
  return false;
}

function isJunkPage(html) {
  const $ = cheerio.load(html);
  const title = $('title').text().trim();
  for (const pattern of JUNK_PAGE_TITLES) {
    if (pattern.test(title)) return true;
  }
  // Check for HTTrack wrapper pages (they have a specific structure)
  const bodyText = $('body').text().trim().substring(0, 500).toLowerCase();
  if (bodyText.includes('httrack website copier') || bodyText.includes('httrack index')) return true;
  if (bodyText.includes('cloudflare') && bodyText.includes('email protection')) return true;
  return false;
}

function extractTextBlocks(htmlPath, projectDir) {
  const fullPath = path.join(projectDir, htmlPath);
  const html = fs.readFileSync(fullPath, 'utf-8');

  // Skip entire junk pages
  if (isJunkPage(html)) return [];

  const $ = cheerio.load(html);

  $('script, style, noscript, link, meta').remove();

  const blocks = [];
  const seen = new Set();

  const selectors = 'h1, h2, h3, h4, h5, h6, p, li, a, span, td, th, label, button, [class*="title"], [class*="heading"], [class*="desc"], [class*="text"], blockquote, figcaption, dt, dd';

  $(selectors).each((i, el) => {
    const $el = $(el);
    let text = '';
    $el.contents().each((_, node) => {
      if (node.type === 'text') text += $(node).text();
    });
    text = text.trim();

    const fullText = $el.text().trim();

    if (!fullText || fullText.length < 2 || fullText.length > 2000) return;
    const key = fullText.substring(0, 100);
    if (seen.has(key)) return;
    seen.add(key);

    if (/^[\d\s.,;:!?]+$/.test(fullText)) return;
    if (fullText.startsWith('{') || fullText.startsWith('function')) return;
    if (fullText.startsWith('//') || fullText.startsWith('/*')) return;
    if (isJunkText(fullText)) return;

    const tag = el.tagName?.toLowerCase() || 'unknown';
    const classes = $el.attr('class') || '';
    const id = $el.attr('id') || '';

    let type = 'text';
    if (['h1', 'h2', 'h3', 'h4', 'h5', 'h6'].includes(tag)) type = 'heading';
    else if (tag === 'a') type = 'link';
    else if (tag === 'button') type = 'button';
    else if (tag === 'li') type = 'list-item';
    else if (tag === 'p') type = 'paragraph';

    blocks.push({
      id: `txt_${htmlPath}_${i}`,
      page: htmlPath,
      tag, type,
      text: fullText,
      directText: text,
      classes: classes.substring(0, 200),
      elementId: id,
      index: i
    });
  });

  return blocks;
}

function extractColors(projectDir, _cssFiles, _htmlFiles) {
  const cssFiles = _cssFiles || findCssFiles(projectDir);
  const htmlFiles = _htmlFiles || findHtmlFiles(projectDir);
  const colorMap = new Map();

  const colorRegex = /#(?:[0-9a-fA-F]{3,4}){1,2}\b|rgba?\(\s*\d+\s*,\s*\d+\s*,\s*\d+(?:\s*,\s*[\d.]+)?\s*\)|hsla?\(\s*\d+\s*,\s*[\d.]+%?\s*,\s*[\d.]+%?(?:\s*,\s*[\d.]+)?\s*\)/g;

  for (const cssFile of cssFiles) {
    try {
      const content = fs.readFileSync(path.join(projectDir, cssFile), 'utf-8');
      const matches = content.match(colorRegex) || [];
      for (const color of matches) {
        const norm = color.toLowerCase().replace(/\s+/g, '');
        if (!colorMap.has(norm)) colorMap.set(norm, { color: norm, count: 0, files: new Set() });
        colorMap.get(norm).count++;
        colorMap.get(norm).files.add(cssFile);
      }
    } catch (e) { /* skip */ }
  }

  for (const htmlFile of htmlFiles.slice(0, 15)) {
    try {
      const content = fs.readFileSync(path.join(projectDir, htmlFile), 'utf-8');
      const matches = content.match(colorRegex) || [];
      for (const color of matches) {
        const norm = color.toLowerCase().replace(/\s+/g, '');
        if (!colorMap.has(norm)) colorMap.set(norm, { color: norm, count: 0, files: new Set() });
        colorMap.get(norm).count++;
        colorMap.get(norm).files.add(htmlFile);
      }
    } catch (e) { /* skip */ }
  }

  return Array.from(colorMap.values())
    .map(c => ({ ...c, files: Array.from(c.files) }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 100);
}

function extractLinks(projectDir, _htmlFiles) {
  const htmlFiles = _htmlFiles || findHtmlFiles(projectDir);
  const linkMap = new Map();

  for (const htmlFile of htmlFiles) {
    try {
      const content = fs.readFileSync(path.join(projectDir, htmlFile), 'utf-8');
      const $ = cheerio.load(content);

      $('a[href]').each((i, el) => {
        const href = $(el).attr('href') || '';
        const text = $(el).text().trim().substring(0, 100);
        if (!href || href === '#' || href.startsWith('javascript:') || href.startsWith('#')) return;

        if (!linkMap.has(href)) linkMap.set(href, { href, texts: new Set(), pages: new Set() });
        if (text) linkMap.get(href).texts.add(text);
        linkMap.get(href).pages.add(htmlFile);
      });
    } catch (e) { /* skip */ }
  }

  return Array.from(linkMap.values())
    .map(l => ({ ...l, texts: Array.from(l.texts), pages: Array.from(l.pages) }));
}

function extractMeta(projectDir, _htmlFiles) {
  const htmlFiles = _htmlFiles || findHtmlFiles(projectDir);
  const metaList = [];

  for (const htmlFile of htmlFiles) {
    try {
      const content = fs.readFileSync(path.join(projectDir, htmlFile), 'utf-8');
      const $ = cheerio.load(content);

      metaList.push({
        page: htmlFile,
        title: $('title').first().text().trim(),
        description: $('meta[name="description"]').attr('content') || '',
        ogTitle: $('meta[property="og:title"]').attr('content') || '',
        ogDesc: $('meta[property="og:description"]').attr('content') || '',
        ogImage: $('meta[property="og:image"]').attr('content') || ''
      });
    } catch (e) { /* skip */ }
  }

  return metaList;
}

// Path safety: ensure resolved path stays within project dir
function safePath(projectDir, relPath) {
  const resolved = path.resolve(projectDir, relPath);
  if (!resolved.startsWith(path.resolve(projectDir))) return null;
  return resolved;
}

// ─── Clone jobs ──────────────────────────────────────────────
const cloneJobs = new Map(); // jobId -> { status, progress, message, error, outputDir }

const CLONE_MESSAGES = [
  "Warming up the cloning machine… 🦅",
  "Scanning the target site…",
  "Downloading HTML pages…",
  "Grabbing stylesheets & scripts…",
  "Snagging all those beautiful images…",
  "Following links like a hawk…",
  "Almost there — packaging it up…",
  "Doing a final quality check…",
  "Your site is nearly ready! ✨"
];

function getCloneMessage(progressPct) {
  const idx = Math.min(Math.floor(progressPct / (100 / CLONE_MESSAGES.length)), CLONE_MESSAGES.length - 1);
  return CLONE_MESSAGES[idx];
}

// ─── API Routes ──────────────────────────────────────────────

// Upload ZIP
const upload = multer({
  dest: path.join(WORKSPACE_ROOT, '_uploads'),
  limits: { fileSize: UPLOAD_MAX_MB * 1024 * 1024 }
});

app.post('/api/upload', upload.single('site'), (req, res) => {
  const sid = getSessionId(req, res);

  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

  // Check session limit
  if (sessions.size >= MAX_SESSIONS && !sessions.has(sid)) {
    fs.unlinkSync(req.file.path);
    return res.status(503).json({ error: 'Server at capacity. Try again later.' });
  }

  let session = sessions.get(sid);
  if (!session) session = createSession(sid);

  // Clean previous project if exists
  if (session.projectPath && fs.existsSync(session.projectPath)) {
    fs.rmSync(session.projectPath, { recursive: true, force: true });
  }
  // Clear AI structure cache so new project gets fresh detection
  session._structureCache = null;
  session._structureCacheHomepage = null;
  session.undoStack = [];
  session.redoStack = [];

  const extractDir = path.join(session.path, 'site');
  if (fs.existsSync(extractDir)) fs.rmSync(extractDir, { recursive: true, force: true });
  fs.mkdirSync(extractDir, { recursive: true });

  try {
    // Extract ZIP
    execSync(`unzip -o -q "${req.file.path}" -d "${extractDir}"`, { timeout: 60000 });
    fs.unlinkSync(req.file.path); // clean upload

    // Find the actual site root (might be nested in a folder)
    const entries = fs.readdirSync(extractDir);
    let siteRoot = extractDir;

    // If there's exactly one directory and no HTML files at root, go into it
    if (entries.length === 1) {
      const single = path.join(extractDir, entries[0]);
      if (fs.statSync(single).isDirectory()) {
        siteRoot = single;
      }
    }

    // Also check one more level (common: zip/foldername/www.site.com/)
    const rootFiles = fs.readdirSync(siteRoot);
    const hasHtml = rootFiles.some(f => f.endsWith('.html'));
    if (!hasHtml) {
      // No HTML at current root — look deeper
      const dirs = rootFiles.filter(f => {
        const sub = path.join(siteRoot, f);
        try { return fs.statSync(sub).isDirectory(); } catch(e) { return false; }
      });
      // If only 1-3 directories and one of them has HTML, go into it
      if (dirs.length >= 1 && dirs.length <= 5) {
        for (const entry of dirs) {
          const sub = path.join(siteRoot, entry);
          try {
            const subFiles = fs.readdirSync(sub);
            if (subFiles.some(f => f.endsWith('.html') || f.endsWith('.htm'))) {
              siteRoot = sub;
              break;
            }
            // Check one more level (zip/folder/domain.com/index.html)
            for (const subEntry of subFiles) {
              const subsub = path.join(sub, subEntry);
              try {
                if (fs.statSync(subsub).isDirectory()) {
                  const subsubFiles = fs.readdirSync(subsub);
                  if (subsubFiles.some(f => f.endsWith('.html') || f.endsWith('.htm'))) {
                    siteRoot = subsub;
                    break;
                  }
                }
              } catch (e) { /* skip */ }
            }
            if (siteRoot !== sub && siteRoot !== path.join(siteRoot)) break;
          } catch (e) { /* skip */ }
        }
      }
    }

    session.projectPath = siteRoot;
    session.scanCache = null;
    session.lastAccess = Date.now();

    res.json({ ok: true, path: siteRoot.replace(WORKSPACE_ROOT, '[workspace]') });
  } catch (e) {
    // Clean up on failure
    try { fs.unlinkSync(req.file.path); } catch (_) {}
    try { fs.rmSync(extractDir, { recursive: true, force: true }); } catch (_) {}
    res.status(400).json({ error: 'Failed to extract ZIP: ' + e.message });
  }
});

// ─── Clone from URL ──────────────────────────────────────────
app.post('/api/clone-url', (req, res) => {
  const { url } = req.body;
  if (!url || typeof url !== 'string') return res.status(400).json({ error: 'url is required' });

  // Basic URL validation
  let parsed;
  try { parsed = new URL(url); } catch (e) { return res.status(400).json({ error: 'Invalid URL' }); }
  if (!['http:', 'https:'].includes(parsed.protocol)) return res.status(400).json({ error: 'URL must be http or https' });

  const sid = getSessionId(req, res);
  if (sessions.size >= MAX_SESSIONS && !sessions.has(sid)) {
    return res.status(503).json({ error: 'Server at capacity. Try again later.' });
  }

  let session = sessions.get(sid);
  if (!session) session = createSession(sid);

  // Clean previous project
  if (session.projectPath && fs.existsSync(session.projectPath)) {
    fs.rmSync(session.projectPath, { recursive: true, force: true });
  }
  // Clear AI structure cache so new project gets fresh detection
  session._structureCache = null;
  session._structureCacheHomepage = null;
  session.undoStack = [];
  session.redoStack = [];

  const jobId = crypto.randomBytes(8).toString('hex');
  const outputDir = path.join(session.path, 'clone_' + jobId);
  fs.mkdirSync(outputDir, { recursive: true });

  const job = { status: 'running', progress: 0, message: CLONE_MESSAGES[0], error: null, outputDir };
  cloneJobs.set(jobId, job);

  // Spawn wget --mirror in background (works everywhere, no httrack dependency)
  const siteDir = path.join(outputDir, '_site');
  fs.mkdirSync(siteDir, { recursive: true });

  const wgetArgs = [
    '--mirror',
    '--convert-links',
    '--adjust-extension',
    '--page-requisites',
    '--no-parent',
    '--level=3',
    '--limit-rate=2m',
    '--timeout=15',
    '--tries=2',
    '--wait=0.2',
    '--execute', 'robots=off',
    '--directory-prefix=' + siteDir,
    '--no-verbose',
    '--quota=50m',
    parsed.href
  ];

  const proc = spawn('wget', wgetArgs, {
    cwd: siteDir,
    timeout: 150000 // 2.5 min hard kill
  });

  let lastUpdate = Date.now();
  let fileCount = 0;

  // Parse wget output for progress hints
  const parseOutput = (data) => {
    const text = data.toString();
    // wget --no-verbose prints one line per file: "timestamp URL -> localfile [size]"
    const lines = text.split('\n').filter(l => l.trim());
    fileCount += lines.length;

    const elapsed = (Date.now() - lastUpdate);
    if (elapsed > 1500) {
      job.progress = Math.min(job.progress + 6, 85);
      job.message = getCloneMessage(job.progress) + ` (${fileCount} files)`;
      lastUpdate = Date.now();
    }
  };

  proc.stdout.on('data', parseOutput);
  proc.stderr.on('data', parseOutput);

  // Also bump progress on a timer so the UX feels alive
  const progressTimer = setInterval(() => {
    if (job.status !== 'running') { clearInterval(progressTimer); return; }
    if (job.progress < 85) {
      job.progress = Math.min(job.progress + 5, 85);
      job.message = getCloneMessage(job.progress);
    }
  }, 3000);

  proc.on('close', (code) => {
    clearInterval(progressTimer);

    // wget creates: siteDir/www.example.com/... structure
    // Find the domain folder
    let siteRoot = siteDir;
    try {
      const entries = fs.readdirSync(siteDir).filter(e => {
        return !['.wget-hsts'].includes(e);
      });

      // Look for the domain folder wget creates
      for (const entry of entries) {
        const full = path.join(siteDir, entry);
        if (fs.statSync(full).isDirectory()) {
          // This should be the domain folder (e.g. www.example.com)
          siteRoot = full;
          break;
        }
      }

      // Check if we actually got HTML files
      const htmlFiles = findHtmlFiles(siteRoot);
      if (htmlFiles.length === 0) {
        job.status = 'error';
        job.error = 'Clone produced no HTML files. The site may block crawlers or require JavaScript to render.';
        return;
      }
    } catch (e) {
      job.status = 'error';
      job.error = 'Clone failed: could not read output directory.';
      return;
    }

    // Clean up wget artifacts + junk directories
    for (const junk of ['.wget-hsts', 'robots.txt', 'robots.txt.html']) {
      const jp = path.join(siteRoot, junk);
      try { if (fs.existsSync(jp)) fs.unlinkSync(jp); } catch (_) {}
    }
    try {
      const hsts = path.join(siteDir, '.wget-hsts');
      if (fs.existsSync(hsts)) fs.unlinkSync(hsts);
    } catch (_) {}
    // Remove feed/rss/sitemap directories wget may have created
    for (const junkDir of ['feed', 'feeds', 'rss', 'atom', 'wp-json', 'wp-cron', 'wp-admin', 'wp-login.php', 'xmlrpc.php']) {
      const jp = path.join(siteRoot, junkDir);
      try { if (fs.existsSync(jp)) fs.rmSync(jp, { recursive: true, force: true }); } catch (_) {}
    }

    session.projectPath = siteRoot;
    session.scanCache = null;
    session.lastAccess = Date.now();

    job.status = 'done';
    job.progress = 100;
    job.message = 'Your site is ready! 🦅';
  });

  proc.on('error', (err) => {
    clearInterval(progressTimer);
    job.status = 'error';
    job.error = 'Failed to start clone: ' + err.message;
  });

  res.json({ ok: true, jobId });
});

// Clone status polling
app.get('/api/clone-status/:jobId', (req, res) => {
  const job = cloneJobs.get(req.params.jobId);
  if (!job) return res.status(404).json({ error: 'Job not found' });

  res.json({
    status: job.status,
    progress: job.progress,
    message: job.message,
    error: job.error
  });

  // Clean up completed/errored jobs after client has polled them
  if (job.status === 'done' || job.status === 'error') {
    setTimeout(() => cloneJobs.delete(req.params.jobId), 60000);
  }
});

// Session info
app.get('/api/session', (req, res) => {
  const session = getSession(req, res);
  if (!session) return res.json({ loaded: false });
  res.json({
    loaded: !!session.projectPath,
    ttlHours: SESSION_TTL_HOURS,
    expiresIn: Math.max(0, Math.round((SESSION_TTL_HOURS * 60 * 60 * 1000 - (Date.now() - session.lastAccess)) / 60000)) + ' min'
  });
});

// ─── Logo Detection ──────────────────────────────────────────
// ─── AI-Powered Site Structure Detection ─────────────────────
// Single GPT-4o-mini call to detect logo, nav menu, and footer items from homepage HTML.
// Falls back to basic heuristics if no API key or AI call fails.
async function detectSiteStructure(homepage, projectDir) {
  const result = { logo: null, navMenu: [], footerLinks: [] };
  if (!homepage) return result;

  let html;
  try {
    const htmlPath = path.join(projectDir, homepage);
    if (!fs.existsSync(htmlPath)) return result;
    html = fs.readFileSync(htmlPath, 'utf-8');
  } catch (e) { return result; }

  // Smart extraction: instead of sending raw HTML (which gets truncated on big pages),
  // extract just the structural elements the AI needs — header, nav, footer, and first few hundred chars of body.
  // This is much smaller, always complete, and gives the AI exactly what it needs.
  const $ = cheerio.load(html);

  // Remove scripts, styles, and comments to reduce noise
  $('script, style, noscript, link[rel="stylesheet"]').remove();

  // Extract the key structural sections
  const sections = [];

  // 1. Header content (where logo + nav usually live)
  const header = $('header').first();
  if (header.length) {
    sections.push('<!-- HEADER SECTION -->\n' + $.html(header));
  }

  // 2. All nav elements (primary navigation)
  $('nav').each((_, el) => {
    const navHtml = $.html(el);
    if (!sections.some(s => s.includes(navHtml))) {
      sections.push('<!-- NAV SECTION -->\n' + navHtml);
    }
  });

  // 3. If no header/nav found, look for common menu wrapper patterns, then fallback to body top
  if (!header.length && $('nav').length === 0) {
    // Try common WordPress/Elementor/custom theme patterns
    const menuContainers = $('[class*="menu-container"], [class*="main-menu"], [class*="primary-menu"], [class*="mobile-menu"]');
    let foundMenu = false;
    if (menuContainers.length) {
      // Pick the one with the most links (actual nav, not individual items)
      let best = null;
      menuContainers.each((_, el) => {
        const tag = el.tagName.toLowerCase();
        if (tag === 'li' || tag === 'a') return;
        const linkCount = $(el).find('a').length;
        const h = $.html(el);
        if (linkCount >= 2 && h.length < 5000 && (!best || linkCount > best.links)) {
          best = { html: h, links: linkCount };
        }
      });
      if (best) {
        sections.push('<!-- MENU CONTAINER (no nav/header tags) -->\n' + best.html);
        foundMenu = true;
      }
    }
    if (!foundMenu) {
      const bodyHtml = $('body').html() || '';
      sections.push('<!-- TOP OF BODY (no header/nav tags found) -->\n' + bodyHtml.substring(0, 3000));
    }
  }

  // 4. Footer content — try <footer> tag first, then common class/id patterns
  const footer = $('footer').first();
  if (footer.length) {
    sections.push('<!-- FOOTER SECTION -->\n' + $.html(footer));
  } else {
    // Many WordPress/Elementor sites use divs with footer in class/id instead of <footer>
    // Extract just the links from the footer container (the HTML itself may be huge from Elementor markup)
    const footerCandidates = [];
    $('[id*="footer"], [class*="footer-widget"], [class*="site-footer"], [class*="footer-wrap"], [class*="footer-area"]').each((_, el) => {
      const linkCount = $(el).find('a').length;
      if (linkCount >= 1) {
        // Instead of sending the entire footer HTML (can be 15K+ on Elementor sites),
        // extract just the links with their context — that's all the AI needs
        const links = [];
        $(el).find('a').each((_, a) => {
          const href = $(a).attr('href') || '';
          const text = $(a).text().trim();
          const aria = $(a).attr('aria-label') || '';
          const title = $(a).attr('title') || '';
          const innerHtml = $(a).html() || '';
          links.push(`<a href="${href}" ${aria ? 'aria-label="'+aria+'"' : ''} ${title ? 'title="'+title+'"' : ''}>${innerHtml}</a>`);
        });
        // Also grab any plain text (phone numbers, addresses, etc.)
        const plainTexts = [];
        $(el).find('p, span, div').each((_, t) => {
          const txt = $(t).clone().children().remove().end().text().trim();
          if (txt.length > 3 && txt.length < 200) plainTexts.push(txt);
        });
        footerCandidates.push({
          links: linkCount,
          summary: links.join('\n') + (plainTexts.length ? '\n<!-- Footer text: ' + plainTexts.slice(0, 10).join(' | ') + ' -->' : '')
        });
      }
    });
    footerCandidates.sort((a, b) => b.links - a.links);
    if (footerCandidates.length > 0) {
      sections.push('<!-- FOOTER-LIKE SECTION (extracted links) -->\n' + footerCandidates[0].summary);
    }
  }

  // 5. Any element with "logo" in class/id (in case it's outside header)
  // But skip <body> which on WordPress often has 'wp-custom-logo' class
  $('[class*="logo"], [id*="logo"]').each((_, el) => {
    if (el.tagName.toLowerCase() === 'body' || el.tagName.toLowerCase() === 'html') return;
    const logoHtml = $.html(el);
    if (logoHtml.length < 500 && !sections.some(s => s.includes(logoHtml))) {
      sections.push('<!-- LOGO ELEMENT -->\n' + logoHtml);
    }
  });

  // 5b. Find images with "logo" in their src (many sites don't put "logo" in classes)
  $('img').each((_, el) => {
    const src = ($(el).attr('src') || '').toLowerCase();
    const dataSrc = ($(el).attr('data-src') || $(el).attr('data-lazy-src') || '').toLowerCase();
    if (src.includes('logo') || dataSrc.includes('logo')) {
      const imgHtml = $.html(el);
      if (!sections.some(s => s.includes(imgHtml))) {
        sections.push('<!-- LOGO IMAGE (by src) -->\n' + imgHtml);
      }
    }
  });

  // 6. Menu/navbar elements — pick the best single container (avoid duplicates from nested elements)
  // Prefer containers with 3+ direct links (actual nav bars), skip individual li/menu-item matches
  if ($('nav').length === 0 && !header.length) {
    const menuCandidates = [];
    $('[class*="main-menu"], [class*="primary-menu"], [class*="navbar"], [class*="navigation-wrapper"], [role="navigation"]').each((_, el) => {
      const tag = el.tagName.toLowerCase();
      if (tag === 'li' || tag === 'a') return; // Skip individual items
      const h = $.html(el);
      const linkCount = $(el).find('a').length;
      if (linkCount >= 2 && h.length < 5000 && !sections.some(s => s.includes(h))) {
        menuCandidates.push({ html: h, links: linkCount, size: h.length });
      }
    });
    // Pick the smallest container that has the most links (tightest nav wrapper)
    menuCandidates.sort((a, b) => b.links - a.links || a.size - b.size);
    if (menuCandidates.length > 0) {
      sections.push('<!-- MENU/NAVBAR ELEMENT -->\n' + menuCandidates[0].html);
    }
  }

  const extracted = sections.join('\n\n')
    .replace(/\s{3,}/g, ' ')
    .trim();

  // This should be MUCH smaller than raw HTML — typically 2-8K for most sites
  // But cap at 15K just in case (still way more focused than before)
  const truncated = extracted.length > 15000 ? extracted.substring(0, 15000) : extracted;

  console.log('[scan] Structure extraction: raw HTML=' + html.length + ' chars, extracted=' + extracted.length + ' chars, sent=' + truncated.length + ' chars');
  console.log('[scan] Sections found: ' + sections.length + ' — ' + sections.map(s => s.split('\n')[0]).join(', '));
  // Log first 500 chars of what we're sending so we can debug detection issues
  console.log('[scan] Extracted preview:\n' + truncated.substring(0, 800) + '\n...');

  // Try AI detection first
  if (OPENAI_API_KEY) {
    try {
      const response = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ' + OPENAI_API_KEY
        },
        body: JSON.stringify({
          model: 'gpt-5.4-nano',
          messages: [
            {
              role: 'system',
              content: `You analyze website HTML to detect the site structure. Return ONLY valid JSON, no markdown, no code fences, no explanation.

Detect these 3 things:

1. **logo**: The site's logo image. Look for ANY element that serves as the company/brand logo. This could be:
   - An <img> tag (most common) — return its src and alt
   - An <svg> element used as a logo — return src as null and set "element": "svg"
   - A text-based logo (e.g. <a class="logo">BrandName</a>) — return src as null and set "text" to the brand name
   - A CSS background-image logo — return src as null and note it
   The logo is typically in the header/nav area, often the first visual branding element, often wrapped in a link to the homepage.

2. **navMenu**: The main navigation menu links. These are the primary links visitors use to navigate (Home, About, Services, Contact, etc). Usually in <nav> or <header>. Include the link text and href exactly as written in the HTML. Skip social media icons, login/signup buttons, external links, and utility links (search, cart, etc).

3. **footerLinks**: ALL links in the website footer (<footer> or bottom section). Include EVERYTHING: secondary nav links, legal pages (Privacy, Terms), contact info (email, phone), social media links (Instagram, TikTok, Facebook, Twitter/X, YouTube, LinkedIn), icon-only links (use the platform name as text if the link has no visible text). Include text and href exactly as written. For icon-only social links, use the platform name (e.g. "Instagram", "TikTok") as the text. For email links (mailto:), include the email address as text. For phone links (tel:), include the phone number as text.

Response format:
{
  "logo": { "src": "images/logo.png", "alt": "Company Name", "element": "img" } or null,
  "navMenu": [{ "text": "Home", "href": "/" }, { "text": "About", "href": "/about" }],
  "footerLinks": [{ "text": "Privacy Policy", "href": "/privacy" }, { "text": "Contact", "href": "/contact" }]
}

Rules:
- Return src/href values EXACTLY as they appear in the HTML (don't normalize or clean paths)
- If you can't find a section, return null for logo or [] for arrays
- For navMenu and footerLinks, only include actual meaningful navigation links
- Skip empty href and javascript:void(0)
- Include # anchors that scroll to sections (like #about, #services)
- For footerLinks: include mailto: and tel: links, social media links (even external ones), icon-only links
- Keep text values clean (just the visible link text, no extra whitespace)
- For logo, prefer <img> with src over other types. Check for "logo" in class names, id, alt text, or parent element classes/ids
- If multiple candidate logos exist, pick the one most likely to be the PRIMARY brand logo (usually top-left of page)`
            },
            {
              role: 'user',
              content: 'Here are the key structural sections extracted from the website homepage. Analyze them to detect the logo, navigation menu, and footer links. The sections are labeled with HTML comments indicating where they came from:\n\n' + truncated
            }
          ],
          temperature: 0.1,
          max_completion_tokens: 2000
        })
      });

      if (response.ok) {
        const data = await response.json();
        let content = data.choices?.[0]?.message?.content?.trim();
        console.log('[scan] AI raw response:', content ? content.substring(0, 500) : '(empty)');
        if (content) {
          // Strip markdown fences if present
          content = content.replace(/^```(?:json)?\s*\n?/i, '').replace(/\n?```\s*$/i, '');
          const fb = content.indexOf('{');
          const lb = content.lastIndexOf('}');
          if (fb >= 0 && lb > fb) content = content.substring(fb, lb + 1);

          try {
            const parsed = JSON.parse(content);

            // Process logo — handle img, svg, and text-based logos
            if (parsed.logo) {
              if (parsed.logo.src) {
                let originalSrc = parsed.logo.src;
                let src = parsed.logo.src;
                // Strip full URLs down to relative paths (wget saves files locally)
                try {
                  const urlObj = new URL(src);
                  src = urlObj.pathname.substring(1); // /wp-content/... → wp-content/...
                } catch (e) {
                  // Not a full URL, just clean up relative path
                  src = src.replace(/^\.\//, '');
                  if (src.startsWith('/')) src = src.substring(1);
                }
                result.logo = {
                  src: src,
                  originalSrc: originalSrc, // keep original for proxy fallback
                  alt: parsed.logo.alt || '',
                  element: parsed.logo.element || 'img',
                  page: homepage
                };
              } else if (parsed.logo.element === 'svg') {
                result.logo = {
                  src: null,
                  alt: parsed.logo.alt || '',
                  element: 'svg',
                  page: homepage
                };
              } else if (parsed.logo.text) {
                result.logo = {
                  src: null,
                  alt: '',
                  text: parsed.logo.text,
                  element: 'text',
                  page: homepage
                };
              }
            }

            // Process nav menu
            if (Array.isArray(parsed.navMenu)) {
              result.navMenu = parsed.navMenu
                .filter(item => item.text && item.href)
                .map(item => ({ text: item.text.trim(), href: item.href.trim(), page: homepage }));
            }

            // Process footer links
            if (Array.isArray(parsed.footerLinks)) {
              result.footerLinks = parsed.footerLinks
                .filter(item => item.text && item.href)
                .map(item => ({ text: item.text.trim(), href: item.href.trim(), page: homepage }));
            }

            const logoDesc = result.logo
              ? (result.logo.src || result.logo.text || result.logo.element)
              : 'none';
            console.log('[scan] AI structure detection: logo=' + logoDesc +
              ', nav=' + result.navMenu.length + ' items, footer=' + result.footerLinks.length + ' items');
            return result;
          } catch (parseErr) {
            console.error('[scan] AI detection JSON parse failed:', parseErr.message);
          }
        }
      } else {
        console.error('[scan] AI detection API error:', response.status);
      }
    } catch (aiErr) {
      console.error('[scan] AI detection failed:', aiErr.message);
    }
  }

  // ─── Fallback: basic heuristic detection (no API key or AI failed) ───
  console.log('[scan] Using heuristic fallback for structure detection');
  try {
    const $ = cheerio.load(html);

    // Logo fallback: look for img in header/nav with logo class/id/alt
    let logoImg = null;
    $('header img, nav img').each((_, el) => {
      if (logoImg) return;
      const cls = ($(el).attr('class') || '').toLowerCase();
      const id = ($(el).attr('id') || '').toLowerCase();
      const alt = ($(el).attr('alt') || '').toLowerCase();
      if (cls.includes('logo') || id.includes('logo') || alt.includes('logo')) logoImg = el;
    });
    if (!logoImg) {
      $('img').each((_, el) => {
        if (logoImg) return;
        const cls = ($(el).attr('class') || '').toLowerCase();
        const id = ($(el).attr('id') || '').toLowerCase();
        const alt = ($(el).attr('alt') || '').toLowerCase();
        if (cls.includes('logo') || id.includes('logo') || alt.includes('logo')) logoImg = el;
      });
    }
    if (!logoImg) {
      const headerImg = $('header img').first();
      if (headerImg.length) logoImg = headerImg[0];
      else { const navImg = $('nav img').first(); if (navImg.length) logoImg = navImg[0]; }
    }
    if (logoImg) {
      let src = ($(logoImg).attr('src') || '').replace(/^\.\//, '');
      if (src.startsWith('/')) src = src.substring(1);
      if (src) result.logo = { src, alt: $(logoImg).attr('alt') || '', element: 'img', page: homepage };
    }

    // Nav menu fallback
    let navContainers = $('nav');
    if (!navContainers.length) navContainers = $('header');
    const navSeen = new Set();
    navContainers.find('a').each((_, a) => {
      const href = ($(a).attr('href') || '').trim();
      const text = $(a).text().trim();
      if (!text || !href) return;
      if (href.startsWith('javascript:') || href.startsWith('mailto:') || href.startsWith('tel:')) return;
      if (href.startsWith('http://') || href.startsWith('https://')) return;
      const key = href + '|' + text;
      if (navSeen.has(key)) return;
      navSeen.add(key);
      result.navMenu.push({ text, href, page: homepage });
    });

    // Footer fallback
    const footerSeen = new Set();
    $('footer a').each((_, a) => {
      const href = ($(a).attr('href') || '').trim();
      const text = $(a).text().trim();
      if (!text || !href || href === '#') return;
      if (href.startsWith('javascript:')) return;
      const key = href + '|' + text;
      if (footerSeen.has(key)) return;
      footerSeen.add(key);
      result.footerLinks.push({ text, href, page: homepage });
    });
  } catch (e) {
    console.error('[scan] Heuristic fallback failed:', e.message);
  }

  return result;
}

// Scan project — optimized: file discovery + AI detection run in parallel
app.get('/api/scan', async (req, res) => {
  const session = requireSession(req, res);
  if (!session) return;

  // Return cached scan if available (invalidated on mutations)
  if (session.scanCache) {
    return res.json(session.scanCache);
  }

  try {
    const projectDir = session.projectPath;

    // Phase 1: File discovery — single pass per type, results reused everywhere
    const htmlFiles = findHtmlFiles(projectDir);
    const cssFiles = findCssFiles(projectDir);
    const images = findImageFiles(projectDir);

    // Filter junk pages
    const mainPages = htmlFiles.filter(f => {
      const name = path.basename(f, '.html');
      if (f.includes('/signals/') || f.includes('/schema.org/') ||
          f.includes('hts-cache') || name.startsWith('iwl') ||
          isJunkHtmlFile(f)) return false;
      try {
        const content = fs.readFileSync(path.join(projectDir, f), 'utf-8');
        if (isJunkPage(content)) return false;
      } catch (e) { /* keep if can't read */ }
      return true;
    });

    // Detect homepage early (needed for AI call)
    const homepage = mainPages.find(p => p === 'index.html') 
      || mainPages.find(p => p.match(/^[^/]+\/index\.html$/) && !p.includes('/about') && !p.includes('/contact'))
      || mainPages[0] 
      || null;

    // Phase 2: Reuse cached AI structure detection result if homepage hasn't changed.
    // The AI call detects logo, nav menu, and footer links — these don't change on
    // text edits, color swaps, image replacements, etc. Only re-run AI if homepage changes.
    let structurePromise;
    if (session._structureCache && session._structureCacheHomepage === homepage) {
      structurePromise = Promise.resolve(session._structureCache);
    } else {
      structurePromise = detectSiteStructure(homepage, projectDir).then(result => {
        session._structureCache = result;
        session._structureCacheHomepage = homepage;
        return result;
      });
    }

    // Local extraction runs synchronously while AI call is in flight
    // Pass pre-found file lists to avoid redundant directory walks
    const colors = extractColors(projectDir, cssFiles, htmlFiles);
    const links = extractLinks(projectDir, htmlFiles);
    const meta = extractMeta(projectDir, htmlFiles);
    let textBlocks = [];
    for (const page of mainPages) {
      try {
        textBlocks = textBlocks.concat(extractTextBlocks(page, projectDir));
      } catch (e) { /* skip broken pages */ }
    }

    // Now await the AI result (likely already done by now, or cached)
    const structure = await structurePromise;

    session.scanCache = {
      htmlFiles: mainPages, images, colors, links, meta, textBlocks, homepage,
      logo: structure.logo,
      navMenu: structure.navMenu,
      footerLinks: structure.footerLinks
    };
    res.json(session.scanCache);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Undo System ─────────────────────────────────────────────
const MAX_UNDO = 50;

function pushUndo(session, description, fileSnapshots) {
  // fileSnapshots = [{ filePath, content }]
  if (!session.undoStack) session.undoStack = [];
  if (!session.redoStack) session.redoStack = [];

  session.undoStack.push({
    description,
    timestamp: Date.now(),
    files: fileSnapshots
  });

  // Cap the stack
  if (session.undoStack.length > MAX_UNDO) {
    session.undoStack.shift();
  }

  // Clear redo stack on new action (standard undo/redo behavior)
  session.redoStack = [];
}

function snapshotFiles(filePaths) {
  const snapshots = [];
  for (const fp of filePaths) {
    try {
      snapshots.push({ filePath: fp, content: fs.readFileSync(fp, 'utf-8') });
    } catch (e) { /* skip unreadable */ }
  }
  return snapshots;
}

function restoreSnapshots(fileSnapshots) {
  for (const snap of fileSnapshots) {
    try {
      if (snap.binary) {
        fs.writeFileSync(snap.filePath, snap.content); // Buffer, no encoding
      } else {
        fs.writeFileSync(snap.filePath, snap.content, 'utf-8');
      }
    } catch (e) { /* skip */ }
  }
}

// Undo endpoint
app.post('/api/undo', (req, res) => {
  const session = requireSession(req, res);
  if (!session) return;
  if (!session.undoStack || session.undoStack.length === 0) {
    return res.json({ ok: false, error: 'Nothing to undo' });
  }

  const action = session.undoStack.pop();

  // Snapshot current state for redo BEFORE restoring
  const currentSnapshots = snapshotFiles(action.files.map(f => f.filePath));
  if (!session.redoStack) session.redoStack = [];
  session.redoStack.push({
    description: action.description,
    timestamp: Date.now(),
    files: currentSnapshots
  });

  // Restore old state
  restoreSnapshots(action.files);
  session.scanCache = null; // invalidate cache

  res.json({
    ok: true,
    undone: action.description,
    remaining: session.undoStack.length,
    canRedo: session.redoStack.length > 0
  });
});

// Redo endpoint
app.post('/api/redo', (req, res) => {
  const session = requireSession(req, res);
  if (!session) return;
  if (!session.redoStack || session.redoStack.length === 0) {
    return res.json({ ok: false, error: 'Nothing to redo' });
  }

  const action = session.redoStack.pop();

  // Snapshot current state for undo
  const currentSnapshots = snapshotFiles(action.files.map(f => f.filePath));
  session.undoStack.push({
    description: action.description,
    timestamp: Date.now(),
    files: currentSnapshots
  });

  // Apply redo state
  restoreSnapshots(action.files);
  session.scanCache = null;

  res.json({
    ok: true,
    redone: action.description,
    remaining: session.redoStack.length,
    canUndo: session.undoStack.length > 0
  });
});

// Undo history
app.get('/api/undo/status', (req, res) => {
  const session = requireSession(req, res);
  if (!session) return;
  const undoStack = session.undoStack || [];
  const redoStack = session.redoStack || [];
  res.json({
    canUndo: undoStack.length > 0,
    canRedo: redoStack.length > 0,
    undoCount: undoStack.length,
    redoCount: redoStack.length,
    lastAction: undoStack.length > 0 ? { description: undoStack[undoStack.length - 1].description, timestamp: undoStack[undoStack.length - 1].timestamp } : null,
    history: undoStack.slice(-10).reverse().map(a => ({ description: a.description, time: new Date(a.timestamp).toLocaleTimeString() }))
  });
});

// Text replacement
app.post('/api/text/replace', (req, res) => {
  const session = requireSession(req, res);
  if (!session) return;
  const { page, oldText, newText, global } = req.body;
  if (!oldText) return res.status(400).json({ error: 'oldText required' });

  try {
    const projectDir = session.projectPath;
    if (global) {
      const htmlFiles = findHtmlFiles(projectDir);
      // Snapshot all affected files before edit
      const affectedPaths = [];
      for (const file of htmlFiles) {
        const fp = safePath(projectDir, file);
        if (!fp) continue;
        const content = fs.readFileSync(fp, 'utf-8');
        if (content.includes(oldText)) affectedPaths.push(fp);
      }
      if (affectedPaths.length > 0) {
        pushUndo(session, `Global text replace: "${oldText.substring(0, 40)}${oldText.length > 40 ? '…' : ''}"`, snapshotFiles(affectedPaths));
      }

      let total = 0;
      for (const file of htmlFiles) {
        const fp = safePath(projectDir, file);
        if (!fp) continue;
        let content = fs.readFileSync(fp, 'utf-8');
        const count = (content.split(oldText).length - 1);
        if (count > 0) {
          content = content.split(oldText).join(newText);
          fs.writeFileSync(fp, content, 'utf-8');
          total += count;
        }
      }
      session.scanCache = null;
      res.json({ ok: true, replacements: total });
    } else {
      const fp = safePath(projectDir, page);
      if (!fp) return res.status(400).json({ error: 'Invalid path' });
      pushUndo(session, `Text edit on ${path.basename(page)}: "${oldText.substring(0, 40)}${oldText.length > 40 ? '…' : ''}"`, snapshotFiles([fp]));
      let content = fs.readFileSync(fp, 'utf-8');
      const count = (content.split(oldText).length - 1);
      content = content.split(oldText).join(newText);
      fs.writeFileSync(fp, content, 'utf-8');
      session.scanCache = null;
      res.json({ ok: true, replacements: count });
    }
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Color replacement
app.post('/api/color/replace', (req, res) => {
  const session = requireSession(req, res);
  if (!session) return;
  const { oldColor, newColor } = req.body;

  try {
    const projectDir = session.projectPath;
    const allFiles = [...findCssFiles(projectDir), ...findHtmlFiles(projectDir)];

    // Snapshot affected files
    const affectedPaths = [];
    for (const file of allFiles) {
      const fp = safePath(projectDir, file);
      if (!fp) continue;
      const content = fs.readFileSync(fp, 'utf-8');
      const regex = new RegExp(oldColor.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');
      if (regex.test(content)) affectedPaths.push(fp);
    }
    if (affectedPaths.length > 0) {
      pushUndo(session, `Color replace: ${oldColor} → ${newColor}`, snapshotFiles(affectedPaths));
    }

    let total = 0;
    for (const file of allFiles) {
      const fp = safePath(projectDir, file);
      if (!fp) continue;
      let content = fs.readFileSync(fp, 'utf-8');
      const regex = new RegExp(oldColor.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');
      const matches = content.match(regex);
      if (matches) {
        content = content.replace(regex, newColor);
        fs.writeFileSync(fp, content, 'utf-8');
        total += matches.length;
      }
    }
    session.scanCache = null;
    res.json({ ok: true, replacements: total });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Color replace — page-scoped (replaces in a single HTML page + its linked CSS)
app.post('/api/color/replace-page', (req, res) => {
  const session = requireSession(req, res);
  if (!session) return;
  const { oldColor, newColor, page } = req.body;
  if (!oldColor || !newColor) return res.status(400).json({ error: 'Missing oldColor or newColor' });

  try {
    const projectDir = session.projectPath;
    const regex = new RegExp(oldColor.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');

    // Determine files to search: the HTML page + any CSS files linked from it
    const filesToSearch = [];
    if (page) {
      filesToSearch.push(page);
      // Also parse the HTML to find linked CSS files
      const pageFp = safePath(projectDir, page);
      if (pageFp && fs.existsSync(pageFp)) {
        const html = fs.readFileSync(pageFp, 'utf-8');
        const linkMatches = html.matchAll(/<link[^>]+href=["']([^"']+\.css[^"']*)["'][^>]*>/gi);
        for (const m of linkMatches) {
          let cssPath = m[1].split('?')[0];
          // Resolve relative to page directory
          const pageDir = path.dirname(page);
          const resolved = pageDir === '.' ? cssPath : path.join(pageDir, cssPath);
          filesToSearch.push(resolved);
        }
        // Also check for <style> blocks — those are in the HTML file already
      }
    }
    // Fallback: if no page specified, search all CSS
    if (filesToSearch.length === 0) {
      filesToSearch.push(...findCssFiles(projectDir), ...findHtmlFiles(projectDir));
    }

    // Snapshot + replace
    const affectedPaths = [];
    for (const file of filesToSearch) {
      const fp = safePath(projectDir, file);
      if (!fp || !fs.existsSync(fp)) continue;
      const content = fs.readFileSync(fp, 'utf-8');
      if (regex.test(content)) affectedPaths.push(fp);
    }
    if (affectedPaths.length > 0) {
      pushUndo(session, `Color replace (page): ${oldColor} → ${newColor}`, snapshotFiles(affectedPaths));
    }

    let total = 0;
    for (const fp of affectedPaths) {
      let content = fs.readFileSync(fp, 'utf-8');
      const matches = content.match(regex);
      if (matches) {
        content = content.replace(regex, newColor);
        fs.writeFileSync(fp, content, 'utf-8');
        total += matches.length;
      }
    }
    session.scanCache = null;
    res.json({ ok: true, replacements: total });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Link replacement
app.post('/api/link/replace', (req, res) => {
  const session = requireSession(req, res);
  if (!session) return;
  const { oldHref, newHref } = req.body;

  try {
    const projectDir = session.projectPath;
    const htmlFiles = findHtmlFiles(projectDir);

    // Snapshot affected files
    const affectedPaths = [];
    for (const file of htmlFiles) {
      const fp = safePath(projectDir, file);
      if (!fp) continue;
      const content = fs.readFileSync(fp, 'utf-8');
      if (content.includes(oldHref)) affectedPaths.push(fp);
    }
    if (affectedPaths.length > 0) {
      pushUndo(session, `Link replace: ${oldHref.substring(0, 40)} → ${newHref.substring(0, 40)}`, snapshotFiles(affectedPaths));
    }

    let total = 0;
    for (const file of htmlFiles) {
      const fp = safePath(projectDir, file);
      if (!fp) continue;
      let content = fs.readFileSync(fp, 'utf-8');
      const count = (content.split(oldHref).length - 1);
      if (count > 0) {
        content = content.split(oldHref).join(newHref);
        fs.writeFileSync(fp, content, 'utf-8');
        total += count;
      }
    }
    session.scanCache = null;
    res.json({ ok: true, replacements: total });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Meta update
app.post('/api/meta/update', (req, res) => {
  const session = requireSession(req, res);
  if (!session) return;
  const { page, field, value } = req.body;

  try {
    const fp = safePath(session.projectPath, page);
    if (!fp) return res.status(400).json({ error: 'Invalid path' });
    pushUndo(session, `Meta ${field} update on ${path.basename(page)}`, snapshotFiles([fp]));
    let content = fs.readFileSync(fp, 'utf-8');
    const $ = cheerio.load(content, { decodeEntities: false });

    switch (field) {
      case 'title':
        $('title').first().text(value);
        $('meta[property="og:title"]').attr('content', value);
        $('meta[name="twitter:title"]').attr('content', value);
        $('meta[itemprop="name"]').attr('content', value);
        break;
      case 'description':
        $('meta[name="description"]').attr('content', value);
        $('meta[property="og:description"]').attr('content', value);
        $('meta[name="twitter:description"]').attr('content', value);
        $('meta[itemprop="description"]').attr('content', value);
        break;
    }

    fs.writeFileSync(fp, $.html(), 'utf-8');
    session.scanCache = null;
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Save full page HTML (used by visual editor delete/move)
app.post('/api/page/save', (req, res) => {
  const session = requireSession(req, res);
  if (!session) return;
  const { page, html } = req.body;
  if (!page || !html) return res.status(400).json({ error: 'Missing page or html' });
  try {
    const fp = safePath(session.projectPath, page);
    if (!fp) return res.status(400).json({ error: 'Invalid path' });
    if (!fs.existsSync(fp)) return res.status(404).json({ error: 'Page not found' });
    pushUndo(session, `Page save: ${path.basename(page)}`, snapshotFiles([fp]));
    fs.writeFileSync(fp, html, 'utf-8');
    session.scanCache = null;
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Serve images from project
app.get('/api/image/*', (req, res) => {
  const session = getSession(req, res);
  if (!session?.projectPath) return res.status(400).send('No project');
  let imgPath = req.params[0];
  try { imgPath = decodeURIComponent(imgPath); } catch (e) { /* use as-is */ }
  let fp = safePath(session.projectPath, imgPath);
  // Fallback: search by filename if exact path doesn't match
  if (!fp || !fs.existsSync(fp)) {
    const images = findImageFiles(session.projectPath);
    const name = path.basename(imgPath);
    const match = images.find(i => i.path === imgPath) || images.find(i => path.basename(i.path) === name);
    if (match) fp = path.join(session.projectPath, match.path);
  }
  if (!fp || !fs.existsSync(fp)) return res.status(404).send('Not found');

  const mimeType = mime.lookup(fp) || 'application/octet-stream';
  res.setHeader('Content-Type', mimeType);
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  fs.createReadStream(fp).pipe(res);
});

// Upload replacement image
const imgUpload = multer({
  dest: path.join(WORKSPACE_ROOT, '_uploads'),
  limits: { fileSize: 20 * 1024 * 1024 }
});

app.post('/api/image/replace', imgUpload.single('image'), (req, res) => {
  const session = getSession(req, res);
  if (!session?.projectPath) return res.status(400).json({ error: 'No project loaded' });
  const { targetPath, currentSrc, resolvedSrc } = req.body;
  console.log('[image/replace] targetPath:', targetPath, '| currentSrc:', currentSrc, '| resolvedSrc:', resolvedSrc, '| projectPath:', session.projectPath);

  if (!targetPath) {
    if (req.file) try { fs.unlinkSync(req.file.path); } catch (_) {}
    return res.status(400).json({ error: 'No targetPath provided' });
  }

  if (!req.file) {
    return res.status(400).json({ error: 'No image file uploaded' });
  }

  try {
    // Helper to clean and normalize a src path for resolution
    function cleanSrcPath(raw) {
      if (!raw) return null;
      let cleaned = raw;
      try { cleaned = decodeURIComponent(cleaned); } catch(_) {}
      cleaned = cleaned.split('?')[0].split('#')[0]; // strip query/hash
      if (cleaned.startsWith('/api/preview/')) cleaned = cleaned.substring('/api/preview/'.length);
      if (cleaned.startsWith('/api/image/')) cleaned = cleaned.substring('/api/image/'.length);
      if (cleaned.startsWith('/')) cleaned = cleaned.substring(1);
      return cleaned;
    }

    // Build list of candidate paths to try, in priority order
    const candidatePaths = [
      targetPath,
      cleanSrcPath(targetPath),
      cleanSrcPath(currentSrc),
      cleanSrcPath(resolvedSrc),
    ].filter(Boolean);

    // Remove duplicates
    const uniqueCandidates = [...new Set(candidatePaths)];

    let fp = null;
    let matchedPath = null;

    // Phase 1: Try direct path resolution for each candidate
    for (const candidate of uniqueCandidates) {
      const resolved = safePath(session.projectPath, candidate);
      if (resolved && fs.existsSync(resolved)) {
        fp = resolved;
        matchedPath = candidate;
        console.log('[image/replace] Direct match:', candidate, '→', fp);
        break;
      }
    }

    // Phase 2: If no direct match, try filename-based fallback
    if (!fp) {
      const images = findImageFiles(session.projectPath);
      for (const candidate of uniqueCandidates) {
        const targetName = path.basename(candidate);
        if (!targetName) continue;
        console.log('[image/replace] Trying filename fallback:', targetName, 'from candidate:', candidate);
        const match = images.find(img => img.path === candidate) ||
                      images.find(img => img.path.endsWith('/' + targetName) || img.path === targetName) ||
                      images.find(img => img.name === targetName);
        if (match) {
          fp = path.join(session.projectPath, match.path);
          matchedPath = match.path;
          console.log('[image/replace] Fallback match found:', match.path, '→', fp);
          break;
        }
      }
    }

    // Phase 3: Try partial/fuzzy path matching (for deeply nested httrack structures)
    if (!fp) {
      const images = findImageFiles(session.projectPath);
      for (const candidate of uniqueCandidates) {
        const segments = candidate.replace(/\\/g, '/').split('/').filter(Boolean);
        if (segments.length < 2) continue;
        // Try matching the last 2-3 path segments
        const tail2 = segments.slice(-2).join('/');
        const tail3 = segments.length >= 3 ? segments.slice(-3).join('/') : null;
        const match = images.find(img => img.path.endsWith(tail2)) ||
                      (tail3 ? images.find(img => img.path.endsWith(tail3)) : null);
        if (match) {
          fp = path.join(session.projectPath, match.path);
          matchedPath = match.path;
          console.log('[image/replace] Fuzzy tail match:', candidate, '→', match.path);
          break;
        }
      }
    }

    if (!fp || !fs.existsSync(fp)) {
      const allImages = findImageFiles(session.projectPath);
      console.log('[image/replace] FAILED — target not found. Candidates tried:', uniqueCandidates);
      console.log('[image/replace] Available images:', allImages.map(i => i.path));
      fs.unlinkSync(req.file.path);
      return res.status(404).json({ error: 'Target image not found: ' + targetPath, tried: uniqueCandidates, available: allImages.map(i => i.path).slice(0, 20) });
    }

    // Snapshot the old image binary for undo
    const oldContent = fs.readFileSync(fp);
    if (!session.undoStack) session.undoStack = [];
    if (!session.redoStack) session.redoStack = [];
    session.undoStack.push({
      description: `Image replace: ${path.basename(targetPath)}`,
      timestamp: Date.now(),
      files: [{ filePath: fp, content: oldContent, binary: true }]
    });
    if (session.undoStack.length > MAX_UNDO) session.undoStack.shift();
    session.redoStack = [];

    fs.copyFileSync(req.file.path, fp);
    fs.unlinkSync(req.file.path);
    session.scanCache = null;
    res.json({ ok: true });
  } catch (e) {
    try { fs.unlinkSync(req.file.path); } catch (_) {}
    res.status(500).json({ error: e.message });
  }
});

// Upload a NEW image (for background replacements, etc.)
app.post('/api/image/upload', imgUpload.single('image'), (req, res) => {
  const session = getSession(req, res);
  if (!session?.projectPath) return res.status(400).json({ error: 'No project loaded' });
  const { targetPath } = req.body;
  if (!targetPath || !req.file) {
    if (req.file) try { fs.unlinkSync(req.file.path); } catch (_) {}
    return res.status(400).json({ error: 'Missing targetPath or file' });
  }
  try {
    const fp = safePath(session.projectPath, targetPath);
    if (!fp) {
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ error: 'Invalid path' });
    }
    const dir = path.dirname(fp);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.copyFileSync(req.file.path, fp);
    fs.unlinkSync(req.file.path);
    session.scanCache = null;
    res.json({ ok: true, path: targetPath });
  } catch (e) {
    try { fs.unlinkSync(req.file.path); } catch (_) {}
    res.status(500).json({ error: e.message });
  }
});

// Proxy external images that weren't captured by wget (e.g. CDN-hosted webp)
app.get('/api/image-proxy', async (req, res) => {
  const url = req.query.url;
  if (!url) return res.status(400).send('Missing url');
  try {
    const resp = await fetch(url, {
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; CloneHawk/1.0)' },
      redirect: 'follow',
      signal: AbortSignal.timeout(10000)
    });
    if (!resp.ok) return res.status(resp.status).send('Upstream error');
    const ct = resp.headers.get('content-type') || 'image/jpeg';
    res.setHeader('Content-Type', ct);
    res.setHeader('Cache-Control', 'public, max-age=86400');
    const buffer = Buffer.from(await resp.arrayBuffer());
    res.send(buffer);
  } catch (e) {
    res.status(502).send('Proxy error');
  }
});

// Preview: serve the mirrored site — serves ANY file (HTML, CSS, JS, images, fonts)
// so that relative references within pages resolve correctly.
app.get('/api/preview/*', (req, res) => {
  const session = getSession(req, res);
  if (!session?.projectPath) return res.status(400).send('No project');
  let filePath = req.params[0] || 'index.html';
  // Decode URI components so encoded slashes work: about%2Findex.html → about/index.html
  try { filePath = decodeURIComponent(filePath); } catch (e) { /* use as-is */ }
  const fp = safePath(session.projectPath, filePath);
  if (!fp) return res.status(400).send('Invalid path');

  let fullPath = fp;
  if (fs.existsSync(fullPath) && fs.statSync(fullPath).isDirectory()) {
    fullPath = path.join(fullPath, 'index.html');
  }

  if (!fs.existsSync(fullPath)) {
    // Try common fallbacks: maybe path has extra nesting or missing index.html
    const indexFallback = path.join(fp, 'index.html');
    if (fs.existsSync(indexFallback)) {
      fullPath = indexFallback;
    } else {
      // Try without extension
      const withExt = fp + '.html';
      if (fs.existsSync(withExt)) {
        fullPath = withExt;
      } else {
        // Fuzzy fallback: search all HTML files for a match
        const allHtml = findHtmlFiles(session.projectPath);
        const fuzzyMatch = allHtml.find(f =>
          f === filePath ||
          f.endsWith('/' + filePath) ||
          filePath.endsWith('/' + f) ||
          f.replace(/\\/g, '/') === filePath.replace(/\\/g, '/') ||
          f.replace(/\\/g, '/').toLowerCase() === filePath.replace(/\\/g, '/').toLowerCase()
        );
        if (fuzzyMatch) {
          fullPath = path.join(session.projectPath, fuzzyMatch);
          console.log('[preview] fuzzy match:', filePath, '→', fuzzyMatch);
        } else {
          console.log('[preview 404]', filePath, '→ resolved:', fp, '| exists:', fs.existsSync(fp), '| allHtml:', allHtml.slice(0, 10));
          return res.status(404).send('<html><body style="font-family:Inter,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;color:#94a3b8;"><div style="text-align:center;"><h2 style="color:#64748b;">Page Not Found</h2><p>' + filePath + '</p><p style="font-size:12px;">Try selecting a different page from the dropdown.</p></div></body></html>');
        }
      }
    }
  }

  // Detect XML/RSS content and refuse to serve as preview
  if (isXmlContent(fullPath)) {
    return res.status(400).send('<html><body style="font-family:sans-serif;padding:40px;color:#64748b;text-align:center;"><h3>Not a previewable page</h3><p>This file appears to be an RSS feed or XML sitemap, not an HTML page.</p></body></html>');
  }

  const mimeType = mime.lookup(fullPath) || 'application/octet-stream';
  const ext = path.extname(fullPath).toLowerCase();

  // For HTML files, inject a <base> tag so relative asset refs (CSS, JS, images) resolve correctly
  if (['.html', '.htm'].includes(ext)) {
    let html = fs.readFileSync(fullPath, 'utf-8');
    // Calculate the directory of this HTML file relative to project root
    const htmlRelDir = path.dirname(filePath).replace(/\\/g, '/');
    const baseHref = '/api/preview/' + (htmlRelDir === '.' ? '' : htmlRelDir + '/');
    // Inject <base> right after <head> (or at top if no <head>)
    if (html.includes('<head>')) {
      html = html.replace('<head>', '<head><base href="' + baseHref + '">');
    } else if (html.includes('<head ')) {
      html = html.replace(/<head([^>]*)>/, '<head$1><base href="' + baseHref + '">');
    } else if (html.includes('<HEAD>')) {
      html = html.replace('<HEAD>', '<HEAD><base href="' + baseHref + '">');
    } else {
      // No head tag — prepend
      html = '<base href="' + baseHref + '">' + html;
    }
    // Inject cache-busting script for images so replaced images show immediately
    const bustScript = `<script>(function(){var t=Date.now();document.addEventListener('DOMContentLoaded',function(){document.querySelectorAll('img').forEach(function(img){var s=img.getAttribute('src');if(s&&s.indexOf('data:')!==0){img.setAttribute('src',s+(s.indexOf('?')>-1?'&':'?')+'_cb='+t);}});});})();</script>`;
    // Inject proxy fallback for external images that fail to load (CDN webp, etc.)
    const proxyScript = `<script>(function(){document.addEventListener('error',function(e){var img=e.target;if(img.tagName==='IMG'&&img.src&&img.src.startsWith('http')&&!img.dataset.proxyRetried){img.dataset.proxyRetried='1';img.src='/api/image-proxy?url='+encodeURIComponent(img.src);}},true);})();</script>`;
    const injectedScripts = bustScript + proxyScript;
    if (html.includes('</head>')) {
      html = html.replace('</head>', injectedScripts + '</head>');
    } else if (html.includes('</HEAD>')) {
      html = html.replace('</HEAD>', injectedScripts + '</HEAD>');
    } else {
      html = html + injectedScripts;
    }
    res.setHeader('Content-Type', 'text/html');
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.send(html);
  } else {
    res.setHeader('Content-Type', mimeType);
    // No cache for images — so replaced images show immediately
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    fs.createReadStream(fullPath).pipe(res);
  }
});

// Export as ZIP — clean, deployment-ready folder structure
app.get('/api/export', (req, res) => {
  const session = getSession(req, res);
  if (!session?.projectPath) return res.status(400).send('No project');

  try {
    // Get project name from query param or fall back to domain/generic
    let projectName = (req.query.name || '').trim().replace(/[^a-zA-Z0-9_\- ]/g, '').substring(0, 60);
    if (!projectName) {
      // Try to extract domain from the project folder name
      const folderName = path.basename(session.projectPath);
      projectName = folderName.replace(/^site-/, '').replace(/[^a-zA-Z0-9_\-]/g, '-') || 'my-site';
    }
    const zipName = projectName.replace(/\s+/g, '-').toLowerCase() + '.zip';

    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', `attachment; filename="${zipName}"`);

    const archive = archiver('zip', { zlib: { level: 6 } });
    archive.on('error', (err) => { res.status(500).send('Export failed: ' + err.message); });
    archive.pipe(res);

    const projectDir = session.projectPath;
    const allFiles = getAllFiles(projectDir, projectDir);

    // Build a remap table: oldRelPath → newCleanPath
    const remap = {};
    for (const relPath of allFiles) {
      remap[relPath] = getCleanPath(relPath);
    }

    // Process each file
    for (const relPath of allFiles) {
      const fullPath = path.join(projectDir, relPath);
      const cleanPath = remap[relPath];
      const ext = path.extname(relPath).toLowerCase();

      if (['.html', '.htm'].includes(ext)) {
        // Rewrite references in HTML files
        let content = fs.readFileSync(fullPath, 'utf-8');
        content = rewriteReferences(content, relPath, remap, 'html');
        archive.append(content, { name: cleanPath });
      } else if (ext === '.css') {
        // Rewrite url() references in CSS files
        let content = fs.readFileSync(fullPath, 'utf-8');
        content = rewriteReferences(content, relPath, remap, 'css');
        archive.append(content, { name: cleanPath });
      } else {
        // Binary files (images, fonts, JS, etc.) — stream as-is
        archive.file(fullPath, { name: cleanPath });
      }
    }

    archive.finalize();
  } catch (e) {
    res.status(500).send('Export failed: ' + e.message);
  }
});

// ─── Export Helpers ────────────────────────────────────────────
function getAllFiles(dir, base) {
  let results = [];
  try {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (['hts-cache', 'hts-log.txt', '.wget-hsts', 'node_modules', '.git'].includes(entry.name)) continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        results = results.concat(getAllFiles(full, base));
      } else {
        results.push(path.relative(base, full).replace(/\\/g, '/'));
      }
    }
  } catch (e) { /* skip */ }
  return results;
}

function getCleanPath(relPath) {
  const ext = path.extname(relPath).toLowerCase();
  const basename = path.basename(relPath);

  // HTML files → root
  if (['.html', '.htm'].includes(ext)) {
    // Keep directory-based index files meaningful
    const parts = relPath.replace(/\\/g, '/').split('/');
    if (parts.length <= 1) return basename;  // Already at root
    // Flatten: about/index.html → about.html, keep others as-is but flatten
    if (basename === 'index.html' && parts.length === 2) {
      return parts[0] + '.html';
    }
    // Deeper nesting: preserve relative structure but flatten one level
    if (basename === 'index.html' && parts.length > 2) {
      return parts.slice(-2, -1)[0] + '.html';
    }
    // Non-index HTML at any depth → bring to root (with unique name)
    return basename;
  }

  // CSS files → css/
  if (ext === '.css') {
    return 'css/' + basename;
  }

  // JavaScript → js/
  if (['.js', '.mjs'].includes(ext)) {
    return 'js/' + basename;
  }

  // Images → images/
  if (['.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg', '.ico', '.avif', '.bmp', '.tiff'].includes(ext)) {
    return 'images/' + basename;
  }

  // Fonts → fonts/
  if (['.woff', '.woff2', '.ttf', '.otf', '.eot'].includes(ext)) {
    return 'fonts/' + basename;
  }

  // Everything else → assets/
  return 'assets/' + basename;
}

function rewriteReferences(content, sourceRelPath, remap, fileType) {
  const sourceDir = path.dirname(sourceRelPath).replace(/\\/g, '/');
  const newSourcePath = remap[sourceRelPath] || sourceRelPath;
  const newSourceDir = path.dirname(newSourcePath).replace(/\\/g, '/');

  // For each old path in remap, try to replace references
  for (const [oldRel, newRel] of Object.entries(remap)) {
    if (oldRel === sourceRelPath) continue;

    // Calculate what the reference looked like from the source file's perspective
    const oldRefFromSource = getRelativePath(sourceDir, oldRel);
    if (!oldRefFromSource) continue;

    // Calculate what it should be from the new source location
    const newRefFromSource = getRelativePath(newSourceDir === '.' ? '' : newSourceDir, newRel);
    if (!newRefFromSource || oldRefFromSource === newRefFromSource) continue;

    // Escape for regex
    const escaped = oldRefFromSource.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

    if (fileType === 'html') {
      // Replace in src="...", href="...", url(...)
      const patterns = [
        new RegExp('(src=["\'])' + escaped + '(["\'])', 'g'),
        new RegExp('(href=["\'])' + escaped + '(["\'])', 'g'),
        new RegExp('(srcset=["\'][^"\']*?)' + escaped, 'g'),
        new RegExp('(url\\(["\']?)' + escaped + '(["\']?\\))', 'g'),
      ];
      for (const re of patterns) {
        content = content.replace(re, (match, prefix, suffix) => {
          if (suffix !== undefined) return prefix + newRefFromSource + suffix;
          return prefix + newRefFromSource;
        });
      }
    } else if (fileType === 'css') {
      // Replace url() references in CSS
      const re = new RegExp('(url\\(["\']?)' + escaped + '(["\']?\\))', 'g');
      content = content.replace(re, '$1' + newRefFromSource + '$2');
    }
  }

  return content;
}

function getRelativePath(fromDir, toPath) {
  // Simple relative path calculation
  if (!fromDir || fromDir === '.') return toPath;
  const fromParts = fromDir.split('/').filter(Boolean);
  const toParts = toPath.split('/').filter(Boolean);

  let common = 0;
  while (common < fromParts.length && common < toParts.length && fromParts[common] === toParts[common]) {
    common++;
  }

  const ups = fromParts.length - common;
  const remaining = toParts.slice(common);

  if (ups === 0 && remaining.length === 0) return null;
  return (ups > 0 ? '../'.repeat(ups) : './') + remaining.join('/');
}

// Bulk find/replace
app.post('/api/bulk-replace', (req, res) => {
  const session = requireSession(req, res);
  if (!session) return;
  const { find, replace, fileTypes } = req.body;
  if (!find) return res.status(400).json({ error: 'find text required' });

  try {
    const projectDir = session.projectPath;
    let files = [];
    if (fileTypes === 'all' || !fileTypes) {
      files = [...findHtmlFiles(projectDir), ...findCssFiles(projectDir)];
    } else if (fileTypes === 'html') {
      files = findHtmlFiles(projectDir);
    } else if (fileTypes === 'css') {
      files = findCssFiles(projectDir);
    }

    // Snapshot affected files before bulk replace
    const affectedPaths = [];
    const findRegex = new RegExp(find.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g');
    for (const file of files) {
      const fp = safePath(projectDir, file);
      if (!fp) continue;
      const content = fs.readFileSync(fp, 'utf-8');
      if (findRegex.test(content)) affectedPaths.push(fp);
      findRegex.lastIndex = 0;
    }
    if (affectedPaths.length > 0) {
      pushUndo(session, `Bulk replace: "${find.substring(0, 30)}${find.length > 30 ? '…' : ''}" → "${replace.substring(0, 30)}${replace.length > 30 ? '…' : ''}"`, snapshotFiles(affectedPaths));
    }

    let totalReplacements = 0;
    let filesChanged = 0;

    for (const file of files) {
      const fp = safePath(projectDir, file);
      if (!fp) continue;
      let content = fs.readFileSync(fp, 'utf-8');
      const regex = new RegExp(find.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g');
      const matches = content.match(regex);
      if (matches) {
        content = content.replace(regex, replace);
        fs.writeFileSync(fp, content, 'utf-8');
        totalReplacements += matches.length;
        filesChanged++;
      }
    }
    session.scanCache = null;
    res.json({ ok: true, replacements: totalReplacements, filesChanged });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── AI Routes ───────────────────────────────────────────────
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || '';

app.post('/api/ai/rewrite', async (req, res) => {
  if (!OPENAI_API_KEY) return res.status(400).json({ error: 'OpenAI API key not configured. Set OPENAI_API_KEY env var.' });
  const { text, style, tag } = req.body;
  if (!text || !style) return res.status(400).json({ error: 'text and style are required' });
  if (text.length > 5000) return res.status(400).json({ error: 'Text too long (max 5000 chars)' });

  const stylePrompts = {
    professional: 'Rewrite this text to sound more professional, polished, and business-appropriate.',
    casual: 'Rewrite this text to sound more casual, relaxed, and conversational.',
    persuasive: 'Rewrite this text to be more persuasive and compelling, driving the reader to take action.',
    concise: 'Rewrite this text to be shorter and more concise while keeping the same meaning.',
    friendly: 'Rewrite this text to sound warm, friendly, and approachable.',
    luxury: 'Rewrite this text to sound premium, luxurious, and high-end.',
    urgent: 'Rewrite this text to create a sense of urgency and importance.',
    seo: 'Rewrite this text to be more SEO-friendly while keeping it natural and readable.',
    custom: '' // handled below
  };

  const styleInstruction = stylePrompts[style] || stylePrompts.professional;

  try {
    const response = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + OPENAI_API_KEY
      },
      body: JSON.stringify({
        model: 'gpt-5.4-nano',
        messages: [
          {
            role: 'system',
            content: 'You are a website copywriter. You rewrite text for websites. Return ONLY the rewritten text, nothing else. No quotes, no explanations, no markdown. Keep approximately the same length unless the style calls for shorter text. Preserve any proper nouns, brand names, phone numbers, and addresses exactly. The text is from a <' + (tag || 'p') + '> HTML element.'
          },
          {
            role: 'user',
            content: styleInstruction + '\n\nOriginal text:\n' + text
          }
        ],
        temperature: 0.7,
        max_completion_tokens: 1000
      })
    });

    if (!response.ok) {
      const errBody = await response.text();
      return res.status(502).json({ error: 'OpenAI API error: ' + response.status });
    }

    const data = await response.json();
    const rewritten = data.choices?.[0]?.message?.content?.trim();
    if (!rewritten) return res.status(502).json({ error: 'Empty response from AI' });

    res.json({ ok: true, rewritten, model: 'gpt-5.4-nano' });
  } catch (e) {
    res.status(500).json({ error: 'AI request failed: ' + e.message });
  }
});

app.post('/api/ai/alt-text', async (req, res) => {
  if (!OPENAI_API_KEY) return res.status(400).json({ error: 'OpenAI API key not configured.' });
  const { src, context } = req.body;
  if (!src) return res.status(400).json({ error: 'Image src is required' });

  try {
    const response = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + OPENAI_API_KEY
      },
      body: JSON.stringify({
        model: 'gpt-5.4-nano',
        messages: [
          {
            role: 'system',
            content: 'You write concise, descriptive alt text for website images. Return ONLY the alt text, nothing else. Keep it under 125 characters. Be specific and descriptive.'
          },
          {
            role: 'user',
            content: 'Write alt text for an image with filename: ' + src.split('/').pop() + (context ? '. Page context: ' + context : '')
          }
        ],
        temperature: 0.5,
        max_completion_tokens: 100
      })
    });

    if (!response.ok) return res.status(502).json({ error: 'OpenAI API error' });
    const data = await response.json();
    const altText = data.choices?.[0]?.message?.content?.trim();
    res.json({ ok: true, altText });
  } catch (e) {
    res.status(500).json({ error: 'AI request failed: ' + e.message });
  }
});

app.get('/api/ai/status', (req, res) => {
  res.json({ available: !!OPENAI_API_KEY });
});

// ─── AI Site Transform ──────────────────────────────────────
app.post('/api/ai/transform', async (req, res) => {
  if (!OPENAI_API_KEY) return res.status(400).json({ error: 'OpenAI API key not configured. Set OPENAI_API_KEY env var.' });

  const session = requireSession(req, res);
  if (!session) return;

  const {
    businessName, businessType, phone, email, address, tagline,
    voice, extraContext, pagesToKeep, pagesToRemove,
    additionalInstructions, transformOptions
  } = req.body;

  if (!businessName) return res.status(400).json({ error: 'Business name is required.' });

  const projectDir = session.projectPath;

  try {
    // 1. Gather text blocks from pages to keep
    const keepPages = (pagesToKeep && pagesToKeep.length > 0)
      ? pagesToKeep
      : findHtmlFiles(projectDir).filter(f => !isJunkHtmlFile(f));

    let allTextBlocks = [];
    for (const page of keepPages) {
      try {
        allTextBlocks = allTextBlocks.concat(extractTextBlocks(page, projectDir));
      } catch (e) { /* skip broken pages */ }
    }

    // 2. Gather nav items from scan cache (already detected by AI) or fallback to parsing
    const mainPage = keepPages.find(p => p === 'index.html') || keepPages[0];
    let navItems = [];
    if (session.scanCache && session.scanCache.navMenu && session.scanCache.navMenu.length > 0) {
      // Reuse AI-detected nav items from scan
      navItems = session.scanCache.navMenu.map(n => ({ original: n.text, href: n.href }));
    } else if (mainPage) {
      try {
        const mainHtml = fs.readFileSync(path.join(projectDir, mainPage), 'utf-8');
        const $main = cheerio.load(mainHtml);
        $main('nav a, header a, .nav a, .navbar a, .menu a, [class*="nav"] a').each((i, el) => {
          const text = $main(el).text().trim();
          const href = $main(el).attr('href') || '';
          if (text && text.length > 0 && text.length < 50 && !href.startsWith('javascript:') && !href.startsWith('mailto:') && !href.startsWith('tel:')) {
            if (!navItems.find(n => n.original === text)) {
              navItems.push({ original: text, href });
            }
          }
        });
      } catch (e) { /* skip */ }
    }

    // 3. Gather meta info
    const metaList = extractMeta(projectDir);
    const mainMeta = metaList.find(m => m.page === mainPage) || metaList[0] || {};

    // 4. Build voice description
    const voiceDescriptions = {
      professional: 'Use formal, confident, trustworthy language. Avoid slang. Sound corporate but approachable.',
      friendly: 'Use warm, conversational, approachable language. Like talking to a neighbor.',
      luxury: 'Use elegant, refined, premium language. Evoke exclusivity and sophistication.',
      edgy: 'Use bold, direct, punchy language. Break conventions. Sound modern and fearless.',
      playful: 'Use fun, energetic, lighthearted language. Include wordplay where appropriate.',
      minimal: 'Use clean, sparse, to-the-point language. Fewer words, more impact.'
    };
    const voiceDesc = voiceDescriptions[voice] || voiceDescriptions.professional;

    // 5. Prepare text blocks for GPT (limit to 80 per batch)
    const MAX_BLOCKS_PER_CALL = 80;
    const filteredBlocks = allTextBlocks.filter(b => {
      if (!transformOptions) return true;
      if (b.type === 'heading' && !transformOptions.rewriteText) return false;
      if (b.type === 'paragraph' && !transformOptions.rewriteText) return false;
      if (b.type === 'button' && !transformOptions.rewriteCTAs) return false;
      if (b.type === 'link' && !transformOptions.rewriteText) return false;
      return true;
    });

    // Deduplicate by text content
    const seenTexts = new Set();
    const uniqueBlocks = [];
    for (const block of filteredBlocks) {
      const key = block.text.substring(0, 120);
      if (!seenTexts.has(key)) {
        seenTexts.add(key);
        uniqueBlocks.push(block);
      }
    }

    const batches = [];
    for (let i = 0; i < uniqueBlocks.length; i += MAX_BLOCKS_PER_CALL) {
      batches.push(uniqueBlocks.slice(i, i + MAX_BLOCKS_PER_CALL));
    }

    // 6. Build system prompt
    const systemPrompt = `You are a website copy transformation engine. You rewrite website content to match a new business.

BUSINESS INFO:
- Name: ${businessName}
- Type: ${businessType || 'General business'}
- Phone: ${phone || 'N/A'}
- Email: ${email || 'N/A'}
- Address: ${address || 'N/A'}
- Tagline: ${tagline || '(generate one)'}
- Voice: ${voice || 'professional'}
- Extra context: ${extraContext || 'None'}
- Additional instructions: ${additionalInstructions || 'None'}

RULES:
1. Rewrite ALL text to match this business. Don't leave any original business references.
2. Keep the same approximate length for each text block (within 20%).
3. Preserve HTML entities and special characters if present in the original.
4. For headings, be punchy and engaging.
5. For paragraphs, be descriptive but not wordy.
6. For buttons/CTAs, be action-oriented.
7. For nav items, use standard labels for the business type.
8. Replace any phone numbers with: ${phone || 'the original'}
9. Replace any emails with: ${email || 'the original'}
10. Replace any addresses with: ${address || 'the original'}
11. If tagline is empty, generate an appropriate one.
12. Voice guide: ${voiceDesc}
13. Return ONLY valid JSON, no markdown, no code fences, no explanation.
14. The response must be parseable by JSON.parse(). No trailing commas. No comments.
15. If a text block doesn't need changing (e.g. it's a number or generic), still include it with the same text.`;

    // 7. Call GPT for each batch
    let allReplacements = [];
    let aiMeta = null;
    let aiTagline = tagline || null;
    let aiNavItems = [];
    let aiFooterItems = [];

    for (let batchIdx = 0; batchIdx < batches.length; batchIdx++) {
      const batch = batches[batchIdx];
      const textBlocksJson = batch.map((b, i) => ({
        id: b.id,
        type: b.type,
        tag: b.tag,
        page: b.page,
        text: b.text.substring(0, 500)
      }));

      let userPrompt = `Here are the text blocks to transform (JSON array):\n\n${JSON.stringify(textBlocksJson, null, 0)}`;

      if (batchIdx === 0) {
        // Include nav items and meta in first batch
        if (navItems.length > 0 && transformOptions?.updateNav !== false) {
          userPrompt += `\n\nNAV ITEMS to transform:\n${JSON.stringify(navItems.map(n => n.original))}`;
        }
        // Include footer links from AI scan if available
        const footerLinks = (session.scanCache && session.scanCache.footerLinks) || [];
        if (footerLinks.length > 0) {
          userPrompt += `\n\nFOOTER LINK TEXT to transform:\n${JSON.stringify(footerLinks.map(f => f.text))}`;
        }
        if (transformOptions?.updateMeta !== false) {
          userPrompt += `\n\nCurrent page title: "${mainMeta.title || ''}"`;
          userPrompt += `\nCurrent meta description: "${mainMeta.description || ''}"`;
        }
        userPrompt += `\n\nRespond with a JSON object:
{
  "replacements": [{"id": "...", "original": "exact original text", "replacement": "new text"}, ...],
  "meta": {"title": "new page title", "description": "new meta description"},
  "tagline": "generated tagline or provided one",
  "navItems": [{"original": "Old Label", "replacement": "New Label"}, ...],
  "footerItems": [{"original": "Old Text", "replacement": "New Text"}, ...]
}`;
      } else {
        userPrompt += `\n\nRespond with a JSON object:
{
  "replacements": [{"id": "...", "original": "exact original text", "replacement": "new text"}, ...]
}`;
      }

      const response = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ' + OPENAI_API_KEY
        },
        body: JSON.stringify({
          model: 'gpt-5.4-nano',
          messages: [
            { role: 'system', content: systemPrompt },
            { role: 'user', content: userPrompt }
          ],
          temperature: 0.7,
          max_completion_tokens: 8000
        })
      });

      if (!response.ok) {
        const errText = await response.text();
        console.error('[ai/transform] OpenAI error:', response.status, errText.substring(0, 500));
        return res.status(502).json({ error: 'OpenAI API error: ' + response.status + '. ' + errText.substring(0, 200) });
      }

      const data = await response.json();
      let content = data.choices?.[0]?.message?.content?.trim();
      if (!content) {
        console.error('[ai/transform] Empty AI response. Full data:', JSON.stringify(data).substring(0, 500));
        return res.status(502).json({ error: 'Empty response from AI' });
      }

      console.log('[ai/transform] Raw AI response (first 500 chars):', content.substring(0, 500));

      // Strip markdown code fences if present
      content = content.replace(/^```(?:json)?\s*\n?/i, '').replace(/\n?```\s*$/i, '');

      // Also strip any leading text before the first { 
      const firstBrace = content.indexOf('{');
      if (firstBrace > 0) {
        content = content.substring(firstBrace);
      }

      // Strip any trailing text after the last }
      const lastBrace = content.lastIndexOf('}');
      if (lastBrace >= 0 && lastBrace < content.length - 1) {
        content = content.substring(0, lastBrace + 1);
      }

      let parsed;
      try {
        parsed = JSON.parse(content);
      } catch (parseErr) {
        // Try to find JSON object in the response
        const jsonMatch = content.match(/\{[\s\S]*\}/);
        if (jsonMatch) {
          try {
            parsed = JSON.parse(jsonMatch[0]);
          } catch (e2) {
            console.error('[ai/transform] JSON parse failed. Content:', content.substring(0, 1000));
            return res.status(502).json({ error: 'Failed to parse AI response as JSON. The AI returned invalid output — please try again.' });
          }
        } else {
          console.error('[ai/transform] No JSON found. Content:', content.substring(0, 1000));
          return res.status(502).json({ error: 'AI response was not valid JSON. Please try again.' });
        }
      }

      if (parsed.replacements && Array.isArray(parsed.replacements)) {
        allReplacements = allReplacements.concat(parsed.replacements);
      }
      if (batchIdx === 0) {
        if (parsed.meta) aiMeta = parsed.meta;
        if (parsed.tagline) aiTagline = parsed.tagline;
        if (parsed.navItems && Array.isArray(parsed.navItems)) aiNavItems = parsed.navItems;
        if (parsed.footerItems && Array.isArray(parsed.footerItems)) aiFooterItems = parsed.footerItems;
      }
    }

    // 8. Snapshot all affected files for undo BEFORE making changes
    const affectedPages = new Set();
    for (const r of allReplacements) {
      // Find which page this block is from
      const block = uniqueBlocks.find(b => b.id === r.id);
      if (block) affectedPages.add(block.page);
    }
    for (const nav of aiNavItems) {
      if (mainPage) affectedPages.add(mainPage);
    }
    if (aiMeta && mainPage) affectedPages.add(mainPage);

    // Add all kept pages to affected (for branding replacements)
    for (const p of keepPages) affectedPages.add(p);

    const affectedPaths = [];
    for (const page of affectedPages) {
      const fp = safePath(projectDir, page);
      if (fp && fs.existsSync(fp)) affectedPaths.push(fp);
    }

    pushUndo(session, `AI Transform: site rewritten for "${businessName}"`, snapshotFiles(affectedPaths));

    // 9. Apply text replacements
    let textBlocksUpdated = 0;
    let pagesUpdated = new Set();

    for (const replacement of allReplacements) {
      if (!replacement.original || !replacement.replacement) continue;
      if (replacement.original === replacement.replacement) continue;

      // Find the block to determine which page
      const block = uniqueBlocks.find(b => b.id === replacement.id);
      const searchPages = block ? [block.page] : keepPages;

      for (const page of searchPages) {
        const fp = safePath(projectDir, page);
        if (!fp || !fs.existsSync(fp)) continue;

        let content = fs.readFileSync(fp, 'utf-8');
        if (content.includes(replacement.original)) {
          content = content.split(replacement.original).join(replacement.replacement);
          fs.writeFileSync(fp, content, 'utf-8');
          textBlocksUpdated++;
          pagesUpdated.add(page);
          break; // Only replace in first matching page
        }
      }
    }

    // 10. Apply nav item replacements
    let navUpdated = 0;
    if (aiNavItems.length > 0 && mainPage) {
      const fp = safePath(projectDir, mainPage);
      if (fp && fs.existsSync(fp)) {
        let content = fs.readFileSync(fp, 'utf-8');
        for (const navItem of aiNavItems) {
          if (!navItem.original || !navItem.replacement) continue;
          if (navItem.original === navItem.replacement) continue;
          // Replace nav text — use regex to match within link tags
          const escaped = navItem.original.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
          const navRegex = new RegExp('(>[\\s]*)' + escaped + '([\\s]*<)', 'g');
          const newContent = content.replace(navRegex, '$1' + navItem.replacement + '$2');
          if (newContent !== content) {
            content = newContent;
            navUpdated++;
          }
        }
        fs.writeFileSync(fp, content, 'utf-8');
        if (navUpdated > 0) pagesUpdated.add(mainPage);
      }
    }

    // 10b. Apply footer item replacements
    let footerUpdated = 0;
    if (aiFooterItems.length > 0 && mainPage) {
      const fp = safePath(projectDir, mainPage);
      if (fp && fs.existsSync(fp)) {
        let content = fs.readFileSync(fp, 'utf-8');
        for (const footerItem of aiFooterItems) {
          if (!footerItem.original || !footerItem.replacement) continue;
          if (footerItem.original === footerItem.replacement) continue;
          const escaped = footerItem.original.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
          const footerRegex = new RegExp('(>[\\s]*)' + escaped + '([\\s]*<)', 'g');
          const newContent = content.replace(footerRegex, '$1' + footerItem.replacement + '$2');
          if (newContent !== content) {
            content = newContent;
            footerUpdated++;
          }
        }
        fs.writeFileSync(fp, content, 'utf-8');
        if (footerUpdated > 0) pagesUpdated.add(mainPage);
      }
    }

    // 11. Apply meta tag updates
    let metaUpdated = 0;
    if (aiMeta && mainPage) {
      const fp = safePath(projectDir, mainPage);
      if (fp && fs.existsSync(fp)) {
        let content = fs.readFileSync(fp, 'utf-8');
        const $ = cheerio.load(content, { decodeEntities: false });

        if (aiMeta.title) {
          $('title').first().text(aiMeta.title);
          $('meta[property="og:title"]').attr('content', aiMeta.title);
          $('meta[name="twitter:title"]').attr('content', aiMeta.title);
          metaUpdated++;
        }
        if (aiMeta.description) {
          $('meta[name="description"]').attr('content', aiMeta.description);
          $('meta[property="og:description"]').attr('content', aiMeta.description);
          $('meta[name="twitter:description"]').attr('content', aiMeta.description);
          metaUpdated++;
        }

        fs.writeFileSync(fp, $.html(), 'utf-8');
        if (metaUpdated > 0) pagesUpdated.add(mainPage);
      }
    }

    // 12. Handle page removal — remove nav links pointing to removed pages
    if (pagesToRemove && pagesToRemove.length > 0 && mainPage) {
      const fp = safePath(projectDir, mainPage);
      if (fp && fs.existsSync(fp)) {
        let content = fs.readFileSync(fp, 'utf-8');
        const $ = cheerio.load(content, { decodeEntities: false });
        let removedLinks = 0;

        for (const removePage of pagesToRemove) {
          $('a[href]').each((i, el) => {
            const href = $(el).attr('href') || '';
            if (href === removePage || href === './' + removePage || href === '/' + removePage) {
              const parent = $(el).parent();
              // If inside a nav li, remove the li; otherwise just remove the link
              if (parent.is('li')) {
                parent.remove();
              } else {
                $(el).remove();
              }
              removedLinks++;
            }
          });
        }

        if (removedLinks > 0) {
          fs.writeFileSync(fp, $.html(), 'utf-8');
          pagesUpdated.add(mainPage);
        }
      }
    }

    // 13. Invalidate scan cache
    session.scanCache = null;

    // 14. Return summary
    res.json({
      ok: true,
      summary: {
        textBlocksUpdated,
        pagesUpdated: pagesUpdated.size,
        metaUpdated,
        navUpdated,
        footerUpdated,
        tagline: aiTagline || tagline || ''
      }
    });

  } catch (e) {
    console.error('AI Transform error:', e);
    res.status(500).json({ error: 'AI Transform failed: ' + e.message });
  }
});

// Site colors (semantic color detection)
app.get('/api/site-colors', (req, res) => {
  const session = getSession(req, res);
  if (!session?.projectPath) return res.status(400).json({ error: 'No project' });

  try {
    const projectDir = session.projectPath;
    const cssFiles = findCssFiles(projectDir);
    const htmlFiles = findHtmlFiles(projectDir);

    const result = { background: null, header: null, footer: null, accent: null, text: null, button: null };

    // Patterns to search for semantic colors
    const patterns = {
      background: [/body\s*\{[^}]*?background(?:-color)?\s*:\s*([^;}\s]+(?:\s*[^;}\s]+)*)/i,
                    /html\s*\{[^}]*?background(?:-color)?\s*:\s*([^;}\s]+(?:\s*[^;}\s]+)*)/i],
      header: [/header\s*\{[^}]*?background(?:-color)?\s*:\s*([^;}\s]+(?:\s*[^;}\s]+)*)/i,
               /\.header\s*\{[^}]*?background(?:-color)?\s*:\s*([^;}\s]+(?:\s*[^;}\s]+)*)/i,
               /#header\s*\{[^}]*?background(?:-color)?\s*:\s*([^;}\s]+(?:\s*[^;}\s]+)*)/i,
               /nav\s*\{[^}]*?background(?:-color)?\s*:\s*([^;}\s]+(?:\s*[^;}\s]+)*)/i],
      footer: [/footer\s*\{[^}]*?background(?:-color)?\s*:\s*([^;}\s]+(?:\s*[^;}\s]+)*)/i,
               /\.footer\s*\{[^}]*?background(?:-color)?\s*:\s*([^;}\s]+(?:\s*[^;}\s]+)*)/i,
               /#footer\s*\{[^}]*?background(?:-color)?\s*:\s*([^;}\s]+(?:\s*[^;}\s]+)*)/i],
      accent: [/a\s*\{[^}]*?color\s*:\s*([^;}\s]+)/i,
               /a:link\s*\{[^}]*?color\s*:\s*([^;}\s]+)/i,
               /\.btn-primary\s*\{[^}]*?background(?:-color)?\s*:\s*([^;}\s]+(?:\s*[^;}\s]+)*)/i,
               /\.btn\s*\{[^}]*?background(?:-color)?\s*:\s*([^;}\s]+(?:\s*[^;}\s]+)*)/i],
      text: [/body\s*\{[^}]*?(?<!background-)color\s*:\s*([^;}\s]+)/i,
             /html\s*\{[^}]*?(?<!background-)color\s*:\s*([^;}\s]+)/i],
      button: [/button\s*\{[^}]*?background(?:-color)?\s*:\s*([^;}\s]+(?:\s*[^;}\s]+)*)/i,
               /\.button\s*\{[^}]*?background(?:-color)?\s*:\s*([^;}\s]+(?:\s*[^;}\s]+)*)/i,
               /input\[type="submit"\]\s*\{[^}]*?background(?:-color)?\s*:\s*([^;}\s]+(?:\s*[^;}\s]+)*)/i]
    };

    // Helper to normalize a color value
    const normalizeColor = (val) => {
      if (!val) return null;
      val = val.trim();
      // Skip CSS functions, variables, etc.
      if (val === 'inherit' || val === 'initial' || val === 'unset' || val === 'transparent' || val === 'none') return null;
      if (val.startsWith('var(')) return null;
      return val;
    };

    // Read all content
    let allContent = '';
    for (const f of cssFiles) {
      try { allContent += fs.readFileSync(path.join(projectDir, f), 'utf-8') + '\n'; } catch (_) {}
    }
    // Also check inline styles in main HTML
    const mainHtml = htmlFiles.find(f => f === 'index.html') || htmlFiles[0];
    if (mainHtml) {
      try { allContent += fs.readFileSync(path.join(projectDir, mainHtml), 'utf-8'); } catch (_) {}
    }

    // Search patterns
    for (const [key, patternList] of Object.entries(patterns)) {
      for (const pattern of patternList) {
        const m = allContent.match(pattern);
        if (m && m[1]) {
          const color = normalizeColor(m[1]);
          if (color && !result[key]) {
            result[key] = color;
            break;
          }
        }
      }
    }

    // Fallback: use most common colors from existing extraction
    if (!result.background || !result.accent) {
      const colors = extractColors(projectDir);
      const hexColors = colors.filter(c => c.color.startsWith('#') && c.color.length >= 4);
      if (!result.background && hexColors.length > 0) result.background = hexColors[0].color;
      if (!result.accent && hexColors.length > 1) result.accent = hexColors[1].color;
      if (!result.text && hexColors.length > 2) result.text = hexColors[2].color;
    }

    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Theme Override System ────────────────────────────────────
// Manages a `clonehawk-overrides.css` file in the project root that uses
// !important selectors to override header, footer, button, background, and
// accent/link colors.  The frontend exposes semantic controls; this endpoint
// persists them and injects the stylesheet into every HTML page.

const THEME_FILE = 'clonehawk-overrides.css';

// The six semantic slots we support
const THEME_SLOTS = ['headerBg', 'footerBg', 'buttonBg', 'buttonText', 'bodyBg', 'accent'];

function buildThemeCss(vars) {
  // Only emit rules for slots that have a value
  const lines = [
    '/* CloneHawk Theme Overrides — auto-generated, do not hand-edit */',
    ':root {'
  ];
  if (vars.headerBg)   lines.push(`  --ch-header-bg: ${vars.headerBg};`);
  if (vars.footerBg)   lines.push(`  --ch-footer-bg: ${vars.footerBg};`);
  if (vars.buttonBg)   lines.push(`  --ch-button-bg: ${vars.buttonBg};`);
  if (vars.buttonText) lines.push(`  --ch-button-text: ${vars.buttonText};`);
  if (vars.bodyBg)     lines.push(`  --ch-body-bg: ${vars.bodyBg};`);
  if (vars.accent)     lines.push(`  --ch-accent: ${vars.accent};`);
  lines.push('}');

  if (vars.bodyBg) {
    lines.push(`body { background-color: ${vars.bodyBg} !important; }`);
  }
  if (vars.accent) {
    lines.push(`a, a:link, a:visited { color: ${vars.accent} !important; }`);
  }
  if (vars.headerBg) {
    lines.push(`header, .header, #header, nav, .navbar, .nav, .site-header, [role="banner"] { background-color: ${vars.headerBg} !important; }`);
  }
  if (vars.footerBg) {
    lines.push(`footer, .footer, #footer, .site-footer, [role="contentinfo"] { background-color: ${vars.footerBg} !important; }`);
  }
  if (vars.buttonBg || vars.buttonText) {
    const selectors = 'button, .btn, .button, .wp-block-button__link, [role="button"], input[type="submit"], input[type="button"], a.btn, a.button, .cta, .cta-btn';
    const rules = [];
    if (vars.buttonBg)   rules.push(`background-color: ${vars.buttonBg} !important; background-image: none !important`);
    if (vars.buttonText) rules.push(`color: ${vars.buttonText} !important`);
    lines.push(`${selectors} { ${rules.join('; ')}; }`);
  }

  return lines.join('\n') + '\n';
}

// Ensure the override stylesheet <link> exists in an HTML string.
// Returns the (possibly modified) HTML.
function ensureThemeLink(html) {
  if (html.includes('clonehawk-overrides.css')) return html; // already injected
  const linkTag = '<link rel="stylesheet" href="clonehawk-overrides.css" data-ch-theme="1">';
  // Insert right before </head> so it loads last and wins specificity
  if (html.includes('</head>')) {
    return html.replace('</head>', linkTag + '\n</head>');
  }
  if (html.includes('</HEAD>')) {
    return html.replace('</HEAD>', linkTag + '\n</HEAD>');
  }
  // No </head> — prepend
  return linkTag + '\n' + html;
}

// GET  /api/theme  — return current theme values (or defaults detected from site)
app.get('/api/theme', (req, res) => {
  const session = getSession(req, res);
  if (!session?.projectPath) return res.status(400).json({ error: 'No project' });

  const themePath = path.join(session.projectPath, THEME_FILE);
  const result = { headerBg: '', footerBg: '', buttonBg: '', buttonText: '', bodyBg: '', accent: '' };

  if (fs.existsSync(themePath)) {
    // Parse existing overrides file
    const css = fs.readFileSync(themePath, 'utf-8');
    const varRegex = /--ch-(\w[\w-]*):\s*([^;]+)/g;
    let m;
    while ((m = varRegex.exec(css)) !== null) {
      const key = m[1].replace(/-([a-z])/g, (_, c) => c.toUpperCase()); // kebab → camel
      if (THEME_SLOTS.includes(key)) {
        result[key] = m[2].trim();
      }
    }
  }

  res.json(result);
});

// POST /api/theme  — save theme values, write CSS, inject link into all HTML pages
app.post('/api/theme', (req, res) => {
  const session = requireSession(req, res);
  if (!session) return;

  const vars = {};
  for (const key of THEME_SLOTS) {
    if (req.body[key] && typeof req.body[key] === 'string') {
      vars[key] = req.body[key].trim();
    }
  }

  try {
    const projectDir = session.projectPath;
    const themePath = path.join(projectDir, THEME_FILE);

    // Snapshot old theme file for undo (if it exists)
    const undoFiles = [];
    if (fs.existsSync(themePath)) {
      undoFiles.push({ filePath: themePath, content: fs.readFileSync(themePath), binary: false });
    }

    // Write the override stylesheet
    const css = buildThemeCss(vars);
    fs.writeFileSync(themePath, css, 'utf-8');

    // Inject <link> into every HTML page that doesn't already have it
    const htmlFiles = findHtmlFiles(projectDir);
    for (const htmlFile of htmlFiles) {
      const fp = safePath(projectDir, htmlFile);
      if (!fp || !fs.existsSync(fp)) continue;
      let html = fs.readFileSync(fp, 'utf-8');
      if (!html.includes('clonehawk-overrides.css')) {
        // Snapshot for undo
        undoFiles.push({ filePath: fp, content: Buffer.from(html, 'utf-8'), binary: false });
        html = ensureThemeLink(html);
        fs.writeFileSync(fp, html, 'utf-8');
      }
    }

    if (undoFiles.length > 0) {
      pushUndo(session, 'Theme color update', undoFiles);
    }

    session.scanCache = null;
    res.json({ ok: true, slots: vars });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    ok: true,
    activeSessions: sessions.size,
    maxSessions: MAX_SESSIONS,
    uptimeMin: Math.round(process.uptime() / 60)
  });
});

// ─── Cleanup previous project (called when user starts a new project) ────────
app.post('/api/cleanup', (req, res) => {
  const session = getSession(req, res);
  if (!session) return res.json({ ok: true });

  if (session.projectPath && fs.existsSync(session.projectPath)) {
    try {
      fs.rmSync(session.projectPath, { recursive: true, force: true });
    } catch (e) { /* ignore */ }
  }
  session.projectPath = null;
  session.scanCache = null;
  session._structureCache = null;
  session._structureCacheHomepage = null;
  session.undoStack = [];
  session.redoStack = [];
  res.json({ ok: true });
});

// ─── Start ───────────────────────────────────────────────────
app.listen(PORT, HOST, () => {
  console.log(`\n  🦅 CloneHawk running at http://${HOST}:${PORT}`);
  console.log(`  📁 Workspaces: ${WORKSPACE_ROOT}`);
  console.log(`  📦 Upload limit: ${UPLOAD_MAX_MB}MB`);
  console.log(`  ⏰ Session TTL: ${SESSION_TTL_HOURS}h`);
  console.log(`  🧹 Cleanup every: ${CLEANUP_INTERVAL_MIN}min\n`);
});
