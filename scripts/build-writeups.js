const fs = require('fs');
const path = require('path');
const marked = require('marked');

const MD_DIR = path.join(__dirname, '..', 'writeups', 'md-writeups');
const OUT_DIR = path.join(__dirname, '..', 'writeups');
const INDEX_FILE = path.join(OUT_DIR, 'index.html');

function slugify(name) {
  return name.replace(/\.md$/i, '').replace(/[^a-z0-9-_]+/gi, '-').toLowerCase();
}

function extractMeta(md) {
  const meta = { title: null, author: null, event: null, category: null, date: null, readtime: null };
  const lines = md.split(/\r?\n/);
  for (let i = 0; i < Math.min(lines.length, 30); i++) {
    const l = lines[i];
    if (!meta.title) {
      const m = l.match(/^#\s+(.*)$/);
      if (m) meta.title = m[1].trim();
    }
    const author = l.match(/\*\*Author:\*\*\s*(.*)$/i) || l.match(/^Author:\s*(.*)$/i);
    if (author && !meta.author) meta.author = author[1].trim();
    const cat = l.match(/\*\*Category:\*\*\s*(.*)$/i) || l.match(/^Category:\s*(.*)$/i);
    if (cat && !meta.category) meta.category = cat[1].trim();
    const event = l.match(/\*\*Event:\*\*\s*(.*)$/i) || l.match(/^Event:\s*(.*)$/i);
    if (event && !meta.event) meta.event = event[1].trim();
    const date = l.match(/\*\*Date:\*\*\s*(.*)$/i) || l.match(/^Date:\s*(.*)$/i);
    if (date && !meta.date) meta.date = date[1].trim();
    const rt = l.match(/\*\*Read Time:\*\*\s*(.*)$/i) || l.match(/^Read Time:\s*(.*)$/i);
    if (rt && !meta.readtime) meta.readtime = rt[1].trim();
  }
  return meta;
}

function buildWriteupHtml(title, contentHtml) {
  return `<!DOCTYPE html>
<html lang="en-us">
<head>
  <meta charset="utf-8">
  <title>${title} - Writeup</title>

  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="CTF Writeup">
  <meta name="author" content="Cyber Saguaros">

  <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Droid+Serif:400|Josefin+Sans:300,400,600,700">
  <link rel="stylesheet" href="/plugins/bootstrap/bootstrap.min.css">
  <link rel="stylesheet" href="/plugins/themefisher-font/themefisher-font.min.css">
  <link rel="stylesheet" href="/scss/style.min.css" media="screen">

  <style>
    body {
      background:
        radial-gradient(circle at top, rgba(203, 166, 247, 0.18), transparent 34%),
        linear-gradient(180deg, #1e1e2e 0%, #181825 100%);
      color: #cdd6f4;
      font-family: 'Droid Serif', 'Josefin Sans', sans-serif;
    }

    header.navigation {
      background-color: #181825;
    }

    /* Force navbar/link colors to match site header even if external CSS didn't load */
    .navigation, .navbar {
      background-color: #181825 !important;
    }
    .navbar-brand, .nav-link {
      color: #cdd6f4 !important;
    }
    .nav-link:hover, .navbar-brand:hover {
      color: #d8bafc !important;
    }

    .writeup-container {
      max-width: 900px;
      margin: 3rem auto;
      background: rgba(24, 24, 37, 0.94);
      border: 1px solid rgba(203, 166, 247, 0.18);
      border-radius: 16px;
      padding: 2rem;
      box-shadow: 0 16px 50px rgba(0, 0, 0, 0.28);
    }

    .markdown-content {
      color: rgba(205, 214, 244, 0.86);
      line-height: 1.8;
    }

    .markdown-content h1 { color: #f5e0dc; font-size: 2.2rem; margin: 0 0 1rem; line-height: 1.2; border-bottom: 2px solid rgba(203,166,247,0.2); padding-bottom:1rem; }
    .markdown-content h2 { color: #f5e0dc; font-size: 1.6rem; margin: 2rem 0 1rem; border-bottom: 1px solid rgba(203,166,247,0.12); padding-bottom:0.5rem; }
    .markdown-content h3 { color: #cba6f7; font-size: 1.3rem; margin: 1.5rem 0 0.8rem; }
    .markdown-content p { margin-bottom: 1rem; }
    .markdown-content code { background: rgba(0,0,0,0.3); color: #94e2d5; padding:0.2rem 0.5rem; border-radius:4px; font-family: 'Courier New', monospace; }
    .markdown-content pre { background: rgba(0,0,0,0.4); border-left: 3px solid #cba6f7; padding:1rem; border-radius:6px; overflow-x:auto; margin:1rem 0; }
    .markdown-content pre code { background:none; color:#89b4fa; padding:0; }
    .markdown-content blockquote { border-left:4px solid #cba6f7; padding-left:1rem; color:rgba(205,214,244,0.76); font-style:italic; }
    .markdown-content table { border-collapse: collapse; width:100%; margin:1rem 0; }
    .markdown-content table th, .markdown-content table td { border:1px solid rgba(203,166,247,0.2); padding:0.75rem; text-align:left; }
    .markdown-content table th { background: rgba(203,166,247,0.1); color:#f5e0dc; font-weight:700; }

    footer.footer { background-color:#1e1e2e; color:#cdd6f4; padding:2rem 1rem; text-align:center; margin-top:3rem; border-top:1px solid rgba(203,166,247,0.12); }
  </style>
</head>

<body>
  <header class="navigation" style="background-color: #1e1e2e;">
    <div class="container">
      <nav class="navbar navbar-expand-lg navbar-dark">
        <a class="navbar-brand" href="/">Cyber Saguaros</a>
        <div class="collapse navbar-collapse">
          <ul class="navbar-nav ml-auto">
            <li class="nav-item"><a class="nav-link" href="/contact/">Contact</a></li>
            <li class="nav-item"><a class="nav-link" href="/calendar/">Calendar</a></li>
            <li class="nav-item"><a class="nav-link" href="/presentations/">Presentations</a></li>
            <li class="nav-item"><a class="nav-link" href="/writeups/">Writeups</a></li>
          </ul>
        </div>
      </nav>
    </div>
  </header>

  <main>
    <div class="container">
      <a href="/writeups/" class="back-link">← Back to Writeups</a>
      <div class="writeup-container">
        <div class="markdown-content">
          ${contentHtml}
        </div>
      </div>
    </div>
  </main>

  <footer class="footer">
    <div class="container">
      <p>&copy; 2024-2026 Cyber Saguaros. All rights reserved.</p>
    </div>
  </footer>

  <script src="/plugins/jquery/jquery.js"></script>
  <script src="/plugins/bootstrap/bootstrap.min.js"></script>
</body>
</html>`;
}

function generate() {
  if (!fs.existsSync(MD_DIR)) {
    console.error('Markdown directory not found:', MD_DIR);
    process.exit(1);
  }

  const files = fs.readdirSync(MD_DIR).filter(f => f.toLowerCase().endsWith('.md'));
  const cards = [];
  const eventSet = new Set();
  const categorySet = new Set();

  files.forEach(file => {
    const mdPath = path.join(MD_DIR, file);
    const md = fs.readFileSync(mdPath, 'utf8');
    const meta = extractMeta(md);
    const html = marked.parse(md);
    const title = meta.title || slugify(file);
    const basename = slugify(file) + '.html';
    const outPath = path.join(OUT_DIR, basename);

    // Wrap generated HTML into full page
    const outHtml = buildWriteupHtml(title, html);
    fs.writeFileSync(outPath, outHtml, 'utf8');
    console.log('Wrote', outPath);

    // collect stats and prepare card metadata
    if (meta.event) eventSet.add(meta.event);
    if (meta.category) categorySet.add(meta.category);
    // Prepare card metadata
    cards.push({
      href: `/writeups/${basename}`,
      author: meta.author || 'Unknown',
      ctf: meta.title ? (meta.title + '') : '',
      category: meta.category || 'misc',
      title: meta.title || file.replace(/\.md$/i, ''),
      copy: '',
      date: meta.date || '',
      readtime: meta.readtime || ''
    });

  // Compute stats
  const totalWriteups = files.length;
  const totalEvents = eventSet.size;
  const totalCategories = categorySet.size;
  });

  // Update index.html between markers
  if (!fs.existsSync(INDEX_FILE)) {
    console.error('Index file not found:', INDEX_FILE);
    process.exit(1);
  }

  let index = fs.readFileSync(INDEX_FILE, 'utf8');
  const startMarker = '<!-- WRITEUPS:START';
  const endMarker = '<!-- WRITEUPS:END -->';
    const start = index.indexOf(startMarker);
    const end = index.indexOf(endMarker, start);
    if (start === -1 || end === -1) {
      console.error('Markers not found in index.html. Please ensure WRITEUPS:START and WRITEUPS:END are present.');
      process.exit(1);
    }

    // Preserve the original start comment and end comment
    const startCommentEnd = index.indexOf('-->', start) + 3;
    const endCommentStart = end; // points to start of '<!-- WRITEUPS:END -->'
    const before = index.slice(0, startCommentEnd);
    const endComment = index.slice(endCommentStart, endCommentStart + endMarker.length);
    const after = index.slice(endCommentStart + endMarker.length);

      // Build new cards HTML (preserve previous formatting)
      const cardsHtml = cards.map(card => `\n\t\t\t\t<div class="col-md-6 mb-4">\n\t\t\t\t\t<a href="${card.href}" style="text-decoration: none; color: inherit;">\n\t\t\t\t\t\t<div class="writeup-card">\n\t\t\t\t\t\t\t<div class="writeup-author">${card.author}</div>\n\t\t\t\t\t\t\t<div class="writeup-topline">\n\t\t\t\t\t\t\t\t<span class="writeup-ctf">${card.ctf}</span>\n\t\t\t\t\t\t\t\t<span class="writeup-category ${card.category}">${card.category}</span>\n\t\t\t\t\t\t\t</div>\n\t\t\t\t\t\t\t<h3 class="writeup-title">${card.title}</h3>\n\t\t\t\t\t\t\t<p class="writeup-copy">${card.copy}</p>\n\t\t\t\t\t\t\t<div class="writeup-footer">\n\t\t\t\t\t\t\t\t<span class="writeup-date">${card.date}</span>\n\t\t\t\t\t\t\t\t<span class="writeup-readtime">${card.readtime}</span>\n\t\t\t\t\t\t\t</div>\n\t\t\t\t\t\t</div>\n\t\t\t\t\t</a>\n\t\t\t\t</div>`).join('\n');

    const newIndex = before + '\n' + cardsHtml + '\n' + endComment + after;
    fs.writeFileSync(INDEX_FILE, newIndex, 'utf8');
    console.log('Updated index:', INDEX_FILE);

      // Compute totals for stats
      const totalWriteups = files.length;
      const totalEvents = eventSet.size;
      const totalCategories = categorySet.size;

      // Replace stats block between WRITEUPS_STATS markers in the writeups index
      try {
        let idxHtml = fs.readFileSync(INDEX_FILE, 'utf8');
        const sStat = '<!-- WRITEUPS_STATS:START';
        const eStat = '<!-- WRITEUPS_STATS:END -->';
        const sPos = idxHtml.indexOf(sStat);
        const ePos = idxHtml.indexOf(eStat, sPos);
        if (sPos !== -1 && ePos !== -1) {
          const startCommentEnd = idxHtml.indexOf('-->', sPos) + 3;
          const afterStat = idxHtml.slice(ePos + eStat.length);
          const statsHtml = `\n\t\t\t\t<div class="feature-panel">\n\t\t\t\t\t<div class="feature-stat">\n\t\t\t\t\t\t<div class="feature-stat-value">${totalWriteups}</div>\n\t\t\t\t\t\t<div>\n\t\t\t\t\t\t\t<div class="feature-stat-label">Writeups</div>\n\t\t\t\t\t\t\t<div class="feature-stat-copy">In-depth technical write-ups</div>\n\t\t\t\t\t\t</div>\n\t\t\t\t\t</div>\n\n\t\t\t\t\t<div class="feature-stat">\n\t\t\t\t\t\t<div class="feature-stat-value">${totalEvents}</div>\n\t\t\t\t\t\t<div>\n\t\t\t\t\t\t\t<div class="feature-stat-label">CTF Events</div>\n\t\t\t\t\t\t\t<div class="feature-stat-copy">Competitions covered</div>\n\t\t\t\t\t\t</div>\n\t\t\t\t\t</div>\n\n\t\t\t\t\t<div class="feature-stat">\n\t\t\t\t\t\t<div class="feature-stat-value">${totalCategories}</div>\n\t\t\t\t\t\t<div>\n\t\t\t\t\t\t\t<div class="feature-stat-label">Categories</div>\n\t\t\t\t\t\t\t<div class="feature-stat-copy">All security domains</div>\n\t\t\t\t\t\t</div>\n\t\t\t\t\t</div>\n\t\t\t\t</div>\n`;
          const newIdx = idxHtml.slice(0, startCommentEnd) + statsHtml + afterStat;
          fs.writeFileSync(INDEX_FILE, newIdx, 'utf8');
          console.log('Updated writeups stats in index');
        } else {
          console.log('WRITEUPS_STATS markers not found in writeups index; skipping stats update');
        }
      } catch (err) {
        console.error('Failed to update writeups stats:', err);
      }

    // Also update root index.html with a latest-writeup summary card if markers present
    try {
      const ROOT_INDEX = path.join(__dirname, '..', 'index.html');
      if (fs.existsSync(ROOT_INDEX)) {
        let rootHtml = fs.readFileSync(ROOT_INDEX, 'utf8');
        const sMarker = '<!-- WRITEUPS_SUMMARY:START';
        const eMarker = '<!-- WRITEUPS_SUMMARY:END -->';
        const s = rootHtml.indexOf(sMarker);
        const e = rootHtml.indexOf(eMarker, s);
        if (s !== -1 && e !== -1) {
          // pick latest writeup by date metadata or mtime
          let latest = null;
          files.forEach(file => {
            const mdPath = path.join(MD_DIR, file);
            const md = fs.readFileSync(mdPath, 'utf8');
            const meta = extractMeta(md);
            let dateVal = null;
            if (meta.date) {
              const parsed = Date.parse(meta.date);
              if (!isNaN(parsed)) dateVal = parsed;
            }
            if (!dateVal) {
              const stats = fs.statSync(mdPath);
              dateVal = stats.mtimeMs;
            }
            const title = meta.title || file.replace(/\.md$/i, '');
            const href = `/writeups/${slugify(file)}.html`;
            const author = meta.author || 'Unknown';
            if (!latest || dateVal > latest.dateVal) latest = { title, href, author, dateVal };
          });

          let summaryHtml = '';
          if (latest) {
            summaryHtml = `\n<div class="writeup-summary" style="margin:2rem 0;">\n  <div class=\"feature-panel\">\n    <div style=\"display:flex;align-items:center;justify-content:space-between;gap:1rem;\">\n      <div>\n        <div style=\"font-weight:700;color:#f5e0dc;margin-bottom:0.25rem;\">Latest Writeup</div>\n        <a href=\"${latest.href}\" style=\"color:#89b4fa;font-size:1.05rem;text-decoration:none;\">${latest.title}</a>\n        <div style=\"color:rgba(205,214,244,0.78);font-size:0.95rem;\">by ${latest.author}</div>\n      </div>\n      <div>\n        <a href=\"${latest.href}\" class=\"btn btn-main\" style=\"background-color:#cba6f7;border-color:#cba6f7;color:#1e1e2e;\">Read</a>\n      </div>\n    </div>\n  </div>\n</div>\n`;
          }

          const beforeRoot = rootHtml.slice(0, s);
          const afterRoot = rootHtml.slice(e + eMarker.length);
          const newRoot = beforeRoot + summaryHtml + afterRoot;
          fs.writeFileSync(ROOT_INDEX, newRoot, 'utf8');
          console.log('Updated root index with latest writeup summary');
        } else {
          console.log('Root index markers not found; skipping root update');
        }
      }
    } catch (err) {
      console.error('Failed to update root index summary:', err);
    }
}

generate();
