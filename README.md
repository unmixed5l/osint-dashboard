# OSINT Dashboard

Submit an IP, domain, URL or hash and get VirusTotal, AbuseIPDB, GreyNoise, URLhaus, MalwareBazaar, RDAP/WHOIS, geolocation and related news in one view.

- `index.html`: the dashboard (static, hosted on GitHub Pages)
- `worker/`: Cloudflare Worker that keeps your API keys secret and queries the sources

GitHub Pages cannot hide API keys and most OSINT APIs block browser requests, so the Worker is required.

## Deploy the Worker (free)
```
cd worker
npm i -g wrangler && wrangler login
wrangler secret put VT_KEY          # virustotal.com
wrangler secret put ABUSEIPDB_KEY   # abuseipdb.com
wrangler secret put GREYNOISE_KEY   # greynoise.io (community)
wrangler secret put ABUSECH_KEY     # auth.abuse.ch (URLhaus + MalwareBazaar)
wrangler deploy
```
Copy the printed `https://osint-proxy.<you>.workers.dev` URL into `DEFAULT_API` in `index.html`.
Missing keys only disable that source; the rest still work.

## Publish on GitHub Pages
Repo, Settings, Pages, Deploy from branch `main`, folder `/ (root)`.
Then set `ALLOWED_ORIGIN` in `wrangler.toml` to `https://<you>.github.io` and run `wrangler deploy` again.
