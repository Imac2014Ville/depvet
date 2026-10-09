// Human/SEO landing page + crawler files. Single file, inline CSS, no external assets.
const ORIGIN = "https://depvet.imac2014ville.workers.dev";
const TITLE = "DepVet — check npm & PyPI packages before your AI agent installs them";
const DESC = "Pay-per-call dependency risk reports for AI agents: OK/REVIEW/AVOID verdicts from OSV vulnerabilities, malware advisories, license risk, typosquat hints and OpenSSF Scorecard. No API key, x402 USDC on Base, from $0.005.";

const esc = s => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
const code = s => `<pre><code>${esc(s)}</code></pre>`;

const EX_CHECK = `{
  "ok": true,
  "ecosystem": "npm",
  "name": "lodash",
  "version": "4.17.20",
  "license": "MIT",
  "licenseRisk": "permissive",
  "vulnerabilities": { "count": 5, "maxSeverity": "HIGH", "malware": false },
  "deprecated": false,
  "typosquatSuspect": false,
  "verdict": "REVIEW",
  "reasons": ["2 high-severity vulnerability advisory(ies) affect this version."]
}`;
const EX_TYPO = `{
  "ok": true,
  "ecosystem": "npm",
  "name": "expresss",
  "version": "0.0.0",
  "vulnerabilities": { "count": 0, "maxSeverity": "NONE", "malware": false },
  "typosquatSuspect": "express",
  "verdict": "REVIEW",
  "reasons": ["Name is 1 edit(s) from popular package \\"express\\"."]
}`;
const EX_REPORT = `{
  "ok": true, "ecosystem": "npm", "name": "lodash", "version": "4.17.20",
  "latestVersion": "4.18.1", "isLatest": false,
  "verdict": "REVIEW",
  "reasons": [
    { "level": "REVIEW", "code": "high-vuln", "message": "2 high-severity vulnerability advisory(ies) affect this version." },
    { "level": "INFO", "code": "not-latest", "message": "Not the latest version (latest is 4.18.1)." }
  ],
  "license": { "spdx": "MIT", "riskClass": "permissive" },
  "vulnerabilities": { "count": 5, "maxSeverity": "HIGH", "malware": false, "items": [
    { "id": "GHSA-35jh-r3h4-6jhm", "aliases": ["CVE-2021-23337"], "severity": "HIGH",
      "summary": "Command Injection in lodash", "fixedIn": ["4.17.21"] }
  ] },
  "dependencies": { "direct": 0, "transitive": 0 },
  "scorecard": { "repo": "github.com/lodash/lodash", "score": 7.5 },
  "maintenance": { "lastPublish": "2026-04-01T21:01:20Z", "totalVersions": 117, "deprecated": false, "maintainers": 3 },
  "typosquat": { "suspect": false },
  "sources": ["osv.dev", "deps.dev", "registry.npmjs.org"]
}`;
const CURL = `$ curl -i "${ORIGIN}/check?ecosystem=npm&name=express"
HTTP/2 402
payment-required: eyJ4NDAyVmVyc2lvbiI6Mi4uLn0=   # base64 JSON: price, USDC on Base, payTo

# sign the payment with any x402 client, then retry with:
$ curl "${ORIGIN}/check?ecosystem=npm&name=express" \\
    -H "PAYMENT-SIGNATURE: <signed payload>"`;
const JS = `import { wrapFetchWithPaymentFromConfig } from "@x402/fetch";
import { ExactEvmScheme } from "@x402/evm";
import { privateKeyToAccount } from "viem/accounts";

const fetchPaid = wrapFetchWithPaymentFromConfig(fetch, {
  schemes: [{ network: "eip155:8453",
              client: new ExactEvmScheme(privateKeyToAccount(process.env.PRIVATE_KEY)) }],
});

const res = await fetchPaid("${ORIGIN}/check?ecosystem=npm&name=lodash&version=4.17.20");
const { verdict, reasons } = await res.json();   // "REVIEW", [...]`;

const html = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(TITLE)}</title>
<meta name="description" content="${esc(DESC)}">
<link rel="canonical" href="${ORIGIN}/">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<meta property="og:type" content="website"><meta property="og:site_name" content="DepVet">
<meta property="og:title" content="${esc(TITLE)}"><meta property="og:description" content="${esc(DESC)}">
<meta property="og:url" content="${ORIGIN}/"><meta property="og:image" content="${ORIGIN}/favicon.svg">
<meta name="twitter:card" content="summary"><meta name="twitter:title" content="${esc(TITLE)}"><meta name="twitter:description" content="${esc(DESC)}">
<script type="application/ld+json">${JSON.stringify({ "@context": "https://schema.org", "@type": "WebAPI", name: "DepVet", description: DESC, url: ORIGIN + "/", documentation: ORIGIN + "/openapi.json" })}</script>
<style>
:root{--bg:#fff;--fg:#0f172a;--mut:#475569;--card:#f8fafc;--bd:#e2e8f0;--ac:#16a34a;--code:#f1f5f9}
@media(prefers-color-scheme:dark){:root{--bg:#0b1120;--fg:#e2e8f0;--mut:#94a3b8;--card:#111a2e;--bd:#1e293b;--ac:#4ade80;--code:#0f172a}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.6 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:860px;margin:0 auto;padding:32px 16px 64px}
h1{font-size:2rem;line-height:1.2;margin:.2em 0}h2{margin-top:2.2em;border-bottom:1px solid var(--bd);padding-bottom:.3em}
a{color:var(--ac)}p,li{color:var(--mut)}strong{color:var(--fg)}
pre{background:var(--code);border:1px solid var(--bd);border-radius:8px;padding:12px;overflow-x:auto;font-size:.82rem;line-height:1.45}
code{font-family:ui-monospace,Menlo,Consolas,monospace}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:8px;border-bottom:1px solid var(--bd);vertical-align:top}
.price{font-weight:700;color:var(--ac);white-space:nowrap}.tag{display:inline-block;background:var(--card);border:1px solid var(--bd);border-radius:99px;padding:0 10px;font-size:.8rem;color:var(--mut)}
.links a{margin-right:16px;display:inline-block}
@media(max-width:600px){h1{font-size:1.5rem}}
</style></head><body><main>
<p><span class="tag">x402 · USDC on Base · no API key</span></p>
<h1>Check npm &amp; PyPI packages before your AI agent installs them</h1>
<p>DepVet returns an <strong>OK / REVIEW / AVOID</strong> verdict, with reasons, for any npm or PyPI package. Deterministic rules over public data, no LLM, paid per call from $0.005.</p>
<p class="links"><a href="/openapi.json">OpenAPI</a><a href="https://github.com/Imac2014Ville/depvet">GitHub</a><a href="https://www.x402scan.com/">x402scan</a><a href="/llms.txt">llms.txt</a></p>

<h2>The problem</h2>
<p>AI coding agents run <code>npm install</code> and <code>pip install</code> on names they half-remember. That is how hallucinated package names, typosquats (<code>expresss</code> for <code>express</code>), packages carrying malware advisories, and versions with known high-severity CVEs end up in your project. Agents rarely stop to check. DepVet is the check they can call in one HTTP request, without an account or key.</p>

<h2>What a report contains</h2>
<ul>
<li><strong>Verdict</strong> OK, REVIEW or AVOID, with machine-readable reasons</li>
<li><strong>Vulnerabilities</strong> from OSV with severity and fixed versions, plus malware advisories</li>
<li><strong>License</strong> as SPDX id and risk class (permissive, copyleft, unknown)</li>
<li><strong>Dependencies</strong> direct and transitive counts</li>
<li><strong>OpenSSF Scorecard</strong> score and weak checks</li>
<li><strong>Maintenance</strong> last publish, release cadence, deprecated or yanked, maintainer count</li>
<li><strong>Typosquat hint</strong> with the popular package it resembles; unknown names return 404 with a did-you-mean</li>
</ul>

<h2>Endpoints and prices</h2>
<table>
<tr><th>Endpoint</th><th>Price</th><th>Returns</th></tr>
<tr><td><code>/report</code></td><td class="price">$0.02</td><td>Full risk report</td></tr>
<tr><td><code>/check</code></td><td class="price">$0.005</td><td>Light check: vulns, license, deprecated, verdict</td></tr>
<tr><td><code>/batch</code></td><td class="price">$0.05</td><td>Light check of up to 20 packages (a lockfile)</td></tr>
</table>
<p>Params: <code>ecosystem</code> (<code>npm</code> or <code>pypi</code>), <code>name</code>, optional <code>version</code>. GET with query params or POST JSON. Bad input (400) and unknown packages (404) are rejected before payment, so you are never charged for them.</p>

<h3>Example: <code>GET /check?ecosystem=npm&amp;name=lodash&amp;version=4.17.20</code></h3>
${code(EX_CHECK)}
<h3>Example: a typosquat, <code>GET /check?ecosystem=npm&amp;name=expresss</code></h3>
${code(EX_TYPO)}
<h3>Example: <code>GET /report?ecosystem=npm&amp;name=lodash&amp;version=4.17.20</code> (trimmed)</h3>
${code(EX_REPORT)}

<h2>How to call it</h2>
<p>Unpaid requests get HTTP 402 with payment requirements. Sign with any x402 client and retry.</p>
${code(CURL)}
<p>With <code>@x402/fetch</code> the 402 handshake is automatic:</p>
${code(JS)}

<h2>Links</h2>
<p class="links"><a href="/openapi.json">/openapi.json</a><a href="https://github.com/Imac2014Ville/depvet">GitHub</a><a href="https://www.x402scan.com/">x402scan</a><a href="https://baselens.imac2014ville.workers.dev">BaseLens</a> (sister service: Base wallet and token intelligence for agents)</p>
</main></body></html>`;

export const landingHtml = () => html;
export const LLMS = `# DepVet

> Pre-install dependency vetting for AI agents. Check an npm or PyPI package and get an OK/REVIEW/AVOID verdict with reasons: OSV vulnerabilities, malware advisories, license risk, deprecation, maintenance, OpenSSF Scorecard, typosquat hints. Pay per call in USDC on Base via x402. No API key.

## Endpoints (GET query params or POST JSON; ecosystem = npm | pypi)
- GET ${ORIGIN}/check?ecosystem=npm&name=express[&version=] : $0.005, light check
- GET ${ORIGIN}/report?ecosystem=npm&name=express[&version=] : $0.02, full report
- GET ${ORIGIN}/batch?ecosystem=npm&packages=express,lodash@4.17.20 : $0.05, up to 20 packages
- Invalid input returns 400 and unknown packages 404 before payment; you are not charged.
- Unpaid requests return HTTP 402 with x402 payment requirements; use @x402/fetch or any x402 client.

## Links
- OpenAPI: ${ORIGIN}/openapi.json
- Docs (JSON): fetch ${ORIGIN}/ with Accept: application/json
- Source: https://github.com/Imac2014Ville/depvet
- Sister service: https://baselens.imac2014ville.workers.dev
`;
export const ROBOTS = `User-agent: *\nAllow: /\n\nSitemap: ${ORIGIN}/sitemap.xml\n`;
export const SITEMAP = `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${["/", "/openapi.json", "/llms.txt"].map(p => `  <url><loc>${ORIGIN}${p}</loc></url>`).join("\n")}\n</urlset>\n`;
