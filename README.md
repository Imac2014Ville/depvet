# DepVet

Pre-install dependency vetting for AI agents. Check an **npm** or **PyPI** package before you install it. **No API key, no signup.** Pay per call in **USDC on Base**, automatically via [x402](https://x402.org).

**Live:** https://depvet.imac2014ville.workers.dev · [OpenAPI](https://depvet.imac2014ville.workers.dev/openapi.json)

Landing page: https://depvet.imac2014ville.workers.dev/ · Payments settle via PayAI with automatic failover.

| Endpoint | Price | What it does |
|---|---|---|
| `POST /report` `{ "ecosystem": "npm", "name": "lodash", "version": "4.17.20" }` | $0.02 | Full report: verdict `OK` / `REVIEW` / `AVOID` with reasons, known vulnerabilities (OSV.dev) with severity and fixed versions, malware advisories, SPDX license + risk class, dependency counts, OpenSSF Scorecard, maintenance signals (last publish, release cadence, deprecated, maintainers), typosquat hint. |
| `POST /check` `{ "ecosystem": "pypi", "name": "requests" }` | $0.005 | Light check: vulnerability count + max severity, malware flag, license, deprecated, verdict. |
| `POST /batch` `{ "ecosystem": "npm", "packages": [{"name": "express"}, {"name": "lodash", "version": "4.17.20"}] }` | $0.05 | Light check of up to 20 packages (a lockfile), plus an overall verdict. |

`ecosystem` is `npm` or `pypi`; `version` defaults to the latest. `GET` with query params works too (`/check?ecosystem=npm&name=express`, batch: `packages=express,lodash@4.17.20`).

Invalid input returns `400` and unknown packages `404` **before any payment is settled**, so you are never charged for them. The 404 includes a `didYouMean` when the name is a near-miss of a popular package (handy against hallucinated or typosquatted names).

## Verdict rules (deterministic, no LLM)

- **AVOID**: malware/compromised-package advisory (e.g. OSV `MAL-*`), a critical vulnerability, or a likely typosquat (near a popular name *and* brand new).
- **REVIEW**: high/moderate vulnerabilities, deprecated or yanked, strong-copyleft or unknown license, typosquat-like name, no release for 2+ years, no maintainers, OpenSSF Scorecard below 3, or OSV unreachable.
- **OK**: none of the above. `reasons` lists every rule that fired (including informational ones such as install scripts).

Data: [OSV.dev](https://osv.dev), [deps.dev](https://deps.dev), the npm registry and PyPI. Results are cached for 10 minutes.

## Use it from an agent

```js
import { wrapFetchWithPaymentFromConfig } from "@x402/fetch";
import { ExactEvmScheme } from "@x402/evm";
import { privateKeyToAccount } from "viem/accounts";

const pay = wrapFetchWithPaymentFromConfig(fetch, {
  schemes: [{ network: "eip155:8453", client: new ExactEvmScheme(privateKeyToAccount(process.env.PK)) }],
});
const r = await pay("https://depvet.imac2014ville.workers.dev/check", {
  method: "POST", headers: { "content-type": "application/json" },
  body: JSON.stringify({ ecosystem: "npm", name: "lodash", version: "4.17.20" }),
});
console.log(await r.json());
```

## Example response (`/check`)

```json
{
  "ok": true, "ecosystem": "npm", "name": "lodash", "version": "4.17.20",
  "license": "MIT", "licenseRisk": "permissive",
  "vulnerabilities": { "count": 5, "maxSeverity": "HIGH", "malware": false },
  "deprecated": false, "typosquatSuspect": false,
  "verdict": "REVIEW", "reasons": ["2 high-severity vulnerability advisory(ies) affect this version."]
}
```

## Self-host

Cloudflare Worker, Hono, and `@x402/hono`. No third-party API keys.

```sh
npm install && npx wrangler deploy
```

Change `PAY_TO` and `ORIGIN` in `src/index.js`. Settlement goes through the PayAI facilitator. For local testing: `npx wrangler dev --var DEV_FREE:1` bypasses the paywall (never set this in production).

MIT licensed.

Listed on x402scan (https://www.x402scan.com).

Sister project: [baselens](https://github.com/Imac2014Ville/baselens)
