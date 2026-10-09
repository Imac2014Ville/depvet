// DepVet — pay-per-call dependency risk reports for AI agents (x402, USDC on Base).
import { Hono } from "hono";
import { paymentMiddleware, x402ResourceServer } from "@x402/hono";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { FailoverFacilitatorClient } from "./facilitator.js";
import { bazaarResourceServerExtension, declareDiscoveryExtension } from "@x402/extensions/bazaar";
import { typosquat } from "./popular.js";
import { landingHtml, LLMS, ROBOTS, SITEMAP } from "./landing.js";
import { report, check, batch, batchCost, validatePkg, NotFound } from "./vet.js";

const PAY_TO = "0xbBB1338E3990a9Ab5DB36546a28cEe06cCB03D05";
const NETWORK = "eip155:8453";
const ORIGIN = "https://depvet.imac2014ville.workers.dev";
const PRICE = "$0.02";

const app = new Hono();
const server = new x402ResourceServer(new FailoverFacilitatorClient())
  .register(NETWORK, new ExactEvmScheme());
server.registerExtension(bazaarResourceServerExtension);

const route = (description, input, inputSchema, example, price = PRICE) => ({
  accepts: { scheme: "exact", price, network: NETWORK, payTo: PAY_TO },
  description, mimeType: "application/json",
  extensions: declareDiscoveryExtension({ input, inputSchema, output: { example } }),
});

const ECO = { type: "string", enum: ["npm", "pypi"], description: "Package ecosystem" };
const NAME = { type: "string", description: "Package name, e.g. express, @types/node, requests" };
const VERSION = { type: "string", description: "Exact version (default: latest)" };

const ROUTES = {
  "GET /report": route("Full dependency risk report before you install an npm or PyPI package: verdict OK/REVIEW/AVOID with reasons, known vulnerabilities (OSV) with severity and fixed versions, malware advisories, SPDX license and risk class, dependency counts, OpenSSF Scorecard, maintenance signals (last publish, release cadence, deprecated, maintainers), and a typosquat hint. Deterministic rules, no LLM.",
    { ecosystem: "npm", name: "lodash", version: "4.17.20" },
    { type: "object", properties: { ecosystem: ECO, name: NAME, version: VERSION }, required: ["ecosystem", "name"] },
    { ok: true, ecosystem: "npm", name: "lodash", version: "4.17.20", verdict: "REVIEW", reasons: [{ level: "REVIEW", code: "high-vuln", message: "3 high-severity vulnerability advisory(ies) affect this version." }], license: { spdx: "MIT", riskClass: "permissive" }, vulnerabilities: { count: 4, maxSeverity: "HIGH" }, dependencies: { direct: 0, transitive: 0 }, typosquat: { suspect: false } }),
  "GET /check": route("Light pre-install check for an npm or PyPI package: vulnerability count and max severity, malware flag, license + risk class, deprecated, typosquat hint, and an OK/REVIEW/AVOID verdict. Cheap enough to run on every install.",
    { ecosystem: "pypi", name: "requests" },
    { type: "object", properties: { ecosystem: ECO, name: NAME, version: VERSION }, required: ["ecosystem", "name"] },
    { ok: true, ecosystem: "pypi", name: "requests", version: "2.32.3", verdict: "OK", license: "Apache-2.0", licenseRisk: "permissive", vulnerabilities: { count: 0, maxSeverity: "NONE", malware: false }, deprecated: false, typosquatSuspect: false }, "$0.005"),
  "GET /batch": route("Light check of up to 20 npm or PyPI packages in one call (e.g. a whole lockfile or requirements.txt): per-package vulns, license, deprecated, verdict, plus an overall verdict. GET form takes packages=name@version,name2,...",
    { ecosystem: "npm", packages: "express,lodash@4.17.20,event-stream@3.3.6" },
    { type: "object", properties: { ecosystem: ECO, packages: { type: "string", description: "Comma-separated name or name@version, max 20" } }, required: ["ecosystem", "packages"] },
    { ok: true, ecosystem: "npm", count: 3, overallVerdict: "AVOID", summary: { OK: 1, REVIEW: 1, AVOID: 1, errors: 0 }, results: [{ name: "express", verdict: "OK" }] }, "$0.05"),
};
const TAGS = { "/report": ["security", "dependencies", "npm", "pypi", "supply-chain", "devtools"], "/check": ["security", "dependencies", "npm", "pypi", "supply-chain"], "/batch": ["security", "dependencies", "npm", "pypi", "lockfile", "supply-chain"] };
for (const k of Object.keys(ROUTES)) {
  const r = ROUTES[k], path = k.split(" ")[1];
  ROUTES["POST " + path] = { ...r, extensions: declareDiscoveryExtension({ bodyType: "json", input: r.extensions.bazaar.info.input.queryParams,
    inputSchema: r.extensions.bazaar.schema.properties.input.properties.queryParams, output: { example: r.extensions.bazaar.info.output.example } }) };
}
// batch takes a real array in the POST body
ROUTES["POST /batch"] = { ...ROUTES["POST /batch"], extensions: declareDiscoveryExtension({ bodyType: "json",
  input: { ecosystem: "npm", packages: [{ name: "express" }, { name: "lodash", version: "4.17.20" }, { name: "event-stream", version: "3.3.6" }] },
  inputSchema: { type: "object", properties: { ecosystem: ECO, packages: { type: "array", maxItems: 20, items: { type: "object", properties: { name: NAME, version: VERSION }, required: ["name"] } } }, required: ["ecosystem", "packages"] },
  output: { example: ROUTES["GET /batch"].extensions.bazaar.info.output.example } }) };

for (const [k, r] of Object.entries(ROUTES)) {
  const path = k.split(" ")[1];
  Object.assign(r, { resource: ORIGIN + path, serviceName: "DepVet", tags: TAGS[path], iconUrl: ORIGIN + "/favicon.svg" });
}

// ---------- input parsing + free pre-payment validation ----------
const readParams = async c => {
  if (c.req.method === "POST") { const b = await c.req.json().catch(() => null); return b && typeof b === "object" ? b : {}; }
  return c.req.query();
};
function parsePackages(raw) {
  const list = Array.isArray(raw) ? raw : typeof raw === "string" ? raw.split(",").map(s => s.trim()).filter(Boolean) : null;
  if (!list) return null;
  return list.map(p => {
    if (typeof p === "string") { const i = p.lastIndexOf("@"); return i > 0 ? { name: p.slice(0, i), version: p.slice(i + 1) } : { name: p }; }
    return p && typeof p === "object" ? { name: typeof p.name === "string" ? p.name.trim() : p.name, version: p.version == null ? undefined : String(p.version) } : { name: undefined };
  });
}
// Returns { error } or the cleaned input. Pure and cheap: no network.
async function getInput(c, path) {
  const p = await readParams(c), eco = String(p.ecosystem || "").toLowerCase();
  if (eco !== "npm" && eco !== "pypi") return { error: "ecosystem must be 'npm' or 'pypi'" };
  if (path === "/batch") {
    const pkgs = parsePackages(p.packages);
    if (!pkgs || !pkgs.length) return { error: "packages must be a non-empty array of {name, version?} (GET: comma-separated name@version)" };
    if (pkgs.length > 20) return { error: "max 20 packages per batch" };
    for (const x of pkgs) { const e = validatePkg(eco, x); if (e) return { error: e }; }
    if (batchCost(eco, pkgs) > 44) return { error: "too many unversioned PyPI packages for one batch (upstream call budget); pass versions or split the batch" };
    return { eco, pkgs: pkgs.map(x => ({ name: x.name.trim(), version: x.version || undefined })) };
  }
  const e = validatePkg(eco, p);
  if (e) return { error: e };
  return { eco, name: p.name.trim(), version: p.version ? String(p.version) : undefined };
}
const hasPayment = c => !!(c.req.header("payment-signature") || c.req.header("x-payment"));
// Reject malformed requests with 400 BEFORE the paywall so a buyer is never charged for bad input.
// A bare unpaid probe (no params, no payment header) still gets the 402 challenge, so discovery crawlers work.
app.use(async (c, next) => {
  const path = c.req.path;
  if (!["/report", "/check", "/batch"].includes(path) || !["GET", "POST"].includes(c.req.method)) return next();
  const probe = !hasPayment(c) && (c.req.method === "GET" ? !c.req.url.includes("?") : !c.req.header("content-length") || c.req.header("content-length") === "0");
  if (probe) return next();
  const r = await getInput(c, path);
  if (r.error) return c.json({ ok: false, error: "bad_request", message: r.error }, 400);
  return next();
});

// Workers forbid I/O at global scope and sharing promises across requests, so the
// facilitator sync runs inside whichever request gets there first, until it succeeds.
let paywall, synced = false;
app.use(async (c, next) => {
  if (c.env?.DEV_FREE === "1") return next(); // local testing only (wrangler dev --var DEV_FREE:1); never set in production
  if (!synced && ROUTES[`${c.req.method} ${c.req.path}`]) { await server.initialize(); synced = true; }
  paywall ??= paymentMiddleware(ROUTES, server, undefined, undefined, false);
  return paywall(c, next);
});

// ---------- handlers ----------
const fail = (c, e) => e instanceof NotFound
  ? c.json({ ok: false, error: "not_found", message: e.message, ecosystem: e.eco, name: e.name, version: e.version || null, ...(typosquat(e.eco, e.name).suspect ? { didYouMean: typosquat(e.eco, e.name).similarTo } : {}), hint: "Check the spelling; AI-suggested package names are sometimes hallucinated. You were not charged." }, 404)
  : c.json({ ok: false, error: "upstream_error", message: String(e.message || e), hint: "Retry shortly; you were not charged." }, 502);
const strip = r => { const { _nocache, ...rest } = r; return rest; };
const single = fn => async c => {
  const i = await getInput(c, c.req.path);
  if (i.error) return c.json({ ok: false, error: "bad_request", message: i.error }, 400);
  try { return c.json(strip(await fn(i.eco, i.name, i.version))); } catch (e) { return fail(c, e); }
};
app.on(["GET", "POST"], "/report", single(report));
app.on(["GET", "POST"], "/check", single(check));
app.on(["GET", "POST"], "/batch", async c => {
  const i = await getInput(c, "/batch");
  if (i.error) return c.json({ ok: false, error: "bad_request", message: i.error }, 400);
  try { return c.json(await batch(i.eco, i.pkgs)); } catch (e) { return fail(c, e); }
});

const DOCS = {
  name: "DepVet", description: "Dependency risk reports for AI agents: check an npm or PyPI package before you install it. Verdict OK/REVIEW/AVOID from known vulnerabilities (OSV), malware advisories, license risk, deprecation, maintenance and OpenSSF Scorecard, and typosquat hints. No API key: pay USDC on Base per call via x402.",
  payment: { protocol: "x402 v2", network: NETWORK, asset: "USDC", payTo: PAY_TO },
  endpoints: [
    { method: "POST", path: "/report {ecosystem, name, version?}", price: "$0.02", what: "Full risk report with verdict and reasons" },
    { method: "POST", path: "/check {ecosystem, name, version?}", price: "$0.005", what: "Light check: vulns, license, deprecated, verdict" },
    { method: "POST", path: "/batch {ecosystem, packages:[{name, version?}]}", price: "$0.05", what: "Light check of up to 20 packages (lockfile)" },
  ],
  notes: "ecosystem is 'npm' or 'pypi'. Invalid input returns 400 and unknown packages return 404 before any payment is settled. GET with query params also works (batch: packages=a@1.0,b).",
  howToPay: "Call any endpoint; you get HTTP 402 with payment requirements. Use an x402 client (e.g. @x402/fetch, x402-axios, or an MCP x402 wallet) to sign and retry.",
};
app.get("/", c => (c.req.header("accept") || "").includes("text/html")
  ? c.html(landingHtml(), 200, { "cache-control": "public, max-age=300", vary: "Accept" }) : c.json(DOCS, 200, { vary: "Accept" }));
app.get("/llms.txt", c => c.text(LLMS));
app.get("/robots.txt", c => c.text(ROBOTS));
app.get("/d32fa5f5b0aa09cc644601941586b1c1.txt", c => c.text("d32fa5f5b0aa09cc644601941586b1c1"));
app.get("/sitemap.xml", c => c.body(SITEMAP, 200, { "content-type": "application/xml" }));
app.get("/openapi.json", c => {
  const paths = {};
  for (const [k, r] of Object.entries(ROUTES)) {
    const [method, path] = k.split(" "), m = method.toLowerCase();
    const info = r.extensions.bazaar.info, schema = r.extensions.bazaar.schema.properties.input.properties;
    const inSchema = schema.queryParams || schema.body;
    const op = {
      operationId: path.slice(1) + (m === "post" ? "Post" : "Get"), summary: r.description.split(":")[0], description: r.description, tags: ["Dependencies"],
      "x-payment-info": { price: { mode: "fixed", currency: "USD", amount: r.accepts.price.slice(1) }, protocols: [{ x402: {} }] },
      responses: { 200: { description: "Successful response", content: { "application/json": { schema: { type: "object" }, example: info.output.example } } }, 400: { description: "Invalid input (not charged)" }, 402: { description: "Payment Required" }, 404: { description: "Package not found (not charged)" } },
    };
    if (m === "post") op.requestBody = { required: true, content: { "application/json": { schema: inSchema } } };
    else op.parameters = Object.entries(inSchema.properties).map(([name, s]) => ({ name, in: "query", required: (inSchema.required || []).includes(name), schema: s, description: s.description }));
    (paths[path] ??= {})[m] = op;
  }
  return c.json({ openapi: "3.1.0", info: { title: "DepVet", version: "1.0.0", contact: { name: "DepVet", url: "https://github.com/Imac2014Ville/depvet" }, description: DOCS.description,
    "x-guidance": "Pre-install dependency vetting for agents, paid per call in USDC on Base via x402. POST /report {ecosystem: npm|pypi, name, version?} ($0.02) returns an OK/REVIEW/AVOID verdict with reasons, OSV vulnerabilities with severity and fixed versions, malware advisories, license risk class, dependency counts, OpenSSF Scorecard, maintenance signals and typosquat hints. POST /check {ecosystem, name, version?} ($0.005) is the light version (vuln count and max severity, license, deprecated, verdict). POST /batch {ecosystem, packages:[{name, version?}] up to 20} ($0.05) light-checks a whole lockfile. Bad input returns 400 and unknown packages 404, neither charged. GET with query params also works." },
    servers: [{ url: new URL(c.req.url).origin }], paths });
});
app.get("/.well-known/x402", c => c.json({ version: 1, resources: [...new Set(Object.keys(ROUTES).map(k => ORIGIN + k.split(" ")[1]))] }));
app.get("/health", c => c.json({ ok: true }));
const ICON = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="14" fill="#0f172a"/><path d="M32 10l18 7v14c0 11-8 19-18 23C22 50 14 42 14 31V17z" fill="none" stroke="#fff" stroke-width="5" stroke-linejoin="round"/><path d="M24 32l6 6 11-12" fill="none" stroke="#22c55e" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
app.get("/favicon.ico", c => c.body(ICON, 200, { "content-type": "image/svg+xml", "cache-control": "public, max-age=86400" }));
app.get("/favicon.svg", c => c.body(ICON, 200, { "content-type": "image/svg+xml", "cache-control": "public, max-age=86400" }));

export default app;
