import { typosquat } from "./popular.js";

const UA = "DepVet/1.0 (+https://depvet.imac2014ville.workers.dev)";
const TTL = 10 * 60 * 1000;
const cache = new Map();
async function cached(key, fn) {
  const hit = cache.get(key);
  if (hit && hit.exp > Date.now()) return hit.v;
  const v = await fn();
  if (v && !v._nocache) {
    if (cache.size >= 300) cache.delete(cache.keys().next().value);
    cache.set(key, { exp: Date.now() + TTL, v });
  }
  return v;
}

// ---- upstream helpers (every call is time-bounded) ----
async function getJson(url, init = {}) {
  const r = await fetch(url, { ...init, headers: { accept: "application/json", "user-agent": UA, ...(init.headers || {}) }, signal: AbortSignal.timeout(7000) });
  if (r.status === 404) return { status: 404 };
  if (!r.ok) throw new Error(`${new URL(url).host} returned ${r.status}`);
  return { status: 200, data: await r.json() };
}
const soft = async (p, label, warnings) => { try { return await p; } catch (e) { warnings.push(`${label} unavailable: ${e.message}`); return null; } };

export const normName = (eco, n) => eco === "pypi" ? n.toLowerCase().replace(/[-_.]+/g, "-") : n.toLowerCase();
const npmPath = n => n.replace("/", "%2F");
const depsSys = eco => eco;
const osvEco = eco => eco === "npm" ? "npm" : "PyPI";

// ---- validation ----
const NPM_RE = /^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/;
const PYPI_RE = /^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$/;
const VER_RE = /^[A-Za-z0-9][A-Za-z0-9._+!~-]{0,63}$/;
export function validatePkg(eco, p) {
  if (!p || typeof p.name !== "string" || !p.name.trim()) return "missing package name";
  const name = p.name.trim();
  if (name.length > (eco === "npm" ? 214 : 100) || !(eco === "npm" ? NPM_RE : PYPI_RE).test(name)) return `invalid ${eco} package name: ${name.slice(0, 60)}`;
  if (p.version != null && p.version !== "" && !VER_RE.test(String(p.version))) return `invalid version: ${String(p.version).slice(0, 40)}`;
  return null;
}

// ---- licenses ----
const RANK = { permissive: 0, "weak-copyleft": 1, "strong-copyleft": 2, unknown: 3 };
function classifyOne(s) {
  const t = s.trim();
  if (!t) return "unknown";
  if (/AGPL|Affero|SSPL|Server Side Public|\bGPL|GNU General Public|EUPL|\bOSL|CC-BY-SA|CC-BY-NC|Commons Clause|BUSL|Business Source/i.test(t) && !/LGPL|Lesser/i.test(t)) return "strong-copyleft";
  if (/LGPL|Lesser General|\bMPL|Mozilla|\bEPL|Eclipse|CDDL|\bCPL|Common Public|Artistic|MS-RL|\bOFL/i.test(t)) return "weak-copyleft";
  if (/^MIT|\bMIT\b|BSD|Apache|\bISC\b|0BSD|Unlicense|CC0|Zlib|BlueOak|PSF|Python|WTFPL|CC-BY-[0-9]|Public Domain|X11|NCSA|Artistic-2|MIT-0|Libpng|HPND/i.test(t)) return "permissive";
  return "unknown";
}
export function classifyLicense(expr) {
  if (!expr) return { spdx: null, riskClass: "unknown" };
  const str = String(expr).replace(/[()]/g, " ").replace(/\s+/g, " ").trim();
  if (/^(SEE LICENSE|UNLICENSED|NONE)/i.test(str)) return { spdx: str.slice(0, 80), riskClass: "unknown" };
  const ors = str.split(/\s+OR\s+/i).map(alt => {
    const ands = alt.split(/\s+AND\s+/i).map(x => classifyOne(x.replace(/\s+WITH\s+.*/i, "")));
    return ands.reduce((a, b) => RANK[b] > RANK[a] ? b : a, "permissive");
  });
  const cls = ors.reduce((a, b) => RANK[b] < RANK[a] ? b : a, "unknown");
  return { spdx: str.length > 80 ? str.slice(0, 80) + "…" : str, riskClass: cls };
}

// ---- OSV ----
const SEV_RANK = { NONE: 0, UNKNOWN: 1, LOW: 2, MODERATE: 3, HIGH: 4, CRITICAL: 5 };
const bucket = s => s >= 9 ? "CRITICAL" : s >= 7 ? "HIGH" : s >= 4 ? "MODERATE" : s > 0 ? "LOW" : "NONE";
function cvss3(vec) {
  const m = Object.fromEntries(vec.split("/").slice(1).map(x => x.split(":")));
  const AV = { N: .85, A: .62, L: .55, P: .2 }[m.AV], AC = { L: .77, H: .44 }[m.AC], UI = { N: .85, R: .62 }[m.UI];
  const ch = m.S === "C", PR = (ch ? { N: .85, L: .68, H: .5 } : { N: .85, L: .62, H: .27 })[m.PR];
  const cia = k => ({ H: .56, L: .22, N: 0 })[m[k]];
  if ([AV, AC, UI, PR, cia("C"), cia("I"), cia("A")].some(x => x === undefined)) return null;
  const iss = 1 - (1 - cia("C")) * (1 - cia("I")) * (1 - cia("A"));
  const imp = ch ? 7.52 * (iss - .029) - 3.25 * Math.pow(iss - .02, 15) : 6.42 * iss;
  const ex = 8.22 * AV * AC * PR * UI;
  if (imp <= 0) return 0;
  const up = x => Math.ceil(x * 10 - 1e-9) / 10;
  return up(Math.min(ch ? 1.08 * (imp + ex) : imp + ex, 10));
}
function vulnSeverity(v) {
  const ds = String(v.database_specific?.severity || "").toUpperCase();
  if (SEV_RANK[ds] !== undefined && ds) return { severity: ds, score: null };
  for (const s of v.severity || []) {
    if (s.type === "CVSS_V3" && typeof s.score === "string" && s.score.startsWith("CVSS:3")) {
      const sc = cvss3(s.score); if (sc != null) return { severity: bucket(sc), score: sc };
    }
  }
  return { severity: "UNKNOWN", score: null };
}
const MAL_RE = /malicious (code|package|version|release|payload|dependency|module)|embedded malicious|\bmalware\b|backdoor|compromised (package|version|account|release)/i;
function summarizeVulns(vulns, eco, name) {
  const items = vulns.map(v => {
    const { severity, score } = vulnSeverity(v);
    const fixed = new Set();
    for (const a of v.affected || []) {
      if (a.package && normName(eco, a.package.name || "") !== normName(eco, name)) continue;
      for (const r of a.ranges || []) for (const e of r.events || []) if (e.fixed) fixed.add(e.fixed);
    }
    const malware = /^MAL-/.test(v.id) || MAL_RE.test(String(v.summary || "").slice(0, 300));
    return { id: v.id, aliases: (v.aliases || []).filter(a => a.startsWith("CVE-")).slice(0, 3), severity, cvss: score, summary: String(v.summary || "").slice(0, 160), malware, fixedIn: [...fixed].slice(0, 5), published: v.published || null };
  }).sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity]);
  const max = items.length ? items[0].severity : "NONE";
  return { checked: true, count: items.length, maxSeverity: max, malware: items.some(i => i.malware), items: items.slice(0, 15), truncated: items.length > 15 };
}
async function osvQuery(eco, name, version) {
  const body = JSON.stringify({ package: { name: normName(eco, name), ecosystem: osvEco(eco) }, version });
  const r = await getJson("https://api.osv.dev/v1/query", { method: "POST", body, headers: { "content-type": "application/json" } });
  return summarizeVulns(r.data?.vulns || [], eco, name);
}

// ---- package metadata ----
const daysSince = iso => iso ? Math.floor((Date.now() - Date.parse(iso)) / 86400000) : null;
const npmLicense = l => typeof l === "string" ? l : l && typeof l === "object" ? l.type || null : null;
async function npmManifest(name, version) {
  const r = await getJson(`https://registry.npmjs.org/${npmPath(name)}/${encodeURIComponent(version || "latest")}`);
  if (r.status === 404) return null;
  const m = r.data;
  const s = m.scripts || {};
  return { version: m.version, license: npmLicense(m.license) || (Array.isArray(m.licenses) ? m.licenses.map(npmLicense).filter(Boolean).join(" OR ") : null),
    deprecated: m.deprecated ? String(m.deprecated).slice(0, 200) : null, maintainers: Array.isArray(m.maintainers) ? m.maintainers.length : null,
    installScripts: !!(s.preinstall || s.install || s.postinstall || m.hasInstallScript), directDeps: Object.keys(m.dependencies || {}).length };
}
async function pypiVersion(name, version) {
  const r = await getJson(`https://pypi.org/pypi/${encodeURIComponent(name)}/${encodeURIComponent(version)}/json`);
  if (r.status === 404) return null;
  const i = r.data.info || {};
  let lic = i.license_expression || null;
  if (!lic) {
    const cls = (i.classifiers || []).filter(c => c.startsWith("License ::")).map(c => c.split("::").pop().trim()).filter(c => !/^OSI Approved$/i.test(c));
    lic = cls.length ? cls.join(" OR ") : (i.license && i.license.length <= 60 ? i.license : (i.license ? i.license.slice(0, 60) : null));
  }
  return { version: i.version, license: lic, deprecated: (i.classifiers || []).includes("Development Status :: 7 - Inactive") ? "classified as Inactive" : null, yanked: !!i.yanked, yankedReason: i.yanked_reason || null,
    maintainers: null, installScripts: false, directDeps: null };
}
async function depsPackage(eco, name) {
  const r = await getJson(`https://api.deps.dev/v3/systems/${depsSys(eco)}/packages/${encodeURIComponent(eco === "pypi" ? normName(eco, name) : name)}`);
  if (r.status === 404) return null;
  const vs = (r.data.versions || []).map(v => ({ v: v.versionKey?.version, at: v.publishedAt || null, def: !!v.isDefault, dep: !!v.isDeprecated }));
  return { versions: vs, latest: (vs.find(v => v.def) || vs[vs.length - 1] || {}).v };
}
const depsVer = (eco, name, v) => `https://api.deps.dev/v3/systems/${depsSys(eco)}/packages/${encodeURIComponent(eco === "pypi" ? normName(eco, name) : name)}/versions/${encodeURIComponent(v)}`;

function cadence(versions) {
  const dated = versions.filter(v => v.at).map(v => ({ ...v, t: Date.parse(v.at) })).sort((a, b) => a.t - b.t);
  if (!dated.length) return {};
  const last = dated[dated.length - 1], first = dated[0];
  const yearAgo = Date.now() - 365 * 86400000;
  const recent = dated.slice(-10);
  const gaps = recent.slice(1).map((x, i) => (x.t - recent[i].t) / 86400000);
  return { lastPublish: last.at, daysSinceLastPublish: daysSince(last.at), firstPublish: first.at, totalVersions: dated.length,
    releasesLast12Months: dated.filter(v => v.t >= yearAgo).length, avgDaysBetweenRecentReleases: gaps.length ? Math.round(gaps.reduce((a, b) => a + b, 0) / gaps.length * 10) / 10 : null,
    publishedAtByVersion: Object.fromEntries(dated.map(d => [d.v, d.at])) };
}

export class NotFound extends Error {}
const notFound = (eco, name, version) => Object.assign(new NotFound(`${eco} package${version ? " or version" : ""} not found`), { eco, name, version });

// ---- /check (light) ----
export function check(eco, name, version) {
  return cached(`c:${eco}:${name}:${version || ""}`, async () => {
    const warnings = [];
    let ver = version || null, meta, latestVersion = null;
    if (eco === "npm") {
      meta = await npmManifest(name, ver);
      if (!meta) throw notFound(eco, name, ver);
      ver = meta.version; if (!version) latestVersion = ver;
    } else {
      if (!ver) { const dp = await depsPackage(eco, name); if (!dp) throw notFound(eco, name); ver = latestVersion = dp.latest; }
      meta = await pypiVersion(name, ver);
      if (!meta) throw notFound(eco, name, version);
      ver = meta.version || ver;
    }
    const vulns = await soft(osvQuery(eco, name, ver), "OSV", warnings);
    const lic = classifyLicense(meta.license), ts = typosquat(eco, name);
    const out = { ok: true, ecosystem: eco, name, version: ver, latestVersion, license: lic.spdx, licenseRisk: lic.riskClass,
      vulnerabilities: vulns ? { count: vulns.count, maxSeverity: vulns.maxSeverity, malware: vulns.malware } : { checked: false },
      deprecated: !!meta.deprecated, yanked: !!meta.yanked, typosquatSuspect: ts.suspect ? ts.similarTo : false };
    const reasons = [];
    rules(reasons, { vulns, lic, meta, ts });
    out.verdict = verdictOf(reasons); out.reasons = reasons.map(r => r.message);
    if (warnings.length) { out.warnings = warnings; out._nocache = true; }
    return out;
  });
}

function rules(reasons, { vulns, lic, meta, ts, cad, score, firstPublishRecent }) {
  const add = (level, code, message) => reasons.push({ level, code, message });
  if (!vulns) add("REVIEW", "vuln-data-unavailable", "Vulnerability database (OSV) was unreachable; vulnerabilities unknown.");
  else {
    if (vulns.malware) add("AVOID", "malware", "Known malicious/compromised-package advisory exists for this version.");
    if (vulns.maxSeverity === "CRITICAL") add("AVOID", "critical-vuln", `${vulns.items.filter(i => i.severity === "CRITICAL").length} critical vulnerability advisory(ies) affect this version.`);
    else if (vulns.maxSeverity === "HIGH") add("REVIEW", "high-vuln", `${vulns.items.filter(i => i.severity === "HIGH").length} high-severity vulnerability advisory(ies) affect this version.`);
    else if (vulns.maxSeverity === "MODERATE" || vulns.maxSeverity === "UNKNOWN") add("REVIEW", "vuln", `${vulns.count} known vulnerability advisory(ies) (max severity ${vulns.maxSeverity}).`);
    else if (vulns.count) add("INFO", "low-vuln", `${vulns.count} low-severity advisory(ies).`);
  }
  if (lic.riskClass === "strong-copyleft") add("REVIEW", "strong-copyleft", `Strong-copyleft or restrictive license (${lic.spdx}); check compatibility.`);
  else if (lic.riskClass === "unknown") add("REVIEW", "unknown-license", "License missing or not recognised.");
  else if (lic.riskClass === "weak-copyleft") add("INFO", "weak-copyleft", `Weak-copyleft license (${lic.spdx}).`);
  if (meta.deprecated) add("REVIEW", "deprecated", `Marked deprecated: ${meta.deprecated}`);
  if (meta.yanked) add("REVIEW", "yanked", `This release was yanked${meta.yankedReason ? ": " + meta.yankedReason : ""}.`);
  if (ts.suspect) {
    const recent = firstPublishRecent;
    add(recent ? "AVOID" : "REVIEW", "typosquat", `Name is ${ts.distance} edit(s) from popular package "${ts.similarTo}"${recent ? " and the package is new/has few releases: likely typosquat" : ""}.`);
  }
  if (cad) {
    if (cad.daysSinceLastPublish > 730) add("REVIEW", "stale", `No release for ${Math.round(cad.daysSinceLastPublish / 365 * 10) / 10} years.`);
    if (meta.maintainers === 0) add("REVIEW", "no-maintainers", "No maintainers listed.");
  }
  if (score != null && score < 3) add("REVIEW", "low-scorecard", `Low OpenSSF Scorecard (${score}/10).`);
  if (meta.installScripts) add("INFO", "install-scripts", "Package runs install-time scripts (preinstall/install/postinstall).");
}
const verdictOf = reasons => reasons.some(r => r.level === "AVOID") ? "AVOID" : reasons.some(r => r.level === "REVIEW") ? "REVIEW" : "OK";

// ---- /report (full) ----
export function report(eco, name, version) {
  return cached(`r:${eco}:${name}:${version || ""}`, async () => {
    const warnings = [];
    const [dp, metaMaybe] = await Promise.all([
      soft(depsPackage(eco, name), "deps.dev", warnings),
      eco === "npm" ? npmManifest(name, version) : null,
    ]);
    let ver = version || null, meta = metaMaybe;
    if (eco === "npm") {
      if (!meta) throw notFound(eco, name, version && dp ? version : null);
      ver = meta.version;
    } else {
      if (!dp) { if (warnings.length) throw new Error("deps.dev unreachable"); throw notFound(eco, name); }
      ver ||= dp.latest;
      meta = await pypiVersion(name, ver);
      if (!meta) throw notFound(eco, name, version);
      ver = meta.version || ver;
    }
    const latest = dp?.latest || (eco === "npm" && !version ? ver : null);
    const [vulns, dv, graph] = await Promise.all([
      soft(osvQuery(eco, name, ver), "OSV", warnings),
      soft(getJson(depsVer(eco, name, ver)), "deps.dev version", warnings),
      soft(getJson(depsVer(eco, name, ver) + ":dependencies"), "deps.dev dependencies", warnings),
    ]);
    const dvd = dv?.status === 200 ? dv.data : null;
    let depCount = null;
    if (graph?.status === 200) {
      const nodes = graph.data.nodes || [];
      depCount = { direct: nodes.filter(n => n.relation === "DIRECT").length, transitive: nodes.filter(n => n.relation === "INDIRECT").length };
    } else if (meta.directDeps != null) depCount = { direct: meta.directDeps, transitive: null };
    // OpenSSF scorecard via linked source repo
    let scorecard = null;
    const repo = (dvd?.relatedProjects || []).find(p => p.relationType === "SOURCE_REPO")?.projectKey?.id;
    if (repo) {
      const pr = await soft(getJson(`https://api.deps.dev/v3/projects/${encodeURIComponent(repo)}`), "deps.dev project", warnings);
      const sc = pr?.status === 200 ? pr.data.scorecard : null;
      scorecard = sc ? { repo, score: sc.overallScore ?? null, date: sc.date || null, lowChecks: (sc.checks || []).filter(c => c.score >= 0 && c.score <= 2).map(c => c.name).slice(0, 6) } : { repo, score: null };
    }
    const spdxFromDeps = (dvd?.licenses || []).filter(l => l && l !== "non-standard").join(" AND ");
    const lic = classifyLicense(spdxFromDeps || meta.license);
    const cad = dp ? cadence(dp.versions) : {};
    const verPub = dvd?.publishedAt || cad.publishedAtByVersion?.[ver] || null;
    delete cad.publishedAtByVersion;
    const depDeprecated = dp?.versions.find(v => v.v === ver)?.dep;
    if (depDeprecated && !meta.deprecated) meta.deprecated = "marked deprecated (deps.dev)";
    const ts = typosquat(eco, name);
    const firstPublishRecent = ts.suspect && ((cad.totalVersions != null && cad.totalVersions <= 3) || (cad.firstPublish && daysSince(cad.firstPublish) < 180));
    const reasons = [];
    rules(reasons, { vulns, lic, meta, ts, cad, score: scorecard?.score ?? null, firstPublishRecent });
    if (latest && ver !== latest) reasons.push({ level: "INFO", code: "not-latest", message: `Not the latest version (latest is ${latest}).` });
    const out = {
      ok: true, ecosystem: eco, name, requestedVersion: version || null, version: ver, latestVersion: latest, isLatest: latest ? ver === latest : null,
      verdict: verdictOf(reasons), reasons: reasons.map(r => ({ level: r.level, code: r.code, message: r.message })),
      license: { spdx: lic.spdx, riskClass: lic.riskClass },
      vulnerabilities: vulns || { checked: false },
      dependencies: depCount,
      scorecard,
      maintenance: { versionPublishedAt: verPub, ...cad, deprecated: !!meta.deprecated, deprecatedMessage: meta.deprecated || null, yanked: !!meta.yanked, maintainers: meta.maintainers, installScripts: meta.installScripts || undefined },
      typosquat: ts.suspect ? { suspect: true, similarTo: ts.similarTo, distance: ts.distance } : { suspect: false },
      sources: ["osv.dev", "deps.dev", eco === "npm" ? "registry.npmjs.org" : "pypi.org"], generatedAt: new Date().toISOString(),
    };
    if (warnings.length) { out.warnings = warnings; out._nocache = true; }
    return out;
  });
}

// ---- /batch ----
export function batchCost(eco, pkgs) { return pkgs.reduce((n, p) => n + (eco === "npm" ? 2 : p.version ? 2 : 3), 0); }
export async function batch(eco, pkgs) {
  const seen = new Set(), uniq = [];
  for (const p of pkgs) { const k = p.name + "@" + (p.version || ""); if (!seen.has(k)) { seen.add(k); uniq.push(p); } }
  const results = await Promise.all(uniq.map(async p => {
    try { const r = await check(eco, p.name, p.version); const { ok, ...rest } = r; return rest; }
    catch (e) { return { ecosystem: eco, name: p.name, version: p.version || null, verdict: null, error: e instanceof NotFound ? "not_found" : "upstream_error", message: e.message }; }
  }));
  const tally = { OK: 0, REVIEW: 0, AVOID: 0, errors: 0 };
  results.forEach(r => r.verdict ? tally[r.verdict]++ : tally.errors++);
  const overall = tally.AVOID ? "AVOID" : tally.REVIEW ? "REVIEW" : tally.errors ? "REVIEW" : "OK";
  return { ok: true, ecosystem: eco, count: results.length, overallVerdict: overall, summary: tally, results, generatedAt: new Date().toISOString() };
}
