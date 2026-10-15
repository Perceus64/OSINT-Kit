// Footprint — browser front end. Network fetches happen here; all parsing
// and analysis is done by the Rust/WebAssembly engine in ./pkg.
import init, * as engine from "./pkg/osint_toolkit.js";

const $ = (sel, root = document) => root.querySelector(sel);

/** Tiny DOM builder. Text is always set via textContent, never innerHTML,
 *  because DNS records, file metadata and pasted text are untrusted. */
function h(tag, attrs = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat()) {
    if (kid == null || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}
const link = (href, text) => h("a", { href, target: "_blank", rel: "noopener noreferrer" }, text);
const json = (s) => JSON.parse(s);

function copyButton(value, label = "Copy") {
  const b = h("button", { class: "copy-btn", type: "button" }, label);
  b.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(value);
      b.textContent = "Copied";
    } catch {
      b.textContent = "Copy failed";
    }
    setTimeout(() => (b.textContent = label), 1400);
  });
  return b;
}

function download(name, data, type) {
  const url = URL.createObjectURL(new Blob([data], { type }));
  const a = h("a", { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

const fmtBytes = (n) => {
  const u = ["bytes", "KB", "MB", "GB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${i ? n.toFixed(1) : n} ${u[i]}`;
};

function withTimeout(ms) {
  const c = new AbortController();
  const t = setTimeout(() => c.abort(), ms);
  return { signal: c.signal, done: () => clearTimeout(t) };
}

async function fetchText(url, ms = 15000, opts = {}) {
  const t = withTimeout(ms);
  try {
    const r = await fetch(url, { ...opts, signal: t.signal });
    const body = await r.text();
    if (!r.ok && !body.trim().startsWith("{")) throw new Error(`HTTP ${r.status}`);
    return body;
  } finally {
    t.done();
  }
}

// ------------------------------------------------------------ DNS over HTTPS

const DOH = [
  (n, t) => `https://dns.google/resolve?name=${encodeURIComponent(n)}&type=${t}`,
  (n, t) => `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(n)}&type=${t}&ct=application/dns-json`,
];

async function doh(name, type) {
  let last;
  for (const make of DOH) {
    try {
      return json(await fetchText(make(name, type), 8000));
    } catch (e) {
      last = e;
    }
  }
  throw last ?? new Error("DNS lookup failed");
}

const txtOf = (resp) => (resp?.Answer || []).filter((a) => a.type === 16).map((a) => a.data);
const ptrOf = (resp) => (resp?.Answer || []).filter((a) => a.type === 12).map((a) => a.data.replace(/\.$/, ""));

/** Reverse DNS + ASN for an IP, via Team Cymru over DoH. */
async function enrichIp(ip) {
  const cls = json(engine.classify_ip(ip));
  const out = { ip, cls, ptr: [], origin: null, asName: null };
  if (!cls.valid) return out;
  const tasks = [
    doh(engine.ptr_name(ip), "PTR").then((r) => (out.ptr = ptrOf(r))).catch(() => {}),
  ];
  if (cls.routable) {
    tasks.push(
      doh(engine.asn_origin_query(ip), "TXT")
        .then(async (r) => {
          const t = txtOf(r)[0];
          if (!t) return;
          out.origin = json(engine.parse_asn_origin(t));
          if (out.origin?.asn) {
            const n = await doh(`AS${out.origin.asn}.asn.cymru.com`, "TXT");
            const nt = txtOf(n)[0];
            if (nt) out.asName = json(engine.parse_asn_name(nt));
          }
        })
        .catch(() => {}),
    );
  }
  await Promise.all(tasks);
  return out;
}

/** Run async jobs with limited concurrency. */
async function pool(items, n, fn) {
  const results = new Array(items.length);
  let i = 0;
  await Promise.all(
    Array.from({ length: Math.min(n, items.length) }, async () => {
      while (i < items.length) {
        const idx = i++;
        results[idx] = await fn(items[idx], idx);
      }
    }),
  );
  return results;
}

// ------------------------------------------------------------ tabs

function setupTabs() {
  const tabs = [...document.querySelectorAll('[role="tab"]')];
  const select = (tab, focus = true) => {
    for (const t of tabs) {
      const on = t === tab;
      t.setAttribute("aria-selected", on);
      t.tabIndex = on ? 0 : -1;
      $("#" + t.getAttribute("aria-controls")).hidden = !on;
    }
    if (focus) tab.focus();
    history.replaceState(null, "", "#" + tab.id.replace("tab-", ""));
  };
  tabs.forEach((t, i) => {
    t.addEventListener("click", () => select(t));
    t.addEventListener("keydown", (e) => {
      const d = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0;
      if (d) select(tabs[(i + d + tabs.length) % tabs.length]);
    });
  });
  const fromHash = document.getElementById("tab-" + location.hash.slice(1));
  if (fromHash) select(fromHash, false);
  return (name) => select(document.getElementById("tab-" + name), false);
}

// ------------------------------------------------------------ domain

function block(title, sub) {
  const body = h("div", {}, h("p", { class: "loading" }, "Looking up…"));
  const el = h("section", { class: "block" }, h("div", { class: "block-head" }, h("h2", {}, title)), sub ? h("p", { class: "sub" }, sub) : null, body);
  return { el, body, head: el.firstChild };
}

function fail(body, msg) {
  body.replaceChildren(h("p", { class: "error" }, msg));
}

async function mapDomain(raw) {
  const out = $("#domain-out");
  const domain = engine.normalize_domain(raw);
  if (!domain) {
    out.replaceChildren(h("p", { class: "error" }, "That doesn't look like a domain. Try something like example.com."));
    return;
  }
  $("#domain-input").value = domain;
  history.replaceState(null, "", `#domain=${encodeURIComponent(domain)}`);

  const posture = block("Security posture", `Email spoofing protection, certificate controls and DNSSEC for ${domain}.`);
  const svc = block("Services in use", "Inferred from mail routing, name servers and ownership-verification records.");
  const hosts = block("Where it's hosted", "Addresses the domain points to, with reverse DNS and the network that owns them.");
  const reg = block("Registration", "From RDAP, the structured replacement for WHOIS.");
  const records = block("DNS records");
  const subs = block("Subdomains from certificate logs", "Every name that has appeared in a publicly logged TLS certificate.");
  out.replaceChildren(h("div", { class: "report" }, posture.el, svc.el, hosts.el, reg.el, subs.el, records.el));

  const dnsJob = (async () => {
    const q = [["A", domain, "A"], ["AAAA", domain, "AAAA"], ["CNAME", domain, "CNAME"], ["NS", domain, "NS"], ["MX", domain, "MX"], ["TXT", domain, "TXT"], ["CAA", domain, "CAA"], ["SOA", domain, "SOA"], ["DMARC", `_dmarc.${domain}`, "TXT"], ["MTASTS", `_mta-sts.${domain}`, "TXT"]];
    const bundle = {};
    const settled = await Promise.allSettled(q.map(([, n, t]) => doh(n, t)));
    settled.forEach((s, i) => { if (s.status === "fulfilled") bundle[q[i][0]] = s.value; });
    if (!Object.keys(bundle).length) throw new Error("Couldn't reach a DNS-over-HTTPS resolver. Check your connection or any blocker extensions.");
    const rep = json(engine.analyze_dns(JSON.stringify(bundle)));
    if (rep.error) throw new Error(rep.error);
    return rep;
  })();

  dnsJob.then((rep) => {
    renderPosture(posture.body, rep);
    renderServices(svc.body, rep);
    renderRecords(records.body, rep);
    renderHosts(hosts.body, rep);
  }).catch((e) => {
    for (const b of [posture, svc, records, hosts]) fail(b.body, e.message);
  });

  fetchText(`https://rdap.org/domain/${domain}`, 15000)
    .then((t) => renderRdap(reg.body, json(engine.analyze_rdap(t, Date.now())), domain))
    .catch(() => fail(reg.body, `No RDAP record found. Some country-code domains (including .lb) don't publish RDAP; try the registry's own WHOIS page.`));

  loadSubdomains(subs, domain);
}

function renderPosture(body, rep) {
  if (!rep.exists) {
    body.replaceChildren(h("p", { class: "error" }, rep.findings[0]?.detail || "The domain didn't resolve."));
    return;
  }
  const order = { bad: 0, warn: 1, info: 2, good: 3 };
  const items = [...rep.findings].sort((a, b) => order[a.level] - order[b.level]);
  body.replaceChildren(
    h("div", { class: "posture" },
      h("div", { class: "grade", role: "img", "aria-label": `Grade ${rep.grade}, ${rep.score} out of 100` },
        h("div", {}, h("b", {}, rep.grade), h("span", {}, `${rep.score} / 100`))),
      h("ul", { class: "findings" }, items.map((f) =>
        h("li", {}, h("span", { class: `dot ${f.level}`, "aria-label": f.level }), h("div", {}, h("strong", {}, f.title), f.detail ? h("p", {}, f.detail) : null)))),
    ),
  );
}

function renderServices(body, rep) {
  if (!rep.services.length) {
    body.replaceChildren(h("p", { class: "empty" }, "No recognisable third-party services in the public records."));
    return;
  }
  body.replaceChildren(h("ul", { class: "chips" }, rep.services.map((s) => h("li", { title: s.evidence }, s.name, " ", h("small", {}, s.evidence)))));
}

function renderRecords(body, rep) {
  if (!rep.records.length) {
    body.replaceChildren(h("p", { class: "empty" }, "No records returned."));
    return;
  }
  body.replaceChildren(
    h("div", { class: "table-scroll" },
      h("table", {},
        h("thead", {}, h("tr", {}, h("th", {}, "Type"), h("th", {}, "Name"), h("th", {}, "Value"), h("th", { class: "num" }, "TTL"))),
        h("tbody", {}, rep.records.map((r) => h("tr", {}, h("td", {}, r.rtype), h("td", { class: "mono" }, r.name), h("td", { class: "mono" }, r.value), h("td", { class: "num" }, r.ttl)))))),
  );
}

async function renderHosts(body, rep) {
  const ips = rep.ips.slice(0, 8);
  if (!ips.length) {
    body.replaceChildren(h("p", { class: "empty" }, "The domain has no A or AAAA records."));
    return;
  }
  const rows = await pool(ips, 4, enrichIp);
  body.replaceChildren(
    h("div", { class: "table-scroll" },
      h("table", {},
        h("thead", {}, h("tr", {}, h("th", {}, "Address"), h("th", {}, "Reverse DNS"), h("th", {}, "Network"), h("th", {}, "Prefix"), h("th", {}, "Country"))),
        h("tbody", {}, rows.map((r) => h("tr", {},
          h("td", { class: "mono" }, r.ip, r.cls.routable ? null : h("span", { class: "tag private" }, r.cls.kind)),
          h("td", { class: "mono" }, r.ptr.join(", ") || "—"),
          h("td", {}, r.asName ? `AS${r.asName.asn} ${r.asName.name}` : r.origin ? `AS${r.origin.asn}` : "—"),
          h("td", { class: "mono" }, r.origin?.prefix || "—"),
          h("td", {}, r.origin?.country || "—")))))),
  );
  if (rep.ips.length > ips.length) body.append(h("p", { class: "hint" }, `Showing the first ${ips.length} of ${rep.ips.length} addresses.`));
}

function renderRdap(body, r, domain) {
  if (r.error) return fail(body, r.error);
  const d = (s) => (s ? s.slice(0, 10) : "—");
  const kv = [
    ["Registrar", r.registrar ? `${r.registrar}${r.registrar_iana_id ? ` (IANA ${r.registrar_iana_id})` : ""}` : "—"],
    ["Registered", r.registered ? `${d(r.registered)}, ${r.age_days?.toLocaleString()} days ago` : "—"],
    ["Expires", r.expires ? `${d(r.expires)}${r.days_to_expiry != null ? `, in ${r.days_to_expiry.toLocaleString()} days` : ""}` : "—"],
    ["Last changed", d(r.last_changed)],
    ["Status", r.status.join(", ") || "—"],
    ["Name servers", r.nameservers.join(", ") || "—"],
    ["DNSSEC delegation", r.dnssec_signed == null ? "—" : r.dnssec_signed ? "Signed" : "Not signed"],
    ["Abuse contact", r.abuse_contact || "—"],
  ];
  body.replaceChildren(
    r.notes.length ? h("ul", { class: "warnings" }, r.notes.map((n) => h("li", {}, n))) : "",
    h("dl", { class: "kv" }, kv.flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, v)])),
  );
}

async function loadSubdomains(b, domain) {
  const url = `https://crt.sh/?q=${encodeURIComponent("%." + domain)}&output=json`;
  let text;
  for (let attempt = 0; attempt < 2 && !text; attempt++) {
    try {
      b.body.replaceChildren(h("p", { class: "loading" }, attempt ? "crt.sh is slow, retrying…" : "Searching certificate transparency logs (this can take 20 seconds)…"));
      text = await fetchText(url, 40000);
    } catch { /* retry */ }
  }
  if (!text) {
    b.body.replaceChildren(h("p", { class: "error" }, "crt.sh didn't respond. It's a free service and is often overloaded. ", link(`https://crt.sh/?q=%25.${domain}`, "Open the search on crt.sh"), " or try again in a minute."));
    return;
  }
  const r = json(engine.analyze_certs(text, domain));
  if (r.error) return fail(b.body, r.error);
  if (!r.subdomains.length) {
    b.body.replaceChildren(h("p", { class: "empty" }, "No certificates have been logged for this domain."));
    return;
  }

  const filter = h("input", { class: "filter", type: "search", placeholder: "Filter names", "aria-label": "Filter subdomains" });
  const resolveBtn = h("button", { class: "quiet small", type: "button" }, "Check which resolve");
  const csvBtn = h("button", { class: "quiet small", type: "button" }, "Download CSV");
  b.head.append(h("div", { class: "toolbar" }, filter, resolveBtn, csvBtn));

  const rows = r.subdomains.map((s) => {
    const live = h("td", {}, "");
    const tr = h("tr", { "data-name": s.name },
      h("td", { class: "mono" }, s.name, s.wildcard ? h("span", { class: "tag" }, "wildcard") : null, r.interesting.includes(s.name) ? h("span", { class: "tag private" }, "worth a look") : null),
      h("td", { class: "num" }, s.certs),
      h("td", {}, s.first_seen || "—"),
      h("td", {}, s.last_seen || "—"),
      live);
    return { s, tr, live };
  });

  b.body.replaceChildren(
    h("p", { class: "sub" }, `${r.subdomains.length.toLocaleString()} unique names from ${r.total_certs.toLocaleString()} certificates. Issuers: ${r.issuers.slice(0, 4).map((i) => `${i.name} (${i.certs})`).join(", ")}.`),
    r.interesting.length ? h("p", { class: "hint" }, `${r.interesting.length} names look like admin, staging or internal systems. On your own estate, those are the first to check for exposure.`) : "",
    h("div", { class: "table-scroll tall" },
      h("table", {},
        h("thead", {}, h("tr", {}, h("th", {}, "Name"), h("th", { class: "num" }, "Certs"), h("th", {}, "First seen"), h("th", {}, "Last seen"), h("th", {}, "Resolves"))),
        h("tbody", {}, rows.map((x) => x.tr)))),
  );

  filter.addEventListener("input", () => {
    const q = filter.value.trim().toLowerCase();
    for (const x of rows) x.tr.hidden = q && !x.s.name.includes(q);
  });
  csvBtn.addEventListener("click", () => {
    const lines = ["name,wildcard,certs,first_seen,last_seen,latest_expiry,resolves"];
    for (const x of rows) lines.push([x.s.name, x.s.wildcard, x.s.certs, x.s.first_seen, x.s.last_seen, x.s.latest_expiry, x.live.textContent].join(","));
    download(`${domain}-subdomains.csv`, lines.join("\n"), "text/csv");
  });
  resolveBtn.addEventListener("click", async () => {
    resolveBtn.disabled = true;
    const targets = rows.filter((x) => !x.tr.hidden).slice(0, 300);
    let done = 0;
    await pool(targets, 6, async (x) => {
      x.live.textContent = "…";
      try {
        const resp = await doh(x.s.name, "A");
        const a = (resp.Answer || []).filter((r) => r.type === 1).map((r) => r.data);
        x.live.textContent = a.length ? a.join(", ") : resp.Status === 3 ? "no (NXDOMAIN)" : "no A record";
        x.live.className = a.length ? "mono" : "";
      } catch {
        x.live.textContent = "lookup failed";
      }
      resolveBtn.textContent = `Checked ${++done} of ${targets.length}`;
    });
    resolveBtn.textContent = "Check which resolve";
    resolveBtn.disabled = false;
  });
}

// ------------------------------------------------------------ files

function fileCard(rep, original) {
  const sections = [];

  sections.push(h("section", {},
    h("h3", {}, "Fingerprint"),
    ["md5", "sha1", "sha256"].map((k) => h("div", { class: "hash-row" },
      h("span", {}, k.toUpperCase()),
      h("span", { class: "mono" }, rep.hashes[k]),
      copyButton(rep.hashes[k]))),
    h("p", { class: "hint" }, "Check whether this exact file is known malware: ",
      link(`https://www.virustotal.com/gui/file/${rep.hashes.sha256}`, "VirusTotal"), ", ",
      link(`https://bazaar.abuse.ch/browse.php?search=sha256%3A${rep.hashes.sha256}`, "MalwareBazaar"),
      ". Only the hash is sent when you open these links, not the file."),
  ));

  if (rep.gps) {
    const { lat, lon } = rep.gps;
    sections.push(h("section", {},
      h("h3", {}, "Location"),
      h("p", {}, `${lat.toFixed(6)}, ${lon.toFixed(6)}`, rep.gps.altitude_m != null ? `, ${rep.gps.altitude_m.toFixed(0)} m altitude` : "", "  ",
        link(`https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}#map=17/${lat}/${lon}`, "Open in OpenStreetMap")),
    ));
  }

  if (rep.fields.length) {
    const groups = Map.groupBy ? Map.groupBy(rep.fields, (f) => f.group) : rep.fields.reduce((m, f) => m.set(f.group, [...(m.get(f.group) || []), f]), new Map());
    sections.push(h("section", {},
      h("h3", {}, "Metadata"),
      h("div", { class: "table-scroll tall" },
        h("table", {},
          h("thead", {}, h("tr", {}, h("th", {}, "Source"), h("th", {}, "Field"), h("th", {}, "Value"))),
          h("tbody", {}, [...groups].flatMap(([g, fs]) => fs.map((f) => h("tr", {}, h("td", {}, g), h("td", {}, f.key), h("td", { class: "mono" }, f.value)))))))));
  } else {
    sections.push(h("section", {}, h("h3", {}, "Metadata"), h("p", { class: "empty" }, "No embedded metadata found.")));
  }

  if (rep.iocs?.total) {
    sections.push(h("section", {}, h("h3", {}, "Links and addresses inside the file"), iocGroups(rep.iocs, { compact: true })));
  }

  const clean = engine.strip_metadata(original.bytes);
  const actions = h("div", { class: "toolbar" },
    h("button", { class: "quiet small", type: "button", onclick: () => download(`${rep.name}.report.json`, JSON.stringify(rep, null, 2), "application/json") }, "Download report"));
  if (clean.length) {
    const dot = rep.name.lastIndexOf(".");
    const cleanName = dot > 0 ? `${rep.name.slice(0, dot)}-clean${rep.name.slice(dot)}` : `${rep.name}-clean`;
    actions.prepend(h("button", { class: "primary small", type: "button", onclick: () => download(cleanName, clean, rep.mime) }, "Download copy without metadata"));
  }

  return h("article", { class: "file" },
    h("div", { class: "block-head" }, h("h2", {}, rep.name), actions),
    h("p", { class: "facts" },
      h("span", {}, h("b", {}, rep.detected_type)),
      h("span", {}, fmtBytes(rep.size)),
      h("span", {}, `Entropy ${rep.entropy.toFixed(2)} bits/byte`)),
    rep.warnings.length ? h("ul", { class: "warnings" }, rep.warnings.map((w) => h("li", {}, w))) : "",
    sections);
}

async function analyzeFiles(files) {
  const out = $("#file-out");
  out.replaceChildren();
  for (const f of files) {
    const placeholder = h("p", { class: "loading" }, `Reading ${f.name}…`);
    out.append(placeholder);
    try {
      if (f.size > 200 * 1024 * 1024) throw new Error(`${f.name} is larger than 200 MB; that's too big to analyse in the browser.`);
      const bytes = new Uint8Array(await f.arrayBuffer());
      await new Promise((r) => setTimeout(r)); // let the spinner paint
      const rep = json(engine.analyze_file(bytes, f.name));
      placeholder.replaceWith(fileCard(rep, { bytes }));
    } catch (e) {
      placeholder.replaceWith(h("p", { class: "error" }, e.message || `Couldn't read ${f.name}.`));
    }
  }
}

function setupDrop() {
  const drop = $("#drop");
  const input = $("#file-input");
  drop.addEventListener("click", () => input.click());
  drop.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); input.click(); } });
  input.addEventListener("change", () => input.files.length && analyzeFiles([...input.files]));
  ["dragenter", "dragover"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add("over"); }));
  ["dragleave", "drop"].forEach((ev) => drop.addEventListener(ev, () => drop.classList.remove("over")));
  drop.addEventListener("drop", (e) => { e.preventDefault(); if (e.dataTransfer.files.length) analyzeFiles([...e.dataTransfer.files]); });
}

// ------------------------------------------------------------ indicators

const enc = encodeURIComponent;
const PIVOTS = {
  ipv4: (v) => [["VirusTotal", `https://www.virustotal.com/gui/ip-address/${v}`], ["AbuseIPDB", `https://www.abuseipdb.com/check/${v}`], ["Shodan", `https://www.shodan.io/host/${v}`], ["GreyNoise", `https://viz.greynoise.io/ip/${v}`]],
  ipv6: (v) => [["VirusTotal", `https://www.virustotal.com/gui/ip-address/${v}`], ["AbuseIPDB", `https://www.abuseipdb.com/check/${v}`]],
  domains: (v) => [["VirusTotal", `https://www.virustotal.com/gui/domain/${v}`], ["urlscan", `https://urlscan.io/search/#domain:${v}`]],
  urls: (v) => [["VirusTotal", `https://www.virustotal.com/gui/search/${enc(enc(v))}`], ["URLhaus", `https://urlhaus.abuse.ch/browse.php?search=${enc(v)}`]],
  md5: (v) => [["VirusTotal", `https://www.virustotal.com/gui/file/${v}`], ["MalwareBazaar", `https://bazaar.abuse.ch/browse.php?search=md5%3A${v}`]],
  sha1: (v) => [["VirusTotal", `https://www.virustotal.com/gui/file/${v}`], ["MalwareBazaar", `https://bazaar.abuse.ch/browse.php?search=sha1%3A${v}`]],
  sha256: (v) => [["VirusTotal", `https://www.virustotal.com/gui/file/${v}`], ["MalwareBazaar", `https://bazaar.abuse.ch/browse.php?search=sha256%3A${v}`]],
  cves: (v) => [["NVD", `https://nvd.nist.gov/vuln/detail/${v}`], ["CVE.org", `https://www.cve.org/CVERecord?id=${v}`]],
  emails: () => [],
};
const GROUP_NAMES = { urls: "URLs", domains: "Domains", ipv4: "IPv4 addresses", ipv6: "IPv6 addresses", emails: "Email addresses", sha256: "SHA-256 hashes", sha1: "SHA-1 hashes", md5: "MD5 hashes", cves: "Vulnerabilities" };

let goToTab = () => {};

function iocItem(kind, v, compact) {
  const pivots = h("div", { class: "pivots" },
    PIVOTS[kind](v).map(([n, u]) => link(u, n)),
    kind === "domains" ? h("button", { class: "copy-btn", type: "button", onclick: () => { goToTab("domain"); mapDomain(v); } }, "Map footprint") : null,
    kind === "emails" ? h("button", { class: "copy-btn", type: "button", onclick: () => { goToTab("domain"); mapDomain(v.split("@")[1]); } }, "Map its domain") : null,
    copyButton(engine.defang(v), "Copy defanged"));
  const li = h("li", {});
  const val = h("div", { class: "ioc-val" }, v);
  if (kind === "ipv4" || kind === "ipv6") {
    const c = json(engine.classify_ip(v));
    if (!c.routable) val.append(h("span", { class: "tag private" }, c.kind));
    else if (!compact) {
      const enrich = h("div", { class: "enrich" });
      const btn = h("button", { class: "copy-btn", type: "button" }, "Look up owner");
      btn.addEventListener("click", async () => {
        btn.remove();
        enrich.textContent = "Looking up…";
        const r = await enrichIp(v);
        enrich.textContent = [
          r.asName ? `AS${r.asName.asn} ${r.asName.name}` : r.origin ? `AS${r.origin.asn}` : "Network unknown",
          r.origin?.prefix, r.origin?.country, r.ptr.length ? `rDNS ${r.ptr.join(", ")}` : "no reverse DNS",
        ].filter(Boolean).join(", ");
      });
      pivots.prepend(btn);
      li.append(val, pivots, enrich);
      return li;
    }
  }
  li.append(val, pivots);
  return li;
}

function iocGroups(r, { compact = false } = {}) {
  const wrap = h("div", {});
  for (const kind of Object.keys(GROUP_NAMES)) {
    const list = r[kind];
    if (!list?.length) continue;
    wrap.append(h("div", { class: "ioc-group" },
      h("h3", {}, `${GROUP_NAMES[kind]} (${list.length})`),
      h("ul", { class: "ioc-list" }, list.slice(0, 500).map((v) => iocItem(kind, v, compact)))));
  }
  return wrap;
}

function runIoc() {
  const text = $("#ioc-input").value;
  const out = $("#ioc-out");
  if (!text.trim()) {
    out.replaceChildren(h("p", { class: "empty" }, "Paste some text first, or try the sample."));
    return;
  }
  const r = json(engine.extract_iocs(text));
  if (!r.total) {
    out.replaceChildren(h("p", { class: "empty" }, "No indicators found. The scanner looks for URLs, domains, IPs, email addresses, MD5/SHA-1/SHA-256 hashes and CVE IDs."));
    return;
  }
  const all = Object.keys(GROUP_NAMES).flatMap((k) => (r[k] || []).map((v) => [k, v]));
  const toolbar = h("div", { class: "toolbar" },
    copyButton(all.map(([, v]) => engine.defang(v)).join("\n"), "Copy all, defanged"),
    h("button", { class: "quiet small", type: "button", onclick: () => download("indicators.csv", ["type,value,defanged", ...all.map(([k, v]) => `${k},"${v.replace(/"/g, '""')}","${engine.defang(v).replace(/"/g, '""')}"`)].join("\n"), "text/csv") }, "Download CSV"));
  out.replaceChildren(
    h("section", { class: "block" },
      h("div", { class: "block-head" }, h("h2", {}, `${r.total} indicator${r.total === 1 ? "" : "s"} found`), toolbar),
      iocGroups(r)));
}

const SAMPLE = `Incident note: user reported an invoice email from billing@payr0ll-update[.]com.
The link hxxps://payr0ll-update[.]com/inv/8812.php downloaded Invoice_8812.pdf.exe
(SHA256 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f,
 MD5 44d88612fea8a8f36de82e1278abb02f).
After execution the host 10.20.4.17 beaconed to 45.155.205[.]233 and 2a06:98c1:3121::7 over 443.
Persistence via scheduled task; exploitation attempt against CVE-2024-3400 on the edge firewall.`;

// ------------------------------------------------------------ boot

function drawContours() {
  // Procedural contour lines: a few rings around off-centre peaks.
  const svg = $(".contours");
  const ns = "http://www.w3.org/2000/svg";
  const peaks = [[930, 120, 1], [1120, 360, 0.7], [640, 430, 0.55]];
  for (const [cx, cy, s] of peaks) {
    for (let i = 1; i <= 9; i++) {
      const r = i * 34 * s + 10;
      const pts = [];
      for (let a = 0; a <= 64; a++) {
        const t = (a / 64) * Math.PI * 2;
        const wobble = 1 + 0.13 * Math.sin(3 * t + i * 0.7 + cx) + 0.07 * Math.cos(5 * t + i);
        pts.push(`${(cx + Math.cos(t) * r * 1.35 * wobble).toFixed(1)},${(cy + Math.sin(t) * r * wobble).toFixed(1)}`);
      }
      const p = document.createElementNS(ns, "path");
      p.setAttribute("d", "M" + pts.join("L") + "Z");
      if (i % 4 === 0) p.setAttribute("class", "index");
      svg.append(p);
    }
  }
}

async function main() {
  drawContours();
  goToTab = setupTabs();
  setupDrop();

  try {
    await init();
    $("#engine").textContent = `Engine v${engine.version()} (Rust + WebAssembly) ready.`;
  } catch (e) {
    $("#engine").textContent = "The analysis engine failed to load. Reload the page; if it persists, your browser may block WebAssembly.";
    console.error(e);
    return;
  }

  $("#domain-form").addEventListener("submit", (e) => { e.preventDefault(); mapDomain($("#domain-input").value); });
  $("#ioc-go").addEventListener("click", runIoc);
  $("#ioc-sample").addEventListener("click", () => { $("#ioc-input").value = SAMPLE; runIoc(); });

  const m = location.hash.match(/^#domain=(.+)$/);
  if (m) {
    $("#domain-input").value = decodeURIComponent(m[1]);
    goToTab("domain");
    mapDomain(decodeURIComponent(m[1]));
  }
}

main();
