const $ = (id) => document.getElementById(id);

let lastPw = "";
let lastSite = "";

async function getActiveTabUrl() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab?.url || "";
}

// Minimal domain normalize.
function normalizeDomain(urlStr) {
  try {
    const u = new URL(urlStr);
    if (u.protocol !== "https:") return "insecure";

    return u.hostname.replace(/^www\./, "");
  } catch {
    return "unknown";
  }
}

function toBase64Url(bytes) {
  const bin = String.fromCharCode(...bytes);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function mapToCharset(bytes, charset, length) {
  const out = [];
  for (let i = 0; i < length; i++) out.push(charset[bytes[i] % charset.length]);
  return out.join("");
}

function enforceComplexity(pw) {
  const sym = "!@#$%^&*()-_=+[]{};:,.?";
  let s = pw.split("");

  const needLower = !/[a-z]/.test(pw);
  const needUpper = !/[A-Z]/.test(pw);
  const needDigit = !/[0-9]/.test(pw);
  const needSym = !/[^A-Za-z0-9]/.test(pw);

  if (needLower) s[0] = String.fromCharCode(97 + (s[0].charCodeAt(0) % 26));
  if (needUpper) s[1] = String.fromCharCode(65 + (s[1].charCodeAt(0) % 26));
  if (needDigit) s[2] = String.fromCharCode(48 + (s[2].charCodeAt(0) % 10));
  if (needSym) s[3] = sym[s[3].charCodeAt(0) % sym.length];

  return s.join("");
}

async function derivePassword({ master, site, user, counter, length, mode }) {
  const enc = new TextEncoder();
  //Steps to derive password  
  // 1) PBKDF2(master, salt=site) -> HMAC key
  const masterKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(master),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  const salt = enc.encode(`smp-nano|${site}`);
  const hmacKey = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 200_000, hash: "SHA-256" },
    masterKey,
    { name: "HMAC", hash: "SHA-256", length: 256 },
    false,
    ["sign"]
  );

  // 2) HMAC(site|user|counter) -> bytes
  const msg = enc.encode(`${site}|${user || ""}|${counter}`);
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", hmacKey, msg));

  // 3) Encode
  let pw = "";
  if (mode === "base64url") {
    pw = toBase64Url(sig).slice(0, length);
  } else {
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{};:,.?";
    pw = mapToCharset(sig, charset, length);
  }

  // 4) Complexity tweak
  pw = enforceComplexity(pw).slice(0, length);
  return pw;
}

async function mainInit() {
  const url = await getActiveTabUrl();
  lastSite = normalizeDomain(url);
  $("siteLine").textContent = `Site: ${lastSite}`;
}

$("gen").addEventListener("click", async () => {
  const master = $("master").value;
  if (!master) {
    $("out").textContent = "Enter master secret.";
    return;
  }

  const user = $("user").value.trim();
  const counter = Math.max(1, Number($("ctr").value) || 1);
  const length = Math.max(12, Math.min(64, Number($("len").value) || 20));
  const mode = $("mode").value;

  $("out").textContent = "Generating…";

  const pw = await derivePassword({ master, site: lastSite, user, counter, length, mode });
  lastPw = pw;

  //Clearing the master input immediately
  $("master").value = "";

  $("out").textContent = pw;
  $("copy").disabled = false;
  $("fill").disabled = false;
});

$("copy").addEventListener("click", async () => {
  if (!lastPw) return;
  await navigator.clipboard.writeText(lastPw);
});

$("fill").addEventListener("click", async () => {
  if (!lastPw) return;
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) return;

  // Send the derived password to content script for one-time fill
  chrome.tabs.sendMessage(tab.id, { type: "SMPNANO_FILL", password: lastPw });

  //clearing local variable after sending
  lastPw = "";
  $("fill").disabled = true;
});

mainInit();