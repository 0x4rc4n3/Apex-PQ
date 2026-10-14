/**
 * popup.js — Apex wallet.
 * Keys live only in an AES-256-GCM vault in chrome.storage.local, encrypted with a key derived
 * from the user's passphrase (PBKDF2-SHA256, 600k iterations). Plaintext keys exist only in this
 * popup's memory while it is open.
 */
const PBKDF2_ITERS = 600000;
const DEMO_PIN = "12345";
const enc = new TextEncoder(), dec = new TextDecoder();

let LMS_URL = "http://localhost:8080";
let accounts = [], currentIdx = 0;
let vaultKey = null, vaultSalt = null;       // in-memory only
let detectedPage = null, detectedChallenge = null, keyVisible = false;

// ── helpers ───────────────────────────────────────────────────────────────
const $ = (id) => document.getElementById(id);
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (s) => Uint8Array.from(atob(s), c => c.charCodeAt(0));
function toast(msg, ms = 1800) {
  const el = $("toast"); if (!el) return;
  el.textContent = msg; el.classList.add("show");
  setTimeout(() => el.classList.remove("show"), ms);
}
const currentAccount = () => accounts[currentIdx] || null;
const shortDID = (d) => !d ? "—" : d.length > 28 ? `${d.slice(0, 16)}…${d.slice(-10)}` : d;
const initials = (n) => (n || "?").split(/\s+/).map(w => w[0]).slice(0, 2).join("").toUpperCase();
const store = {
  get: (k) => chrome.storage.local.get(k),
  set: (o) => chrome.storage.local.set(o),
};

// ── vault crypto ──────────────────────────────────────────────────────────
async function deriveKey(pass, salt, iters = PBKDF2_ITERS) {
  const base = await crypto.subtle.importKey("raw", enc.encode(pass), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: iters, hash: "SHA-256" },
    base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
async function saveVault() {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, vaultKey,
    enc.encode(JSON.stringify({ accounts, currentIdx })));
  await store.set({ vault: { v: 1, iters: PBKDF2_ITERS, salt: b64(vaultSalt), iv: b64(iv), ct: b64(ct) } });
}
async function openVault(vault, pass) {
  const salt = unb64(vault.salt);
  const key = await deriveKey(pass, salt, vault.iters);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(vault.iv) }, key, unb64(vault.ct));
  const data = JSON.parse(dec.decode(pt));
  return { key, salt, data };
}

function isSupportedAppUrl(value) {
  try {
    const u = new URL(value);
    return ["localhost:8080", "127.0.0.1:8080"].includes(u.host) ||
      (u.protocol === "https:" && (u.hostname.endsWith(".onrender.com") ||
        u.hostname.endsWith(".manus.computer")));
  } catch { return false; }
}
async function resolveAppUrl() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !isSupportedAppUrl(tab.url)) return false;
  LMS_URL = new URL(tab.url).origin;
  return true;
}
async function fetchDemoAccounts() {
  if (!await resolveAppUrl()) throw new Error("Open the Apex-PQ site, then reopen the wallet.");
  const response = await fetch(`${LMS_URL}/api/demo/accounts`, { cache: "no-store" });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || !data.ok || !Array.isArray(data.accounts) || !data.accounts.length)
    throw new Error(data.error || "Could not sync demo accounts from this Apex-PQ site.");
  return data.accounts.map(a => ({
    name: a.name || a.full_name, roll_no: a.roll_no, email: a.email,
    role: a.role === "admin" ? "admin" : "student", did: a.did,
    pubkey_hex: a.pubkey_hex, privkey_hex: a.privkey_hex, demo_seed: true,
  }));
}
async function syncDemoAccounts() {
  const selectedRoll = currentAccount()?.roll_no;
  const seeded = await fetchDemoAccounts();
  const seededRolls = new Set(["admin", "student1", "student2", "student3"]);
  accounts = accounts.filter(a => !a.demo_seed && !seededRolls.has(a.roll_no));
  accounts = [...seeded, ...accounts];
  const selectedIndex = accounts.findIndex(a => a.roll_no === selectedRoll);
  currentIdx = selectedIndex >= 0 ? selectedIndex : Math.min(currentIdx, accounts.length - 1);
}
async function initializeDemoVault() {
  const seeded = await fetchDemoAccounts();
  accounts = seeded;
  currentIdx = 0;
  vaultSalt = crypto.getRandomValues(new Uint8Array(16));
  vaultKey = await deriveKey(DEMO_PIN, vaultSalt);
  await saveVault();
}

// ── lock screen ───────────────────────────────────────────────────────────
async function showLockScreen() {
  const { vault } = await store.get(["vault"]);
  const state = await store.get(["failCount", "lockUntil"]);
  let failCount = state.failCount || 0, lockUntil = state.lockUntil || 0;
  $("pin-title").textContent = "Wallet PIN";
  $("pin-sub").textContent = vault
    ? "Enter the shared demo PIN to unlock: 12345"
    : "Enter PIN 12345 to load and unlock the four demo accounts.";
  $("ext-pin").placeholder = "5-digit PIN";
  $("ext-pin2").style.display = "none";
  $("btn-pin-confirm").textContent = "Unlock Wallet";
  $("pin-overlay").style.display = "flex";
  $("ext-pin").focus();

  $("btn-pin-confirm").onclick = async () => {
    const alertEl = $("pin-alert"), pass = $("ext-pin").value;
    const fail = (m) => { alertEl.textContent = m; alertEl.style.display = "block"; };
    try {
      const wait = lockUntil - Date.now();
      if (wait > 0) return fail(`Too many attempts. Wait ${Math.ceil(wait / 1000)}s.`);
      const wrongPin = async () => {
        failCount += 1;
        lockUntil = Date.now() + Math.min(2 ** failCount, 300) * 1000;
        await store.set({ failCount, lockUntil });
        return fail("Wrong PIN.");
      };
      if (!vault) {
        if (pass !== DEMO_PIN) return wrongPin();
        await initializeDemoVault();
      } else {
        let opened;
        try { opened = await openVault(vault, pass); }
        catch { return wrongPin(); }
        vaultKey = opened.key; vaultSalt = opened.salt;
        accounts = opened.data.accounts || []; currentIdx = opened.data.currentIdx || 0;
      }
      await store.set({ failCount: 0, lockUntil: 0 });
      // Existing vaults can be unlocked once with their old passphrase, then use the demo PIN.
      if (pass !== DEMO_PIN) {
        vaultSalt = crypto.getRandomValues(new Uint8Array(16));
        vaultKey = await deriveKey(DEMO_PIN, vaultSalt);
      }
      try { await syncDemoAccounts(); }
      catch (e) { toast(`Account sync unavailable: ${e.message}`, 3000); }
      $("ext-pin").value = $("ext-pin2").value = "";
      await absorbPending();
      await saveVault();
      $("pin-overlay").style.display = "none";
      await startUI();
    } catch (e) { fail("Error: " + e.message); }
  };
}
$("ext-pin").addEventListener("keydown", e => { if (e.key === "Enter") $("btn-pin-confirm").click(); });
$("ext-pin2").addEventListener("keydown", e => { if (e.key === "Enter") $("btn-pin-confirm").click(); });

// Move identities created on the signup page into the vault.
async function absorbPending() {
  const { pending = [] } = await chrome.storage.session.get(["pending"]);
  for (const p of pending) if (!accounts.some(a => a.did === p.did)) accounts.push(p);
  if (pending.length) { currentIdx = accounts.length - 1; await chrome.storage.session.remove("pending"); }
}

// ── UI ────────────────────────────────────────────────────────────────────
function renderAccount() {
  const acc = currentAccount();
  keyVisible = false;
  $("key-reveal").classList.remove("show");
  $("key-reveal-value").textContent = "";
  $("btn-show-key").textContent = "Show Private Key";
  if (!acc) {
    $("acc-name").textContent = "No accounts";
    $("acc-email").textContent = "Import or create an identity";
    $("did-value").textContent = "—";
    return;
  }
  const avatar = $("acc-avatar");
  avatar.textContent = initials(acc.name);
  const hue = (acc.name.charCodeAt(0) * 17) % 360;
  avatar.style.background = `linear-gradient(135deg, hsl(${hue},65%,50%), hsl(${hue + 50},75%,60%))`;
  $("acc-name").textContent = acc.name;
  $("acc-email").textContent = acc.email || `${acc.roll_no || ""}@apex.edu`;
  $("did-value").textContent = shortDID(acc.did);
  $("did-value").title = acc.did || "";
  $("btn-delete-acc").style.display = acc.role === "admin" ? "none" : "block";
}
function renderSelect() {
  const sel = $("acc-select"); sel.innerHTML = "";
  accounts.forEach((acc, i) => {
    const opt = document.createElement("option");
    opt.value = i; opt.textContent = acc.name.split(" ")[0] || `Account ${i + 1}`;
    opt.selected = i === currentIdx; sel.appendChild(opt);
  });
}
async function startUI() { renderSelect(); renderAccount(); await detectPage(); }

async function detectPage() {
  const signBtn = $("btn-sign-login");
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  detectedPage = null; detectedChallenge = null; signBtn.disabled = false; signBtn.textContent = "Sign & Login";
  if (!tab || !tab.url) return;
  let u; try { u = new URL(tab.url); } catch { return; }
  if (!isSupportedAppUrl(tab.url)) return;
  LMS_URL = u.origin;
  if (u.pathname.startsWith("/login")) {
    try {
      const r = await chrome.tabs.sendMessage(tab.id, { type: "GET_CHALLENGE" });
      if (r && r.challenge) { detectedPage = "login-ready"; detectedChallenge = r.challenge; signBtn.textContent = "Sign Challenge & Enter"; }
      else { detectedPage = "login"; signBtn.textContent = "Fill & Sign In"; }
    } catch { detectedPage = "login"; signBtn.textContent = "Fill & Sign In"; }
  } else if (u.pathname.startsWith("/signup")) {
    detectedPage = "signup"; signBtn.textContent = "Open Login";
  } else if (u.pathname.startsWith("/dashboard") || u.pathname.startsWith("/admin")) {
    detectedPage = "dashboard"; signBtn.textContent = "Identity Active ✓"; signBtn.disabled = true;
  }
}

// ── events ────────────────────────────────────────────────────────────────
$("btn-copy-did").addEventListener("click", async () => {
  const acc = currentAccount(); if (!acc) return;
  try { await navigator.clipboard.writeText(acc.did); toast("DID copied"); } catch { toast("Failed to copy"); }
});
$("btn-show-key").addEventListener("click", () => {
  const acc = currentAccount(); if (!acc) return;
  keyVisible = !keyVisible;
  $("key-reveal-value").textContent = keyVisible ? acc.privkey_hex : "";
  $("key-reveal").classList.toggle("show", keyVisible);
  $("btn-show-key").textContent = keyVisible ? "Hide Private Key" : "Show Private Key";
});
$("acc-select").addEventListener("change", async (e) => {
  currentIdx = parseInt(e.target.value, 10); await saveVault(); renderAccount(); detectPage();
});
$("btn-delete-acc").addEventListener("click", () => {
  const acc = currentAccount(); if (!acc) return;
  $("delete-target-name").textContent = acc.name;
  $("confirm-overlay").style.display = "flex";
});
$("btn-cancel-delete").addEventListener("click", () => { $("confirm-overlay").style.display = "none"; });
$("btn-confirm-delete").addEventListener("click", async () => {
  if (currentAccount()?.role === "admin") {
    $("confirm-overlay").style.display = "none";
    toast("The administrator account cannot be removed");
    return;
  }
  accounts.splice(currentIdx, 1); currentIdx = Math.max(0, currentIdx - 1);
  await saveVault(); $("confirm-overlay").style.display = "none";
  toast("Identity removed"); startUI();
});
$("btn-import-toggle").addEventListener("click", () => {
  const box = $("import-box"); box.style.display = box.style.display === "none" ? "block" : "none";
});
$("btn-import").addEventListener("click", async () => {
  try {
    const o = JSON.parse($("import-text").value);
    const ok = o && /^did:key:z/.test(o.did) && /^[0-9a-f]{2624}$/.test(o.pubkey_hex) && /^[0-9a-f]{5120}$/.test(o.privkey_hex);
    if (!ok) throw new Error("Not a valid identity");
    if (accounts.some(a => a.did === o.did)) throw new Error("Already imported");
    accounts.push({ name: String(o.name || "Imported").slice(0, 80), roll_no: o.roll_no || "",
      email: o.email || `${o.roll_no || ""}@apex.edu`, role: o.role === "admin" ? "admin" : "student",
      did: o.did, pubkey_hex: o.pubkey_hex, privkey_hex: o.privkey_hex });
    currentIdx = accounts.length - 1; await saveVault();
    $("import-text").value = ""; $("import-box").style.display = "none";
    toast("Identity imported"); startUI();
  } catch (e) { toast(e.message); }
});

// ── sign & login ──────────────────────────────────────────────────────────
$("btn-sign-login").addEventListener("click", async () => {
  const acc = currentAccount(); if (!acc) return toast("No account selected");
  const btn = $("btn-sign-login"), orig = btn.textContent;
  btn.disabled = true; btn.textContent = "Working…";
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (detectedPage === "login-ready") { await signAndSubmit(tab, acc, detectedChallenge); setTimeout(() => window.close(), 900); }
    else if (detectedPage === "login")  { await fillAndSign(tab, acc); setTimeout(() => window.close(), 900); }
    else chrome.tabs.create({ url: `${LMS_URL}/login` });
  } catch (e) { toast("Error: " + e.message, 3500); }
  finally { btn.disabled = false; btn.textContent = orig; }
});

async function signAndSubmit(tab, acc, challenge) {
  const resp = await fetch(`${LMS_URL}/api/sign`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ did: acc.did, challenge, privkey_hex: acc.privkey_hex }),
  });
  if (resp.status === 404) throw new Error("Server signing is disabled (APEX_DEMO_MODE=0). Use tools/sign.py.");
  const data = await resp.json();
  if (!data.ok) throw new Error(data.error || "Signing failed");
  await chrome.tabs.sendMessage(tab.id, { type: "FILL_SIGNATURE_AND_SUBMIT", signature: data.signature });
  toast("✓ Signed & logged in");
}

async function fillAndSign(tab, acc) {
  await chrome.tabs.sendMessage(tab.id, { type: "FILL_ROLLNO", roll_no: acc.roll_no || acc.email.split("@")[0] });
  for (let i = 0; i < 16; i++) {
    await new Promise(r => setTimeout(r, 400));
    try {
      const r = await chrome.tabs.sendMessage(tab.id, { type: "GET_CHALLENGE" });
      if (r && r.challenge) return signAndSubmit(tab, acc, r.challenge);
    } catch { /* page still updating */ }
  }
  toast("Challenge timed out");
}

showLockScreen();
