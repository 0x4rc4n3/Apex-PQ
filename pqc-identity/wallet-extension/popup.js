/**
 * popup.js — Apex Identity Wallet Extension
 * Minimal, modern identity manager with PQC signing.
 */

let LMS_URL      = "http://localhost:8080";
function getSignUrl() { return `${LMS_URL}/api/sign`; }
const SEEDS_URL  = chrome.runtime.getURL("seeds.json");

// ── State ─────────────────────────────────────────────────────────────────
let accounts          = [];
let currentIdx        = 0;
let detectedPage      = null;  // 'login-ready' | 'login' | 'signup' | 'home' | 'dashboard' | null
let detectedChallenge = null;
let keyVisible        = false;

// ── Helpers ───────────────────────────────────────────────────────────────
function toast(msg, ms = 1800) {
  const el = document.getElementById("toast");
  if (!el) return;
  el.textContent = msg;
  el.classList.add("show");
  setTimeout(() => el.classList.remove("show"), ms);
}

function currentAccount() { return accounts[currentIdx] || null; }

function shortDID(did) {
  if (!did) return "—";
  return did.length > 28 ? `${did.slice(0, 16)}…${did.slice(-10)}` : did;
}

function initials(name) {
  return (name || "?").split(" ").map(w => w[0]).join("").slice(0, 2).toUpperCase();
}

// ── Load / Sync Accounts ──────────────────────────────────────────────────
async function syncToBackend() {
  try {
    await fetch(`${LMS_URL}/api/wallet/seeds`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(accounts)
    });
  } catch(e) {
    console.warn("Backend sync failed:", e);
  }
}

async function loadAccounts() {
  return new Promise(resolve => {
    chrome.storage.local.get(["accounts", "currentIdx"], async (data) => {
      // Sync from backend seeds if available
      try {
        const resp = await fetch(`${LMS_URL}/api/wallet/seeds`);
        if (resp.ok) {
          const seeds = await resp.json();
          if (Array.isArray(seeds) && seeds.length > 0) {
            accounts = seeds;
            currentIdx = data.currentIdx || 0;
            if (currentIdx >= accounts.length) currentIdx = 0;
            chrome.storage.local.set({ accounts, currentIdx });
            resolve();
            return;
          }
        }
      } catch(e) {}

      if (data.accounts && data.accounts.length > 0) {
        accounts   = data.accounts;
        currentIdx = data.currentIdx || 0;
        resolve();
      } else {
        // Load default seeds.json
        try {
          const resp = await fetch(SEEDS_URL);
          const seeds = await resp.json();
          accounts   = Array.isArray(seeds) ? seeds : [];
          currentIdx = 0;
          chrome.storage.local.set({ accounts, currentIdx });
          resolve();
        } catch(e) {
          accounts = [];
          resolve();
        }
      }
    });
  });
}

function saveCurrentIdx() {
  chrome.storage.local.set({ currentIdx });
}

// ── Render UI ─────────────────────────────────────────────────────────────
function renderAccount() {
  const acc = currentAccount();
  if (!acc) {
    document.getElementById("acc-name").textContent  = "No accounts";
    document.getElementById("acc-email").textContent = "";
    document.getElementById("did-value").textContent = "—";
    return;
  }

  const avatar = document.getElementById("acc-avatar");
  avatar.textContent = initials(acc.name);
  const hue = (acc.name.charCodeAt(0) * 17) % 360;
  avatar.style.background = `linear-gradient(135deg, hsl(${hue},65%,50%), hsl(${hue+50},75%,60%))`;

  document.getElementById("acc-name").textContent  = acc.name;
  document.getElementById("acc-email").textContent = acc.email || `${acc.roll_no || ''}@apex.edu`;
  document.getElementById("did-value").textContent = shortDID(acc.did);
  document.getElementById("did-value").title       = acc.did || "";
  document.getElementById("key-reveal-value").textContent = acc.privkey_hex || "—";
  
  const delBtn = document.getElementById("btn-delete-acc");
  if (delBtn) {
    delBtn.style.display = acc.role === "admin" ? "none" : "block";
  }
}

function renderSelect() {
  const sel = document.getElementById("acc-select");
  sel.innerHTML = "";
  accounts.forEach((acc, i) => {
    const opt = document.createElement("option");
    opt.value = i;
    opt.textContent = acc.name.split(" ")[0] || `Account ${i+1}`;
    if (i === currentIdx) opt.selected = true;
    sel.appendChild(opt);
  });
}

// ── Page Detection & Auto-Adapt ───────────────────────────────────────────
async function detectPage() {
  const signBtn = document.getElementById("btn-sign-login");
  if (!signBtn) return;

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url) {
    detectedPage = null;
    signBtn.textContent = "Sign & Login";
    return;
  }

  const isLMS = tab.url.includes("localhost:8080") || tab.url.includes("127.0.0.1:8080");
  if (!isLMS) {
    detectedPage = null;
    signBtn.textContent = "Sign & Login";
    return;
  }
  
  try {
    const tabUrl = new URL(tab.url);
    LMS_URL = tabUrl.origin;
  } catch(e) {}

  const url = tab.url;

  if (url.includes("/login")) {
    try {
      const resp = await chrome.tabs.sendMessage(tab.id, { type: "GET_CHALLENGE" });
      if (resp && resp.challenge) {
        detectedPage      = "login-ready";
        detectedChallenge = resp.challenge;
        signBtn.textContent = "Sign Challenge & Enter";
        signBtn.disabled    = false;
      } else {
        detectedPage = "login";
        signBtn.textContent = "Fill & Sign In";
        signBtn.disabled    = false;
      }
    } catch(e) {
      detectedPage = "login";
      signBtn.textContent = "Fill & Sign In";
      signBtn.disabled    = false;
    }
  } else if (url.includes("/signup")) {
    detectedPage = "signup";
    signBtn.textContent = "Fill DID on Signup";
    signBtn.disabled    = false;
  } else if (url.includes("/dashboard") || url.includes("/admin")) {
    detectedPage = "dashboard";
    signBtn.textContent = "Identity Active ✓";
    signBtn.disabled    = true;
  } else {
    detectedPage = null;
    signBtn.textContent = "Sign & Login";
    signBtn.disabled    = false;
  }
}

// ── Master PIN Verification ───────────────────────────────────────────────
document.getElementById("btn-pin-confirm").addEventListener("click", () => {
  const pinInput = document.getElementById("ext-pin");
  const alertEl  = document.getElementById("pin-alert");
  if (pinInput.value.trim() !== "1342") {
    alertEl.textContent = "Invalid master PIN";
    alertEl.style.display = "block";
    pinInput.focus();
    return;
  }
  alertEl.style.display = "none";
  document.getElementById("pin-overlay").style.display = "none";
});

document.getElementById("ext-pin").addEventListener("keydown", (e) => {
  if (e.key === "Enter") document.getElementById("btn-pin-confirm").click();
});

// ── Copy DID ──────────────────────────────────────────────────────────────
document.getElementById("btn-copy-did").addEventListener("click", async () => {
  const acc = currentAccount();
  if (!acc || !acc.did) return;
  try {
    await navigator.clipboard.writeText(acc.did);
    const btn = document.getElementById("btn-copy-did");
    btn.textContent = "Copied";
    btn.classList.add("copied");
    setTimeout(() => { btn.textContent = "Copy"; btn.classList.remove("copied"); }, 1500);
  } catch(e) {
    toast("Failed to copy");
  }
});

// ── Show / Hide Key ───────────────────────────────────────────────────────
document.getElementById("btn-show-key").addEventListener("click", () => {
  keyVisible = !keyVisible;
  document.getElementById("key-reveal").classList.toggle("show", keyVisible);
  document.getElementById("btn-show-key").textContent = keyVisible ? "Hide Private Key" : "Show Private Key";
});

// ── Account Switcher ──────────────────────────────────────────────────────
document.getElementById("acc-select").addEventListener("change", (e) => {
  currentIdx = parseInt(e.target.value);
  saveCurrentIdx();
  renderAccount();
  keyVisible = false;
  document.getElementById("key-reveal").classList.remove("show");
  document.getElementById("btn-show-key").textContent = "Show Private Key";
  detectPage();
});

// ── Account Removal ───────────────────────────────────────────────────────
document.getElementById("btn-delete-acc").addEventListener("click", () => {
  if (accounts.length === 0) return;
  const acc = currentAccount();
  document.getElementById("delete-target-name").textContent = acc.name;
  document.getElementById("confirm-overlay").style.display = "flex";
});

document.getElementById("btn-cancel-delete").addEventListener("click", () => {
  document.getElementById("confirm-overlay").style.display = "none";
});

document.getElementById("btn-confirm-delete").addEventListener("click", () => {
  accounts.splice(currentIdx, 1);
  currentIdx = Math.max(0, currentIdx - 1);
  chrome.storage.local.set({ accounts, currentIdx }, async () => {
    await syncToBackend();
    toast("Identity Removed");
    document.getElementById("confirm-overlay").style.display = "none";
    renderSelect();
    renderAccount();
    detectPage();
  });
});

// ── Sign & Login Execution ────────────────────────────────────────────────
document.getElementById("btn-sign-login").addEventListener("click", async () => {
  const acc = currentAccount();
  if (!acc) { toast("No account selected"); return; }
  
  const btn = document.getElementById("btn-sign-login");
  const origText = btn.textContent;
  btn.disabled = true;
  btn.textContent = "Working…";

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    if (detectedPage === "login-ready" && detectedChallenge) {
      await signAndSubmit(tab, acc, detectedChallenge);
      setTimeout(() => window.close(), 900);
    } else if (detectedPage === "login") {
      await fillDIDAndSign(tab, acc);
      setTimeout(() => window.close(), 900);
    } else if (detectedPage === "signup") {
      await chrome.tabs.sendMessage(tab.id, { type: "FILL_SIGNUP_DID", did: acc.did });
      toast("DID filled on form");
      setTimeout(() => window.close(), 900);
    } else {
      chrome.tabs.create({ url: `${LMS_URL}/login` });
    }
  } catch(e) {
    toast("Error: " + e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = origText;
  }
});

async function signAndSubmit(tab, acc, challenge) {
  const resp = await fetch(getSignUrl(), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ challenge, privkey_hex: acc.privkey_hex })
  });
  const data = await resp.json();
  if (!data.ok) throw new Error(data.error || "Signing failed");

  await chrome.tabs.sendMessage(tab.id, {
    type: "FILL_SIGNATURE_AND_SUBMIT",
    signature: data.signature
  });
  toast("✓ Signed & Logged In!");
}

async function fillDIDAndSign(tab, acc) {
  await chrome.tabs.sendMessage(tab.id, { 
    type: "FILL_ROLLNO", 
    roll_no: acc.roll_no || acc.email.split("@")[0] 
  });

  let challenge = null;
  for (let i = 0; i < 16; i++) {
    await new Promise(r => setTimeout(r, 400));
    try {
      const resp = await chrome.tabs.sendMessage(tab.id, { type: "GET_CHALLENGE" });
      if (resp && resp.challenge) { challenge = resp.challenge; break; }
    } catch(e) {}
  }

  if (!challenge) { toast("Challenge timed out"); return; }
  await signAndSubmit(tab, acc, challenge);
}

// ── Initialization ────────────────────────────────────────────────────────
(async () => {
  await detectPage();
  await loadAccounts();
  renderSelect();
  renderAccount();
  await detectPage();
})();
