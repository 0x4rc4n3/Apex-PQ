/**
 * content.js — QuantumID Wallet Extension Content Script
 * Injected into http://localhost:8080/* pages.
 * Bridges between the popup and the LMS DOM.
 */

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {

  // ── Get current challenge from login page ──────────────────────
  if (msg.type === "GET_CHALLENGE") {
    const el = document.getElementById("challenge-value");
    const challenge = el ? el.textContent.trim() : null;
    sendResponse({ challenge: challenge || null });
    return true;
  }

  // ── Fill roll number and trigger Continue button ───────────────
  if (msg.type === "FILL_ROLLNO") {
    const rollInput = document.getElementById("rollno-input");
    const btn       = document.getElementById("btn-get-challenge");
    if (rollInput && btn) {
      rollInput.value = msg.roll_no;
      rollInput.dispatchEvent(new Event("input", { bubbles: true }));
      setTimeout(() => btn.click(), 120);
      sendResponse({ ok: true });
    } else {
      sendResponse({ ok: false, error: "Roll number input not found" });
    }
    return true;
  }

  // ── Legacy DID fill (kept for backward compat) ──────────────────
  if (msg.type === "FILL_DID") {
    const rollInput = document.getElementById("rollno-input");
    if (rollInput) {
      // Try to extract roll from DID context — not ideal but keeps compat
      sendResponse({ ok: false, error: "Use FILL_ROLLNO instead" });
    } else {
      sendResponse({ ok: false, error: "Not on login page" });
    }
    return true;
  }

  // ── Fill signature and click Verify ───────────────────────────
  if (msg.type === "FILL_SIGNATURE_AND_SUBMIT") {
    const sigInput = document.getElementById("sig-input");
    const verifyBtn = document.getElementById("btn-verify");
    if (sigInput && verifyBtn) {
      sigInput.value = msg.signature;
      sigInput.dispatchEvent(new Event("input", { bubbles: true }));
      setTimeout(() => verifyBtn.click(), 150);
      sendResponse({ ok: true });
    } else {
      sendResponse({ ok: false, error: "Signature input not found — is the challenge step active?" });
    }
    return true;
  }

  // ── Fill DID on signup form ────────────────────────────────────
  if (msg.type === "FILL_SIGNUP_DID") {
    // Relying on PQC_IDENTITY_GENERATED auto-save now instead of filling.
    sendResponse({ ok: true });
    return true;
  }

  // ── Get current page URL info ──────────────────────────────────
  if (msg.type === "GET_PAGE_INFO") {
    sendResponse({
      url:       window.location.href,
      pathname:  window.location.pathname,
      challenge: document.getElementById("challenge-value")?.textContent?.trim() || null,
      loggedIn:  document.querySelector(".topbar-user") !== null,
    });
    return true;
  }

  return false;
});

// Identity generated on the signup page: forward to the background worker, which
// holds it in memory until the user unlocks the wallet (it is never stored in plaintext on disk).
window.addEventListener("PQC_IDENTITY_GENERATED", (e) => {
  const d = e.detail;
  if (d && d.did) chrome.runtime.sendMessage({ type: "PENDING_IDENTITY", identity: d });
});
