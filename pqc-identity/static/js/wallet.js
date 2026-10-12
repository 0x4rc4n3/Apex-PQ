/**
 * wallet.js — Client-Side Portal & Wallet Helper Utility
 * Provides cross-browser clipboard fallback, DID formatting, and wallet detection.
 */

window.QuantumWallet = {
  version: "1.0.0",

  /**
   * Copy text to clipboard with fallback for non-HTTPS / local iframe contexts
   */
  async copy(text, btnElement) {
    let success = false;
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
        success = true;
      } else {
        const textarea = document.createElement("textarea");
        textarea.value = text;
        textarea.style.position = "fixed";
        textarea.style.opacity = "0";
        document.body.appendChild(textarea);
        textarea.focus();
        textarea.select();
        success = document.execCommand("copy");
        document.body.removeChild(textarea);
      }
    } catch (e) {
      console.warn("Clipboard copy fallback triggered:", e);
    }

    if (btnElement && success) {
      const orig = btnElement.innerHTML;
      btnElement.classList.add("copied");
      btnElement.innerHTML = "✓ Copied";
      setTimeout(() => {
        btnElement.classList.remove("copied");
        btnElement.innerHTML = orig;
      }, 1800);
    }
    return success;
  },

  /**
   * Truncate DID or Hex keys cleanly for compact displays
   */
  truncate(str, front = 12, back = 8) {
    if (!str || str.length <= front + back + 3) return str || "—";
    return `${str.slice(0, front)}…${str.slice(-back)}`;
  }
};

// Global fallback bridge for copyToClipboard
if (typeof window.copyToClipboard !== "function") {
  window.copyToClipboard = (text, btn) => window.QuantumWallet.copy(text, btn);
}
