/**
 * background.js — receives a freshly generated identity from the page (via the
 * content script) and parks it in chrome.storage.session, which lives in memory
 * only and is never written to disk. The popup moves it into the encrypted
 * vault the next time the user unlocks the wallet.
 */
const HEX = /^[0-9a-f]+$/;

function valid(d) {
  return d && typeof d.did === "string" && d.did.startsWith("did:key:z") && d.did.length < 100 &&
    typeof d.pubkey_hex === "string" && d.pubkey_hex.length === 1312 * 2 && HEX.test(d.pubkey_hex) &&
    typeof d.privkey_hex === "string" && d.privkey_hex.length === 2560 * 2 && HEX.test(d.privkey_hex) &&
    typeof d.full_name === "string" && d.full_name.length <= 80 &&
    typeof d.roll_no === "string" && /^[a-z0-9][a-z0-9._-]{1,31}$/.test(d.roll_no);
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg && msg.type === "PENDING_IDENTITY" && sender.tab && valid(msg.identity)) {
    chrome.storage.session.get(["pending"]).then(({ pending = [] }) => {
      if (!pending.some(p => p.did === msg.identity.did)) {
        pending.push({
          name: msg.identity.full_name, roll_no: msg.identity.roll_no,
          email: `${msg.identity.roll_no}@apex.edu`, role: "student",
          did: msg.identity.did, pubkey_hex: msg.identity.pubkey_hex,
          privkey_hex: msg.identity.privkey_hex,
        });
      }
      return chrome.storage.session.set({ pending });
    }).then(() => sendResponse({ ok: true }));
    return true;
  }
  return false;
});
