function findPasswordField() {
  const pw = document.querySelector('input[type="password"]');
  return pw || null;
}

chrome.runtime.onMessage.addListener((msg) => {
  if (msg?.type !== "SMPNANO_FILL") return;
  //find 'input[type="password"]' to the relevant site to login.
  const pwField = findPasswordField();
  if (!pwField) return;

  pwField.focus();
  pwField.value = msg.password;

  pwField.dispatchEvent(new Event("input", { bubbles: true }));
  pwField.dispatchEvent(new Event("change", { bubbles: true }));
});