chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  if (msg?.target !== "offscreen") return false;
  const t = document.getElementById("t");
  t.value = msg.text;
  t.select();
  let ok = false;
  try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
  reply(ok);
  return false;
});
