const api = globalThis.browser ?? globalThis.chrome;
const $ = (id) => document.getElementById(id);
const DEFAULTS = { key: "", lifetime: 0, server: "https://pixshare.fr", history: [], lifetimes: [] };
const isFirefox = navigator.userAgent.includes("Firefox");

function status(text, kind) {
  const el = $("status");
  el.textContent = text;
  el.className = "status " + kind;
}

async function copy(text) {
  try { await navigator.clipboard.writeText(text); return true; } catch (e) { return false; }
}

function renderHistory(items) {
  $("recent").hidden = !items.length;
  $("history").replaceChildren(...items.map((h) => {
    const li = document.createElement("li");
    const a = document.createElement("a");
    a.href = h.url; a.target = "_blank"; a.rel = "noopener"; a.textContent = h.name || h.url; a.title = h.url;
    const b = document.createElement("button");
    b.type = "button"; b.textContent = "Copier";
    b.addEventListener("click", async () => { b.textContent = (await copy(h.url)) ? "Copié ✓" : "Échec"; });
    li.append(a, b);
    return li;
  }));
}

async function run(message, label) {
  for (const b of document.querySelectorAll("button")) b.disabled = true;
  status(label, "info");
  const answer = await api.runtime.sendMessage(message);
  for (const b of document.querySelectorAll("button")) b.disabled = false;
  if (!answer?.ok) { status(answer?.error || "Échec de l'envoi.", "err"); return; }
  const copied = await copy(answer.data.page_url);
  status(copied ? answer.data.message : `Envoyé : ${answer.data.page_url}`, "ok");
  renderHistory((await api.storage.local.get(DEFAULTS)).history);
}

async function sendFile(file) {
  if (!file) return;
  const bytes = await file.arrayBuffer();
  await run({ cmd: "file", bytes, name: file.name || "image.png", type: file.type || "application/octet-stream" }, "Envoi en cours…");
}

async function init() {
  const s = await api.storage.local.get(DEFAULTS);
  const openOptions = (e) => { e?.preventDefault(); api.runtime.openOptionsPage(); window.close(); };
  $("openOptions1").addEventListener("click", openOptions);
  $("openOptions2").addEventListener("click", openOptions);
  if (!s.key) { $("noKey").hidden = false; return; }
  $("main").hidden = false;

  const select = $("lifetime");
  const choices = s.lifetimes.length ? s.lifetimes : [{ minutes: 0, label: "Par défaut" }];
  for (const c of choices) {
    const o = document.createElement("option");
    o.value = c.minutes; o.textContent = c.label;
    if (Number(c.minutes) === Number(s.lifetime)) o.selected = true;
    select.append(o);
  }
  select.addEventListener("change", () => api.storage.local.set({ lifetime: Number(select.value) }));

  $("capture").addEventListener("click", async () => {
    const win = await api.windows.getCurrent();
    await run({ cmd: "capture", windowId: win.id }, "Capture et envoi en cours…");
  });
  $("pick").addEventListener("click", () => {
    if (isFirefox) {
      // Firefox ferme cette fenêtre quand le sélecteur de fichiers s'ouvre : on passe par le site.
      api.tabs.create({ url: `${s.server}/#upload-tool` });
      window.close();
    } else {
      $("file").click();
    }
  });
  $("file").addEventListener("change", () => sendFile($("file").files[0]));
  document.addEventListener("paste", (e) => {
    const item = [...(e.clipboardData?.items || [])].find((i) => i.kind === "file");
    if (item) sendFile(item.getAsFile());
  });
  $("mySpace").addEventListener("click", (e) => { e.preventDefault(); api.tabs.create({ url: `${s.server}/#mes-fichiers` }); window.close(); });
  renderHistory(s.history);
}
init();
