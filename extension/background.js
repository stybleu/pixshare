// PixShare — envoi d'images et de captures depuis le navigateur (membres).
// La clé personnelle vient de « Mon compte » sur pixshare.fr ; elle reste dans ce navigateur.
const api = globalThis.browser ?? globalThis.chrome;
const DEFAULTS = { key: "", lifetime: 0, server: "https://pixshare.fr", history: [] };

async function settings() {
  return api.storage.local.get(DEFAULTS);
}

function createMenus() {
  api.contextMenus.removeAll(() => {
    api.contextMenus.create({ id: "pixshare-image", title: "Envoyer cette image sur PixShare", contexts: ["image"] });
    api.contextMenus.create({ id: "pixshare-page", title: "Capturer cette page sur PixShare", contexts: ["page"] });
  });
}
api.runtime.onInstalled.addListener((details) => {
  createMenus();
  if (details.reason === "install") api.runtime.openOptionsPage();
});
api.runtime.onStartup?.addListener(createMenus);

async function upload({ blob, filename, imageUrl }) {
  const s = await settings();
  if (!s.key) throw new Error("Ajoute d'abord ta clé PixShare dans les réglages de l'extension.");
  const form = new FormData();
  if (blob) form.append("file", blob, filename || "image.png");
  else form.append("image_url", imageUrl);
  if (s.lifetime) form.append("lifetime", String(s.lifetime));
  let response;
  try {
    response = await fetch(`${s.server}/extension/envoi`, {
      method: "POST",
      headers: { Authorization: `Bearer ${s.key}` },
      body: form,
      credentials: "omit",
    });
  } catch (e) {
    throw new Error("PixShare est injoignable. Vérifie ta connexion.");
  }
  let data = {};
  try { data = await response.json(); } catch (e) { /* réponse non JSON */ }
  if (!response.ok || !data.ok) throw new Error(data.error || `Erreur ${response.status}`);
  const history = [{ url: data.page_url, direct: data.direct_url, name: filename || "image", at: Date.now() }, ...s.history].slice(0, 8);
  await api.storage.local.set({ history });
  return data;
}

async function captureVisible(windowId) {
  const dataUrl = await api.tabs.captureVisibleTab(windowId, { format: "png" });
  const blob = await (await fetch(dataUrl)).blob();
  const stamp = new Date().toISOString().slice(0, 19).replace(/[T:]/g, "-");
  return { blob, filename: `capture-${stamp}.png` };
}

async function copyText(text) {
  // Chrome : document hors écran ; Firefox : presse-papiers directement.
  if (api.offscreen?.createDocument) {
    try {
      const has = await api.offscreen.hasDocument?.();
      if (!has) {
        await api.offscreen.createDocument({ url: "offscreen.html", reasons: ["CLIPBOARD"], justification: "Copier le lien PixShare" });
      }
      const ok = await api.runtime.sendMessage({ target: "offscreen", text });
      if (ok) return true;
    } catch (e) { /* on essaie autrement */ }
  }
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (e) {
    return false;
  }
}

function notify(title, message) {
  api.notifications.create({ type: "basic", iconUrl: "icons/icon-128.png", title, message });
}

async function send(job) {
  try {
    const data = await upload(job);
    const copied = await copyText(data.page_url);
    notify("PixShare ✅", copied ? data.message : `Envoyé : ${data.page_url}`);
    return data;
  } catch (e) {
    notify("PixShare : échec", e.message || String(e));
    throw e;
  }
}

api.contextMenus.onClicked.addListener(async (info, tab) => {
  try {
    if (info.menuItemId === "pixshare-image" && info.srcUrl) {
      if (info.srcUrl.startsWith("data:") || info.srcUrl.startsWith("blob:")) {
        const blob = await (await fetch(info.srcUrl)).blob();
        await send({ blob, filename: "image." + ((blob.type.split("/")[1] || "png").replace("jpeg", "jpg")) });
      } else {
        await send({ imageUrl: info.srcUrl });
      }
    } else if (info.menuItemId === "pixshare-page") {
      await send(await captureVisible(tab?.windowId));
    }
  } catch (e) { /* déjà notifié */ }
});

// Messages de la fenêtre de l'extension (popup).
api.runtime.onMessage.addListener((msg, sender, reply) => {
  if (msg?.target === "offscreen") return false;
  (async () => {
    try {
      if (msg.cmd === "capture") reply({ ok: true, data: await upload(await captureVisible(msg.windowId)) });
      else if (msg.cmd === "file") reply({ ok: true, data: await upload({ blob: new Blob([msg.bytes], { type: msg.type }), filename: msg.name }) });
      else reply({ ok: false, error: "Commande inconnue" });
    } catch (e) {
      reply({ ok: false, error: e.message || String(e) });
    }
  })();
  return true;
});
