const api = globalThis.browser ?? globalThis.chrome;
const $ = (id) => document.getElementById(id);
const DEFAULTS = { key: "", server: "https://pixshare.fr" };

function status(text, kind) {
  $("status").textContent = text;
  $("status").className = "status " + kind;
}

async function check(key, server) {
  const response = await fetch(`${server}/extension/moi`, { headers: { Authorization: `Bearer ${key}` }, credentials: "omit" });
  let data = {};
  try { data = await response.json(); } catch (e) { /* non JSON */ }
  if (!response.ok || !data.ok) throw new Error(data.error || `Erreur ${response.status}`);
  return data;
}

async function init() {
  const s = await api.storage.local.get(DEFAULTS);
  $("key").value = s.key;
  if (s.key) status("Une clé est enregistrée.", "info");
  $("save").addEventListener("click", async () => {
    const key = $("key").value.trim();
    if (!key.startsWith("pxs_")) { status("Cette clé n'a pas le bon format (elle commence par pxs_).", "err"); return; }
    status("Vérification…", "info");
    try {
      const data = await check(key, s.server);
      await api.storage.local.set({ key, lifetimes: data.lifetimes, lifetime: data.default_lifetime });
      status(`C'est bon ✅ Connecté au compte ${data.email}. Jusqu'à ${data.max_mb} Mo par fichier.`, "ok");
    } catch (e) {
      status(e.message || String(e), "err");
    }
  });
  $("forget").addEventListener("click", async () => {
    await api.storage.local.set({ key: "", lifetimes: [], history: [] });
    $("key").value = "";
    status("Clé retirée de ce navigateur.", "info");
  });
}
init();
