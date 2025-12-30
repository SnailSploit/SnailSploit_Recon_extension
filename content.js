
// Content script - Extracts page resources and DOM hints for security analysis
// Runs on every page to collect: scripts, meta tags, favicon, HTML samples, and resource paths
(function(){
  const abs = (u) => { try { return new URL(u, location.href).href; } catch { return null; } };
  const state = { external: new Set(), inline: [], favicon: null, meta: {}, domHints: { paths: [] }, htmlSample: null, storage: null, lastSent: 0 };

  // Capture current page state: scripts, meta tags, links, favicon, and HTML sample
  function snapshot(){
    try {
      document.querySelectorAll('script').forEach(s => {
        if (s.src) { const u = abs(s.src); if (u) state.external.add(u); }
        else if (s.textContent && s.textContent.length > 20) {
          if (state.inline.length < 16) state.inline.push(s.textContent.slice(0, 20000));
        }
      });
      const gen = document.querySelector('meta[name="generator"]');
      const mcsp = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
      state.meta = {
        generator: gen ? (gen.content || "").slice(0,160) : null,
        metaCSP: mcsp ? (mcsp.content || "").slice(0,500) : null
      };
      const urls = [
        ...Array.from(document.querySelectorAll('link[href]')).map(x=>abs(x.getAttribute('href'))),
        ...Array.from(document.querySelectorAll('script[src]')).map(x=>abs(x.getAttribute('src')))
      ].filter(Boolean).slice(0,200);
      state.domHints.paths = urls.map(u => { try { return new URL(u).pathname; } catch { return null; } }).filter(Boolean);
      if (!state.favicon) {
        const icon = document.querySelector('link[rel~="icon"]');
        state.favicon = icon && icon.href ? abs(icon.href) : abs('/favicon.ico');
      }
      // Capture HTML sample for intel extraction (emails, comments, forms, etc.)
      if (!state.htmlSample && document.documentElement) {
        state.htmlSample = document.documentElement.outerHTML.slice(0, 100000); // 100KB limit
      }
      // Extract localStorage and sessionStorage for security analysis
      if (!state.storage) {
        const storage = { localStorage: {}, sessionStorage: {} };
        try {
          for (let i = 0; i < localStorage.length && i < 50; i++) {
            const key = localStorage.key(i);
            if (key) storage.localStorage[key] = String(localStorage.getItem(key)).slice(0, 500);
          }
        } catch {}
        try {
          for (let i = 0; i < sessionStorage.length && i < 50; i++) {
            const key = sessionStorage.key(i);
            if (key) storage.sessionStorage[key] = String(sessionStorage.getItem(key)).slice(0, 500);
          }
        } catch {}
        state.storage = storage;
      }
    } catch {}
  }

  // Send page resources to service worker (throttled to avoid spam)
  function send(throttleMs=500){
    const now = Date.now();
    if (now - state.lastSent < throttleMs) return;
    state.lastSent = now;
    chrome.runtime.sendMessage({
      type: "pageResources",
      url: location.href,
      externalScripts: Array.from(state.external).slice(0, 100),
      inlineScripts: state.inline.slice(0, 16),
      favicon: state.favicon,
      meta: state.meta,
      domHints: state.domHints,
      htmlSample: state.htmlSample,
      storage: state.storage
    });
  }

  try {
    snapshot(); send(0);
    const mo = new MutationObserver(() => { snapshot(); send(300); });
    mo.observe(document.documentElement, { childList: true, subtree: true });
    setTimeout(()=>mo.disconnect(), 10000);
  } catch (e) {
    chrome.runtime.sendMessage({ type: "pageResources", error: String(e) });
  }
})();
