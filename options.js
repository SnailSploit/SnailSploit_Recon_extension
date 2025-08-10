
(async()=>{
  const vtEl=document.getElementById("vt"); const init=await chrome.storage.local.get(["vtApiKey"]); if(init.vtApiKey) vtEl.value=init.vtApiKey;
  document.getElementById("save").onclick=async()=>{ await chrome.storage.local.set({ vtApiKey: vtEl.value.trim() }); alert("Saved"); };
  document.getElementById("clear").onclick=async()=>{ await chrome.storage.local.remove(["vtApiKey"]); vtEl.value=""; alert("Cleared"); };
})();
