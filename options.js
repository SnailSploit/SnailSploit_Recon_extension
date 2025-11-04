
(async()=>{
  const vtEl=document.getElementById("vt");
  const openaiEl=document.getElementById("openai");
  const init=await chrome.storage.local.get(["vtApiKey", "openaiApiKey"]);
  if(init.vtApiKey) vtEl.value=init.vtApiKey;
  if(init.openaiApiKey) openaiEl.value=init.openaiApiKey;

  document.getElementById("save").onclick=async()=>{
    await chrome.storage.local.set({
      vtApiKey: vtEl.value.trim(),
      openaiApiKey: openaiEl.value.trim()
    });
    alert("Saved successfully!");
  };

  document.getElementById("clear").onclick=async()=>{
    await chrome.storage.local.remove(["vtApiKey", "openaiApiKey"]);
    vtEl.value="";
    openaiEl.value="";
    alert("All API keys cleared");
  };
})();
