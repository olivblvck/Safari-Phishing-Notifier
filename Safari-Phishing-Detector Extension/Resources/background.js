// background.js – minimalny helper

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message && message.type === "GET_ACTIVE_URL") {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (!tabs || !tabs.length) {
        sendResponse({ ok: false, error: "Brak aktywnej karty" });
        return;
      }
      const url = tabs[0].url || "";
      sendResponse({ ok: true, url });
    });
    return true; // async
  }
});
