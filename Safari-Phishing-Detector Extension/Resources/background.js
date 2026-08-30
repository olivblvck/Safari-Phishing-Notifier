// background.js

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || !['GET_ACTIVE_URL', 'GET_ACTIVE_PAGE_CONTEXT'].includes(message.type)) return;

  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs && tabs[0];
    if (!tab) {
      sendResponse({ ok: false, error: 'Brak aktywnej karty' });
      return;
    }

    const url = tab.url || '';
    if (message.type === 'GET_ACTIVE_URL' || !tab.id) {
      sendResponse({ ok: true, url });
      return;
    }

    chrome.tabs.sendMessage(tab.id, { type: 'GET_PAGE_RISK_SIGNALS' }, (response) => {
      const messageError = chrome.runtime.lastError;
      sendResponse({
        ok: true,
        url,
        signals: !messageError && response?.ok ? response.signals : {}
      });
    });
  });

  return true;
});
