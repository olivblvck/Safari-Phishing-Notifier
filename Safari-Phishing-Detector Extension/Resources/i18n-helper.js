//
//  i18n-helper.js
//  Safari-Phishing-Detector
//
//  Created by Oliwia on 15/07/2026.
//

// i18n-helper.js – nadpisuje domyślny chrome.i18n wybranym językiem

let customMessages = null;

async function loadCustomMessages(lang) {
  if (lang === 'auto') {
    customMessages = null;
    return;
  }
  try {
    const url = chrome.runtime.getURL(`_locales/${lang}/messages.json`);
    const res = await fetch(url);
    customMessages = await res.json();
  } catch (e) {
    console.warn('Nie udało się wczytać tłumaczenia:', lang, e);
    customMessages = null;
  }
}

function getMessage(key, substitutions) {
  if (customMessages && customMessages[key]) {
    let msg = customMessages[key].message;
    if (substitutions) {
      const subs = Array.isArray(substitutions) ? substitutions : [substitutions];
      subs.forEach((sub, i) => {
        msg = msg.replace(new RegExp(`\\$${i + 1}`, 'g'), sub);
      });
    }
    return msg;
  }
  // fallback do domyślnego systemowego chrome.i18n
  return chrome.i18n.getMessage(key, substitutions);
}

async function initI18n() {
  return new Promise((resolve) => {
    chrome.storage.local.get(['spd_language'], async (data) => {
      const lang = data.spd_language || 'auto';
      await loadCustomMessages(lang);
      resolve();
    });
  });
}
