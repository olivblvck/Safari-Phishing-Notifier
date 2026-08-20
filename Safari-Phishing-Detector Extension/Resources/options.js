//
//  options.js
//  Safari-Phishing-Detector
//
//  Created by Oliwia on 15/07/2026.
//

const select = document.getElementById('language-select');
const status = document.getElementById('status');

chrome.storage.local.get(['spd_language'], (data) => {
  select.value = data.spd_language || 'auto';
});

select.addEventListener('change', () => {
  const lang = select.value;
  chrome.storage.local.set({ spd_language: lang }, () => {
    status.classList.add('visible');
    setTimeout(() => status.classList.remove('visible'), 1500);
  });
});
