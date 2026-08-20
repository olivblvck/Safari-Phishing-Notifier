// popup.js – logika popup Safari

// --- lokalna whitelist w localStorage ---

function getLocalWhitelist() {
  try {
    const raw = localStorage.getItem('spd_local_whitelist');
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

// --- główne wejście ---

document.addEventListener('DOMContentLoaded', async () => {
  await initI18n();
  initDetailsToggle();

  chrome.runtime.sendMessage({ type: "GET_ACTIVE_URL" }, (response) => {
    if (!response || !response.ok) {
      showError(response && response.error ? response.error : getMessage("errorNoData"));
      return;
    }

    const url = response.url || "";

    const extra = getLocalWhitelist();
    const effectiveConfig = {
      ...CONFIG,
      whitelist: Array.from(new Set([...CONFIG.whitelist, ...extra]))
    };

    try {
      const checker = new DomainSecurityChecker(effectiveConfig);
      const result = checker.checkDomain(url);
      displayResult(result, url);
    } catch (e) {
      showError(e.message);
    }
  });
});

// --- przycisk i lista szczegółów ---

let toggleDetailsBtn = null;
let analysisList = null;

function initDetailsToggle() {
  toggleDetailsBtn = document.getElementById('toggle-details');
  analysisList = document.getElementById('analysis-details');

  if (toggleDetailsBtn && analysisList) {
    toggleDetailsBtn.textContent = getMessage("toggleShowDetails");

    toggleDetailsBtn.addEventListener('click', () => {
      analysisList.classList.toggle('visible');
      toggleDetailsBtn.textContent = analysisList.classList.contains('visible')
        ? getMessage("toggleHideDetails")
        : getMessage("toggleShowDetails");
    });
  }
}

// --- render wyniku ---

function displayResult(result, url) {
  document.getElementById('result').classList.remove('hidden');

  const badge = document.getElementById('statusBadge');
  badge.textContent = result.status.toUpperCase();
  badge.className = `status-badge ${result.color}`;

  const warningBox = document.getElementById('warningBox');
  warningBox.className = `warning ${result.color}`;

  const domainHtml = `<strong>${result.domain}</strong>`;
  let message;
  if (result.status === 'safe') {
    message = getMessage("statusSafe", [domainHtml]);
  } else if (result.status === 'warning') {
    message = getMessage("statusWarning", [domainHtml]);
  } else {
    message = getMessage("statusDanger", [domainHtml]);
  }
  warningBox.innerHTML = message;

  const scoreFill = document.getElementById('scoreFill');
  scoreFill.style.width = `${result.score}%`;
  scoreFill.className = `score-fill ${result.color}`;

  const level =
    result.score <= 25 ? getMessage("riskLow") :
    result.score <= 60 ? getMessage("riskMedium") :
                          getMessage("riskHigh");

  document.getElementById('scoreNumber').textContent =
    `${result.score}/100 • ${level}`;

  // --- szczegółowa analiza z punktami ---
  if (analysisList && toggleDetailsBtn) {
    const totalDetailPoints = (result.details || [])
      .reduce((sum, d) => sum + (d.points || 0), 0);

    if (totalDetailPoints > 0) {
      toggleDetailsBtn.style.display = 'inline-block';
      analysisList.innerHTML = result.details
        .map(d => `<li>${d.reason} <span class="points">(+${d.points})</span></li>`)
        .join('');
    } else {
      toggleDetailsBtn.style.display = 'none';
      analysisList.innerHTML = '';
    }
  }

  renderButtons(result, url);
}

// --- przyciski ---

function renderButtons(result, url) {
  const buttonGroup = document.getElementById('buttons');
  buttonGroup.innerHTML = "";

  const btnSafe = document.createElement('button');
  btnSafe.textContent = "🔒 " + getMessage("btnSafeBrowsing");
  btnSafe.addEventListener('click', () => openSafeBrowsing(result.domain));

  const btnTp = document.createElement('button');
  btnTp.textContent = "⭐ " + getMessage("btnTrustpilot");
  btnTp.addEventListener('click', () => openTrustpilot(result.domain));

  const btnTrust = document.createElement('button');
  btnTrust.classList.add('secondary-button');

  // „goła” domena do whitelist
  const parts = result.domain.split('.');
  const bare = parts.length > 2 ? parts.slice(-2).join('.') : result.domain;

  function isTrustedDomain(list) {
    return list.includes(bare);
  }

  function updateTrustButton() {
    const list = getLocalWhitelist();
    if (isTrustedDomain(list)) {
      btnTrust.textContent = getMessage("btnRemoveTrusted");
    } else {
      btnTrust.textContent = getMessage("btnAddTrusted");
    }
  }

  btnTrust.addEventListener('click', () => {
    const list = getLocalWhitelist();
    let updated;

    if (isTrustedDomain(list)) {
      updated = list.filter(d => d !== bare);
    } else {
      updated = [...list, bare];
    }
    localStorage.setItem('spd_local_whitelist', JSON.stringify(updated));

    // przelicz wynik z nową konfiguracją
    const effectiveConfig = {
      ...CONFIG,
      whitelist: Array.from(new Set([...CONFIG.whitelist, ...updated]))
    };
    const checker = new DomainSecurityChecker(effectiveConfig);
    const newResult = checker.checkDomain(url);

    updateTrustButton();
    displayResult(newResult, url); // odśwież cały widok
  });

  updateTrustButton();

  buttonGroup.appendChild(btnSafe);
  buttonGroup.appendChild(btnTp);
  buttonGroup.appendChild(btnTrust);
}

// --- akcje pomocnicze ---

function getEffectiveLanguage() {
  return new Promise((resolve) => {
    chrome.storage.local.get(['spd_language'], (data) => {
      const lang = data.spd_language;
      if (lang && lang !== 'auto') {
        resolve(lang);
      } else {
        resolve(chrome.i18n.getUILanguage().split('-')[0]);
      }
    });
  });
}

async function openSafeBrowsing(domain) {
  const lang = await getEffectiveLanguage();
  chrome.tabs.create({
    url: `https://transparencyreport.google.com/safe-browsing/search?url=${encodeURIComponent(domain)}&hl=${lang}`
  });
}

async function openTrustpilot(domain) {
  const lang = await getEffectiveLanguage();
const trustpilotLangs = ['pl', 'de', 'fr', 'it', 'es', 'sv', 'no', 'fi'];
  const subdomain = trustpilotLangs.includes(lang) ? `${lang}.` : '';
  chrome.tabs.create({
    url: `https://${subdomain}trustpilot.com/review/${domain}`
  });
}
// -- ustawienia

document.getElementById('open-settings')?.addEventListener('click', () => {
  chrome.runtime.openOptionsPage();
});
