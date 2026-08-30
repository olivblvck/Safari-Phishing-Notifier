// popup.js – logika popup Safari

let activePageSignals = {};

function getLocalWhitelist() {
  try {
    const raw = localStorage.getItem('spd_local_whitelist');
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

document.addEventListener('DOMContentLoaded', async () => {
  await initI18n();
  initDetailsToggle();

  chrome.runtime.sendMessage({ type: 'GET_ACTIVE_PAGE_CONTEXT' }, (response) => {
    if (!response || !response.ok) {
      showError(response?.error || getMessage('errorNoData'));
      return;
    }

    const url = response.url || '';
    activePageSignals = response.signals || {};
    const extra = getLocalWhitelist();
    const effectiveConfig = {
      ...CONFIG,
      whitelist: Array.from(new Set([...CONFIG.whitelist, ...extra]))
    };

    try {
      const checker = new DomainSecurityChecker(effectiveConfig);
      displayResult(checker.checkDomain(url, activePageSignals), url);
    } catch (error) {
      showError(error.message);
    }
  });
});

let toggleDetailsBtn = null;
let analysisList = null;

function initDetailsToggle() {
  toggleDetailsBtn = document.getElementById('toggle-details');
  analysisList = document.getElementById('analysis-details');

  if (toggleDetailsBtn && analysisList) {
    toggleDetailsBtn.textContent = getMessage('toggleShowDetails');
    toggleDetailsBtn.addEventListener('click', () => {
      analysisList.classList.toggle('visible');
      toggleDetailsBtn.textContent = analysisList.classList.contains('visible')
        ? getMessage('toggleHideDetails')
        : getMessage('toggleShowDetails');
    });
  }
}

function displayResult(result, url) {
  document.getElementById('result').classList.remove('hidden');

  const badge = document.getElementById('statusBadge');
  badge.textContent = result.status.toUpperCase();
  badge.className = `status-badge ${result.color}`;

  const warningBox = document.getElementById('warningBox');
  warningBox.className = `warning ${result.color}`;

  const domainHtml = `<strong>${result.domain}</strong>`;
  const message = result.status === 'safe'
    ? getMessage('statusSafe', [domainHtml])
    : result.status === 'warning'
      ? getMessage('statusWarning', [domainHtml])
      : getMessage('statusDanger', [domainHtml]);
  warningBox.innerHTML = message;

  const scoreFill = document.getElementById('scoreFill');
  scoreFill.style.width = `${result.score}%`;
  scoreFill.className = `score-fill ${result.color}`;

  const level = result.score <= 25
    ? getMessage('riskLow')
    : result.score <= 60
      ? getMessage('riskMedium')
      : getMessage('riskHigh');
  document.getElementById('scoreNumber').textContent = `${result.score}/100 • ${level}`;

  if (analysisList && toggleDetailsBtn) {
    const totalDetailPoints = (result.details || []).reduce((sum, detail) => sum + (detail.points || 0), 0);
    if (totalDetailPoints > 0) {
      toggleDetailsBtn.style.display = 'inline-block';
      analysisList.innerHTML = result.details
        .map((detail) => `<li>${detail.reason} <span class="points">(+${detail.points})</span></li>`)
        .join('');
    } else {
      toggleDetailsBtn.style.display = 'none';
      analysisList.innerHTML = '';
    }
  }

  renderButtons(result, url);
}

function renderButtons(result, url) {
  const buttonGroup = document.getElementById('buttons');
  buttonGroup.innerHTML = '';

  const btnVirusTotal = document.createElement('button');
  btnVirusTotal.textContent = '🔎 Sprawdź w VirusTotal';
  btnVirusTotal.addEventListener('click', () => openVirusTotal(result.domain));

  const btnTrustpilot = document.createElement('button');
  btnTrustpilot.textContent = '⭐ ' + getMessage('btnTrustpilot');
  btnTrustpilot.addEventListener('click', () => openTrustpilot(result.domain));

  const btnTrust = document.createElement('button');
  btnTrust.classList.add('secondary-button');
  const parts = result.domain.split('.');
  const bare = parts.length > 2 ? parts.slice(-2).join('.') : result.domain;

  function isTrustedDomain(list) {
    return list.includes(bare);
  }

  function updateTrustButton() {
    btnTrust.textContent = isTrustedDomain(getLocalWhitelist())
      ? getMessage('btnRemoveTrusted')
      : getMessage('btnAddTrusted');
  }

  btnTrust.addEventListener('click', () => {
    const list = getLocalWhitelist();
    const updated = isTrustedDomain(list)
      ? list.filter((domain) => domain !== bare)
      : [...list, bare];
    localStorage.setItem('spd_local_whitelist', JSON.stringify(updated));

    const effectiveConfig = {
      ...CONFIG,
      whitelist: Array.from(new Set([...CONFIG.whitelist, ...updated]))
    };
    const checker = new DomainSecurityChecker(effectiveConfig);
    updateTrustButton();
    displayResult(checker.checkDomain(url, activePageSignals), url);
  });

  updateTrustButton();
  buttonGroup.appendChild(btnVirusTotal);
  buttonGroup.appendChild(btnTrustpilot);
  buttonGroup.appendChild(btnTrust);
}

function getEffectiveLanguage() {
  return new Promise((resolve) => {
    chrome.storage.local.get(['spd_language'], (data) => {
      const lang = data.spd_language;
      resolve(lang && lang !== 'auto' ? lang : chrome.i18n.getUILanguage().split('-')[0]);
    });
  });
}

function openVirusTotal(domain) {
  chrome.tabs.create({
    url: `https://www.virustotal.com/gui/domain/${encodeURIComponent(domain)}`
  });
}

async function openTrustpilot(domain) {
  const lang = await getEffectiveLanguage();
  const trustpilotLangs = ['pl', 'de', 'fr', 'it', 'es', 'sv', 'no', 'fi'];
  const subdomain = trustpilotLangs.includes(lang) ? `${lang}.` : '';
  chrome.tabs.create({ url: `https://${subdomain}trustpilot.com/review/${domain}` });
}

document.getElementById('open-settings')?.addEventListener('click', () => {
  chrome.runtime.openOptionsPage();
});
