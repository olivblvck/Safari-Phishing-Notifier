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

document.addEventListener('DOMContentLoaded', () => {
  // inicjalizacja przycisku szczegółów
  initDetailsToggle();

  chrome.runtime.sendMessage({ type: "GET_ACTIVE_URL" }, (response) => {
    if (!response || !response.ok) {
      showError(response && response.error ? response.error : "Brak danych");
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
    toggleDetailsBtn.addEventListener('click', () => {
      analysisList.classList.toggle('visible');
      toggleDetailsBtn.textContent = analysisList.classList.contains('visible')
        ? 'Ukryj szczegóły analizy'
        : 'Pokaż szczegóły analizy';
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

  let message;
  if (result.status === 'safe') {
    message =
      `✅ Domena <strong>${result.domain}</strong> wygląda typowo. ` +
      `Pamiętaj jednak, by zawsze uważać przy podawaniu danych.`;
  } else if (result.status === 'warning') {
    message =
      `⚠️ Uważaj! Domena <strong>${result.domain}</strong> wygląda nietypowo. ` +
      `Sprawdź ją przed podaniem danych.`;
  } else {
    message =
      `🚨 WYSOKIE RYZYKO! Domena <strong>${result.domain}</strong> wygląda bardzo podejrzanie. ` +
      `NIE podawaj żadnych danych.`;
  }
  warningBox.innerHTML = message;

  const scoreFill = document.getElementById('scoreFill');
  scoreFill.style.width = `${result.score}%`;
  scoreFill.className = `score-fill ${result.color}`;

  const level =
    result.score <= 25 ? 'Niskie ryzyko' :
    result.score <= 60 ? 'Średnie ryzyko' :
                        'Wysokie ryzyko';

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
  btnSafe.textContent = "🔒 Safe Browsing";
  btnSafe.addEventListener('click', () => openSafeBrowsing(result.domain));

  const btnTp = document.createElement('button');
  btnTp.textContent = "⭐ Trustpilot";
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
      btnTrust.textContent = "Usuń z zaufanych";
    } else {
      btnTrust.textContent = "Dodaj do zaufanych";
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

function openSafeBrowsing(domain) {
  chrome.tabs.create({
    url: `https://transparencyreport.google.com/safe-browsing/search?url=${encodeURIComponent(domain)}&hl=pl`
  });
}

function openTrustpilot(domain) {
  chrome.tabs.create({
    url: `https://pl.trustpilot.com/review/${domain}`
  });
}

function showError(message) {
  const errorBox = document.getElementById('error');
  errorBox.classList.remove('hidden');
  document.getElementById('errorMessage').textContent = message;
}
