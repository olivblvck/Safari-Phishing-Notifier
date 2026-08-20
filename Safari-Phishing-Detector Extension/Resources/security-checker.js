// security-checker.js

class DomainSecurityChecker {
  constructor(config) {
    this.config = config;
  }

  checkDomain(url) {
    const domain = this.extractDomain(url);
    const tld = this.extractTLD(domain);

    // 1. Whitelist – natychmiastowy SAFE
    if (this.config.whitelist &&
        this.config.whitelist.some(d => domain === d || domain.endsWith('.' + d))) {
      return {
        domain,
        status: 'safe',
        score: 0,
        reason: chrome.i18n.getMessage("reasonWhitelisted"),
        color: 'green',
        details: [],
        warning: false
      };
    }

    let score = 25;
    const details = [];

    // bazowy poziom ostrożności
    details.push({
      reason: chrome.i18n.getMessage("detailBaseCaution"),
      points: 25
    });

    // 2. TLD
    const tldCheck = this.checkTLD(tld);
    score += tldCheck.points;
    if (tldCheck.reason) {
      details.push({ reason: tldCheck.reason, points: tldCheck.points });
    }

    // 3. Typosquatting względem whitelist
    const typoCheck = this.checkTyposquatting(domain);
    if (typoCheck.detected) {
      score += typoCheck.points;
      details.push({ reason: typoCheck.reason, points: typoCheck.points });
    }

    // 4. Słowa kluczowe
    const keywordCheck = this.checkKeywords(domain);
    score += keywordCheck.points;
    if (keywordCheck.reason) {
      details.push({ reason: keywordCheck.reason, points: keywordCheck.points });
    }

    // 5. Bonus za combo: literówka + phishingowe słowo
    if (typoCheck.detected && keywordCheck.points > 0) {
      const comboPoints = 20;
      score += comboPoints;
      details.push({
        reason: chrome.i18n.getMessage("detailTypoKeywordCombo"),
        points: comboPoints
      });
    }

    // 6. Długość domeny
    const domainName = domain.split('.')[0];
    if (domainName.length > 30) {
      const longPoints = 15;
      score += longPoints;
      details.push({
        reason: chrome.i18n.getMessage("detailLongDomain"),
        points: longPoints
      });
    }

    score = Math.min(score, 100);

    let status, reason, color;
    if (score <= 25) {
      status = 'safe';
      reason = chrome.i18n.getMessage("reasonSafe");
      color = 'green';
    } else if (score <= 60) {
      status = 'warning';
      reason = chrome.i18n.getMessage("reasonWarning");
      color = 'yellow';
    } else {
      status = 'danger';
      reason = chrome.i18n.getMessage("reasonDanger");
      color = 'red';
    }

    return {
      domain,
      status,
      score,
      reason,
      color,
      details,
      warning: status !== 'safe'
    };
  }

  extractDomain(url) {
    try {
      const urlObj = new URL(url);
      return urlObj.hostname.toLowerCase();
    } catch {
      return url.toLowerCase();
    }
  }

  extractTLD(domain) {
    const parts = domain.split('.');
    return '.' + parts[parts.length - 1];
  }

  checkTLD(tld) {
    const safe = this.config.safe_tlds || [];
    const medium = this.config.medium_risk_tlds || [];
    const high = this.config.high_risk_tlds || [];

    if (safe.includes(tld)) {
      return { points: 0, reason: null };
    }
    if (medium.includes(tld)) {
      return {
        points: 20,
        reason: chrome.i18n.getMessage("tldMediumRisk", [tld])
      };
    }
    if (high.includes(tld)) {
      return {
        points: 40,
        reason: chrome.i18n.getMessage("tldHighRisk", [tld])
      };
    }
    return { points: 10, reason: null };
  }

  checkKeywords(domain) {
    let points = 0;
    let reason = null;

    for (const keyword of this.config.risky_keywords || []) {
      if (domain.includes(keyword)) {
        points += 15;
        reason = chrome.i18n.getMessage("keywordRisky", [keyword]);
        break;
      }
    }

    for (const keyword of this.config.spam_keywords || []) {
      if (domain.includes(keyword) && !reason) {
        points += 10;
        reason = chrome.i18n.getMessage("keywordSpam", [keyword]);
        break;
      }
    }

    return { points, reason };
  }

  levenshteinDistance(s1, s2) {
    const m = s1.length;
    const n = s2.length;
    const dp = Array(m + 1)
      .fill(null)
      .map(() => Array(n + 1).fill(0));

    for (let i = 0; i <= m; i++) dp[i][0] = i;
    for (let j = 0; j <= n; j++) dp[0][j] = j;

    for (let i = 1; i <= m; i++) {
      for (let j = 1; j <= n; j++) {
        if (s1[i - 1] === s2[j - 1]) {
          dp[i][j] = dp[i - 1][j - 1];
        } else {
          dp[i][j] =
            1 +
            Math.min(
              dp[i - 1][j],     // usunięcie
              dp[i][j - 1],     // wstawienie
              dp[i - 1][j - 1]  // zamiana
            );
        }
      }
    }
    return dp[m][n];
  }

  similarityScore(a, b) {
    const dist = this.levenshteinDistance(a, b);
    const maxLen = Math.max(a.length, b.length);
    if (maxLen === 0) return 1;
    return 1 - dist / maxLen; // [0,1]
  }

  hasCommonSubstring(a, b, minLen) {
    for (let i = 0; i <= a.length - minLen; i++) {
      const sub = a.slice(i, i + minLen);
      if (b.includes(sub)) return true;
    }
    return false;
  }

  checkTyposquatting(domain) {
    const domainName = domain.split('.')[0];
    let bestMatch = null;

    const whitelist = this.config.whitelist || [];

    for (const trusted of whitelist) {
      const trustedHost = trusted.toLowerCase();

      // Prawdziwa domena/subdomena z whitelist – już wcześniej jako SAFE
      if (domain === trustedHost || domain.endsWith('.' + trustedHost)) {
        continue;
      }

      const trustedName = trustedHost.split('.')[0];

      // Filtruj bardzo krótkie nazwy
      if (trustedName.length < 5 || domainName.length < 5) {
        continue;
      }

      const score = this.similarityScore(
        domainName.toLowerCase(),
        trustedName.toLowerCase()
      );

      // próg: 0.85 + wspólny substring długości >= 4
      if (score >= 0.85) {
        if (!this.hasCommonSubstring(
          domainName.toLowerCase(),
          trustedName.toLowerCase(),
          4
        )) {
          continue;
        }

        if (!bestMatch || score > bestMatch.score) {
          bestMatch = { trustedHost, trustedName, score };
        }
      }
    }

    if (bestMatch) {
      const points = bestMatch.score > 0.8 ? 60 : 45;
      const reason =
        bestMatch.score > 0.8
          ? chrome.i18n.getMessage("typoImpersonation", [bestMatch.trustedHost])
          : chrome.i18n.getMessage("typoSimilar", [bestMatch.trustedHost]);

      return {
        detected: true,
        points,
        reason
      };
    }

    return { detected: false, points: 0, reason: null };
  }
}

if (typeof module !== 'undefined') {
  module.exports = DomainSecurityChecker;
}
