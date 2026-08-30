// security-checker.js

class DomainSecurityChecker {
  constructor(config) {
    this.config = config || {};
  }

  checkDomain(url, pageSignals = {}) {
    const domain = this.extractDomain(url);

    if (this.isWhitelisted(domain)) {
      return {
        domain,
        status: 'safe',
        score: 0,
        reason: chrome.i18n.getMessage('reasonWhitelisted'),
        color: 'green',
        details: [],
        warning: false
      };
    }

    if (!globalThis.PhishingRiskEngine) {
      throw new Error('Risk engine is not loaded.');
    }

    const analysis = globalThis.PhishingRiskEngine.analyse(url, pageSignals);
    const color = analysis.status === 'safe' ? 'green' : analysis.status === 'warning' ? 'yellow' : 'red';
    const reasonKey = analysis.status === 'safe'
      ? 'reasonSafe'
      : analysis.status === 'warning'
        ? 'reasonWarning'
        : 'reasonDanger';

    return {
      domain,
      status: analysis.status,
      score: analysis.score,
      reason: chrome.i18n.getMessage(reasonKey),
      color,
      details: [
        ...analysis.signals.critical,
        ...analysis.signals.strong,
        ...analysis.signals.weak
      ].map((signal) => ({ reason: signal.label, points: signal.points })),
      warning: analysis.status !== 'safe'
    };
  }

  extractDomain(url) {
    const normalized = globalThis.PhishingRiskEngine?.normalizeUrl(url);
    return normalized ? normalized.hostname : String(url || '').toLowerCase();
  }

  isWhitelisted(domain) {
    return (this.config.whitelist || []).some((trusted) => {
      const normalized = String(trusted).toLowerCase();
      return domain === normalized || domain.endsWith(`.${normalized}`);
    });
  }
}

if (typeof module !== 'undefined') {
  module.exports = DomainSecurityChecker;
}
