(() => {
  'use strict';

  const SUSPICIOUS_TLDS = new Set(['zip', 'mov', 'click', 'link', 'top', 'xyz', 'country', 'gq', 'tk', 'work', 'support']);
  const VISUAL_ASCII_REPLACEMENTS = [
    [/rn/g, 'm'],
    [/vv/g, 'w'],
    [/0/g, 'o'],
    [/1/g, 'l'],
    [/3/g, 'e']
  ];

  function normalizeUrl(value) {
    try {
      const url = new URL(value);
      url.hash = '';
      url.hostname = url.hostname.toLowerCase().replace(/\.$/, '');
      return url;
    } catch (_) {
      return null;
    }
  }

  function isIpAddress(host) {
    return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(host) || host.includes(':');
  }

  function hasMixedScripts(host) {
    const withoutAscii = host.replace(/[\x00-\x7F]/g, '');
    if (!withoutAscii) return false;
    const scripts = [/[\u0400-\u052F]/, /[\u0370-\u03FF]/, /[\u3040-\u30FF]/, /[\u4E00-\u9FFF]/];
    return scripts.filter((pattern) => pattern.test(host)).length > 1 || /[a-z]/i.test(host);
  }

  function registrableLabel(host) {
    const labels = host.split('.').filter(Boolean);
    return labels.length > 1 ? labels.at(-2) : labels[0] || '';
  }

  function visualSkeleton(label) {
    return VISUAL_ASCII_REPLACEMENTS.reduce(
      (value, [pattern, replacement]) => value.replace(pattern, replacement),
      label.toLowerCase()
    );
  }

  function findVisualLookalike(host, trustedDomains) {
    const candidate = registrableLabel(host);
    const candidateSkeleton = visualSkeleton(candidate);
    if (!candidate || candidate === candidateSkeleton) return null;

    for (const trustedDomain of trustedDomains || []) {
      const trustedUrl = normalizeUrl(`https://${String(trustedDomain).replace(/^https?:\/\//, '')}`);
      if (!trustedUrl) continue;
      const trustedLabel = registrableLabel(trustedUrl.hostname);
      if (candidate !== trustedLabel && candidateSkeleton === trustedLabel) {
        return trustedUrl.hostname;
      }
    }
    return null;
  }

  function addSignal(bucket, id, label, points) {
    bucket.push({ id, label, points });
  }

  function analyse(urlValue, pageSignals = {}, options = {}) {
    const url = normalizeUrl(urlValue);
    const result = {
      status: 'safe',
      score: 0,
      url: url ? url.href : String(urlValue || ''),
      signals: { critical: [], strong: [], weak: [] },
      reasons: []
    };

    if (!url) {
      addSignal(result.signals.strong, 'invalid-url', 'The page URL is malformed.', 25);
      return finalize(result);
    }

    const host = url.hostname;
    const labels = host.split('.').filter(Boolean);
    const tld = labels.at(-1) || '';

    if (pageSignals.hasSeedPhraseField) addSignal(result.signals.critical, 'seed-phrase', 'This page requests a recovery or seed phrase.', 100);
    if (pageSignals.hasPrivateKeyField) addSignal(result.signals.critical, 'private-key', 'This page requests a private key.', 100);
    if (pageSignals.hasExactKnownPhishingUrl) addSignal(result.signals.critical, 'exact-match', 'This exact URL is marked as phishing by a local rule.', 100);

    const lookalikeOf = findVisualLookalike(host, options.trustedDomains);
    if (lookalikeOf) addSignal(result.signals.strong, 'visual-lookalike', `The domain visually imitates ${lookalikeOf}.`, 45);
    if (host.startsWith('xn--') || host.includes('.xn--')) addSignal(result.signals.strong, 'punycode', 'The domain uses Punycode.', 30);
    if (hasMixedScripts(host)) addSignal(result.signals.strong, 'mixed-script', 'The domain mixes writing systems.', 30);
    if (isIpAddress(host)) addSignal(result.signals.strong, 'ip-host', 'The page is hosted directly on an IP address.', 25);
    if (pageSignals.hasPasswordForm) addSignal(result.signals.strong, 'password-form', 'The page contains a password form.', 20);
    if (pageSignals.hasWalletConnect) addSignal(result.signals.strong, 'wallet-connect', 'The page asks to connect a crypto wallet.', 20);
    if (pageSignals.hasBrandDomainMismatch) addSignal(result.signals.strong, 'brand-mismatch', 'The claimed brand does not match the website domain.', 30);

    if (SUSPICIOUS_TLDS.has(tld)) addSignal(result.signals.weak, 'unusual-tld', 'The domain uses a higher-risk top-level domain.', 5);
    if (labels.length > 4) addSignal(result.signals.weak, 'many-subdomains', 'The URL has an unusually deep subdomain structure.', 4);
    if (host.length > 45) addSignal(result.signals.weak, 'long-domain', 'The domain name is unusually long.', 3);
    if ((host.match(/-/g) || []).length >= 3) addSignal(result.signals.weak, 'many-hyphens', 'The domain contains many hyphens.', 3);

    return finalize(result);
  }

  function finalize(result) {
    const allSignals = Object.values(result.signals).flat();
    result.score = Math.min(100, allSignals.reduce((total, signal) => total + signal.points, 0));
    result.reasons = allSignals.map((signal) => signal.label);

    const hasVisualLookalike = result.signals.strong.some((signal) => signal.id === 'visual-lookalike');
    if (result.signals.critical.length > 0 || result.signals.strong.length >= 2) {
      result.status = 'danger';
    } else if (hasVisualLookalike || (result.signals.strong.length >= 1 && result.signals.weak.length >= 2) || result.score >= 45) {
      result.status = 'warning';
    }

    return result;
  }

  const api = Object.freeze({ analyse, normalizeUrl });
  globalThis.PhishingRiskEngine = api;
  if (typeof module !== 'undefined') module.exports = api;
})();
