(() => {
  'use strict';

  const runtime = globalThis.browser?.runtime || globalThis.chrome?.runtime;
  if (!runtime) return;

  const SECRET_TERMS = [
    'seed phrase', 'recovery phrase', 'secret phrase', 'mnemonic',
    'private key', 'seed words', 'fraza odzyskiwania', 'fraza seed',
    'klucz prywatny'
  ];
  const WALLET_TERMS = [
    'connect wallet', 'walletconnect', 'metamask', 'connect your wallet',
    'połącz portfel', 'podłącz portfel'
  ];

  function fieldMetadata(field) {
    const labelledBy = field.getAttribute('aria-labelledby');
    const labelledText = labelledBy
      ? labelledBy.split(/\s+/).map((id) => document.getElementById(id)?.textContent || '').join(' ')
      : '';
    const parentText = field.closest('label, form, [role=dialog]')?.innerText || '';

    return [
      field.type, field.name, field.id, field.placeholder, field.autocomplete,
      field.getAttribute('aria-label'), labelledText, parentText.slice(0, 500)
    ].filter(Boolean).join(' ').toLowerCase();
  }

  function includesAny(text, terms) {
    return terms.some((term) => text.includes(term));
  }

  function collectPageSignals() {
    const fields = [...document.querySelectorAll('input, textarea')];
    const metadata = fields.map(fieldMetadata);
    const visibleText = document.body?.innerText?.slice(0, 10000).toLowerCase() || '';

    return {
      hasPasswordForm: fields.some((field) => field.type === 'password'),
      hasSeedPhraseField: metadata.some((text) => includesAny(text, SECRET_TERMS)),
      hasPrivateKeyField: metadata.some((text) => text.includes('private key') || text.includes('klucz prywatny')),
      hasWalletConnect: includesAny(visibleText, WALLET_TERMS),
      hasBrandDomainMismatch: false
    };
  }

  runtime.onMessage.addListener((request) => {
    if (request?.type === 'GET_PAGE_RISK_SIGNALS') {
      return Promise.resolve({ ok: true, signals: collectPageSignals() });
    }
    return undefined;
  });
})();
