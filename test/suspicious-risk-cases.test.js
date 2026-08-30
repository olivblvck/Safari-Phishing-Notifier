const test = require('node:test');
const assert = require('node:assert/strict');
const engine = require('../Safari-Phishing-Detector Extension/Resources/risk-engine.js');

global.chrome = {
  i18n: {
    getMessage: (key) => key
  }
};
const DomainSecurityChecker = require('../Safari-Phishing-Detector Extension/Resources/security-checker.js');

const trustedDomains = ['microsoft.com', 'google.com', 'github.com'];

function hasSignal(result, group, id) {
  return result.signals[group].some((signal) => signal.id === id);
}

test('marks rnicrosoft.com as a warning without visiting it', () => {
  const result = engine.analyse('https://rnicrosoft.com/', {}, { trustedDomains });
  assert.equal(result.status, 'warning');
  assert.equal(result.score, 45);
  assert.ok(hasSignal(result, 'strong', 'visual-lookalike'));
});

test('marks g00gle.com as a warning without visiting it', () => {
  const result = engine.analyse('https://g00gle.com/', {}, { trustedDomains });
  assert.equal(result.status, 'warning');
  assert.equal(result.score, 45);
  assert.ok(hasSignal(result, 'strong', 'visual-lookalike'));
});

test('marks a Microsoft lookalike collecting a password as danger', () => {
  const result = engine.analyse(
    'https://rnicrosoft.com/login',
    { hasPasswordForm: true },
    { trustedDomains }
  );
  assert.equal(result.status, 'danger');
  assert.equal(result.score, 65);
  assert.ok(hasSignal(result, 'strong', 'visual-lookalike'));
  assert.ok(hasSignal(result, 'strong', 'password-form'));
});

test('marks an IP-address host collecting a password as danger', () => {
  const result = engine.analyse(
    'https://192.0.2.1/login',
    { hasPasswordForm: true },
    { trustedDomains }
  );
  assert.equal(result.status, 'danger');
  assert.equal(result.score, 45);
  assert.ok(hasSignal(result, 'strong', 'ip-host'));
  assert.ok(hasSignal(result, 'strong', 'password-form'));
});

test('marks a Punycode host collecting a password as danger', () => {
  const result = engine.analyse(
    'https://xn--e1afmkfd.xn--p1ai/login',
    { hasPasswordForm: true },
    { trustedDomains }
  );
  assert.equal(result.status, 'danger');
  assert.ok(hasSignal(result, 'strong', 'punycode'));
  assert.ok(hasSignal(result, 'strong', 'password-form'));
});

test('marks a seed phrase prompt as danger regardless of URL', () => {
  const result = engine.analyse(
    'https://example.test/wallet',
    { hasSeedPhraseField: true },
    { trustedDomains }
  );
  assert.equal(result.status, 'danger');
  assert.equal(result.score, 100);
  assert.ok(hasSignal(result, 'critical', 'seed-phrase'));
});

test('marks a private key prompt as danger regardless of URL', () => {
  const result = engine.analyse(
    'https://example.test/connect',
    { hasPrivateKeyField: true },
    { trustedDomains }
  );
  assert.equal(result.status, 'danger');
  assert.equal(result.score, 100);
  assert.ok(hasSignal(result, 'critical', 'private-key'));
});

test('does not mark an unusual TLD as dangerous by itself', () => {
  const result = engine.analyse('https://example.zip/', {}, { trustedDomains });
  assert.equal(result.status, 'safe');
  assert.equal(result.score, 5);
  assert.ok(hasSignal(result, 'weak', 'unusual-tld'));
});

test('does not let a whitelist override a seed phrase danger signal', () => {
  const checker = new DomainSecurityChecker({ whitelist: ['example.com'] });
  const result = checker.checkDomain(
    'https://example.com/restore-wallet',
    { hasSeedPhraseField: true }
  );
  assert.equal(result.status, 'danger');
  assert.equal(result.color, 'red');
  assert.ok(result.details.some((detail) => detail.reason.includes('recovery or seed phrase')));
});
