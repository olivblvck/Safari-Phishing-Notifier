const test = require('node:test');
const assert = require('node:assert/strict');
const engine = require('../Safari-Phishing-Detector Extension/Resources/risk-engine.js');

const trustedDomains = ['microsoft.com', 'google.com', 'github.com'];

test('marks a typical known domain as safe', () => {
  const result = engine.analyse('https://www.microsoft.com/en-us/', {}, { trustedDomains });
  assert.equal(result.status, 'safe');
  assert.equal(result.score, 0);
});

test('marks rnicrosoft.com as a visual lookalike warning', () => {
  const result = engine.analyse('https://rnicrosoft.com/', {}, { trustedDomains });
  assert.equal(result.status, 'warning');
  assert.equal(result.score, 45);
  assert.ok(result.signals.strong.some((signal) => signal.id === 'visual-lookalike'));
});

test('marks a visual lookalike with password form as danger', () => {
  const result = engine.analyse(
    'https://rnicrosoft.com/login',
    { hasPasswordForm: true },
    { trustedDomains }
  );
  assert.equal(result.status, 'danger');
  assert.ok(result.signals.strong.some((signal) => signal.id === 'visual-lookalike'));
  assert.ok(result.signals.strong.some((signal) => signal.id === 'password-form'));
});

test('marks a seed phrase prompt as danger', () => {
  const result = engine.analyse('https://example.com/wallet', { hasSeedPhraseField: true }, { trustedDomains });
  assert.equal(result.status, 'danger');
  assert.ok(result.signals.critical.some((signal) => signal.id === 'seed-phrase'));
});

test('does not penalize a trusted source domain without page signals', () => {
  const result = engine.analyse('https://github.com/login', {}, { trustedDomains });
  assert.equal(result.status, 'safe');
  assert.equal(result.score, 0);
});
