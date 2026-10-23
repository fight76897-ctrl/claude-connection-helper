const test = require('node:test');
const assert = require('node:assert/strict');
const { isDesktopCallback } = require('../src/browser.cjs');

test('desktop callback is accepted only from an authenticated Claude or Anthropic origin', () => {
  const callback = 'claude://auth-callback?code=local-test-code';
  assert.equal(isDesktopCallback(callback, 'https://claude.ai/login'), true);
  assert.equal(isDesktopCallback(callback, 'https://console.anthropic.com/login'), true);
  assert.equal(isDesktopCallback(callback, 'https://anthropic.com/'), true);
  for (const source of ['http://claude.ai', 'https://claude.ai.evil.test', 'https://evil.test', 'data:text/html,test', 'about:blank', '', 'https://user:pass@claude.ai']) {
    assert.equal(isDesktopCallback(callback, source), false, source);
  }
});

test('desktop callback never forwards other protocols, credentials or control characters', () => {
  for (const url of ['file:///C:/test.exe', 'cmd://test', 'https://claude.ai/', 'claude:auth-callback', 'claude://', 'claude://user:password@auth', 'claude://auth\r\n-callback', 'not-a-url']) {
    assert.equal(isDesktopCallback(url, 'https://claude.ai'), false, url);
  }
});
