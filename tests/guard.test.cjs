const test = require('node:test');
const assert = require('node:assert/strict');
const { normalizePaths, buildApplyScript, buildRemoveScript, parseInspection, GROUP, REMOTE_RANGES } = require('../src/guard.cjs');

test('guard rejects relative paths and non executables, preserving a quoted absolute path safely', () => {
  assert.throws(() => normalizePaths(['node.exe']));
  assert.throws(() => normalizePaths(['C:\\tools\\start.cmd']));
  assert.throws(() => normalizePaths([]));
  assert.throws(() => normalizePaths(['C:\\bad\nname.exe']));
  assert.deepEqual(normalizePaths(['C:\\Tools\\app.exe', 'c:\\tools\\app.exe']), ['C:\\Tools\\app.exe']);
  const script = buildApplyScript(["C:\\O'Brien\\app.exe"], 'C:\\result.json');
  assert.ok(script.includes("'C:\\O''Brien\\app.exe'"));
  assert.ok(script.includes('-Direction Outbound -Action Block -Enabled True -Profile Any -Protocol Any'));
  for (const range of REMOTE_RANGES) assert.ok(script.includes(range));
});

test('removal is limited to this application group, never all firewall rules', () => {
  const script = buildRemoveScript('C:\\result.json');
  assert.ok(script.includes(`Get-NetFirewallRule -Group '${GROUP}'`));
  assert.ok(!script.includes('Set-NetFirewallProfile'));
  assert.ok(!script.includes('Disable-NetFirewallProfile'));
});

test('status does not report protection enabled when profiles or local rule policy disallow it', () => {
  assert.equal(parseInspection(JSON.stringify({ profiles: [{ enabled: true, localAllowed: true }], rules: [] })).enabled, false);
  const profiles = [1, 2, 3].map(() => ({ enabled: true, localAllowed: true }));
  assert.equal(parseInspection(JSON.stringify({ profiles, rules: [], serviceRunning: true })).enabled, true);
  profiles[1].enabled = false;
  assert.equal(parseInspection(JSON.stringify({ profiles, rules: [], serviceRunning: true })).enabled, false);
  profiles[1].enabled = true; profiles[2].localAllowed = false;
  assert.equal(parseInspection(JSON.stringify({ profiles, rules: [], serviceRunning: true })).enabled, false);
  assert.throws(() => parseInspection('not json'));
});
