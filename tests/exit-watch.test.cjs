const test = require('node:test');
const assert = require('node:assert/strict');
const { createExitMonitor, validateExit } = require('../src/exit-watch.cjs');

test('only the configured IP and US country pass exit validation', () => {
  assert.equal(validateExit({ ip: '1.2.3.4', country: 'US' }, '1.2.3.4').ip, '1.2.3.4');
  for (const result of [{ ip: '1.2.3.5', country: 'US' }, { ip: '1.2.3.4', country: 'CN' }, { ip: 'bad', country: 'US' }]) {
    assert.throws(() => validateExit(result, '1.2.3.4'));
  }
  assert.throws(() => createExitMonitor({ expectedIp: '', probe() {} }));
});

test('periodic probe mismatch runs the fail-closed callback and ends monitoring', async t => {
  let probes = 0;
  let passes = 0;
  let failed;
  const stopped = new Promise(resolve => failed = resolve);
  const monitor = createExitMonitor({ expectedIp: '1.2.3.4', intervalMs: 15,
    probe: async () => ({ ip: ++probes === 1 ? '1.2.3.4' : '5.6.7.8', country: 'US' }),
    onVerified: () => passes++, onFailure: error => failed(error),
  });
  t.after(() => monitor.stop());
  await monitor.check();
  const error = await stopped;
  assert.match(error.message, /不一致/);
  assert.equal(passes, 1);
  assert.equal(probes, 2);
  assert.equal(monitor.active, false);
});

test('probe failure is awaited before rejection and cannot silently leave traffic active', async () => {
  let closed = false;
  const monitor = createExitMonitor({ expectedIp: '1.2.3.4', probe: async () => { throw new Error('offline'); },
    onFailure: async () => { await Promise.resolve(); closed = true; },
  });
  await assert.rejects(monitor.check(), /offline/);
  assert.equal(closed, true);
  assert.equal(monitor.active, false);
});

test('stop aborts a running probe and discards its late successful result', async () => {
  let finish;
  let signal;
  let verified = 0;
  const monitor = createExitMonitor({ expectedIp: '1.2.3.4',
    probe: s => { signal = s; return new Promise(resolve => finish = resolve); },
    onVerified: () => verified++,
  });
  const pending = monitor.check();
  monitor.stop();
  assert.equal(signal.aborted, true);
  finish({ ip: '1.2.3.4', country: 'US' });
  await assert.rejects(pending, /取消/);
  assert.equal(verified, 0);
});
