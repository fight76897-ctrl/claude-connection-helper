const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { buildProxyEnv, powershellCommand, detectApps, desktopProxyArgs, hasRunningExecutable, refreshInstalledApps, readAppVersions } = require('../src/launchers.cjs');

test('launcher replaces conflicting proxy variables and only bypasses local callbacks', () => {
  const env = buildProxyEnv({ https_proxy: 'http://wrong:88', HTTP_PROXY: 'http://wrong:90',
    ALL_PROXY: 'socks5://wrong:99', no_proxy: '*', NO_PROXY: '.anthropic.com',
    PATH: 'keep-path', ANTHROPIC_API_KEY: 'keep-existing-key', ELECTRON_RUN_AS_NODE: '1',
  }, 17861);
  assert.equal(env.HTTPS_PROXY, 'http://127.0.0.1:17861');
  assert.equal(env.HTTP_PROXY, 'http://127.0.0.1:17861');
  assert.equal(env.NO_PROXY, 'localhost,127.0.0.1,::1');
  assert.equal(env.https_proxy, undefined);
  assert.equal(env.ALL_PROXY, undefined);
  assert.equal(env.ELECTRON_RUN_AS_NODE, undefined);
  assert.equal(env.PATH, 'keep-path');
  assert.equal(env.ANTHROPIC_API_KEY, 'keep-existing-key');
});

test('launcher escapes PowerShell metacharacters in filesystem paths without interpolation', () => {
  const command = powershellCommand("C:\\O'Brien\\claude.cmd", "E:\\a'b $x; $(whoami)");
  assert.match(command, /Set-Location -LiteralPath 'E:\\a''b \$x; \$\(whoami\)'/);
  assert.match(command, /& 'C:\\O''Brien\\claude.cmd'/);
});

test('discovers official Desktop and versioned Science installations and honors selected executables', t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'claude-launchers-'));
  const original = { LOCALAPPDATA: process.env.LOCALAPPDATA, USERPROFILE: process.env.USERPROFILE, PATH: process.env.PATH };
  t.after(() => {
    Object.assign(process.env, original);
    fs.rmSync(root, { recursive: true, force: true });
  });
  process.env.LOCALAPPDATA = path.join(root, 'local');
  process.env.USERPROFILE = path.join(root, 'home');
  process.env.PATH = path.join(root, 'bin');
  const make = file => { fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, 'fixture'); return file; };
  make(path.join(process.env.LOCALAPPDATA, 'AnthropicClaude', 'app-1.9.0', 'claude.exe'));
  const desktop = make(path.join(process.env.LOCALAPPDATA, 'AnthropicClaude', 'app-1.10.0', 'claude.exe'));
  const science = make(path.join(process.env.USERPROFILE, '.claude-science', 'electron', '42.10.0', 'claude-science.exe'));
  const code = make(path.join(process.env.PATH, 'claude.cmd'));
  assert.deepEqual(detectApps(), { browser: process.execPath, desktop, code, science });
  const selected = make(path.join(root, 'selected', 'claude.exe'));
  assert.equal(detectApps({ desktop: selected }).desktop, selected);
});

test('desktop Chromium arguments force the helper proxy and disable QUIC', () => {
  assert.deepEqual(desktopProxyArgs(17861), [
    '--proxy-server=http://127.0.0.1:17861',
    '--proxy-bypass-list=localhost;127.0.0.1;[::1]',
    '--disable-quic',
  ]);
});

test('running Desktop check compares full paths so a Claude Code executable cannot match', () => {
  const desktop = 'C:\\Users\\Test\\AppData\\Local\\AnthropicClaude\\app-1.0\\claude.exe';
  const processes = [{ ExecutablePath: 'C:\\Users\\Test\\.local\\bin\\claude.exe' }];
  assert.equal(hasRunningExecutable(processes, desktop), false);
  processes.push({ ExecutablePath: desktop.toUpperCase() });
  assert.equal(hasRunningExecutable(processes, desktop), true);
  assert.equal(hasRunningExecutable([{ ExecutablePath: null }], desktop), false);
});

test('refresh tracks replacement MSIX version paths without retaining the old preferred version', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'claude-msix-'));
  t.after(async () => { await refreshInstalledApps(async () => ({ stdout: '[]' })); fs.rmSync(root, { recursive: true, force: true }); });
  const make = version => {
    const directory = path.join(root, `Claude_${version}`);
    fs.mkdirSync(path.join(directory, 'app'), { recursive: true });
    fs.writeFileSync(path.join(directory, 'app', 'Claude.exe'), 'fixture');
    return directory;
  };
  const first = make('1.0');
  const updated = make('2.0');
  await refreshInstalledApps(async () => ({ stdout: JSON.stringify(first) }));
  assert.equal(detectApps().desktop, path.join(first, 'app', 'Claude.exe'));
  await refreshInstalledApps(async () => ({ stdout: JSON.stringify(updated) }));
  assert.equal(detectApps().desktop, path.join(updated, 'app', 'Claude.exe'));
});

test('executable versions read only selected Desktop and Science paths as PowerShell literals', async () => {
  const desktop = "C:\\O'Brien $x; $(whoami)\\Claude.exe";
  const science = 'C:\\Tools\\Claude Science\\claude-science.exe';
  let calls = 0;
  const versions = await readAppVersions({ desktop, science, code: 'C:\\private-code.exe', browser: process.execPath }, async (executable, args, options) => {
    calls++;
    assert.equal(executable, 'powershell.exe');
    assert.equal(options.windowsHide, true);
    const script = Buffer.from(args.at(-1), 'base64').toString('utf16le');
    assert.ok(script.includes("-LiteralPath 'C:\\O''Brien $x; $(whoami)\\Claude.exe'"));
    assert.ok(script.includes("-LiteralPath 'C:\\Tools\\Claude Science\\claude-science.exe'"));
    assert.ok(script.includes('VersionInfo'));
    assert.equal(script.includes('private-code.exe'), false);
    assert.doesNotMatch(script, /Start-Process|CommandLine|Environment/);
    return { stdout: '\uFEFF' + JSON.stringify({ desktop: { product: ' 1.2.3+build4 ', file: '1.2.3.0' }, science: { product: '', file: '42.10.0' } }) };
  });
  assert.equal(calls, 1);
  assert.deepEqual(versions, { desktop: '1.2.3+build4', science: '42.10.0' });
});

test('missing or unreadable executable version metadata remains unknown', async () => {
  assert.deepEqual(await readAppVersions({}, async () => { assert.fail('No process should be started without selected executables'); }), { desktop: null, science: null });
  assert.deepEqual(await readAppVersions({ desktop: 'relative.exe', science: 'https://example.com/science.exe' }, async () => { assert.fail('Relative paths and URLs must not be inspected'); }), { desktop: null, science: null });
  const apps = { desktop: 'C:\\Claude\\Claude.exe', science: 'C:\\Science\\claude-science.exe' };
  assert.deepEqual(await readAppVersions(apps, async () => ({ stdout: '{}' })), { desktop: null, science: null });
  assert.deepEqual(await readAppVersions(apps, async () => { throw new Error('No metadata'); }), { desktop: null, science: null });
});

test('version metadata rejects unbounded text and control characters while accepting a valid fallback', async () => {
  const apps = { desktop: 'C:\\Claude\\Claude.exe', science: 'C:\\Science\\claude-science.exe' };
  const versions = await readAppVersions(apps, async () => ({ stdout: JSON.stringify({
    desktop: { product: '1.2.3\nsecret', file: '1.2.3.0' },
    science: { product: '1'.repeat(100), file: 'Authorization: secret' },
  }) }));
  assert.deepEqual(versions, { desktop: '1.2.3.0', science: null });
});
