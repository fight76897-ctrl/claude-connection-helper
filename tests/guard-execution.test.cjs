const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { promisify } = require('node:util');
const { execFile } = require('node:child_process');
const { buildApplyScript, buildRemoveScript, GROUP } = require('../src/guard.cjs');
const run = promisify(execFile);

// Execute the generated PowerShell in a disposable cmdlet fixture. No real firewall
// command is reached; this checks parameter binding, quoting, scope and branching.
async function executeFixture(t, operation, disabled = false) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cch-firewall-test-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const exe = path.join(dir, "O'Brien $(not-a-command).exe");
  fs.writeFileSync(exe, 'fixture only');
  const result = path.join(dir, 'result.json');
  const output = path.join(dir, 'rules.json');
  const quote = value => "'" + value.replaceAll("'", "''") + "'";
  const setup = `
$script:rules = @(@{ Name='unrelated'; Group='OtherApplication'; Program='C:\\other.exe' }, @{ Name='old-cch'; Group='${GROUP}'; Program='C:\\old.exe' })
function Get-Service { param($Name) @{Status='Running'} }
function Get-NetFirewallProfile { param($PolicyStore) 1..3 | ForEach-Object { @{Enabled=$${disabled ? 'false' : 'true'};AllowLocalFirewallRules='True'} } }
function Get-NetFirewallRule { param($Name,$Group,$ErrorAction) $script:rules | Where-Object { if ($Name) { $_.Name -eq $Name } else { $_.Group -eq $Group } } }
function New-NetFirewallRule { param($Name,$DisplayName,$Group,$Direction,$Action,$Enabled,$Profile,$Protocol,$Program,$RemoteAddress)
  $script:rules += @{Name=$Name;Group=$Group;Direction=$Direction;Action=$Action;Enabled=$Enabled;Profile=$Profile;Protocol=$Protocol;Program=$Program;RemoteAddress=$RemoteAddress}
}
function Set-NetFirewallRule { [CmdletBinding()] param($Name,$NewDisplayName,$Direction,$Action,$Enabled,$Profile,$Protocol,$Program,$RemoteAddress)
  $item = $script:rules | Where-Object { $_.Name -eq $Name }
  $item.Program=$Program; $item.Action=$Action; $item.RemoteAddress=$RemoteAddress
}
function Remove-NetFirewallRule { param([Parameter(ValueFromPipeline=$true)]$InputObject) process { $removeName=$InputObject.Name; $script:rules=@($script:rules | Where-Object { $_.Name -ne $removeName }) } }
`;
  let body = operation === 'remove' ? buildRemoveScript(result) : buildApplyScript([exe], result);
  if (operation === 'update') body += '\n' + buildApplyScript([exe], result);
  if (operation === 'recovery') body = `. ${quote(path.resolve(__dirname, '../scripts/restore-network.ps1'))} -Elevated -ResultFile ${quote(result)}`;
  // The production script exits on failure; finally still records the fixture.
  const script = setup + `\ntry {\n${body}\n} finally { ConvertTo-Json -InputObject @($script:rules) -Depth 5 | Set-Content -LiteralPath ${quote(output)} -Encoding UTF8 }`;
  const file = path.join(dir, 'test.ps1');
  fs.writeFileSync(file, '\uFEFF' + script, 'utf8');
  await run('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', file], { windowsHide: true, timeout: 10000 }).catch(error => { if (error.code !== 1) throw error; });
  const read = file => JSON.parse(fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, ''));
  return { exe, result: read(result), rules: read(output) };
}

test('generated apply script creates non-loopback block for exact selected executable and preserves other applications', { skip: process.platform !== 'win32' }, async t => {
  const { exe, result, rules } = await executeFixture(t, 'apply');
  assert.equal(result.ok, true, result.error);
  assert.equal(rules.length, 2);
  assert.equal(rules[0].Name, 'unrelated');
  const created = rules.find(rule => rule.Group === GROUP);
  assert.equal(created.Program, exe);
  assert.equal(created.Action, 'Block');
  assert.equal(created.Direction, 'Outbound');
  assert.equal(created.Protocol, 'Any');
  assert.deepEqual(created.RemoteAddress, ['0.0.0.0-126.255.255.255', '128.0.0.0-255.255.255.255', '::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff']);
});

test('generated remove script deletes only this helper rules', { skip: process.platform !== 'win32' }, async t => {
  const { result, rules } = await executeFixture(t, 'remove');
  assert.equal(result.ok, true);
  assert.deepEqual(rules.map(rule => rule.Name), ['unrelated']);
});

test('applying protection again updates an existing rule with valid Set-NetFirewallRule parameters', { skip: process.platform !== 'win32' }, async t => {
  const { exe, result, rules } = await executeFixture(t, 'update');
  assert.equal(result.ok, true, result.error);
  assert.equal(rules.length, 2);
  assert.equal(rules.find(rule => rule.Group === GROUP).Program, exe);
});

test('generated apply script refuses disabled firewall before changing rules', { skip: process.platform !== 'win32' }, async t => {
  const { result, rules } = await executeFixture(t, 'apply', true);
  assert.equal(result.ok, false);
  assert.deepEqual(rules.map(rule => rule.Name), ['unrelated', 'old-cch']);
});

test('standalone recovery removes helper rules and preserves unrelated rules', { skip: process.platform !== 'win32' }, async t => {
  const { result, rules } = await executeFixture(t, 'recovery');
  assert.equal(result.ok, true, result.error);
  assert.deepEqual(rules.map(rule => rule.Name), ['unrelated']);
});
