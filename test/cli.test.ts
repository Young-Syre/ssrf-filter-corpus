import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const CLI = fileURLToPath(new URL('../src/cli.js', import.meta.url));

interface Run {
  code: number;
  stdout: string;
  stderr: string;
}

/**
 * Run the built CLI. Async deliberately: spawnSync blocks the event loop,
 * which matters the moment a test in this file needs to serve anything.
 */
function run(args: readonly string[]): Promise<Run> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk: string) => (stdout += chunk));
    child.stderr.on('data', (chunk: string) => (stderr += chunk));
    child.on('error', reject);
    child.on('close', (code) => resolve({ code: code ?? -1, stdout, stderr }));
  });
}

test('a misspelled option is an error, not a silently ignored flag', async () => {
  // --categry used to be collected as a flag and its value left as an ignored
  // positional, so this printed the whole corpus and exited 0 -- which reads
  // exactly like a filtered result.
  const result = await run(['list', '--categry', 'ipv6-ula']);
  assert.equal(result.code, 2);
  assert.match(result.stderr, /unknown option --categry/);
  assert.match(result.stderr, /did you mean --category/);
  assert.equal(result.stdout, '');
});

test('a misspelled option in --name=value form is an error too', async () => {
  const result = await run(['self-test', '--categoryy=scheme']);
  assert.equal(result.code, 2);
  assert.match(result.stderr, /unknown option --categoryy/);
});

test('a known option is still accepted in both forms', async () => {
  for (const args of [
    ['list', '--category', 'ipv6-ula'],
    ['list', '--category=ipv6-ula'],
  ]) {
    const result = await run(args);
    assert.equal(result.code, 0, result.stderr);
    assert.match(result.stdout, /ipv6-ula/);
    assert.doesNotMatch(result.stdout, /ipv4-decimal/, 'the filter was applied');
  }
});

test('--block-on status: rejects an empty or out-of-range code', async () => {
  // Number('') is 0 and 0 is an integer, so `status:` built a rule that
  // matched nothing and every blocking entry was reported as a bypass.
  for (const rule of ['status:', 'status:403,', 'status:0', 'status:99', 'status:600', 'status:abc']) {
    const result = await run(['probe', '--target', 'https://x.invalid/?u={{URL}}', '--yes', '--block-on', rule]);
    assert.equal(result.code, 2, `${rule} should be rejected: ${result.stdout}`);
    assert.match(result.stderr, /--block-on status:/);
  }
});

test('--block-on body: rejects a regex that will not compile', async () => {
  const result = await run(['probe', '--target', 'https://x.invalid/?u={{URL}}', '--yes', '--block-on', 'body:[']);
  assert.equal(result.code, 2);
  assert.match(result.stderr, /invalid regex/);
});

test('probe refuses to send anything without --yes', async () => {
  const result = await run(['probe', '--target', 'https://x.invalid/?u={{URL}}']);
  assert.equal(result.code, 2);
});

test('self-test scores the reference filter at 100% and exits 0', async () => {
  const result = await run(['self-test']);
  assert.equal(result.code, 0, result.stderr);
  assert.match(result.stdout, /\(100%\)/);
  assert.match(result.stdout, /0 bypasses\s+0 over-blocks\s+0 errors/);
});

test('every scheme-category entry is blocked by the reference filter', async () => {
  const result = await run(['self-test', '--category', 'scheme', '--json']);
  assert.equal(result.code, 0, result.stderr);
  const report = JSON.parse(result.stdout) as { bypasses: unknown[]; overBlocks: unknown[] };
  assert.deepEqual(report.bypasses, []);
  assert.deepEqual(report.overBlocks, []);
});
