import test from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateUses, validateWorkflowText, validateWorkflows } from './check-action-pins.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SHA = '0123456789abcdef0123456789abcdef01234567';

test('accepts immutable external and local references', () => {
  assert.equal(validateUses(`actions/checkout@${SHA}`), null);
  assert.equal(validateUses(`org/reusable/.github/workflows/check.yml@${SHA}`), null);
  assert.equal(validateUses('./.github/actions/local'), null);
  assert.equal(validateUses('../shared/action'), null);
  assert.deepEqual(validateWorkflowText(`# uses: actions/checkout@v4\nname: test\njobs: {verify: {runs-on: ubuntu-latest}}`), []);
});

test('rejects mutable, dynamic, malformed, and unsupported references', () => {
  for (const ref of ['actions/checkout@v4', 'actions/checkout@v1', 'actions/checkout@main', 'actions/checkout@master', 'actions/checkout@latest', 'actions/checkout@stable', 'actions/checkout@release', 'actions/checkout@0123456', 'actions/checkout@${{ github.ref }}', 'org/reusable/.github/workflows/check.yml@main', 'actions/checkout', 'docker://alpine:3.20']) {
    assert.notEqual(validateUses(ref), null, ref);
  }
});

test('real Core workflows contain no mutable Action references', async () => {
  assert.deepEqual(await validateWorkflows(root), []);
});

test('CI artifact names use PR head fallback and fail-closed retention settings', async () => {
  const text = await fs.readFile(path.join(root, '.github', 'workflows', 'ci.yml'), 'utf8');
  assert.match(text, /SOURCE_SHA:\s*\$\{\{\s*github\.event\.pull_request\.head\.sha\s*\|\|\s*github\.sha\s*\}\}/);
  assert.match(text, /name:\s*profile-drift-\$\{\{\s*env\.SOURCE_SHA\s*\}\}/);
  assert.match(text, /retention-days:\s*90/);
  assert.match(text, /if-no-files-found:\s*error/);
});
