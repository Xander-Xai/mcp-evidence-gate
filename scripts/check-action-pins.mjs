import { promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import YAML from 'yaml';

const HEX_SHA = /^[0-9a-f]{40}$/i;
const LOCAL_REF = /^(?:\.\.\/|\.\/)/;
const EXTERNAL_REF = /^[^/@\s]+\/[^@\s]+@(.+)$/;

export function validateUses(ref, source = 'workflow') {
  if (typeof ref !== 'string' || ref.trim() !== ref || ref.length === 0) {
    return `${source}: uses must be a non-empty scalar`;
  }
  if (LOCAL_REF.test(ref)) return null;
  if (ref.startsWith('docker://')) return `${source}: docker actions are unsupported; pin a supported external Action by full commit SHA`;
  const match = EXTERNAL_REF.exec(ref);
  if (!match) return `${source}: malformed external Action or reusable workflow reference: ${ref}`;
  if (!HEX_SHA.test(match[1])) return `${source}: external reference must use a full 40-character commit SHA: ${ref}`;
  return null;
}

function walk(node, visit, location = '$') {
  if (Array.isArray(node)) {
    node.forEach((value, index) => walk(value, visit, `${location}[${index}]`));
    return;
  }
  if (!node || typeof node !== 'object') return;
  for (const [key, value] of Object.entries(node)) {
    const childLocation = `${location}.${key}`;
    if (key === 'uses') visit(value, childLocation);
    walk(value, visit, childLocation);
  }
}

export function validateWorkflowText(text, source = 'workflow') {
  let document;
  try {
    document = YAML.parseDocument(text, { prettyErrors: true });
    if (document.errors.length > 0) return document.errors.map((error) => `${source}: ${error.message}`);
    const value = document.toJS();
    const errors = [];
    walk(value, (ref, location) => {
      const error = validateUses(ref, `${source}${location}`);
      if (error) errors.push(error);
    });
    return errors;
  } catch (error) {
    return [`${source}: ${error instanceof Error ? error.message : String(error)}`];
  }
}

export async function collectWorkflowFiles(root) {
  const workflowRoot = path.join(root, '.github', 'workflows');
  const files = [];
  async function visitDirectory(directory) {
    const entries = await fs.readdir(directory, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(directory, entry.name);
      if (entry.isDirectory()) await visitDirectory(fullPath);
      else if (entry.isFile() && /\.(?:yml|yaml)$/i.test(entry.name)) files.push(fullPath);
    }
  }
  await visitDirectory(workflowRoot);
  return files;
}

export async function validateWorkflows(root) {
  const errors = [];
  for (const file of await collectWorkflowFiles(root)) {
    const text = await fs.readFile(file, 'utf8');
    errors.push(...validateWorkflowText(text, path.relative(root, file)));
  }
  return errors;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const errors = await validateWorkflows(root);
  if (errors.length > 0) {
    console.error(errors.join('\n'));
    process.exitCode = 1;
  } else {
    console.log('CI action pin validation passed');
  }
}
