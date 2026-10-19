#!/usr/bin/env node
// Builds the E2EE module for the client's worker: node build-wasm.mjs OUT_DIR
// Runs itself inside this repo's nix dev shell when wasm-bindgen is not on PATH and nix is.
import { spawnSync } from 'node:child_process'
import { mkdirSync, readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const repo = dirname(fileURLToPath(import.meta.url))
const script = fileURLToPath(import.meta.url)

function fail(message) {
  console.error(message)
  process.exit(1)
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { stdio: 'inherit', ...options })
  if (result.error) fail(`${command}: ${result.error.message}`)
  if (result.status !== 0) process.exit(result.status ?? 1)
}

// The version line, or null when the command isn't on PATH.
function version(command) {
  const result = spawnSync(command, ['--version'], { encoding: 'utf8' })
  return result.error || result.status !== 0 ? null : result.stdout.trim()
}

if (!process.argv[2]) fail('usage: node build-wasm.mjs OUT_DIR')
const out = resolve(process.argv[2])

// The CLI must match the wasm-bindgen crate in Cargo.lock exactly.
const lock = readFileSync(join(repo, 'Cargo.lock'), 'utf8')
const pinned = lock.match(/name = "wasm-bindgen"\r?\nversion = "([^"]+)"/)?.[1]
if (!pinned) fail('wasm-bindgen is missing from Cargo.lock')
const install = `cargo install wasm-bindgen-cli --version ${pinned} --locked`

const found = version('wasm-bindgen')
if (!found) {
  if (process.env.PYLON_E2EE_IN_DEV_SHELL) fail('wasm-bindgen is missing from the pylon-e2ee dev shell')
  if (process.platform === 'win32' || !version('nix')) {
    fail(`wasm-bindgen is not on PATH. Install it with:\n  ${install}`)
  }
  // path: so the flake works before its files are tracked in git.
  run('nix', ['develop', `path:${repo}`, '--command', process.execPath, script, out], {
    env: { ...process.env, PYLON_E2EE_IN_DEV_SHELL: '1' }
  })
  process.exit(0)
}
if (found !== `wasm-bindgen ${pinned}`) {
  fail(`${found} is on PATH, but Cargo.lock pins ${pinned}. Install the matching CLI with:\n  ${install}`)
}

mkdirSync(out, { recursive: true })
run('cargo', [
  'build',
  '--manifest-path',
  join(repo, 'Cargo.toml'),
  '--target-dir',
  join(repo, 'target'),
  '--features',
  'wasm',
  '--target',
  'wasm32-unknown-unknown',
  '--release'
])

run('wasm-bindgen', [
  '--target',
  'web',
  '--out-dir',
  out,
  '--out-name',
  'pylon_e2ee',
  join(repo, 'target', 'wasm32-unknown-unknown', 'release', 'pylon_e2ee.wasm')
])

console.log(`pylon-e2ee wasm written to ${out}`)
