// Loaded by run.sh into a VS Code started by `hush run`. Sends the placeholder
// in $CHECK_SECRET to an echo service each way an extension can, writes what
// came back to $CHECK_OUT, and quits VS Code.
const vscode = require('vscode');
const https = require('https');
const fs = require('fs');
const { execFile } = require('child_process');

const url = process.env.CHECK_URL;
const out = process.env.CHECK_OUT;
const key = process.env[process.env.CHECK_SECRET] || '';
const header = 'Bearer ' + key;

// What the echo says the server received: the real value shows up redacted
// in the echo, the placeholder only if hush didn't swap it.
function verdict(body) {
  const m = /"authorization":\s*"([^"]*)"/i.exec(body || '');
  if (!m) return 'no authorization header in the echo';
  if (m[1].includes('HUSH_REDACTED')) return 'ok';
  if (m[1].includes('hush_ph_')) return 'placeholder sent, not swapped';
  return 'unexpected value';
}

function viaHttps() {
  return new Promise(resolve => {
    const req = https.get(url, { headers: { Authorization: header } }, res => {
      let body = '';
      res.on('data', d => body += d);
      res.on('end', () => resolve(verdict(body)));
    });
    req.on('error', e => resolve('error: ' + e.message));
    req.setTimeout(20000, () => req.destroy(new Error('timed out')));
  });
}

async function viaFetch() {
  try {
    const res = await fetch(url, { headers: { Authorization: header }, signal: AbortSignal.timeout(20000) });
    return verdict(await res.text());
  } catch (e) {
    return 'error: ' + e.message + (e.cause ? ' (' + e.cause.message + ')' : '');
  }
}

// A process an extension starts, such as a bundled CLI or an MCP server.
function viaNodeChild() {
  const code = `fetch(${JSON.stringify(url)}, { headers: { Authorization: ${JSON.stringify(header)} } })
    .then(r => r.text()).then(t => console.log(t))
    .catch(e => console.log('error: ' + e.message + (e.cause ? ' (' + e.cause.message + ')' : '')))`;
  return new Promise(resolve => execFile(process.execPath, ['-e', code],
    { env: { ...process.env, ELECTRON_RUN_AS_NODE: '1' }, timeout: 30000 },
    (e, stdout) => resolve(stdout.startsWith('error:') ? stdout.trim() : e ? 'error: ' + e.message : verdict(stdout))));
}

function viaCurl() {
  return new Promise(resolve => execFile('curl', ['-sS', '-m', '20', '-H', 'Authorization: ' + header, url],
    (e, stdout, stderr) => resolve(e ? 'error: ' + (stderr.trim() || e.message) : verdict(stdout))));
}

// The integrated terminal: it should have the placeholder too.
function viaTerminal() {
  const file = out + '.terminal';
  vscode.window.createTerminal({
    name: 'hush check', shellPath: '/bin/sh',
    shellArgs: ['-c', `printf %s "$${process.env.CHECK_SECRET}" > '${file}.tmp'; mv '${file}.tmp' '${file}'`],
  });
  return new Promise(resolve => {
    let tries = 0;
    const timer = setInterval(() => {
      if (fs.existsSync(file)) {
        clearInterval(timer);
        resolve(fs.readFileSync(file, 'utf8').startsWith('hush_ph_') ? 'ok' : 'no placeholder in the terminal');
      } else if (++tries > 40) {
        clearInterval(timer);
        resolve('terminal never ran');
      }
    }, 250);
  });
}

async function activate() {
  const results = {};
  if (!key.startsWith('hush_ph_')) {
    results.environment = `no placeholder in $${process.env.CHECK_SECRET}: is it in the vault?`;
  } else {
    for (const [name, check] of [['https', viaHttps], ['fetch', viaFetch], ['child process', viaNodeChild],
                                 ['curl', viaCurl], ['terminal', viaTerminal]]) {
      results[name] = await check();
    }
  }
  fs.writeFileSync(out, Object.entries(results).map(([name, result]) => `${name}: ${result}\n`).join(''));
  setTimeout(() => vscode.commands.executeCommand('workbench.action.quit'), 500);
}

module.exports = { activate, deactivate() {} };
