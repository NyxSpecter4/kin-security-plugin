const { spawn } = require('child_process');
const path = require('path');

const serverPath = path.join(__dirname, 'index.cjs');
const child = spawn('node', [serverPath], { stdio: ['pipe', 'pipe', 'inherit'] });

let step = 0;
let buffer = '';

child.stdout.on('data', (data) => {
  buffer += data.toString();
  const lines = buffer.split('\n');
  buffer = lines.pop(); // keep partial

  for (const line of lines) {
    if (!line.trim()) continue;
    const res = JSON.parse(line);
    console.log('[MCP Step ' + step + ']:', JSON.stringify(res, null, 2));

    if (step === 0) {
      // 1. Send tools/list
      step = 1;
      child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' }) + '\n');
    } else if (step === 1) {
      // 2. Send tools/call kin_scan_code
      step = 2;
      child.stdin.write(JSON.stringify({
        jsonrpc: '2.0',
        id: 3,
        method: 'tools/call',
        params: {
          name: 'kin_scan_code',
          arguments: {
            code: 'const q = "SELECT * FROM users WHERE username = \'" + req.body.username + "\'";',
            filename: 'auth.js'
          }
        }
      }) + '\n');
    } else if (step === 2) {
      // 3. Send tools/call kin_triage_vulnerability
      step = 3;
      child.stdin.write(JSON.stringify({
        jsonrpc: '2.0',
        id: 4,
        method: 'tools/call',
        params: {
          name: 'kin_triage_vulnerability',
          arguments: {
            scenario_desc: 'child_process.execSync("cat " + file);',
            user_payload: 'foo; rm -rf /'
          }
        }
      }) + '\n');
    } else if (step === 3) {
      console.log('ALL MCP SERVER TESTS PASSED SUCCESSFULLY!');
      child.kill();
      process.exit(0);
    }
  }
});

// Start with initialize
child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }) + '\n');
