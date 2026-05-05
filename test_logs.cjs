const { exec } = require('child_process');
const os = require('os');

const execAsync = (cmd, opts = {}) => new Promise((resolve, reject) => {
  exec(cmd, opts, (error, stdout, stderr) => {
    if (error) reject(error);
    else resolve({ stdout, stderr });
  });
});

async function fetchWindowsEventLogs(logNames, maxEvents) {
  const nameList  = logNames.map(n => `'${n}'`).join(',');
  const psScript  =
    `try {` +
    `  $evts = Get-WinEvent -LogName ${nameList} -MaxEvents ${maxEvents} -ErrorAction SilentlyContinue;` +
    `  if ($null -eq $evts) { Write-Output '[]'; return }` +
    `  $arr = @($evts | Select-Object @{Name='Id';Expression={[int]$_.Id}}, TimeCreated, LevelDisplayName, TaskDisplayName, ProviderName, LogName, MachineName, Message);` +
    `  Write-Output ($arr | ConvertTo-Json -Compress -Depth 3)` +
    `} catch { Write-Output '[]' }`;

  const encoded = Buffer.from(psScript, 'utf16le').toString('base64');
  const { stdout } = await execAsync(`powershell -NoProfile -NonInteractive -EncodedCommand ${encoded}`, { timeout: 20000 });
  const trimmed = stdout.trim();
  if (!trimmed || trimmed === '[]') return [];
  const parsed = JSON.parse(trimmed);
  return Array.isArray(parsed) ? parsed : [parsed];
}

async function test() {
  try {
    const sysAppLogs = await fetchWindowsEventLogs(['System', 'Application', 'Setup'], 5);
    console.log(JSON.stringify(sysAppLogs, null, 2));
  } catch (e) {
    console.error("Error:", e);
  }
}
test();
