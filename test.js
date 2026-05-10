import { execSync } from 'child_process';
const psScript = `
try {
  $ProgressPreference = 'SilentlyContinue'
  $channels = @('Security', 'System', 'Application')
  $evts = Get-WinEvent -LogName $channels -MaxEvents 100 -ErrorAction SilentlyContinue
  if ($null -eq $evts) { return '[]' }
  $arr = @($evts | Select-Object @{Name='Id';Expression={[int]$_.Id}}, TimeCreated, LevelDisplayName, TaskDisplayName, ProviderName, LogName, Message)
  return ($arr | ConvertTo-Json -Compress -Depth 2)
} catch { return '[]' }
`;
const encoded = Buffer.from(psScript, 'utf16le').toString('base64');
try {
  const stdout = execSync('powershell -NoProfile -NonInteractive -EncodedCommand ' + encoded).toString();
  console.log("LAST 100 CHARS:", stdout.trim().slice(-100));
  JSON.parse(stdout.trim());
  console.log("JSON Parse: SUCCESS");
} catch(e) {
  console.error("JSON Parse Error:", e.message);
}
