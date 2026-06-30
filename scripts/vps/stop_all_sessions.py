"""Stop all scan sessions on VPS (screen sessions, recon processes). Leave Discord bot untouched."""
import sys, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from vps_helper import connect_vps, run_remote

ssh, cfg = connect_vps()
rp = cfg['remote_path']

print('[*] Current screen sessions:')
out = run_remote(ssh, 'screen -ls', silent=True)
print(out or '  (none)')

print('\n[*] Killing all scan screen sessions...')
run_remote(ssh,
    'screen -ls | grep -oP "\\d+\\.\\S+" | xargs -I{} screen -X -S {} quit 2>&1 || true',
    silent=True)
time.sleep(1)

print('[*] Killing scan processes (run_sequential, recon_master, nuclei, subfinder, httpx)...')
run_remote(ssh,
    'pkill -f run_sequential.sh 2>/dev/null; '
    'pkill -f recon_master.py 2>/dev/null; '
    'pkill -f bulk_runner.py 2>/dev/null; '
    'pkill -f run_bulk.sh 2>/dev/null; '
    'pkill -f nuclei 2>/dev/null; '
    'pkill -f subfinder 2>/dev/null; '
    'pkill -f httpx 2>/dev/null; '
    'true',
    silent=True)
time.sleep(1)

print('\n[*] Remaining sessions:')
out = run_remote(ssh, 'screen -ls 2>/dev/null || echo "(none)"', silent=True)
print(out)

print('[*] Remaining scan processes:')
out = run_remote(ssh,
    'pgrep -fa "run_sequential|recon_master|bulk_runner|nuclei|subfinder" 2>/dev/null || echo "(none)"',
    silent=True)
print(out)

ssh.close()
print('\n[+] All scan sessions stopped. Discord bot is unaffected.')
