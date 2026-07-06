import paramiko

IP='134.209.72.156'; USER='root'; PASS='Kingo@123Kingo'
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(IP, username=USER, password=PASS, timeout=20)

cmds = [
    ('load / uptime',        'uptime'),
    ('screen sessions',      'screen -ls 2>&1'),
    ('python processes',     'ps aux | grep python | grep -v grep'),
    ('recon processes',      'ps aux | grep -E "bounty|recon_" | grep -v grep'),
    ('last 5 output dirs',   'ls -lt /root/recon-tools/output/ | head -6'),
    ('output dir count',     'ls /root/recon-tools/output/ | wc -l'),
    ('disk free',            'df -h / | tail -1'),
    ('bot service status',   'systemctl status recon-bot --no-pager 2>&1 | head -8'),
    ('scan state.json last', 'ls -lt /root/recon-tools/output/*_state.json 2>/dev/null | head -3'),
    ('git log',              'cd /root/recon-tools && git log --oneline -3'),
]

for label, cmd in cmds:
    _, stdout, _ = ssh.exec_command(cmd, timeout=15)
    out = stdout.read().decode().strip()
    print(f'=== {label} ===')
    print(out or '(empty)')
    print()

ssh.close()
print('Done.')
