import csv
import io
import urllib.parse

csv_data = '''identifier,asset_type,instruction,eligible_for_bounty,eligible_for_submission,availability_requirement,confidentiality_requirement,integrity_requirement,max_severity,system_tags,created_at,updated_at
*.junelife.com,WILDCARD,"",true,true,medium,high,medium,critical,"Python, Node.js, Rust, PostgresSQL, Java, Nginx, Amazon DynamoDB, Amazon Web Services, Flask, Go, TypeScript",2022-02-23 21:03:25 UTC,2023-05-15 16:38:32 UTC
juneoven.com,URL,"",true,true,none,low,low,medium,,2022-02-23 21:03:59 UTC,2022-02-28 22:53:52 UTC
weber.com,URL,"",true,true,,,,critical,,2022-02-23 21:04:16 UTC,2024-04-03 15:58:14 UTC
*.walker-cloud.com,WILDCARD,"",true,true,medium,high,medium,critical,"Python, Amazon DynamoDB, Amazon Web Services, Flask, Go, Java, Nginx, PostgresSQL, Rust",2022-02-23 21:47:40 UTC,2023-05-15 16:38:32 UTC
github.com/junelife,SOURCE_CODE,"",true,true,,,,critical,,2022-06-13 20:41:44 UTC,2022-06-13 20:41:44 UTC
api.walker-cloud.com,URL,"",true,true,high,high,high,critical,,2022-09-14 22:56:04 UTC,2022-09-14 22:56:04 UTC
artifacts.junelife.com,URL,"",false,false,none,none,none,none,,2023-08-15 16:38:28 UTC,2023-08-15 16:38:28 UTC
com.weberstephen.connect,APPLE_STORE_APP_ID,Weber Connect iOS app on Apple App Store.,true,true,high,high,high,critical,,2024-04-15 16:33:54 UTC,2024-04-15 16:56:32 UTC
com.weber.connect,GOOGLE_PLAY_APP_ID,Weber Connect Android app on Google Play.,true,true,high,high,high,critical,,2024-04-15 16:35:31 UTC,2024-04-15 16:56:11 UTC
iGrill mini/2/3 Device,HARDWARE,"This refers to the iGrill hardware device, and the firmware running on it. Reports referring to this asset will only be accepted if found on actual hardware.",true,true,none,none,high,high,,2024-04-15 16:38:04 UTC,2024-04-15 16:38:04 UTC
com.igrill.igrilliPhone,APPLE_STORE_APP_ID,Weber iGrill iOS app on Apple App Store.,true,true,,,,critical,,2024-04-15 16:50:25 UTC,2024-04-15 16:56:41 UTC
com.weber.igrill,GOOGLE_PLAY_APP_ID,Weber iGrill Android app on Google Play.,true,true,high,high,high,critical,,2024-04-15 16:51:58 UTC,2024-04-15 16:55:31 UTC
Weber Connect Hardware,HARDWARE,"Applies to hardware/firmware for the following products: Smart Grilling Hub, SmokeFire Pellet Grill family, Genesis II Smart Grill family, Spirit Smart Grill family, Genesis Smart Grill family, SearWood Pellet Grill family. Reports referring to this asset will only be accepted if found on actual hardware.",true,true,high,medium,high,critical,,2024-04-15 16:54:57 UTC,2024-04-15 16:57:18 UTC
*.weber.com,WILDCARD,This applies to any subdomains of weber.com.,true,true,high,high,high,critical,,2025-09-11 18:02:40 UTC,2025-09-11 18:03:28 UTC'''

domains = []
reader = csv.DictReader(io.StringIO(csv_data))
for row in reader:
    if row['asset_type'] in ['URL', 'WILDCARD'] and row['eligible_for_submission'].lower() == 'true':
        raw_domain = row['identifier'].strip()
        d = raw_domain
        if d.startswith('http://') or d.startswith('https://'):
            d = urllib.parse.urlparse(d).netloc
        if d.startswith('*.'):
            d = d[2:]
        if '/' in d:
            d = d.split('/')[0]
        if d and d not in domains:
            domains.append(d)

formatted_lines = []
handle = 'weber-grills'
formatted_lines.append('\n')
formatted_lines.append(f'# === {handle} (HackerOne) ===\n')
formatted_lines.append(f'# Program: https://hackerone.com/{handle}/policy_scopes\n')
formatted_lines.append(f'# Scope: {len(domains)} domains\n')
formatted_lines.append(f'# STATUS: PENDING\n')
for d in domains:
    formatted_lines.append(f'{d} | {handle}\n')

with open('targets/targets.txt', 'a', encoding='utf-8') as f:
    f.writelines(formatted_lines)
    
print(f'Successfully added {len(domains)} domains for weber-grills to targets.txt!')
