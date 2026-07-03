import requests
import json
import urllib.parse
from collections import defaultdict

handles = ['metamask', 'wealthsimple', 'kayak', 'shein', 'weber-grills', 'instacart']
query = '''
query TeamAssets($handle: String!) {
  team(handle: $handle) {
    structured_scopes(first: 100, archived: false) {
      edges {
        node {
          asset_identifier
          asset_type
          eligible_for_submission
        }
      }
    }
  }
}
'''

groups = defaultdict(list)
for handle in handles:
    try:
        r = requests.post(
            'https://hackerone.com/graphql',
            json={'query': query, 'variables': {'handle': handle}},
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        if r.status_code != 200:
            print(f'{handle}: HTTP {r.status_code}')
            continue
            
        data = r.json()
        edges = data.get('data', {}).get('team', {}).get('structured_scopes', {}).get('edges', [])
        
        domains = []
        for e in edges:
            if e['node']['asset_type'] in ['URL', 'WILDCARD'] and e['node'].get('eligible_for_submission'):
                raw_domain = e['node']['asset_identifier'].strip()
                
                # Format to origin domain
                d = raw_domain
                if d.startswith('http://') or d.startswith('https://'):
                    d = urllib.parse.urlparse(d).netloc
                if d.startswith('*.'):
                    d = d[2:]
                if '/' in d:
                    d = d.split('/')[0]
                if d:
                    domains.append(d)
        
        # Deduplicate
        unique_domains = []
        for d in domains:
            if d not in unique_domains:
                unique_domains.append(d)
                
        groups[handle] = unique_domains
        print(f'{handle}: {len(unique_domains)} domains extracted')
    except Exception as e:
        print(f'{handle}: Error {e}')

formatted_lines = []
for handle, domains in groups.items():
    if not domains: continue
    formatted_lines.append('\n')
    formatted_lines.append(f'# === {handle} (HackerOne) ===\n')
    formatted_lines.append(f'# Program: https://hackerone.com/{handle}/policy_scopes\n')
    formatted_lines.append(f'# Scope: {len(domains)} domains\n')
    formatted_lines.append(f'# STATUS: PENDING\n')
    for d in domains:
        formatted_lines.append(f'{d} | {handle}\n')

with open('targets/targets.txt', 'a', encoding='utf-8') as f:
    f.writelines(formatted_lines)
    
print('Successfully appended to targets.txt!')
