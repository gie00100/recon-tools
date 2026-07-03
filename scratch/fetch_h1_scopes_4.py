import requests
import json

handles = ['kiwicom', 'yuga_labs', 'expediagroup_bbp', 'deribit', 'vercel', 'mongodb', 'sidefx', 'siriusxm']
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

all_domains = []
for handle in handles:
    try:
        r = requests.post(
            'https://hackerone.com/graphql',
            json={'query': query, 'variables': {'handle': handle}},
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36'}
        )
        if r.status_code != 200:
            print(f'{handle}: HTTP {r.status_code}')
            continue
        data = r.json()
        edges = data.get('data', {}).get('team', {}).get('structured_scopes', {}).get('edges', [])
        if not edges:
            print(f'{handle}: No scopes found or private program')
            continue
            
        domains = [e['node']['asset_identifier'] for e in edges if e['node']['asset_type'] in ['URL', 'WILDCARD'] and e['node'].get('eligible_for_submission')]
        print(f'{handle}: {len(domains)} domains')
        for d in domains:
            all_domains.append((d, handle))
    except Exception as e:
        print(f'{handle}: Error {e}')

print('Total domains:', len(all_domains))
with open('targets/targets.txt', 'a', encoding='utf-8') as f:
    for d, h in all_domains:
        f.write(f'{d} | {h}\n')
