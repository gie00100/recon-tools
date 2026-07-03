import browser_cookie3
import requests
import re
import os

def fetch_private_scopes():
    print('Loading Chrome cookies...')
    try:
        # Load HackerOne cookies from Chrome
        cookies = browser_cookie3.chrome(domain_name='hackerone.com')
        print(f'Found {len(cookies)} cookies.')
        
        print('Fetching CSRF token...')
        r = requests.get('https://hackerone.com/bug-bounty-programs', cookies=cookies, headers={'User-Agent': 'Mozilla/5.0'})
        m = re.search(r'name="csrf-token" content="([^"]+)"', r.text)
        if not m:
            print('Could not find CSRF token on page.')
            return
            
        csrf = m.group(1)
        print('Got CSRF token')
        
        handles = ['vercel', 'siriusxm']
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
            print(f'Fetching {handle}...')
            r2 = requests.post(
                'https://hackerone.com/graphql',
                json={'query': query, 'variables': {'handle': handle}},
                cookies=cookies,
                headers={'User-Agent': 'Mozilla/5.0', 'x-csrf-token': csrf}
            )
            
            if r2.status_code != 200:
                print(f'{handle}: HTTP {r2.status_code}')
                continue
                
            data = r2.json()
            team = data.get('data', {}).get('team')
            if not team:
                print(f'{handle}: Not authorized or not found.')
                continue
                
            edges = team.get('structured_scopes', {}).get('edges', [])
            domains = [e['node']['asset_identifier'] for e in edges if e['node']['asset_type'] in ['URL', 'WILDCARD'] and e['node'].get('eligible_for_submission')]
            print(f'{handle}: {len(domains)} domains')
            all_domains.extend(domains)
            
            # Save to targets.txt immediately
            with open('targets/targets.txt', 'a', encoding='utf-8') as f:
                for d in domains:
                    f.write(f'{d} | {handle}\n')
                    
        print(f'Added {len(all_domains)} private domains to targets.txt')
        
    except Exception as e:
        print('Error:', e)

if __name__ == '__main__':
    fetch_private_scopes()
