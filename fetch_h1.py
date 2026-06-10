import requests

headers = {'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0'}
query = """query TeamScopes($handle: String!) {
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
}"""

for handle in ['mpesa', 'hubspot', 'verily_life_sciences']:
    print(f'\n# === {handle} ===')
    r = requests.post('https://hackerone.com/graphql', json={'query': query, 'variables': {'handle': handle}}, headers=headers)
    try:
        data = r.json()['data']['team']['structured_scopes']['edges']
        for edge in data:
            node = edge['node']
            if node['eligible_for_submission'] and node['asset_type'] in ['URL', 'WILDCARD']:
                ident = node["asset_identifier"]
                if ident.startswith("*."):
                    ident = ident[2:]
                print(ident)
    except Exception as e:
        print('Error:', e, r.text)
