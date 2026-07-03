const handles = ['kiwicom', 'yuga_labs', 'expediagroup_bbp', 'vercel', 'siriusxm'];
const query = `query TeamAssets($handle: String!) { team(handle: $handle) { structured_scopes(first: 100, archived: false) { edges { node { asset_identifier asset_type eligible_for_submission } } } } }`;
const allDomains = {};

async function fetchScopes() {
  for (const handle of handles) {
    console.log(`Fetching ${handle}...`);
    try {
      const res = await fetch('https://hackerone.com/graphql', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json', 
          'x-csrf-token': document.querySelector('meta[name="csrf-token"]')?.content || '' 
        },
        body: JSON.stringify({ query, variables: { handle } })
      });
      const data = await res.json();
      const edges = data.data?.team?.structured_scopes?.edges || [];
      allDomains[handle] = edges
        .filter(e => ['URL', 'WILDCARD'].includes(e.node.asset_type) && e.node.eligible_for_submission)
        .map(e => e.node.asset_identifier);
    } catch (e) {
      console.error(`Error fetching ${handle}:`, e);
    }
  }
  
  const jsonStr = JSON.stringify(allDomains, null, 2);
  console.log("SCOPES EXTRACTED:\n\n" + jsonStr);
  
  // Create a downloadable file
  const blob = new Blob([jsonStr], {type: "application/json"});
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "h1_private_scopes.json";
  a.click();
}

fetchScopes();
