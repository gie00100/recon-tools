import asyncio
import aiohttp
import json

API_KEY = "AIzaSyBE3JpOF9gNSsb83dpZKLUqFkmBAsPr0-w"

# Test endpoints - if unrestricted, these will return data instead of 403
TESTS = {
    "Maps Geocoding": f"https://maps.googleapis.com/maps/api/geocode/json?address=test&key={API_KEY}",
    "Maps Directions": f"https://maps.googleapis.com/maps/api/directions/json?origin=NYC&destination=LA&key={API_KEY}",
    "Maps Static": f"https://maps.googleapis.com/maps/api/staticmap?center=0,0&zoom=1&size=100x100&key={API_KEY}",
    "Custom Search": f"https://www.googleapis.com/customsearch/v1?q=test&key={API_KEY}",
    "YouTube Data": f"https://www.googleapis.com/youtube/v3/search?part=snippet&q=test&key={API_KEY}",
    "Cloud Translation": f"https://translation.googleapis.com/language/translate/v2?q=hello&target=es&key={API_KEY}",
    "FCM Send (Firebase)": "FCM_POST",
    "Blogger": f"https://www.googleapis.com/blogger/v3/blogs/2399953?key={API_KEY}",
    "Cloud Vision": "VISION_POST",
}

async def test_key():
    print(f"Testing Google API Key: {API_KEY[:15]}...\n")
    
    async with aiohttp.ClientSession() as session:
        for name, url in TESTS.items():
            if url == "FCM_POST":
                # Test Firebase Cloud Messaging
                try:
                    async with session.post(
                        "https://fcm.googleapis.com/fcm/send",
                        headers={"Authorization": f"key={API_KEY}", "Content-Type": "application/json"},
                        json={"registration_ids": ["test"]},
                        timeout=10
                    ) as resp:
                        status = resp.status
                        body = await resp.text()
                        result = "ACCESSIBLE" if status == 200 else f"BLOCKED ({status})"
                        print(f"  {name:25s} -> {result}")
                except Exception as e:
                    print(f"  {name:25s} -> ERROR: {e}")
                continue
                
            if url == "VISION_POST":
                # Test Cloud Vision API
                try:
                    async with session.post(
                        f"https://vision.googleapis.com/v1/images:annotate?key={API_KEY}",
                        json={"requests": [{"image": {"source": {"imageUri": "https://example.com/test.jpg"}}, "features": [{"type": "LABEL_DETECTION"}]}]},
                        timeout=10
                    ) as resp:
                        status = resp.status
                        result = "ACCESSIBLE" if status in (200, 400) else f"BLOCKED ({status})"
                        print(f"  {name:25s} -> {result}")
                except Exception as e:
                    print(f"  {name:25s} -> ERROR: {e}")
                continue
            
            try:
                async with session.get(url, timeout=10) as resp:
                    status = resp.status
                    body = await resp.text()
                    
                    if status == 200:
                        # Check if it actually returned useful data
                        try:
                            data = json.loads(body)
                            if data.get("error"):
                                result = f"BLOCKED (API error: {data['error'].get('message', '')[:60]})"
                            else:
                                result = "ACCESSIBLE - BILLABLE!"
                        except:
                            result = "ACCESSIBLE (non-JSON response)"
                    elif status == 403:
                        result = "BLOCKED (403 Forbidden)"
                    elif status == 400:
                        result = f"BLOCKED ({status})"
                    else:
                        result = f"Status {status}"
                        
                    # Color coding
                    flag = "***" if "ACCESSIBLE" in result and "BILLABLE" in result else "   "
                    print(f"{flag} {name:25s} -> {result}")
                    
            except Exception as e:
                print(f"    {name:25s} -> ERROR: {e}")

    print("\n=== VERDICT ===")
    print("If any API shows 'ACCESSIBLE - BILLABLE!', the key is unrestricted and exploitable.")
    print("If only Maps APIs work, it's a public restricted key (NO bounty).")

asyncio.run(test_key())
