import urllib.request
import re
import os
import json
from urllib.parse import unquote

os.makedirs('benchmark/vercel', exist_ok=True)
url = 'https://vercel.com/docs/vercel-firewall/firewall-observability'
req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})

try:
    with urllib.request.urlopen(req) as resp:
        html = resp.read().decode('utf-8', errors='ignore')
    
    with open('benchmark/vercel/page.html', 'w', encoding='utf-8') as f:
        f.write(html)
        
    print(f"Saved page.html ({len(html)} bytes)")

    # Find image candidates
    # Next.js image links: /_next/image?url=...
    next_imgs = re.findall(r'/_next/image\?url=([^&"\'>]+)', html)
    direct_imgs = re.findall(r'(https://[^"\'<>]+\.(?:png|jpg|jpeg|webp|svg))', html)
    asset_imgs = re.findall(r'(https://assets\.vercel\.com/[^"\'<>\s]+)', html)
    img_tags = re.findall(r'<img[^>]+src=["\']([^"\']+)["\']', html)
    
    all_candidates = set()
    for img in next_imgs:
        decoded = unquote(img)
        if decoded.startswith('/'):
            decoded = 'https://vercel.com' + decoded
        all_candidates.add(decoded)
    for img in direct_imgs:
        all_candidates.add(img)
    for img in asset_imgs:
        all_candidates.add(img)
    for img in img_tags:
        if 'image?url=' in img:
            match = re.search(r'url=([^&"\'>]+)', img)
            if match:
                decoded = unquote(match.group(1))
                if decoded.startswith('/'):
                    decoded = 'https://vercel.com' + decoded
                all_candidates.add(decoded)
        elif img.startswith('http'):
            all_candidates.add(img)
        elif img.startswith('/'):
            all_candidates.add('https://vercel.com' + img)

    print(f"Found {len(all_candidates)} candidates:")
    valid_images = []
    idx = 1
    for cand in sorted(all_candidates):
        print(f"Candidate: {cand}")
        if any(ext in cand.lower() for ext in ['.png', '.jpg', '.jpeg', '.webp']) and ('firewall' in cand.lower() or 'dashboard' in cand.lower() or 'traffic' in cand.lower() or 'observability' in cand.lower() or 'docs' in cand.lower() or 'assets.vercel.com' in cand.lower()):
            filename = f"vercel_firewall_{idx}_{cand.split('/')[-1].split('?')[0]}"
            if not filename.endswith(('.png', '.jpg', '.jpeg', '.webp')):
                filename += '.png'
            dest = os.path.join('benchmark/vercel', filename)
            try:
                img_req = urllib.request.Request(cand, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(img_req) as r:
                    content = r.read()
                    with open(dest, 'wb') as f:
                        f.write(content)
                print(f"Downloaded: {cand} -> {dest} ({len(content)} bytes)")
                valid_images.append({'url': cand, 'path': dest, 'size': len(content)})
                idx += 1
            except Exception as e:
                print(f"Failed to download {cand}: {e}")

    with open('benchmark/vercel/manifest.json', 'w', encoding='utf-8') as f:
        json.dump(valid_images, f, indent=2)
    print("Completed manifest.")
except Exception as e:
    print(f"Error fetching page: {e}")
