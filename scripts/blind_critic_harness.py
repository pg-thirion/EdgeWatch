import os
import json
import random
import time
from PIL import Image, ImageDraw, ImageFont

BENCHMARK_DIR = 'benchmark/vercel'
OUTPUT_DIR = 'benchmark/critic_rounds'
os.makedirs(OUTPUT_DIR, exist_ok=True)

TARGET_MAP = {
    'overview': {
        'ref': os.path.join(BENCHMARK_DIR, 'vercel_firewall_3_vercel-waf-overview-tab-dark.png'),
        'route': '/?tab=overview',
        'desc': 'Firewall Observability Overview Dashboard'
    },
    'traffic': {
        'ref': os.path.join(BENCHMARK_DIR, 'vercel_firewall_5_vercel-waf-traffic-tab-dark.png'),
        'route': '/?tab=traffic',
        'desc': 'Traffic & Threat Dimensions Explorer'
    },
    'eventsheet': {
        'ref': os.path.join(BENCHMARK_DIR, 'vercel_firewall_1_vercel-waf-event-sheet-dark.png'),
        'route': '/?tab=events&inspect=evt_demo_1',
        'desc': 'WAF Event Telemetry Sheet & Rule Inspection'
    }
}

def create_blind_comparison(piece_name, edgewatch_screenshot_path, round_num=1):
    target = TARGET_MAP.get(piece_name)
    if not target or not os.path.exists(target['ref']):
        raise ValueError(f"Unknown target or missing reference image for {piece_name}")

    ref_img = Image.open(target['ref']).convert('RGB')
    cand_img = Image.open(edgewatch_screenshot_path).convert('RGB')

    # Normalize dimensions to standard width 1400, proportional height
    std_w = 1400
    ref_h = int(ref_img.height * (std_w / ref_img.width))
    cand_h = int(cand_img.height * (std_w / cand_img.width))

    ref_resized = ref_img.resize((std_w, ref_h), Image.Resampling.LANCZOS)
    cand_resized = cand_img.resize((std_w, cand_h), Image.Resampling.LANCZOS)

    # Randomize assignment: Option A vs Option B
    is_ref_a = random.choice([True, False])
    opt_a = ref_resized if is_ref_a else cand_resized
    opt_b = cand_resized if is_ref_a else ref_resized

    # Save blind anonymous images
    opt_a_path = os.path.join(OUTPUT_DIR, f"{piece_name}_round_{round_num}_option_A.png")
    opt_b_path = os.path.join(OUTPUT_DIR, f"{piece_name}_round_{round_num}_option_B.png")
    opt_a.save(opt_a_path)
    opt_b.save(opt_b_path)

    # Combine into side-by-side or stacked blind comparison image
    max_h = max(opt_a.height, opt_b.height)
    combined = Image.new('RGB', (std_w * 2 + 40, max_h + 80), color=(15, 15, 18))
    draw = ImageDraw.Draw(combined)

    # Header labels
    draw.text((40, 25), "CANDIDATE OPTION A (Labels Masked)", fill=(200, 200, 200))
    draw.text((std_w + 60, 25), "CANDIDATE OPTION B (Labels Masked)", fill=(200, 200, 200))

    combined.paste(opt_a, (20, 60))
    combined.paste(opt_b, (std_w + 40, 60))

    combined_path = os.path.join(OUTPUT_DIR, f"{piece_name}_round_{round_num}_blind_combined.png")
    combined.save(combined_path)

    key_record = {
        'piece_name': piece_name,
        'round': round_num,
        'timestamp': time.time(),
        'option_A': 'REFERENCE_BENCHMARK' if is_ref_a else 'EDGEWATCH_CANDIDATE',
        'option_B': 'EDGEWATCH_CANDIDATE' if is_ref_a else 'REFERENCE_BENCHMARK',
        'combined_path': combined_path,
        'option_A_path': opt_a_path,
        'option_B_path': opt_b_path,
        'edgewatch_path': edgewatch_screenshot_path,
        'reference_path': target['ref']
    }

    key_file = os.path.join(OUTPUT_DIR, f"{piece_name}_round_{round_num}_key.json")
    with open(key_file, 'w', encoding='utf-8') as f:
        json.dump(key_record, f, indent=2)

    return key_record

if __name__ == '__main__':
    print("Blind Critic Harness initialized.")
