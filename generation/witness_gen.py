import json
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

def split_hex(hex_str, num_bytes):
    num_chars = num_bytes * 2
    return [hex_str[i:i+num_chars] for i in range(0, len(hex_str), num_chars)]

def to_u128_hex(hex_str): return "0x" + hex_str if hex_str else "0"
def to_base10(hex_str): return str(int(hex_str, 16)) if hex_str else "0"
def format_arr(arr): return "[" + ", ".join(arr) + "]"

def parse_file(filename):
    data = {}
    current_key = None
    if not os.path.exists(filename): return None
    with open(filename, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('='): continue
            if line.startswith('['):
                current_key = line.strip('[]')
                data[current_key] = ""
            elif current_key and not line.startswith('-'):
                data[current_key] += line
    return data

WITNESS_TYPE_STATELESS = "(u256, (u128, u128), ((u256, ([u128; 6], [u128; 91])), [((u256, u32, [u128; 64]), [u128; 12]); 2]))"

# --- STATELESS PARSING ---
stateless_txt_path = os.path.join(SCRIPT_DIR, 'parsed_witness_data.txt')
data_sl = parse_file(stateless_txt_path)
if data_sl:
    msg = to_base10(data_sl['MESSAGE'])
    pk_1 = to_u128_hex(data_sl['PK_SEED'])
    pk_2 = to_u128_hex(data_sl['PK_ROOT'])
    
    pors_r = to_base10(data_sl['PORS_R'])
    pors_combined = data_sl['PORS_SECRETS_AND_AUTH']
    pors_sigs = [to_u128_hex(c) for c in split_hex(pors_combined[:192], 16)]
    pors_auth = [to_u128_hex(c) for c in split_hex(pors_combined[192:], 16)]
    
    layers_str = []
    for i in range(2):
        r = to_base10(data_sl[f'XMSS_LAYER_{i}_R'])
        ctr = to_base10(data_sl[f'XMSS_LAYER_{i}_CTR'])
        chains = [to_u128_hex(c) for c in split_hex(data_sl[f'XMSS_LAYER_{i}_CHAINS'], 16)]
        auth = [to_u128_hex(c) for c in split_hex(data_sl[f'XMSS_LAYER_{i}_AUTH'], 16)]
        layers_str.append(f"(({r}, {ctr}, {format_arr(chains)}), {format_arr(auth)})")
        
    # Removed Right() wrapper and the trailing sf_hex root
    value_str = f"({msg}, ({pk_1}, {pk_2}), (({pors_r}, ({format_arr(pors_sigs)}, {format_arr(pors_auth)})), [{layers_str[0]}, {layers_str[1]}]))"
    
    stateless_wit_path = os.path.join(SCRIPT_DIR, 'shrincs_main_stateless.wit')
    with open(stateless_wit_path, 'w') as f:
        json.dump({"PROOF": {"type": WITNESS_TYPE_STATELESS, "value": value_str}}, f, indent=4)
    print(f"Successfully generated: {stateless_wit_path}")

# --- STATEFUL PARSING ---
'''
stateful_txt_path = os.path.join(SCRIPT_DIR, 'parsed_witness_data_stateful.txt')
data_sf = parse_file(stateful_txt_path)
if data_sf:
    msg = to_base10(data_sf['MESSAGE'])
    pk_1 = to_u128_hex(data_sf['PK_SEED'])
    pk_2 = to_u128_hex(data_sf['PK_ROOT'])
    sl_hex = to_u128_hex(data_sf['PK_SL'])
    
    uxmss_r = to_base10(data_sf['UXMSS_R'])
    uxmss_ctr = to_base10(data_sf['UXMSS_CTR'])
    uxmss_chains = [to_u128_hex(c) for c in split_hex(data_sf['UXMSS_CHAINS'], 16)]
    
    auth_hex = data_sf.get('UXMSS_AUTH', '')
    uxmss_auth = [to_u128_hex(c) for c in split_hex(auth_hex, 16)] if auth_hex else []
    uxmss_q = data_sf['UXMSS_Q'].strip()
    
    while len(uxmss_auth) < 256:
        uxmss_auth.append("0")
    
    wots_sig = f"({uxmss_r}, {uxmss_ctr}, {format_arr(uxmss_chains)})"
    uxmss_signature = f"({wots_sig}, {format_arr(uxmss_auth)}, {uxmss_q})"
    
    value_str = f"({msg}, ({pk_1}, {pk_2}), Left({uxmss_signature}), {sl_hex})"
    
    stateful_wit_path = os.path.join(SCRIPT_DIR, 'shrincs_main_stateful.wit')
    with open(stateful_wit_path, 'w') as f:
        json.dump({"PROOF": {"type": WITNESS_TYPE, "value": value_str}}, f, indent=4)
    print(f"Successfully generated: {stateful_wit_path}")

if not data_sl and not data_sf:
    print("No parsed data files found! Please run the C++ generator first.")
else:
    print("\nSuccess.")
    '''