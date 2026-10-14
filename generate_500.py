import re
import json

log_path = r"C:\Users\arify\OneDrive\Desktop\Document's\firewall_traffic.log"
output_json_path = r"C:\Users\arify\.gemini\antigravity-ide\scratch\firewall-dashboard\data.json"
output_js_path = r"C:\Users\arify\.gemini\antigravity-ide\scratch\firewall-dashboard\data.js"

kv_pattern = re.compile(r'([a-zA-Z0-9_]+)=(".*?"|\S+)')

# Sample 500 records evenly across the dataset (394170 / 500 ≈ 788)
target_count = 500
step = 788
sample_records = []
success_count = 0
failed_count = 0

with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
    for idx, line in enumerate(f):
        line = line.strip()
        if not line:
            continue
        
        if idx % step == 0 and len(sample_records) < target_count:
            parts = line.split(' ', 1)
            ts = parts[0]
            data = {}
            if len(parts) > 1:
                data = dict(kv_pattern.findall(parts[1]))
            
            action = data.get('action', 'UNKNOWN')
            is_success = (action == 'ALLOW')
            if is_success:
                success_count += 1
            else:
                failed_count += 1

            sample_records.append({
                "id": f"LOG-{len(sample_records)+1:04d}",
                "timestamp": ts,
                "firewall": data.get('firewall', 'FW-EDGE-01'),
                "src_ip": data.get('src_ip', '0.0.0.0'),
                "src_port": data.get('src_port', '0'),
                "dst_ip": data.get('dst_ip', '0.0.0.0'),
                "dst_port": data.get('dst_port', '0'),
                "protocol": data.get('protocol', 'TCP'),
                "service": data.get('service', 'HTTP'),
                "action": action,
                "status": "Success" if is_success else "Failed",
                "rule": data.get('rule', 'UNKNOWN'),
                "packets": int(data.get('packets', 0)),
                "bytes": int(data.get('bytes', 0)),
                "tcp_flags": data.get('tcp_flags', 'NONE').strip('"'),
                "src_zone": data.get('src_zone', 'LAN'),
                "dst_zone": data.get('dst_zone', 'DMZ'),
                "severity": data.get('severity', 'INFO').strip('"'),
                "attack": data.get('attack', '').strip('"') if data.get('attack') else None,
                "raw_log": line
            })

output = {
    "summary": {
        "total_records": len(sample_records),
        "success_count": success_count,
        "failed_count": failed_count,
        "firewall_id": "FW-EDGE-01"
    },
    "records": sample_records
}

with open(output_json_path, 'w', encoding='utf-8') as out_f:
    json.dump(output, out_f, indent=2)

with open(output_js_path, 'w', encoding='utf-8') as out_f:
    out_f.write("window.FIREWALL_DATA = " + json.dumps(output, indent=2) + ";")

print(f"Generated {len(sample_records)} records: {success_count} Success, {failed_count} Failed.")
