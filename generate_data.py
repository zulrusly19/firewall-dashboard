import re
import json

log_path = r"C:\Users\arify\OneDrive\Desktop\Document's\firewall_traffic.log"
output_json_path = r"C:\Users\arify\.gemini\antigravity-ide\scratch\firewall-dashboard\data.json"
output_js_path = r"C:\Users\arify\.gemini\antigravity-ide\scratch\firewall-dashboard\data.js"

kv_pattern = re.compile(r'([a-zA-Z0-9_]+)=(".*?"|\S+)')

# Global aggregations
total_events = 0
action_counts = {"ALLOW": 0, "DENY": 0, "DROP": 0}
severity_counts = {"INFO": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
attack_counts = {}
protocol_counts = {}
service_counts = {}
zone_counts = {"LAN": 0, "Internet": 0}
hourly_stats = {} # "YYYY-MM-DDTHH": {"hour": "HH:00", "success": 0, "failed": 0, "bytes": 0, "threats": 0}
top_sources = {}
top_dests = {}
total_bytes = 0
total_packets = 0

# Sample 2000 records
sample_records = []
step = 197 # 394170 / 2000 ≈ 197 to get evenly distributed records across the entire 12-hour span

with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
    for idx, line in enumerate(f):
        line = line.strip()
        if not line:
            continue
        total_events += 1
        
        parts = line.split(' ', 1)
        ts = parts[0]
        hour_key = ts[:13] + ":00"
        
        if hour_key not in hourly_stats:
            hourly_stats[hour_key] = {"hour": ts[11:16], "success": 0, "failed": 0, "bytes": 0, "threats": 0}
            
        data = {}
        if len(parts) > 1:
            data = dict(kv_pattern.findall(parts[1]))
            
        action = data.get('action', 'UNKNOWN')
        if action in action_counts:
            action_counts[action] += 1
            
        is_success = (action == "ALLOW")
        if is_success:
            hourly_stats[hour_key]["success"] += 1
        else:
            hourly_stats[hour_key]["failed"] += 1
            
        sev = data.get('severity', 'INFO').strip('"')
        if sev in severity_counts:
            severity_counts[sev] += 1
            
        proto = data.get('protocol', 'UNKNOWN')
        protocol_counts[proto] = protocol_counts.get(proto, 0) + 1
        
        serv = data.get('service', 'UNKNOWN')
        service_counts[serv] = service_counts.get(serv, 0) + 1
        
        sz = data.get('src_zone', 'LAN')
        zone_counts[sz] = zone_counts.get(sz, 0) + 1
        
        sip = data.get('src_ip', '0.0.0.0')
        top_sources[sip] = top_sources.get(sip, 0) + 1
        
        dip = data.get('dst_ip', '0.0.0.0')
        top_dests[dip] = top_dests.get(dip, 0) + 1
        
        try:
            b = int(data.get('bytes', 0))
            total_bytes += b
            hourly_stats[hour_key]["bytes"] += b
        except:
            b = 0
            
        try:
            p = int(data.get('packets', 0))
            total_packets += p
        except:
            p = 0
            
        attack = data.get('attack')
        if attack:
            att_clean = attack.strip('"')
            attack_counts[att_clean] = attack_counts.get(att_clean, 0) + 1
            hourly_stats[hour_key]["threats"] += 1

        # Collect sample records
        if idx % step == 0 and len(sample_records) < 2000:
            sample_records.append({
                "id": f"LOG-{idx+1:06d}",
                "timestamp": ts,
                "firewall": data.get('firewall', 'FW-EDGE-01'),
                "src_ip": sip,
                "src_port": data.get('src_port', '0'),
                "dst_ip": dip,
                "dst_port": data.get('dst_port', '0'),
                "protocol": proto,
                "service": serv,
                "action": action,
                "status": "Success" if is_success else "Failed",
                "rule": data.get('rule', 'UNKNOWN'),
                "packets": p,
                "bytes": b,
                "tcp_flags": data.get('tcp_flags', 'NONE').strip('"'),
                "src_zone": sz,
                "dst_zone": data.get('dst_zone', 'DMZ'),
                "severity": sev,
                "attack": data.get('attack', '').strip('"') if data.get('attack') else None,
                "raw_log": line
            })

# Sort hourly stats
sorted_hourly = [hourly_stats[k] for k in sorted(hourly_stats.keys())]

# Top 10 services
sorted_services = sorted(service_counts.items(), key=lambda x: x[1], reverse=True)[:8]

# Top 10 attacks
sorted_attacks = sorted(attack_counts.items(), key=lambda x: x[1], reverse=True)[:10]

# Top 5 attacker IPs
sorted_sources = [{"ip": k, "count": v} for k, v in sorted(top_sources.items(), key=lambda x: x[1], reverse=True)[:5]]

# Top 5 targets
sorted_dests = [{"ip": k, "count": v} for k, v in sorted(top_dests.items(), key=lambda x: x[1], reverse=True)[:5]]

output = {
    "summary": {
        "total_records": total_events,
        "success_count": action_counts["ALLOW"],
        "failed_count": action_counts["DENY"] + action_counts["DROP"],
        "deny_count": action_counts["DENY"],
        "drop_count": action_counts["DROP"],
        "threats_count": sum(attack_counts.values()),
        "total_bytes": total_bytes,
        "total_packets": total_packets,
        "firewall_id": "FW-EDGE-01",
        "sample_size": len(sample_records)
    },
    "severity_counts": severity_counts,
    "protocol_counts": protocol_counts,
    "top_services": sorted_services,
    "top_attacks": sorted_attacks,
    "hourly_timeline": sorted_hourly,
    "top_sources": sorted_sources,
    "top_dests": sorted_dests,
    "records": sample_records
}

# Write data.json
with open(output_json_path, 'w', encoding='utf-8') as out_f:
    json.dump(output, out_f, indent=2)

# Write data.js for zero-configuration local and CDN loading
with open(output_js_path, 'w', encoding='utf-8') as out_f:
    out_f.write("window.FIREWALL_DATA = " + json.dumps(output, indent=2) + ";")

print(f"Successfully processed {total_events} events.")
print(f"Generated {len(sample_records)} sample records in data.json and data.js")
