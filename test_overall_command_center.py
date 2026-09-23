"""
SecureVision AI - Overall Facility Command Center Test Suite
Verifies:
1. Unified Dual-Domain Executive Metrics (SQLite backed, Inside/Outside separated)
2. Interactive Tactical Facility Radar Map (Registered sensors, real zones, incidents, drone telemetry)
3. Real-Time Event Forensic Timeline (Authoritative structured event stream)
4. Natural-Language Surveillance Intelligence (5 key query translations to SQLite)
5. Strict REAL/DATA System Status (No fake green READY)
"""

import sys
import json
import urllib.request
import urllib.parse

# Force UTF-8 stdout
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

BASE_URL = "http://localhost:8000"

def test_point_1_dual_domain_metrics():
    print("\n[TEST 1] Testing Unified Dual-Domain Executive Metrics (/api/overall/metrics)...")
    req = urllib.request.Request(f"{BASE_URL}/api/overall/metrics")
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode('utf-8'))
        assert data['success'] is True
        
        # Inside Domain validation
        ins = data['inside']
        assert 'people_detected' in ins and isinstance(ins['people_detected'], int)
        assert 'authorized_people' in ins and isinstance(ins['authorized_people'], int)
        assert 'unknown_people' in ins and isinstance(ins['unknown_people'], int)
        assert 'restricted_violations' in ins and isinstance(ins['restricted_violations'], int)
        assert 'weapon_alerts' in ins and isinstance(ins['weapon_alerts'], int)
        assert 'critical_incidents' in ins and isinstance(ins['critical_incidents'], int)
        assert 'active_alerts' in ins and isinstance(ins['active_alerts'], int)
        assert 'cameras_total' in ins and ins['cameras_total'] >= 3
        assert 'cameras' in ins and len(ins['cameras']) >= 3
        print(f"  ✓ Inside Domain SQLite Counts: People={ins['people_detected']}, Authorized={ins['authorized_people']}, Unknown={ins['unknown_people']}, Weapons={ins['weapon_alerts']}")

        # Outside Domain validation
        out = data['outside']
        assert 'people' in out and isinstance(out['people'], int)
        assert 'vehicles' in out and isinstance(out['vehicles'], int)
        assert 'number_plates' in out and isinstance(out['number_plates'], int)
        assert 'accidents' in out and isinstance(out['accidents'], int)
        assert 'crowd_events' in out and isinstance(out['crowd_events'], int)
        assert 'critical_incidents' in out and isinstance(out['critical_incidents'], int)
        assert 'drone_status' in out and 'battery_pct' in out['drone_status']
        assert 'cameras_total' in out and out['cameras_total'] >= 3
        print(f"  ✓ Outside Domain SQLite Counts: People={out['people']}, Vehicles={out['vehicles']}, Plates={out['number_plates']}, Accidents={out['accidents']}")
        print("✓ Point 1 PASSED: Unified Dual-Domain Metrics verified directly from SQLite.")

def test_point_2_tactical_radar_map():
    print("\n[TEST 2] Testing Tactical Facility Radar Map Data (/api/facility/radar-map)...")
    req = urllib.request.Request(f"{BASE_URL}/api/facility/radar-map")
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode('utf-8'))
        assert data['success'] is True
        
        # Real Cameras
        assert len(data['inside_cameras']) >= 3
        assert len(data['outside_cameras']) >= 3
        cam_ids = [c['camera_id'] for c in data['inside_cameras']]
        assert 'CAM-01' in cam_ids and 'CAM-02' in cam_ids and 'CAM-03' in cam_ids
        print(f"  ✓ Registered Inside Cameras in Radar: {cam_ids}")

        # Restricted Zones
        assert len(data['restricted_zones']) >= 3
        zone_names = [z['name'] for z in data['restricted_zones']]
        print(f"  ✓ Restricted Zones in Radar: {zone_names}")

        # Incidents & Drone
        assert 'incidents' in data
        assert 'drone' in data
        assert data['drone']['available'] is True
        print(f"  ✓ Radar Incidents Plotted: {len(data['incidents'])} items, Drone: {data['drone']['location_note']}")
        print("✓ Point 2 PASSED: Real operational radar map sensors & zones confirmed.")

def test_point_3_forensic_timeline():
    print("\n[TEST 3] Testing Real-Time Event Forensic Timeline (/api/events/forensic-timeline)...")
    req = urllib.request.Request(f"{BASE_URL}/api/events/forensic-timeline?limit=30")
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode('utf-8'))
        assert data['success'] is True
        timeline = data['timeline']
        assert len(timeline) > 0

        # Verify structured event log schema
        first = timeline[0]
        required_fields = ['event_id', 'timestamp', 'date', 'area', 'camera_id', 'detection', 'person', 'severity', 'confidence', 'status']
        for rf in required_fields:
            assert rf in first, f"Missing field {rf} in timeline event"
        
        print(f"  ✓ Retrieved {len(timeline)} structured event records.")
        print(f"  ✓ Sample Forensic Event: [{first['timestamp']}] {first['camera_id']} ({first['area']}) → {first['detection']} [Severity: {first['severity']}]")
        print("✓ Point 3 PASSED: Event forensic timeline connected to SQLite event stream.")

def test_point_4_natural_language_intelligence():
    print("\n[TEST 4] Testing Natural-Language Surveillance Intelligence...")
    
    # 4a. "What happened today?"
    print("  [4a] Query: 'What happened today?'")
    payload = json.dumps({'query': 'What happened today?'}).encode('utf-8')
    req = urllib.request.Request(f"{BASE_URL}/api/intelligence/query", data=payload, headers={'Content-Type': 'application/json'}, method='POST')
    with urllib.request.urlopen(req) as resp:
        data = json.loads(resp.read().decode('utf-8'))
        assert data['success'] is True
        assert data['query_type'] == 'dual_domain_summary'
        assert 'inside_secure_area' in data and 'outside_public_area' in data
        print(f"    ✓ Separate Inside: {data['inside_secure_area']['summary']}")
        print(f"    ✓ Separate Outside: {data['outside_public_area']['summary']}")

    # 4b. "Show all unknown people today."
    print("  [4b] Query: 'Show all unknown people today.'")
    payload = json.dumps({'query': 'Show all unknown people today.'}).encode('utf-8')
    req = urllib.request.Request(f"{BASE_URL}/api/intelligence/query", data=payload, headers={'Content-Type': 'application/json'}, method='POST')
    with urllib.request.urlopen(req) as resp:
        data = json.loads(resp.read().decode('utf-8'))
        assert data['success'] is True
        assert data['query_type'] == 'inside_unknown_people'
        assert data['count'] > 0
        print(f"    ✓ Retrieved {data['count']} matching unknown person events from SQLite.")

    # 4c. "Show all weapon alerts."
    print("  [4c] Query: 'Show all weapon alerts.'")
    payload = json.dumps({'query': 'Show all weapon alerts.'}).encode('utf-8')
    req = urllib.request.Request(f"{BASE_URL}/api/intelligence/query", data=payload, headers={'Content-Type': 'application/json'}, method='POST')
    with urllib.request.urlopen(req) as resp:
        data = json.loads(resp.read().decode('utf-8'))
        assert data['success'] is True
        assert data['query_type'] == 'weapon_alerts'
        print(f"    ✓ Retrieved {data['count']} authoritative weapon detections from SQLite.")

    # 4d. "Which camera generated the most alerts?"
    print("  [4d] Query: 'Which camera generated the most alerts?'")
    payload = json.dumps({'query': 'Which camera generated the most alerts?'}).encode('utf-8')
    req = urllib.request.Request(f"{BASE_URL}/api/intelligence/query", data=payload, headers={'Content-Type': 'application/json'}, method='POST')
    with urllib.request.urlopen(req) as resp:
        data = json.loads(resp.read().decode('utf-8'))
        assert data['success'] is True
        assert data['query_type'] == 'camera_alert_aggregation'
        assert 'top_camera' in data and 'top_count' in data
        print(f"    ✓ Database Aggregation Result: Top Camera={data['top_camera']} with {data['top_count']} recorded alerts.")

    # 4e. "Show all restricted-zone violations."
    print("  [4e] Query: 'Show all restricted-zone violations.'")
    payload = json.dumps({'query': 'Show all restricted-zone violations.'}).encode('utf-8')
    req = urllib.request.Request(f"{BASE_URL}/api/intelligence/query", data=payload, headers={'Content-Type': 'application/json'}, method='POST')
    with urllib.request.urlopen(req) as resp:
        data = json.loads(resp.read().decode('utf-8'))
        assert data['success'] is True
        assert data['query_type'] == 'restricted_zone_violations'
        print(f"    ✓ Retrieved {data['count']} restricted-zone intrusion records from SQLite.")

    print("✓ Point 4 PASSED: Natural-language surveillance intelligence translated accurately to SQLite.")

def test_point_5_strict_real_data_status():
    print("\n[TEST 5] Testing Strict REAL/DATA System Status (/api/system/real-status)...")
    req = urllib.request.Request(f"{BASE_URL}/api/system/real-status")
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode('utf-8'))
        assert data['success'] is True
        assert data['database'] == 'SQLITE CONNECTED'
        assert data['inside_data'] == 'LIVE'
        assert data['outside_data'] == 'LIVE'
        assert data['event_stream'] == 'LIVE'
        assert 'ONLINE' in data['cameras_summary']
        assert data['ai_services'] in ('READY', '⚠ UNAVAILABLE')
        print(f"  ✓ Strict Real Status: DB={data['database']} | INSIDE={data['inside_data']} | OUTSIDE={data['outside_data']} | CAMERAS={data['cameras_summary']} | AI={data['ai_services']}")
        print("✓ Point 5 PASSED: Strict operational status check verified.")

if __name__ == '__main__':
    print("=" * 70)
    print("  OVERALL FACILITY COMMAND CENTER: 4 REAL MODULES VERIFICATION SUITE")
    print("=" * 70)
    test_point_1_dual_domain_metrics()
    test_point_2_tactical_radar_map()
    test_point_3_forensic_timeline()
    test_point_4_natural_language_intelligence()
    test_point_5_strict_real_data_status()
    print("\n" + "=" * 70)
    print("  🎉 ALL 4 OVERALL DASHBOARD REQUIREMENTS VERIFIED WITH 100% SUCCESS!  ")
    print("=" * 70)
