import sys
import threading
import time
import urllib.request
import urllib.parse
import json
import http.server
import server

# Force UTF-8 stdout
if sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

def run_http_tests():
    port = 8089
    httpd = http.server.HTTPServer(('127.0.0.1', port), server.SecureVisionHandler)
    server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(0.5)

    base_url = f"http://127.0.0.1:{port}"

    print(f"[HTTP] Server running on {base_url}")

    # 1. GET /api/visitors
    with urllib.request.urlopen(f"{base_url}/api/visitors") as res:
        assert res.status == 200
        data = json.loads(res.read().decode('utf-8'))
        assert 'visitors' in data and 'kpis' in data
        print(f"✓ GET /api/visitors returned {len(data['visitors'])} visitors and KPIs: {data['kpis']}")
        first_ticket = data['visitors'][0]['ticket_id'] if data['visitors'] else None

    # 2. GET /api/tickets/<ticket_id>
    if first_ticket:
        with urllib.request.urlopen(f"{base_url}/api/tickets/{urllib.parse.quote(first_ticket)}") as res:
            assert res.status == 200
            ticket_data = json.loads(res.read().decode('utf-8'))
            assert ticket_data['success'] is True
            assert ticket_data['ticket']['ticket_id'] == first_ticket
            print(f"✓ GET /api/tickets/{first_ticket} retrieved authoritative SQLite ticket.")

    # 3. GET /api/visitors/repair-tickets
    with urllib.request.urlopen(f"{base_url}/api/visitors/repair-tickets") as res:
        assert res.status == 200
        repair_data = json.loads(res.read().decode('utf-8'))
        assert repair_data['success'] is True
        print(f"✓ GET /api/visitors/repair-tickets succeeded: {repair_data['message']}")

    # 4. POST /api/visitors/register
    reg_payload = {
        'full_name': "Dr. Sarah D'Angelo",
        'email': "sarah.dangelo@security.ai",
        'mobile_number': "+1 415 555 0199",
        'whatsapp_number': "+1 415 555 0199",
        'visit_date': "2026-08-31",
        'visit_time': "04:00 PM",
        'purpose': "Security Architecture Audit",
        'department': "Executive Wing",
        'host_name': "Commander Vance",
        'authorization_level': "VIP Visitor",
        'allowed_zone': "All Zones (Full Access Pass)",
        'status': "Approved"
    }

    req = urllib.request.Request(
        f"{base_url}/api/visitors/register",
        data=json.dumps(reg_payload).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )
    with urllib.request.urlopen(req) as res:
        assert res.status == 200
        reg_res = json.loads(res.read().decode('utf-8'))
        assert reg_res['success'] is True
        new_ticket_id = reg_res['ticket']['ticket_id']
        print(f"✓ POST /api/visitors/register generated ticket {new_ticket_id} for {reg_payload['full_name']}")

    # 5. POST /api/visitors/check-in
    checkin_req = urllib.request.Request(
        f"{base_url}/api/visitors/check-in",
        data=json.dumps({'identifier': new_ticket_id}).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )
    with urllib.request.urlopen(checkin_req) as res:
        assert res.status == 200
        checkin_res = json.loads(res.read().decode('utf-8'))
        assert checkin_res['success'] is True
        print(f"✓ POST /api/visitors/check-in verified ticket: {checkin_res['message']}")

    httpd.shutdown()
    print("\n🎉 ALL HTTP ENDPOINTS & SQLITE PERSISTENCE VERIFIED SUCCESSFULLY!")

if __name__ == '__main__':
    run_http_tests()
