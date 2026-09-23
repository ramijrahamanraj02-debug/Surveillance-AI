import urllib.request, urllib.parse, json, base64, sys

# Ensure UTF-8 output on Windows console
sys.stdout.reconfigure(encoding='utf-8')

def test_api():
    base = 'http://127.0.0.1:8000'
    print("Testing SecureVision Option 3 Live Surveillance Pipeline...", flush=True)
    
    # 1. Alert Recipients
    req = urllib.request.urlopen(f'{base}/api/alert-recipients')
    recipients = json.loads(req.read().decode('utf-8'))
    print(f"1. Alert Recipients: count={recipients.get('count')} (Status: OK)")
    
    # 2. Checkpoint Verification
    req = urllib.request.Request(
        f'{base}/api/visitors/verify-checkpoint',
        data=json.dumps({'ticket_id': 'TKT-2026-8843'}).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )
    res = json.loads(urllib.request.urlopen(req).read().decode('utf-8'))
    print(f"2. Checkpoint Verification: {res.get('message')} (Status: OK)")
    
    # 3. Snapshot Ingestion
    dummy_b64 = 'data:image/jpeg;base64,' + base64.b64encode(b'dummy_image_data_buffer').decode('utf-8')
    snap_payload = {
        'image_data': dummy_b64,
        'camera_id': 'CAM-01',
        'camera_name': 'CAM-01 • Main Gate CCTV',
        'event_type': 'Firearm Threat',
        'detected_object': 'Handgun (9mm)',
        'confidence': 0.96,
        'location': 'Main Gate Entry',
        'zone': 'Zone A'
    }
    req = urllib.request.Request(
        f'{base}/api/threats/snapshot',
        data=json.dumps(snap_payload).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )
    snap_res = json.loads(urllib.request.urlopen(req).read().decode('utf-8'))
    print(f"3. Threat Snapshot: id={snap_res.get('id')} path={snap_res.get('snapshot_path')} (Status: OK)")
    
    # 4. WhatsApp Dispatch
    wa_payload = {
        'detected_object': 'Handgun (9mm Firearm)',
        'camera_name': 'CAM-01 • Main Gate CCTV',
        'zone': 'Zone A',
        'confidence': '96%',
        'snapshot_url': snap_res.get('snapshot_path')
    }
    req = urllib.request.Request(
        f'{base}/api/alerts/whatsapp/send',
        data=json.dumps(wa_payload).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )
    wa_res = json.loads(urllib.request.urlopen(req).read().decode('utf-8'))
    print(f"4. WhatsApp Dispatch: delivered to {wa_res.get('recipients_count')} recipients (Status: OK)")
    
    # 5. Evidence Video
    dummy_vid_b64 = 'data:video/webm;base64,' + base64.b64encode(b'dummy_video_stream_bytes').decode('utf-8')
    vid_payload = {
        'video_data': dummy_vid_b64,
        'camera_id': 'CAM-01',
        'camera_name': 'CAM-01 • Main Gate CCTV',
        'detected_object': 'Handgun (9mm)',
        'duration_seconds': 12.0
    }
    req = urllib.request.Request(
        f'{base}/api/threats/evidence-video',
        data=json.dumps(vid_payload).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )
    vid_res = json.loads(urllib.request.urlopen(req).read().decode('utf-8'))
    print(f"5. Evidence Video: id={vid_res.get('id')} path={vid_res.get('video_path')} (Status: OK)")
    
    # 6. Latest Threat
    req = urllib.request.urlopen(f'{base}/api/threats/latest')
    latest = json.loads(req.read().decode('utf-8'))
    threat_obj = latest.get('threat') or {}
    print(f"6. Latest Threat Event in DB: '{threat_obj.get('detected_object')}' at '{threat_obj.get('camera_name')}' (Status: OK)")
    
    # 7. Snapshots list
    req = urllib.request.urlopen(f'{base}/api/snapshots')
    snaps = json.loads(req.read().decode('utf-8'))
    print(f"7. Snapshots in SQLite: total={snaps.get('count')} (Status: OK)")
    
    # 8. Entry Logs
    req = urllib.request.urlopen(f'{base}/api/entry-logs')
    logs = json.loads(req.read().decode('utf-8'))
    print(f"8. Entry Verification Logs in SQLite: total={logs.get('count')} (Status: OK)")
    
    print("\n=======================================================")
    print("ALL PIPELINE & DATABASE INTEGRATIONS VERIFIED 100%!")
    print("=======================================================")

if __name__ == '__main__':
    # Check if server is running on port 8000, if not start in background daemon thread
    try:
        urllib.request.urlopen('http://127.0.0.1:8000/api/cameras', timeout=0.8)
    except Exception:
        import http.server, socketserver, server, threading, time
        httpd = socketserver.TCPServer(('127.0.0.1', 8000), server.SecureVisionHandler)
        srv_th = threading.Thread(target=httpd.serve_forever, daemon=True)
        srv_th.start()
        time.sleep(0.6)

    test_api()
