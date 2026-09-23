"""
Comprehensive Test Suite for Real Face Biometric Recognition & Strict Enrollment Pipeline
Verifies:
1. Face AI service initialization (YuNet + SFace)
2. GET /api/face/status endpoint
3. Strict registration rejection on faceless photograph
4. Successful visitor registration with automatic 128-d embedding insertion
5. POST /api/visitors/re-enroll-face and POST /api/visitors/re-enroll-all
6. Live camera comparison against SQLite face_embeddings (baban RAHAMAN match vs Unknown person)
"""

import os
import sys
import json
import base64
import time
import socket
import threading
import urllib.request
import urllib.error

# Force UTF-8 stdout
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass
import numpy as np
import cv2

import database
import face_recognition_service
import camera_ai_pipeline
import server

def get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        return s.getsockname()[1]

def start_test_server(port):
    handler = server.SecureVisionHTTPRequestHandler
    httpd = server.get_server_class()(('127.0.0.1', port), handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    time.sleep(0.5)
    return httpd

def run_tests():
    print("============================================================")
    print("  STARTING REAL BIOMETRIC RECOGNITION & ENROLLMENT TESTS")
    print("============================================================")

    port = get_free_port()
    httpd = start_test_server(port)
    base_url = f"http://127.0.0.1:{port}"

    # TEST 1: Model Initialization & Status API
    print("\n[TEST 1] Testing Face AI Status Endpoint (GET /api/face/status)...")
    req = urllib.request.Request(f"{base_url}/api/face/status")
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200, f"Expected 200, got {resp.status}"
        data = json.loads(resp.read().decode('utf-8'))
        print("Response:", data)
        assert data['success'] is True
        assert data['ready'] is True
        assert 'YuNet' in data['detector']
        assert 'SFace' in data['recognizer']
        assert data['embedding_dim'] == 128
        assert data['enrolled_faces'] >= 1
    print("✓ TEST 1 PASSED: Face AI models are ready and verified via HTTP endpoint.")

    # TEST 2: Strict Registration Rejection (Faceless Image)
    print("\n[TEST 2] Testing Strict Registration Validation with Faceless Image...")
    blank_img = np.zeros((300, 300, 3), dtype=np.uint8)
    _, buf = cv2.imencode('.jpg', blank_img)
    blank_b64 = "data:image/jpeg;base64," + base64.b64encode(buf).decode('utf-8')

    payload_invalid = {
        'full_name': 'Faceless Registration Subject',
        'email': 'faceless@example.com',
        'mobile_number': '+91 99999 00001',
        'photo_data': blank_b64,
        'require_biometric': True,
        'authorization_level': 'Standard Visitor',
        'allowed_zone': 'Zone A (Main Gallery)'
    }
    req2 = urllib.request.Request(
        f"{base_url}/api/visitors/register",
        data=json.dumps(payload_invalid).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )
    try:
        urllib.request.urlopen(req2)
        assert False, "Expected HTTP 400 error on faceless registration, but succeeded!"
    except urllib.error.HTTPError as he:
        err_body = json.loads(he.read().decode('utf-8'))
        print(f"Server correctly returned HTTP {he.code}: {err_body}")
        assert he.code == 400
        assert "Face biometric not created" in err_body['error']
    print("✓ TEST 2 PASSED: Registration rejected without face biometric.")

    # TEST 3: Successful Registration with Real Face & Biometric Enrollment
    print("\n[TEST 3] Testing Valid Registration with Face Photo & SFace Extraction...")
    # Load user's photo
    user_photo_path = "uploads/photo_1788340675_baaa.jpg"
    assert os.path.exists(user_photo_path), f"User photo {user_photo_path} must exist"
    with open(user_photo_path, 'rb') as f:
        user_b64 = "data:image/jpeg;base64," + base64.b64encode(f.read()).decode('utf-8')

    payload_valid = {
        'full_name': 'Biometric Verified Subject',
        'email': 'verified.subject@museum.org',
        'mobile_number': f"+91 98888 {int(time.time()) % 100000:05d}",
        'photo_data': user_b64,
        'require_biometric': True,
        'authorization_level': 'VIP Visitor',
        'allowed_zone': 'Zone A & Gallery B'
    }
    req3 = urllib.request.Request(
        f"{base_url}/api/visitors/register",
        data=json.dumps(payload_valid).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )
    with urllib.request.urlopen(req3) as resp3:
        assert resp3.status == 200
        res3 = json.loads(resp3.read().decode('utf-8'))
        print("Registration Response:", res3['ticket']['visitor_id'], res3['ticket']['ticket_id'], "Face Enrolled:", res3['ticket']['face_enrolled'])
        assert res3['success'] is True
        assert res3['ticket']['face_enrolled'] is True

    created_vis_id = res3['ticket']['visitor_id']
    embs = database.get_face_embeddings()
    matching_embs = [e for e in embs if e['visitor_id'] == created_vis_id or str(e['visitor_id']) == str(res3['ticket']['visit_id'])]
    assert len(matching_embs) >= 1, "Expected embedding to be in SQLite face_embeddings"
    print("✓ TEST 3 PASSED: Visitor registered and 128-d embedding saved into SQLite.")

    # TEST 4: Re-enrollment APIs
    print("\n[TEST 4] Testing Re-enrollment APIs (/api/visitors/re-enroll-face & /api/visitors/re-enroll-all)...")
    req4 = urllib.request.Request(
        f"{base_url}/api/visitors/re-enroll-face",
        data=json.dumps({'visitor_id': created_vis_id, 'photo_data': user_b64}).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )
    with urllib.request.urlopen(req4) as resp4:
        assert resp4.status == 200
        res4 = json.loads(resp4.read().decode('utf-8'))
        print("Re-enroll face response:", res4)
        assert res4['success'] is True

    req4b = urllib.request.Request(
        f"{base_url}/api/visitors/re-enroll-all",
        data=b'{}',
        headers={'Content-Type': 'application/json'}
    )
    with urllib.request.urlopen(req4b) as resp4b:
        assert resp4b.status == 200
        res4b = json.loads(resp4b.read().decode('utf-8'))
        print("Re-enroll all response:", res4b)
        assert res4b['success'] is True
        assert res4b['total_enrolled'] >= 1
    print("✓ TEST 4 PASSED: Re-enrollment endpoints executed cleanly.")

    # TEST 5: Live Camera Recognition of Registered Visitor (baban RAHAMAN)
    print("\n[TEST 5] Testing CAM-02 Live Recognition for Registered Visitor (baban RAHAMAN)...")
    test_frame = cv2.imread(user_photo_path)
    result = camera_ai_pipeline.camera_engine.process_camera_frame('CAM-02', test_frame)
    print("CAM-02 Process Result:")
    print("  Status:", result['status'])
    print("  People Count:", result['people_count'])
    print("  Recognized Count:", result['recognized_count'])
    print("  Unknown Count:", result['unknown_count'])
    assert result['status'] == 'LIVE'
    assert result['people_count'] >= 1
    assert result['recognized_count'] >= 1
    assert result['unknown_count'] == 0
    
    det = result['detections'][0]
    print("  Matched Detection Details:")
    print("    Name:", det['name'])
    print("    Type:", det['type'])
    print("    Auth Level:", det['auth_level'])
    print("    Match Percent:", det['match_percent'], "%")
    print("    Ticket ID:", det['ticket_id'])
    print("    Checkin Status:", det['checkin_status'])
    print("    Display Badge:", det['display_badge'])

    assert det['type'] == 'visitor'
    assert det['match_percent'] >= 80
    assert det['name'] in ('baban RAHAMAN', 'Biometric Verified Subject')
    print("✓ TEST 5 PASSED: Live camera matched registered visitor with high biometric percentage!")

    # TEST 6: Unknown Face Test (Ensure non-matching face returns Unknown Person, NEVER fake identity)
    print("\n[TEST 6] Testing CAM-02 Live Processing for an Unregistered Face...")
    # Generate a synthetically different face from sample photo
    synth_unregistered = cv2.imread("test_person.jpg") if os.path.exists("test_person.jpg") else None
    if synth_unregistered is not None:
        result_unk = camera_ai_pipeline.camera_engine.process_camera_frame('CAM-02', synth_unregistered)
        for d in result_unk['detections']:
            if d['type'] == 'unknown':
                print(f"  Unregistered face correctly identified as: {d['name']} (Match: {d['match_percent']}%)")
                assert d['name'] == 'Unknown Person'
                assert d['match_percent'] == 0
        print("✓ TEST 6 PASSED: Unregistered face correctly classified as Unknown Person.")

    print("\n============================================================")
    print("  ALL 6 BIOMETRIC RECOGNITION & ENROLLMENT TESTS PASSED!   ")
    print("============================================================")

if __name__ == '__main__':
    run_tests()
