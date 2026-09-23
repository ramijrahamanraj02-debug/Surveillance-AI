"""
Verification test for CAM-02 Face Recognition & Biometric Pipeline.
Tests:
- Registered visitor recognition (MATCH -> PERSON DETECTED, FACE VERIFIED)
- Unknown subject recognition (NO MATCH -> PERSON DETECTED, FACE NOT VERIFIED)
- Dual snapshot saving in snapshots/ and assets/snapshots/
- SQLite inside_events & entry_logs persistence
- HTTP POST /api/camera/process-frame
"""
import os
import sys
import time
import json
import base64
import urllib.request
import numpy as np

try:
    import cv2
except ImportError:
    print("OpenCV required for test")
    sys.exit(1)

import database
import camera_ai_pipeline
from face_recognition_service import face_service


def create_face_canvas(seed=42):
    np.random.seed(seed)
    img = np.full((480, 640, 3), 120, dtype=np.uint8)
    # Draw head
    cv2.ellipse(img, (320, 240), (100, 140), 0, 0, 360, (210, 180, 150), -1)
    # Eyes
    cv2.circle(img, (280, 210), 12, (255, 255, 255), -1)
    cv2.circle(img, (280, 210), 6, (40, 40, 40), -1)
    cv2.circle(img, (360, 210), 12, (255, 255, 255), -1)
    cv2.circle(img, (360, 210), 6, (40, 40, 40), -1)
    # Eyebrows
    cv2.line(img, (265, 195), (295, 195), (40, 30, 20), 4)
    cv2.line(img, (345, 195), (375, 195), (40, 30, 20), 4)
    # Nose
    cv2.line(img, (320, 215), (320, 260), (160, 130, 110), 4)
    # Mouth
    cv2.ellipse(img, (320, 290), (35, 15), 0, 0, 180, (80, 60, 160), -1)
    return img


def run_tests():
    database.init_db()
    print("=" * 60)
    print("RUNNING CAM-02 BIOMETRIC VERIFICATION TESTS")
    print("=" * 60)

    # 1. Create a known face
    test_face_bgr = create_face_canvas(seed=99)
    faces = face_service.detect_faces(test_face_bgr)
    print(f"Face detector detected {len(faces)} faces on synthetic face canvas.")

    # Encode to base64
    _, buf = cv2.imencode('.jpg', test_face_bgr)
    face_b64 = "data:image/jpeg;base64," + base64.b64encode(buf).decode('utf-8')

    visitor_data = {
        'full_name': 'Baban Rahaman',
        'phone': '+91 99999 88888',
        'email': 'baban.rahaman@test.gov',
        'visitor_type': 'Official',
        'purpose': 'Biometric Verification Audit',
        'department': 'Security Command',
        'host_name': 'Director Verma',
        'visit_date': time.strftime('%Y-%m-%d'),
        'visit_time': '10:00 AM',
        'allowed_zone': 'Zone A (Main Gallery)',
        'photo_data': face_b64
    }

    vis_res = database.create_visitor_and_visit(visitor_data)
    assert vis_res.get('success'), f"Failed to create visitor: {vis_res}"
    vis_id = vis_res['visitor_id']
    tkt_id = vis_res['ticket_id']
    print(f"Enrolled test visitor: {vis_id} ({visitor_data['full_name']}) Ticket: {tkt_id}")

    # 2. Test CAM-02 with matching face frame
    print("\n[TEST 1] Testing CAM-02 MATCH Pipeline...")
    engine = camera_ai_pipeline.camera_engine
    # Reset debounce to guarantee fresh snapshot capture
    engine._event_debounce.clear()

    res = engine.process_camera_frame('CAM-02', test_face_bgr)
    assert res is not None, "process_camera_frame returned None"
    assert res['status'] == 'LIVE'

    dets = res.get('detections', [])
    print(f"Detections count: {len(dets)}")
    assert len(dets) >= 1, "Expected at least 1 detection"

    matched = next((d for d in dets if d.get('type') == 'visitor' or d.get('is_verified')), None)
    assert matched is not None, "Expected matching registered visitor detection"
    print(f"Match detection details:")
    print(f"  Name: {matched.get('name')}")
    print(f"  Visitor ID: {matched.get('visitor_id')}")
    print(f"  Match %: {matched.get('match_percent')}%")
    print(f"  Authorization: {matched.get('authorization')}")
    print(f"  Status: {matched.get('status')}")
    print(f"  Is Verified: {matched.get('is_verified')}")

    assert matched['is_verified'] is True
    assert matched['status'] == 'VERIFIED'
    assert matched['authorization'] == 'Registered'
    assert 'Baban' in matched['name']
    assert matched['visitor_id'] == vis_id
    print("✓ TEST 1 PASSED: Registered face verified with all required fields.")

    # Check snapshot creation
    latest_event = res.get('latest_event')
    assert latest_event is not None, "Expected latest_event in result"
    snap_path = latest_event.get('snapshot_url') or latest_event.get('snapshot')
    print(f"Captured snapshot: {snap_path}")
    assert snap_path, "Snapshot path should not be empty"

    abs_snap = os.path.join(camera_ai_pipeline.BASE_DIR, snap_path)
    assert os.path.exists(abs_snap), f"Snapshot file does not exist on disk: {abs_snap}"
    print("✓ Snapshot exists in snapshots/")

    assets_snap = os.path.join(camera_ai_pipeline.ASSETS_SNAPSHOTS_DIR, os.path.basename(snap_path))
    assert os.path.exists(assets_snap), f"Snapshot file does not exist in assets/snapshots/: {assets_snap}"
    print("✓ Snapshot mirrored to assets/snapshots/")

    # Check SQLite inside_events
    inside_events = database.get_inside_events()
    recent_ev = next((e for e in inside_events if e.get('person') == matched['name']), None)
    assert recent_ev is not None, "Expected event in SQLite inside_events"
    print(f"SQLite inside_events record: {recent_ev['id']} for {recent_ev['person']}")
    print("✓ TEST 2 PASSED: SQLite event persistence confirmed.")

    # 3. Test Unknown face (NO MATCH scenario)
    print("\n[TEST 3] Testing CAM-02 UNKNOWN / NOT REGISTERED Pipeline...")
    engine._event_debounce.clear()
    orig_get_embeddings = database.get_face_embeddings
    try:
        # Simulate an unregistered person standing in front of CAM-02 (no matching embedding in SQLite)
        database.get_face_embeddings = lambda: []
        res_unk = engine.process_camera_frame('CAM-02', test_face_bgr)
        dets_unk = res_unk.get('detections', [])
        print(f"Unknown detection count: {len(dets_unk)}")
        unk_det = next((d for d in dets_unk if d.get('type') == 'unknown' or not d.get('is_verified')), None)
        assert unk_det is not None, "Expected unknown detection for unregistered subject"
        print(f"Unknown detection details:")
        print(f"  Name: {unk_det.get('name')}")
        print(f"  Visitor ID: {unk_det.get('visitor_id')}")
        print(f"  Match: {unk_det.get('match_percent')}")
        print(f"  Authorization: {unk_det.get('authorization')}")
        print(f"  Status: {unk_det.get('status')}")
        print(f"  Is Verified: {unk_det.get('is_verified')}")

        assert unk_det['is_verified'] is False
        assert unk_det['status'] == 'NOT REGISTERED'
        assert unk_det['authorization'] == 'Not Registered'
        assert unk_det['visitor_id'] == '—'
        assert unk_det['name'] == 'Unknown'
        print("✓ TEST 3 PASSED: Unknown face tagged as NOT REGISTERED.")
    finally:
        database.get_face_embeddings = orig_get_embeddings

    # 4. Test HTTP POST /api/camera/process-frame
    print("\n[TEST 4] Testing HTTP POST /api/camera/process-frame...")
    payload = json.dumps({'camera_id': 'CAM-02', 'image_data': face_b64}).encode('utf-8')

    req = urllib.request.Request(
        'http://localhost:8000/api/camera/process-frame',
        data=payload,
        headers={'Content-Type': 'application/json'},
        method='POST'
    )
    with urllib.request.urlopen(req, timeout=25) as response:
        assert response.status == 200
        resp_data = json.loads(response.read().decode('utf-8'))
        assert resp_data.get('success') is True
        assert 'camera' in resp_data
        cam_state = resp_data['camera']
        assert cam_state['camera_id'] == 'CAM-02'
        print(f"HTTP response: camera_id={cam_state['camera_id']}, status={cam_state['status']}, people={cam_state.get('people_count')}")
        print("✓ TEST 4 PASSED: HTTP API /api/camera/process-frame returns camera telemetry.")

    print("\n" + "=" * 60)
    print("ALL CAM-02 VERIFICATION TESTS PASSED SUCCESSFULLY! ✓")
    print("=" * 60)


if __name__ == '__main__':
    run_tests()
