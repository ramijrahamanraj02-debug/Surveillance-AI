"""
test_camera_ai_pipeline.py
Unit and Integration Tests for Real-world Camera AI Pipeline:
  - Database schema & cleanup verification (CAM-01, CAM-02, CAM-03 only)
  - Automatic YuNet + SFace face embedding enrollment on visitor registration
  - Live frame processing: Face detection, SFace extraction, SQLite matching
  - Check-in status separation: "Check-in required" vs "Checked In"
  - Quick check-in operation updating SQLite state
  - Real SQLite KPIs and live counter queries (zero fake numbers)
  - Strict weapon detection separation
"""

import os
import sys
import json
import time
import numpy as np

if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

try:
    import cv2
except ImportError:
    cv2 = None

import database
import face_recognition_service
import camera_ai_pipeline

def create_synthetic_face_image():
    """Generates a synthetic 300x300 image with facial features for testing."""
    img = np.ones((300, 300, 3), dtype=np.uint8) * 180
    # Head / Face oval
    cv2.ellipse(img, (150, 150), (70, 95), 0, 0, 360, (140, 175, 220), -1)
    # Eyes
    cv2.circle(img, (125, 130), 12, (255, 255, 255), -1)
    cv2.circle(img, (175, 130), 12, (255, 255, 255), -1)
    cv2.circle(img, (125, 130), 5, (40, 40, 40), -1)
    cv2.circle(img, (175, 130), 5, (40, 40, 40), -1)
    # Eyebrows
    cv2.line(img, (110, 115), (140, 115), (30, 30, 30), 3)
    cv2.line(img, (160, 115), (190, 115), (30, 30, 30), 3)
    # Nose
    cv2.line(img, (150, 135), (150, 170), (100, 130, 180), 3)
    cv2.line(img, (145, 170), (155, 170), (100, 130, 180), 3)
    # Mouth
    cv2.ellipse(img, (150, 195), (25, 10), 0, 0, 180, (50, 50, 160), 3)
    return img

def test_camera_database_cleanup():
    print("\n[TEST 1] Testing Camera Database Cleanup...")
    cams = database.get_all_cameras(area='Inside')
    cam_ids = [c['camera_id'] for c in cams]
    print(f"Inside Cameras found: {cam_ids}")
    assert 'CAM-01' in cam_ids, "CAM-01 (CCTV) must exist"
    assert 'CAM-02' in cam_ids, "CAM-02 (Laptop) must exist"
    assert 'CAM-03' in cam_ids, "CAM-03 (Mobile) must exist"
    assert 'CAM-04' not in cam_ids, "CAM-04 should have been purged"
    assert 'CAM-05' not in cam_ids, "CAM-05 should have been purged"
    print("✓ Test 1 Passed: Camera whitelist CAM-01..CAM-03 confirmed.")

def test_sqlite_live_counters():
    print("\n[TEST 2] Testing SQLite-backed Live Counters (Zero fake numbers)...")
    counters = database.get_live_counters()
    print("Live counters:", counters)
    assert 'people_today' in counters
    assert 'recognized_visitors' in counters
    assert 'active_visitors' in counters
    assert 'weapons_detected' in counters
    assert 'daily_summary' in counters
    daily = counters['daily_summary']
    assert isinstance(daily['totalPeople'], int)
    assert isinstance(daily['authorizedPeople'], int)
    assert isinstance(daily['unknownPeople'], int)
    print("✓ Test 2 Passed: Dynamic SQLite aggregation confirmed.")

def test_face_enrollment_and_matching():
    print("\n[TEST 3] Testing Automatic Face Enrollment & Real Matching...")
    svc = face_recognition_service.face_service
    assert svc.is_ready, "FaceRecognitionService models must be initialized"
    
    # Generate test image and encode as base64
    synthetic_img = create_synthetic_face_image()
    ok, buf = cv2.imencode('.jpg', synthetic_img)
    assert ok, "Image encoding failed"
    import base64
    b64_str = "data:image/jpeg;base64," + base64.b64encode(buf).decode('ascii')
    
    # Register test visitor with photo
    test_vis_data = {
        'full_name': 'Test Officer Sharma',
        'mobile_number': '+91 99999 11111',
        'purpose': 'Security Audit',
        'allowed_zone': 'Zone A (Main Gallery)',
        'photo_data': b64_str
    }
    
    vis_res = database.create_visitor_and_visit(test_vis_data)
    assert vis_res.get('success'), f"Visitor registration failed: {vis_res}"
    print(f"Created visitor: {vis_res.get('visitor_id')}, Ticket: {vis_res.get('ticket_id')}")
    
    # Check if face embedding was auto-enrolled in SQLite
    embs = database.get_face_embeddings()
    matching_embs = [e for e in embs if e.get('visitor_id') == vis_res.get('visitor_id')]
    print(f"Found {len(matching_embs)} embeddings enrolled for {vis_res.get('visitor_id')}")
    assert len(matching_embs) >= 1, "Face embedding must be enrolled in SQLite"
    
    # Now run AI pipeline on the same test image
    engine = camera_ai_pipeline.camera_engine
    result = engine.process_camera_frame('CAM-02', synthetic_img)
    assert result is not None, "Pipeline execution failed"
    print(f"Camera result: status={result['status']}, detections={len(result['detections'])}")
    
    # Check detections
    dets = result.get('detections', [])
    assert len(dets) >= 1, "Should detect at least 1 person/face"
    matched_det = next((d for d in dets if d.get('type') == 'visitor'), None)
    assert matched_det is not None, "Should match registered visitor"
    assert matched_det['name'] == 'Test Officer Sharma'
    assert matched_det['ticket_id'] == vis_res.get('ticket_id')
    assert matched_det['is_checked_in'] is False, "Newly registered visitor must require check-in"
    assert matched_det['checkin_status'] == "Check-in required"
    print("✓ Recognition succeeded: 'Visitor detected — Check-in required'")

    # Test Quick Check-In
    print("\n[TEST 4] Testing Quick Check-In from CCTV Feed...")
    checkin_res = database.quick_checkin_visitor(vis_res.get('ticket_id'))
    assert checkin_res.get('success'), f"Check-in failed: {checkin_res}"
    print(f"Check-in response: {checkin_res}")

    # Re-run pipeline on the same frame: status should now be "Checked In"
    result2 = engine.process_camera_frame('CAM-02', synthetic_img)
    matched_det2 = next((d for d in result2.get('detections', []) if d.get('type') == 'visitor'), None)
    assert matched_det2 is not None
    assert matched_det2['is_checked_in'] is True, "Status must now be Checked In"
    assert matched_det2['checkin_status'] == "Checked In"
    assert matched_det2['color'] == '#10B981', "Color must be Green (#10B981) for authorized checked-in visitor"
    print("✓ Quick check-in succeeded: Status transitioned to 'Checked In'")

def test_strict_weapon_separation():
    print("\n[TEST 5] Testing Strict Weapon Separation (Face Match never equals Threat)...")
    synthetic_img = create_synthetic_face_image()
    engine = camera_ai_pipeline.camera_engine
    result = engine.process_camera_frame('CAM-02', synthetic_img)
    assert result['weapons_count'] == 0, "Normal face must NOT produce weapon detections"
    for d in result.get('detections', []):
        assert d['type'] != 'weapon', "Visitor detection must never be typed as weapon"
    print("✓ Strict weapon separation verified.")

if __name__ == '__main__':
    database.init_db()
    test_camera_database_cleanup()
    test_sqlite_live_counters()
    test_face_enrollment_and_matching()
    test_strict_weapon_separation()
    print("\n" + "=" * 60)
    print("  ALL 5 CAMERA AI PIPELINE TESTS PASSED SUCCESSFULLY!  ")
    print("=" * 60)
