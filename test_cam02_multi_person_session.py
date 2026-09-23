"""
Multi-person recognition session & debounce verification test for CAM-02.
Verifies:
1. Person 1 (Baban Rahaman) detected -> Latest Event is Baban.
2. Same session debounce (frames within 4.5s) -> No duplicate event logged.
3. Person 2 (Another Registered Visitor) detected -> Latest Event becomes Person 2; Person 1 is in Recent Events.
4. Unknown person detected -> Marked 'NO MATCH', 'NOT REGISTERED', 'Name: Unknown', 'Visitor ID: —'.
"""
import time
import base64
import numpy as np
import cv2
import database
import camera_ai_pipeline
from face_recognition_service import face_service

def create_face(seed, color=(210, 180, 150)):
    np.random.seed(seed)
    img = np.full((480, 640, 3), 120, dtype=np.uint8)
    cv2.ellipse(img, (320, 240), (100, 140), 0, 0, 360, color, -1)
    cv2.circle(img, (280, 210), 12, (255, 255, 255), -1)
    cv2.circle(img, (280, 210), 6, (40, 40, 40), -1)
    cv2.circle(img, (360, 210), 12, (255, 255, 255), -1)
    cv2.circle(img, (360, 210), 6, (40, 40, 40), -1)
    cv2.line(img, (265, 195), (295, 195), (40, 30, 20), 4)
    cv2.line(img, (345, 195), (375, 195), (40, 30, 20), 4)
    cv2.line(img, (320, 215), (320, 260), (160, 130, 110), 4)
    cv2.ellipse(img, (320, 290), (35, 15), 0, 0, 180, (80, 60, 160), -1)
    return img

def main():
    database.init_db()
    engine = camera_ai_pipeline.camera_engine
    engine._active_sessions.clear()
    engine._event_debounce.clear()

    # Step 1: Enroll Person 1 (Baban Rahaman)
    face1 = create_face(seed=101)
    _, buf1 = cv2.imencode('.jpg', face1)
    b64_1 = "data:image/jpeg;base64," + base64.b64encode(buf1).decode('utf-8')
    res1 = database.create_visitor_and_visit({
        'full_name': 'Baban Rahaman',
        'phone': '+91 99999 11111',
        'email': 'baban@test.local',
        'visitor_type': 'Official',
        'purpose': 'Audit',
        'department': 'Security',
        'host_name': 'Host A',
        'visit_date': time.strftime('%Y-%m-%d'),
        'visit_time': '10:00 AM',
        'allowed_zone': 'Zone A (Main Gallery)',
        'photo_data': b64_1
    })
    vis1_id = res1['visitor_id']
    print(f"Enrolled Person 1: Baban Rahaman ({vis1_id})")

    # Step 2: Enroll Person 2 (Another Registered Visitor)
    face2 = create_face(seed=202, color=(190, 160, 130))
    _, buf2 = cv2.imencode('.jpg', face2)
    b64_2 = "data:image/jpeg;base64," + base64.b64encode(buf2).decode('utf-8')
    res2 = database.create_visitor_and_visit({
        'full_name': 'Sarah Jenkins',
        'phone': '+91 99999 22222',
        'email': 'sarah@test.local',
        'visitor_type': 'VIP',
        'purpose': 'Inspection',
        'department': 'Operations',
        'host_name': 'Host B',
        'visit_date': time.strftime('%Y-%m-%d'),
        'visit_time': '10:15 AM',
        'allowed_zone': 'Zone A (Main Gallery)',
        'photo_data': b64_2
    })
    vis2_id = res2['visitor_id']
    print(f"Enrolled Person 2: Sarah Jenkins ({vis2_id})")

    # TEST A: Person 1 (Baban) appears in front of CAM-02
    print("\n--- TEST A: Person 1 (Baban) detected on CAM-02 ---")
    st1 = engine.process_camera_frame('CAM-02', face1)
    ev1 = st1['latest_event']
    assert ev1 is not None, "ev1 should not be None"
    print(f"Latest Event Name: {ev1['name']}")
    print(f"Latest Event Visitor ID: {ev1['visitor_id']}")
    print(f"Latest Event Recognition: {ev1['recognition']}")
    print(f"Latest Event Camera: {ev1['camera_name']}")
    assert 'Baban' in ev1['name']
    assert ev1['visitor_id'].startswith('VIS-')
    assert ev1['recognition'] == 'MATCHED'
    assert ev1['status'] == 'VERIFIED'
    ev1_id = ev1['id']
    vis1_actual_id = ev1['visitor_id']
    print(f"✓ Test A Passed: Latest Event is Baban Rahaman with actual SQLite Visitor ID ({vis1_actual_id}).")

    # TEST B: Debounce frame spam (00:28:31, 00:28:32, etc.)
    print("\n--- TEST B: Same Person (Baban) continues in front of camera (Frame Spam) ---")
    st1_again = engine.process_camera_frame('CAM-02', face1)
    ev1_again = st1_again['latest_event']
    assert ev1_again['id'] == ev1_id, "Should reuse existing event in same recognition session without creating duplicate!"
    print("✓ Test B Passed: Continuous session recognized; no duplicate SQLite event created.")

    # TEST C: Person 2 (Sarah Jenkins) appears in front of CAM-02
    print("\n--- TEST C: Person 2 (Sarah Jenkins) detected on CAM-02 ---")
    st2 = engine.process_camera_frame('CAM-02', face2)
    ev2 = st2['latest_event']
    assert ev2 is not None, "ev2 should not be None"
    print(f"New Latest Event Name: {ev2['name']}")
    print(f"New Latest Event Visitor ID: {ev2['visitor_id']}")
    print(f"New Latest Event Recognition: {ev2['recognition']}")
    assert 'Sarah' in ev2['name']
    assert ev2['visitor_id'] == vis2_id
    assert ev2['recognition'] == 'MATCHED'
    
    # Check that Person 1 is now in Recent Events!
    recents = st2.get('recent_events', [])
    print(f"Recent events count: {len(recents)}")
    found_p1 = any(e['id'] == ev1_id or 'Baban' in str(e.get('person', '')) for e in recents)
    assert found_p1, "Person 1 (Baban) should now be present in Recent Events list!"
    print(f"✓ Test C Passed: Person 2 is Latest Event ({ev2['name']}), and Person 1 (Baban) has moved to Recent Events!")

    # TEST D: Unregistered person appears
    print("\n--- TEST D: Unregistered Person appears on CAM-02 ---")
    face_unk = create_face(seed=303, color=(160, 130, 110))
    # Clear sessions to simulate new person arriving
    engine._active_sessions['CAM-02'] = None
    # Temporarily mock embeddings to simulate unknown
    orig_emb = database.get_face_embeddings
    try:
        database.get_face_embeddings = lambda: []
        st_unk = engine.process_camera_frame('CAM-02', face_unk)
        ev_unk = st_unk['latest_event']
        assert ev_unk is not None
        print(f"Unregistered Event Name: {ev_unk['name']}")
        print(f"Unregistered Event Visitor ID: {ev_unk['visitor_id']}")
        print(f"Unregistered Event Recognition: {ev_unk['recognition']}")
        print(f"Unregistered Event Status: {ev_unk['status']}")
        assert ev_unk['name'] == 'Unknown'
        assert ev_unk['visitor_id'] == '—'
        assert ev_unk['recognition'] == 'NO MATCH'
        assert ev_unk['status'] == 'NOT REGISTERED'
        assert ev_unk['is_verified'] is False
        print("✓ Test D Passed: Unregistered person strictly logged as 'NO MATCH' / 'NOT REGISTERED'.")
    finally:
        database.get_face_embeddings = orig_emb

    print("\n" + "=" * 60)
    print("ALL MULTI-PERSON & RECOGNITION SESSION TESTS PASSED! ✓")
    print("=" * 60)

if __name__ == '__main__':
    main()
