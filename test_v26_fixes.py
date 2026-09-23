"""
Comprehensive Automated Test Suite for SecureVision AI Real-World Fix v2.6
Verifies:
1. Option 3 cameras (CAM-01, CAM-02, CAM-03) in SQLite
2. Live SQLite Counters
3. Face Recognition Service (YuNet + SFace)
4. Checkpoint State Checks & Biometric Verification
5. Alert Recipients CRUD & Field Name compatibility
6. Clean Video Pipeline (No fake gun keyword triggers)
7. Camera Settings Persistence (Username, Password, Resolution, FPS)
8. Network IP & Mobile LAN URL
"""

import os
import sys
import json
import sqlite3
import unittest
import numpy as np

import database
import detection_pipeline
import face_recognition_service
import server

class TestSecureVisionV26(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        database.init_db()

    def test_01_option3_cameras(self):
        """Option 3 has strictly CAM-01, CAM-02, and CAM-03 for Inside area."""
        cams = database.get_all_cameras(area='Inside')
        cam_ids = [c['camera_id'] for c in cams]
        print("\n[TEST 1] Inside Cameras in SQLite:", cam_ids)
        self.assertIn('CAM-01', cam_ids)
        self.assertIn('CAM-02', cam_ids)
        self.assertIn('CAM-03', cam_ids)
        self.assertEqual(len(cam_ids), 3, f"Expected exactly 3 cameras (CAM-01, CAM-02, CAM-03), got {cam_ids}")

    def test_02_camera_settings_persistence(self):
        """Camera settings are saved directly to SQLite (username, password, resolution, fps)."""
        update_data = {
            'username': 'admin_sec',
            'password': 'vault_password_99',
            'resolution': '4K UHD',
            'fps': 60,
            'location': 'Main Vault Alpha',
            'stream_url': 'rtsp://192.168.1.120:554/stream1'
        }
        ok = database.update_camera('CAM-01', update_data)
        self.assertTrue(ok)

        cam = database.get_camera_by_id('CAM-01')
        print("[TEST 2] Updated CAM-01 settings from SQLite:", {
            'username': cam.get('username'),
            'resolution': cam.get('resolution'),
            'fps': cam.get('fps'),
            'stream_url': cam.get('stream_url')
        })
        self.assertEqual(cam.get('username'), 'admin_sec')
        self.assertEqual(cam.get('password'), 'vault_password_99')
        self.assertEqual(cam.get('resolution'), '4K UHD')
        self.assertEqual(cam.get('fps'), 60)

    def test_03_live_sqlite_counters(self):
        """Live counters are fetched directly from SQLite, not hard-coded."""
        counters = database.get_live_counters()
        print("[TEST 3] Real SQLite Live Counters:", counters)
        self.assertIsInstance(counters, dict)
        self.assertIn('visitor_visits', counters)
        self.assertIn('checked_in_visitors', counters)
        self.assertIn('weapon_detections', counters)
        self.assertIn('face_matches', counters)
        self.assertIn('total_visitors', counters)
        self.assertGreaterEqual(counters['visitor_visits'], 0)
        self.assertGreaterEqual(counters['total_visitors'], 0)

    def test_04_face_recognition_service(self):
        """OpenCV YuNet + SFace models are downloaded, ready, and extract embeddings."""
        svc = face_recognition_service.face_service
        print("[TEST 4] Face Service Status: is_ready =", svc.is_ready)
        self.assertTrue(svc.is_ready, "Face recognition models should be loaded and ready.")
        self.assertEqual(svc.cosine_threshold, 0.363, "SFace cosine threshold should be standard 0.363.")
        
        # Test synthetic image decoding and embedding extraction
        dummy_img = np.zeros((200, 200, 3), dtype=np.uint8)
        emb = svc.extract_embedding(dummy_img)
        # Dummy blank image has no face, so extract_embedding should gracefully return None
        self.assertIsNone(emb)

    def test_05_checkpoint_state_validation(self):
        """Checkpoint rejects invalid tickets, already checked-in, and completed tickets."""
        # 1. Invalid Ticket
        res_inv = database.verify_visitor_checkpoint('NON_EXISTENT_TICKET_999')
        print("[TEST 5a] Invalid ticket response:", res_inv['status'])
        self.assertFalse(res_inv['success'])
        self.assertEqual(res_inv['status'], 'INVALID_TICKET')

        # 2. Check a visit record in SQLite
        conn = database.get_db()
        # Find a visit to test
        row = conn.execute("SELECT ticket_id, status FROM visits LIMIT 1").fetchone()
        conn.close()

        if row:
            tkt = row[0]
            # Set to Checked In
            conn = database.get_db()
            conn.execute("UPDATE visits SET status = 'Checked In' WHERE ticket_id = ?", (tkt,))
            conn.commit()
            conn.close()

            res_chk = database.verify_visitor_checkpoint(tkt)
            print("[TEST 5b] Already Checked In response:", res_chk['status'])
            self.assertFalse(res_chk['success'])
            self.assertEqual(res_chk['status'], 'ALREADY_CHECKED_IN')

            # Set to Completed
            conn = database.get_db()
            conn.execute("UPDATE visits SET status = 'Completed' WHERE ticket_id = ?", (tkt,))
            conn.commit()
            conn.close()

            res_comp = database.verify_visitor_checkpoint(tkt)
            print("[TEST 5c] Completed visit response:", res_comp['status'])
            self.assertFalse(res_comp['success'])
            self.assertEqual(res_comp['status'], 'VISIT_COMPLETED')

            # Set to Approved without face_data -> should require face
            conn = database.get_db()
            conn.execute("UPDATE visits SET status = 'Approved' WHERE ticket_id = ?", (tkt,))
            conn.commit()
            conn.close()

            res_noface = database.verify_visitor_checkpoint(tkt, face_data=None)
            print("[TEST 5d] Missing face response:", res_noface['status'])
            self.assertFalse(res_noface['success'])
            self.assertEqual(res_noface['status'], 'FACE_REQUIRED')

    def test_06_clean_video_pipeline_no_keyword_triggers(self):
        """Filenames with 'gun' or 'knife' do not trigger fake weapons."""
        res_gun_name = detection_pipeline.process_video_detection('security_vault_gun_footage.mp4')
        print("[TEST 6] Detection on 'security_vault_gun_footage.mp4':", res_gun_name['detection_status'], "| has_threat:", res_gun_name['has_threat'])
        self.assertFalse(res_gun_name['has_threat'])
        self.assertEqual(res_gun_name['detection_status'], 'No threat detected.')

    def test_07_alert_recipients_crud_and_aliases(self):
        """Alert recipients support ON/OFF toggles and both field aliases."""
        recipients = database.get_alert_recipients()
        self.assertGreater(len(recipients), 0, "Expected seed recipients in SQLite.")
        r = recipients[0]
        rec_id = r['id']

        # Check aliases exist
        self.assertIn('receive_weapon_alert', r)
        self.assertIn('receive_weapon_alerts', r)
        self.assertIn('active', r)
        self.assertIn('is_active', r)

        # Toggle weapon alert off
        database.update_alert_recipient(rec_id, {'receive_weapon_alert': 0})
        updated = [x for x in database.get_alert_recipients() if x['id'] == rec_id][0]
        self.assertEqual(updated['receive_weapon_alert'], 0)
        self.assertEqual(updated['receive_weapon_alerts'], False)

        # Toggle weapon alert on
        database.update_alert_recipient(rec_id, {'receive_weapon_alert': 1})
        updated = [x for x in database.get_alert_recipients() if x['id'] == rec_id][0]
        self.assertEqual(updated['receive_weapon_alert'], 1)
        self.assertEqual(updated['receive_weapon_alerts'], True)
        print("[TEST 7] Recipient toggle verified for ID", rec_id, "weapon_alert:", updated['receive_weapon_alert'])

    def test_08_lan_ip_detection(self):
        """get_lan_ip detects a valid IPv4 address."""
        lan_ip = server.get_lan_ip()
        print("[TEST 8] Detected Host LAN IP:", lan_ip)
        self.assertIsInstance(lan_ip, str)
        self.assertNotEqual(lan_ip, "")
        parts = lan_ip.split('.')
        self.assertEqual(len(parts), 4, f"Invalid IPv4 format: {lan_ip}")

if __name__ == '__main__':
    unittest.main(verbosity=2)
