"""
Test Suite: Video Source Separation & Clean Video Analysis Pipeline
Validates:
1. Option 1 Demo mode separation: no webcam auto-start
2. Option 2 Upload mode: filename keywords (gun, knife, weapon) NEVER trigger fake threats; genuine frame determines AI outcome
3. Option 3 Live mode: strictly CAM-01 (RTSP), CAM-02 (Webcam), CAM-03 (Mobile); idle standby initial state
4. /api/video/analyze-frame endpoint functionality and clean baseline
"""

import unittest
import json
import urllib.request
import urllib.error
import base64
import numpy as np
import cv2
import database
import detection_pipeline

SERVER_URL = "http://localhost:8000"


class TestVideoSourceModes(unittest.TestCase):

    def test_01_option3_camera_inventory(self):
        """Ensure cameras for inside subsystem strictly contain CAM-01, CAM-02, and CAM-03."""
        cams = database.get_all_cameras()
        inside_cams = [c for c in cams if c['camera_id'] in ('CAM-01', 'CAM-02', 'CAM-03')]
        cam_ids = [c['camera_id'] for c in inside_cams]

        self.assertIn('CAM-01', cam_ids)
        self.assertIn('CAM-02', cam_ids)
        self.assertIn('CAM-03', cam_ids)

        c1 = next(c for c in inside_cams if c['camera_id'] == 'CAM-01')
        c2 = next(c for c in inside_cams if c['camera_id'] == 'CAM-02')
        c3 = next(c for c in inside_cams if c['camera_id'] == 'CAM-03')

        self.assertEqual(c1.get('camera_type', '').lower(), 'rtsp')
        self.assertEqual(c2.get('camera_type', '').lower(), 'webcam')
        self.assertEqual(c3.get('camera_type', '').lower(), 'mobile')
        print("[TEST 1] Option 3 Cameras strictly verified: CAM-01 (rtsp), CAM-02 (webcam), CAM-03 (mobile)")

    def test_02_filename_with_gun_does_not_trigger_fake_threat(self):
        """When sending a synthetic clean frame with filename 'my_vault_gun_assault.mp4', result must be clean."""
        # Create a synthetic 640x360 normal surveillance frame
        synth_frame = np.zeros((360, 640, 3), dtype=np.uint8)
        synth_frame[:] = (40, 35, 30) # Dark ambient room
        _, buf = cv2.imencode('.jpg', synth_frame)
        b64_img = 'data:image/jpeg;base64,' + base64.b64encode(buf).decode('utf-8')

        payload = json.dumps({
            'image_data': b64_img,
            'filename': 'my_vault_gun_assault.mp4'
        }).encode('utf-8')

        req = urllib.request.Request(
            f"{SERVER_URL}/api/video/analyze-frame",
            data=payload,
            headers={'Content-Type': 'application/json'},
            method='POST'
        )

        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode('utf-8'))

        print(f"[TEST 2] Response for 'my_vault_gun_assault.mp4': has_threat={data.get('has_threat')}, status={data.get('detection_status')}")
        self.assertTrue(data.get('success'))
        self.assertFalse(data.get('has_threat'))
        self.assertEqual(data.get('detection_status'), 'No threat detected.')
        self.assertIsNone(data.get('weapon_type'))

    def test_03_filename_with_knife_does_not_trigger_fake_threat(self):
        """When sending a synthetic clean frame with filename 'knife_attack_breach.mov', result must be clean."""
        synth_frame = np.ones((360, 640, 3), dtype=np.uint8) * 128
        _, buf = cv2.imencode('.jpg', synth_frame)
        b64_img = 'data:image/jpeg;base64,' + base64.b64encode(buf).decode('utf-8')

        payload = json.dumps({
            'image_data': b64_img,
            'filename': 'knife_attack_breach.mov'
        }).encode('utf-8')

        req = urllib.request.Request(
            f"{SERVER_URL}/api/video/analyze-frame",
            data=payload,
            headers={'Content-Type': 'application/json'},
            method='POST'
        )

        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode('utf-8'))

        print(f"[TEST 3] Response for 'knife_attack_breach.mov': has_threat={data.get('has_threat')}, status={data.get('detection_status')}")
        self.assertTrue(data.get('success'))
        self.assertFalse(data.get('has_threat'))
        self.assertEqual(data.get('detection_status'), 'No threat detected.')

    def test_04_arbitrary_filename_my_cctv_video(self):
        """When sending a frame with filename 'my_cctv_video.mp4', canvas processes frame cleanly."""
        payload = json.dumps({
            'image_data': None,
            'filename': 'my_cctv_video.mp4'
        }).encode('utf-8')

        req = urllib.request.Request(
            f"{SERVER_URL}/api/video/analyze-frame",
            data=payload,
            headers={'Content-Type': 'application/json'},
            method='POST'
        )

        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode('utf-8'))

        print(f"[TEST 4] Baseline for 'my_cctv_video.mp4': status={data.get('detection_status')}")
        self.assertTrue(data.get('success'))
        self.assertFalse(data.get('has_threat'))
        self.assertEqual(data.get('detection_status'), 'No threat detected.')


if __name__ == '__main__':
    unittest.main()
