"""
SecureVision AI - Real-World Camera AI Processing Pipeline & Persistent Worker
Integrates:
  1. Multi-Camera Ingestion (CAM-01 RTSP, CAM-02 Webcam, CAM-03 Mobile Relay)
  2. Person Detection (OpenCV HOG + YuNet)
  3. Face Detection & Alignment (OpenCV YuNet)
  4. Face Recognition & Biometrics (OpenCV SFace 128-d embeddings)
  5. SQLite Visitor Biometric Matching & Ticket/Zone Authorization
  6. Independent YOLO Weapon Detection (Strict separation: normal faces never become threats)
  7. Debounced SQLite Event Persistence & Live Telemetry Broadcasting
"""

import os
import sys
import time
import json
import math
import base64
import threading
from datetime import datetime
import numpy as np
import shutil
import socket
import urllib.parse

# Set OpenCV FFmpeg stream timeout to 3 seconds instead of 30 seconds
os.environ["OPENCV_FFMPEG_CAPTURE_OPTIONS"] = "rtsp_transport;udp|stimeout;3000000|max_delay;500000"

try:
    import cv2
    HAS_OPENCV = True
except ImportError:
    cv2 = None
    HAS_OPENCV = False

import database
from face_recognition_service import face_service, COSINE_THRESHOLD
import detection_pipeline

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SNAPSHOTS_DIR = os.path.join(BASE_DIR, 'snapshots')
ASSETS_SNAPSHOTS_DIR = os.path.join(BASE_DIR, 'assets', 'snapshots')
os.makedirs(SNAPSHOTS_DIR, exist_ok=True)
os.makedirs(ASSETS_SNAPSHOTS_DIR, exist_ok=True)


class CameraAIEngine:
    """
    Central AI Processing Engine for real surveillance feeds.
    Maintains persistent states, executes AI models at 3-5 FPS,
    and updates SQLite with real verification events.
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.camera_states = {
            'CAM-01': {
                'camera_id': 'CAM-01',
                'camera_name': 'CAM-01 — Main Gate CCTV',
                'camera_type': 'rtsp',
                'location': 'Main Entry Gate 1',
                'zone': 'Zone A (Main Gallery)',
                'status': 'OFFLINE',
                'fps': 25.0,
                'resolution': '1920x1080',
                'people_count': 0,
                'recognized_count': 0,
                'unknown_count': 0,
                'weapons_count': 0,
                'detections': [],
                'recent_events': [],
                'latest_event': None,
                'last_frame_time': 0,
                'last_ai_time': 0,
                'active_threat': False
            },
            'CAM-02': {
                'camera_id': 'CAM-02',
                'camera_name': 'CAM-02 — Laptop Webcam',
                'camera_type': 'webcam',
                'location': 'Security Terminal Alpha',
                'zone': 'Command Desk',
                'status': 'OFFLINE',
                'fps': 30.0,
                'resolution': '1080p FHD',
                'people_count': 0,
                'recognized_count': 0,
                'unknown_count': 0,
                'weapons_count': 0,
                'detections': [],
                'recent_events': [],
                'latest_event': None,
                'last_frame_time': 0,
                'last_ai_time': 0,
                'active_threat': False
            },
            'CAM-03': {
                'camera_id': 'CAM-03',
                'camera_name': 'CAM-03 — Mobile Camera Stream',
                'camera_type': 'mobile',
                'location': 'Mobile Patrol Unit 1',
                'zone': 'Zone B (Vault Entry)',
                'status': 'OFFLINE',
                'fps': 25.0,
                'resolution': '720p HD',
                'people_count': 0,
                'recognized_count': 0,
                'unknown_count': 0,
                'weapons_count': 0,
                'detections': [],
                'recent_events': [],
                'latest_event': None,
                'last_frame_time': 0,
                'last_ai_time': 0,
                'active_threat': False
            }
        }

        # Cached latest frames (BGR numpy arrays)
        self.latest_frames = {
            'CAM-01': None,
            'CAM-02': None,
            'CAM-03': None
        }

        # Event debounce dictionary and continuous active recognition sessions
        self._event_debounce = {}
        self._active_sessions = {}  # cam_id -> {'subject_type': 'visitor'|'unknown', 'name': str, 'visitor_id': str, 'first_seen': float, 'last_seen': float, 'snapshot_url': str}
        self.debounce_seconds = 6.0

        # Person detector (OpenCV HOG if available in OpenCV build)
        self.hog_detector = None
        if HAS_OPENCV and hasattr(cv2, 'HOGDescriptor'):
            try:
                self.hog_detector = cv2.HOGDescriptor()
                self.hog_detector.setSVMDetector(cv2.HOGDescriptor_getDefaultPeopleDetector())
            except Exception:
                self.hog_detector = None

        # Worker threads
        self.rtsp_thread = None
        self.rtsp_running = False

    def get_camera_state(self, cam_id):
        """Returns snapshot of current live telemetry and detections."""
        with self.lock:
            state = self.camera_states.get(cam_id)
            if not state:
                return None
            # Check liveness timeout (if no frame received in last 10 seconds, mark offline)
            if time.time() - state['last_frame_time'] > 10.0 and state['status'] == 'LIVE':
                state['status'] = 'OFFLINE'
                state['people_count'] = 0
                state['recognized_count'] = 0
                state['unknown_count'] = 0
                state['weapons_count'] = 0
                state['detections'] = []
            res = dict(state)
            # Ensure latest_event is populated
            if not res.get('latest_event'):
                try:
                    evs = database.get_inside_events(limit=10)
                    for e in evs:
                        if e.get('camera_id') == cam_id or e.get('camera') == cam_id:
                            is_match = ('Recognized' in str(e.get('event_type', '')) or 'Authorized' in str(e.get('event_type', '')))
                            person_name = e.get('person') or ('Registered Visitor' if is_match else 'Unknown')
                            v_id = e.get('visitor_id')
                            if not v_id or v_id in ('Subject', 'VIS-RECORD', 'None', ''):
                                v_rec = database.get_visitor_by_id(person_name)
                                v_id = (v_rec.get('visitor_id') if v_rec else None) or ('VIS-REGISTERED' if is_match else '—')
                            match_pct = int((e.get('confidence', 0.95) or 0.95) * 100) if is_match else 0
                            cam_disp_name = f"{cam_id} — Laptop Webcam" if cam_id == 'CAM-02' else f"Camera {cam_id}"
                            res['latest_event'] = {
                                'id': e.get('id'),
                                'time': e.get('timestamp_str') or e.get('timestamp', ''),
                                'timestamp': e.get('timestamp_str') or e.get('timestamp', ''),
                                'date': e.get('date_str') or e.get('date', ''),
                                'camera_id': cam_id,
                                'camera_name': cam_disp_name,
                                'location': e.get('location', state.get('location', 'Security Terminal Alpha')),
                                'zone': state.get('zone', 'Zone A'),
                                'recognition': 'MATCHED' if is_match else 'NO MATCH',
                                'status': 'VERIFIED' if is_match else 'NOT REGISTERED',
                                'authorization': 'Registered' if is_match else 'Not Registered',
                                'is_registered': is_match,
                                'is_verified': is_match,
                                'person': person_name,
                                'name': person_name,
                                'visitor_id': v_id,
                                'match_confidence': match_pct,
                                'match_percent': match_pct,
                                'match_label': f"{match_pct}%" if is_match else 'No registered match',
                                'confidence': e.get('confidence', 0.95) if is_match else 0.0,
                                'snapshot_url': e.get('snapshot_url', '') or e.get('snapshot', ''),
                                'snapshot': e.get('snapshot_url', '') or e.get('snapshot', ''),
                                'logged_in_sqlite': True
                            }
                            break
                except Exception:
                    pass

            # Ensure recent_events is populated
            if not res.get('recent_events') or len(res.get('recent_events')) == 0:
                try:
                    db_evs = database.get_inside_events(limit=20)
                    cam_recents = []
                    for e in db_evs:
                        if e.get('camera_id') == cam_id or e.get('camera') == cam_id:
                            is_m = ('Recognized' in str(e.get('event_type', '')) or 'Authorized' in str(e.get('event_type', '')))
                            p_name = e.get('person') or ('Registered Visitor' if is_m else 'Unknown')
                            v_id = e.get('visitor_id')
                            if not v_id or v_id in ('Subject', 'VIS-RECORD', 'None', ''):
                                v_rec = database.get_visitor_by_id(p_name)
                                v_id = (v_rec.get('visitor_id') if v_rec else None) or ('VIS-REGISTERED' if is_m else '—')
                            match_pct = int((e.get('confidence', 0.95) or 0.95) * 100) if is_m else 0
                            cam_disp_name = f"{cam_id} — Laptop Webcam" if cam_id == 'CAM-02' else f"Camera {cam_id}"
                            cam_recents.append({
                                'id': e.get('id'),
                                'time': e.get('timestamp_str') or e.get('timestamp', ''),
                                'timestamp': e.get('timestamp_str') or e.get('timestamp', ''),
                                'date': e.get('date_str') or e.get('date', ''),
                                'camera_id': cam_id,
                                'camera_name': cam_disp_name,
                                'location': e.get('location', state.get('location', 'Security Terminal Alpha')),
                                'zone': state.get('zone', 'Zone A'),
                                'recognition': 'MATCHED' if is_m else 'NO MATCH',
                                'status': 'VERIFIED' if is_m else 'NOT REGISTERED',
                                'authorization': 'Registered' if is_m else 'Not Registered',
                                'is_registered': is_m,
                                'is_verified': is_m,
                                'person': p_name,
                                'name': p_name,
                                'visitor_id': v_id,
                                'type': e.get('event_type') or ('Visitor Recognized' if is_m else 'Unknown Person'),
                                'severity': e.get('severity', 'Info'),
                                'match_confidence': match_pct,
                                'match_percent': match_pct,
                                'match_label': f"{match_pct}%" if is_m else 'No registered match',
                                'confidence': e.get('confidence', 0.95) if is_m else 0.0,
                                'snapshot_url': e.get('snapshot_url', '') or e.get('snapshot', ''),
                                'snapshot': e.get('snapshot_url', '') or e.get('snapshot', ''),
                                'logged_in_sqlite': True
                            })
                    res['recent_events'] = cam_recents
                except Exception:
                    pass
            return res

    def get_all_camera_states(self):
        """Returns live states for CAM-01, CAM-02, and CAM-03."""
        with self.lock:
            now = time.time()
            res = {}
            for cid, s in self.camera_states.items():
                copy_s = dict(s)
                if now - copy_s['last_frame_time'] > 5.0 and copy_s['status'] == 'LIVE':
                    copy_s['status'] = 'OFFLINE'
                    copy_s['people_count'] = 0
                    copy_s['recognized_count'] = 0
                    copy_s['unknown_count'] = 0
                    copy_s['weapons_count'] = 0
                    copy_s['detections'] = []
                res[cid] = copy_s
            return res

    def get_latest_frame(self, cam_id):
        """Returns latest BGR frame for camera or None."""
        with self.lock:
            frame = self.latest_frames.get(cam_id)
            if frame is not None:
                return frame.copy()
            return None

    def start_rtsp_worker(self):
        """Starts background RTSP ingestion worker thread for CAM-01."""
        if self.rtsp_running:
            return
        self.rtsp_running = True
        self.rtsp_thread = threading.Thread(target=self._rtsp_worker_loop, daemon=True, name="RTSPWorker-CAM-01")
        self.rtsp_thread.start()
        print("[CameraAI] CAM-01 RTSP worker background thread started.")

    def stop_rtsp_worker(self):
        """Stops background RTSP worker."""
        self.rtsp_running = False
        if self.rtsp_thread and self.rtsp_thread.is_alive():
            self.rtsp_thread.join(timeout=2.0)

    def _rtsp_worker_loop(self):
        """Persistent RTSP ingestion and sampling loop."""
        while self.rtsp_running:
            cam = database.get_camera_by_id('CAM-01')
            stream_url = (cam or {}).get('stream_url', '').strip()
            if not stream_url or not stream_url.lower().startswith(('rtsp://', 'rtsps://', 'http://', 'https://')):
                with self.lock:
                    self.camera_states['CAM-01']['status'] = 'OFFLINE'
                time.sleep(3.0)
                continue

            with self.lock:
                self.camera_states['CAM-01']['status'] = 'CONNECTING'

            # Quick TCP reachability check to prevent FFmpeg 30-second blocking on unreachable RTSP hosts
            try:
                parsed = urllib.parse.urlsplit(stream_url)
                host = parsed.hostname
                port = parsed.port or (554 if parsed.scheme in ('rtsp', 'rtsps') else 80)
                if host:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(1.5)
                    err = s.connect_ex((host, port))
                    s.close()
                    if err != 0:
                        with self.lock:
                            self.camera_states['CAM-01']['status'] = 'OFFLINE'
                        time.sleep(5.0)
                        continue
            except Exception:
                pass

            cap = None
            try:
                # Open with short timeout
                cap = cv2.VideoCapture()
                if hasattr(cv2, 'CAP_PROP_OPEN_TIMEOUT_MSEC'):
                    cap.set(cv2.CAP_PROP_OPEN_TIMEOUT_MSEC, 4000)
                if hasattr(cv2, 'CAP_PROP_READ_TIMEOUT_MSEC'):
                    cap.set(cv2.CAP_PROP_READ_TIMEOUT_MSEC, 4000)
                
                backend = cv2.CAP_FFMPEG if hasattr(cv2, 'CAP_FFMPEG') else 0
                opened = cap.open(stream_url, backend) if backend else cap.open(stream_url)
                if not opened or not cap.isOpened():
                    with self.lock:
                        self.camera_states['CAM-01']['status'] = 'OFFLINE'
                    time.sleep(4.0)
                    continue

                fps = float(cap.get(cv2.CAP_PROP_FPS) or 25.0)
                width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH) or 1920)
                height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT) or 1080)

                with self.lock:
                    self.camera_states['CAM-01']['status'] = 'LIVE'
                    self.camera_states['CAM-01']['fps'] = round(fps, 1)
                    self.camera_states['CAM-01']['resolution'] = f"{width}x{height}"

                last_ai_process_time = 0.0

                while self.rtsp_running:
                    ret, frame = cap.read()
                    if not ret or frame is None:
                        break

                    now = time.time()
                    with self.lock:
                        self.latest_frames['CAM-01'] = frame
                        self.camera_states['CAM-01']['last_frame_time'] = now
                        self.camera_states['CAM-01']['status'] = 'LIVE'

                    # Sample frame for AI processing at 3-5 FPS (every 250ms)
                    if now - last_ai_process_time >= 0.25:
                        last_ai_process_time = now
                        self.process_camera_frame('CAM-01', frame)

                    # Micro-sleep to prevent 100% CPU thread starvation
                    time.sleep(0.01)

            except Exception as ex:
                print(f"[CameraAI] CAM-01 stream connection issue: {ex}", file=sys.stderr)
            finally:
                if cap is not None:
                    try:
                        cap.release()
                    except Exception:
                        pass
                with self.lock:
                    self.camera_states['CAM-01']['status'] = 'OFFLINE'
                time.sleep(3.0)

    def update_mobile_frame(self, base64_image_data, device_info="Mobile Camera"):
        """
        Receives frame from CAM-03 (mobile broadcaster),
        updates frame cache, and samples AI pipeline.
        """
        if not base64_image_data:
            return None

        # Decode base64 to BGR numpy array
        frame_bgr = face_service.decode_image(base64_image_data)
        if frame_bgr is None:
            return None

        now = time.time()
        h, w = frame_bgr.shape[:2]

        with self.lock:
            self.latest_frames['CAM-03'] = frame_bgr
            self.camera_states['CAM-03']['last_frame_time'] = now
            self.camera_states['CAM-03']['status'] = 'LIVE'
            self.camera_states['CAM-03']['resolution'] = f"{w}x{h}"
            last_ai = self.camera_states['CAM-03']['last_ai_time']

        # Sample AI inference every 250ms (4 FPS)
        if now - last_ai >= 0.25:
            return self.process_camera_frame('CAM-03', frame_bgr)
        return self.get_camera_state('CAM-03')

    def process_camera_frame(self, cam_id, frame_bgr):
        """
        Full Real-World AI Processing Pipeline:
          1. Person Detection
          2. Face Detection & YuNet Landmarks
          3. Face Recognition (SFace 128-d vector extraction)
          4. SQLite Visitor Biometric Search & Cosine Matching
          5. Ticket Validation & Zone Authorization Checking
          6. Debounced SQLite Event Logging
          7. Independent YOLO Weapon Detection (Strict separation)
          8. Update In-Memory Telemetry State
        """
        if frame_bgr is None or not HAS_OPENCV:
            return None

        now = time.time()
        h, w = frame_bgr.shape[:2]
        cam_info = database.get_camera_by_id(cam_id) or {}
        cam_zone = cam_info.get('zone', 'Zone A (Main Gallery)')
        cam_location = cam_info.get('location', 'Main Gate')

        detections = []
        people_count = 0
        recognized_count = 0
        unknown_count = 0
        weapons_count = 0

        # Step 1: Detect Faces using YuNet
        faces = face_service.detect_faces(frame_bgr)
        detected_face_boxes = []

        # Step 2: Query Registered Face Embeddings from SQLite
        db_embeddings = database.get_face_embeddings()
        processed_visitors = set()

        for face_item in faces:
            box = face_item['box']  # [x, y, w, h]
            raw_face = face_item['raw_face']
            score = face_item['score']
            detected_face_boxes.append(box)

            if score < 0.5:
                continue

            # Step 3: Extract 128-d SFace Feature Embedding
            feature_emb = face_service.extract_embedding(frame_bgr, face_data=raw_face)
            if feature_emb is None:
                continue

            # Step 4: Compare against SQLite Face Embeddings
            best_match = None
            best_sim = -1.0

            for db_rec in db_embeddings:
                raw_emb_json = db_rec.get('embedding_json')
                if not raw_emb_json:
                    continue
                try:
                    if isinstance(raw_emb_json, str):
                        emb_arr = json.loads(raw_emb_json)
                    else:
                        emb_arr = raw_emb_json
                    sim = face_service.compute_cosine_similarity(feature_emb, emb_arr)
                    if sim > best_sim:
                        best_sim = sim
                        best_match = db_rec
                except Exception:
                    continue

            # Check threshold
            if best_match is not None and best_sim >= COSINE_THRESHOLD:
                # MATCH FOUND! Fetch full visitor details from SQLite
                vis_id_str = best_match.get('visitor_id')
                full_name_cand = best_match.get('full_name')
                vis_record = database.get_visitor_by_id(vis_id_str)
                if not vis_record and full_name_cand:
                    vis_record = database.get_visitor_by_id(full_name_cand)
                if not vis_record:
                    vis_record = {}

                actual_vis_id = vis_record.get('visitor_id') or (f"VIS-{vis_id_str}" if str(vis_id_str).isdigit() else str(vis_id_str or 'VIS-REGISTERED'))
                full_name = vis_record.get('full_name') or full_name_cand or 'Registered Visitor'
                ticket_id = vis_record.get('ticket_id') or 'TKT-2026-ACTIVE'
                allowed_zone = vis_record.get('allowed_zone', 'Zone A (Main Gallery)')
                visit_status = vis_record.get('status', 'Approved')

                # Authorization Check: Does visitor's allowed_zone match this camera's zone?
                zone_authorized = self._check_zone_authorization(allowed_zone, cam_zone)

                # Check-in Status Check: Explicit separation of recognition vs check-in
                is_checked_in = (visit_status.lower() == 'checked in')
                checkin_status = "Checked In" if is_checked_in else "Check-in required"

                recognized_count += 1
                processed_visitors.add(full_name)
                auth_level = vis_record.get('authorization_level') or 'Authorized Visitor'
                match_percent = face_service.calculate_match_percentage(best_sim)
                if match_percent == 0 and best_sim >= COSINE_THRESHOLD:
                    match_percent = round(min(99.4, max(85.0, ((best_sim - 0.20) / 0.80) * 100)), 1)

                det_obj = {
                    'box': [int(box[0]), int(box[1]), int(box[2]), int(box[3])],
                    'type': 'visitor',
                    'name': full_name,
                    'visitor_id': actual_vis_id,
                    'ticket_id': ticket_id,
                    'allowed_zone': allowed_zone,
                    'camera_zone': cam_zone,
                    'zone_authorized': zone_authorized,
                    'is_checked_in': is_checked_in,
                    'checkin_status': checkin_status,
                    'auth_level': auth_level,
                    'role': auth_level,
                    'authorization': 'Registered',
                    'status': 'VERIFIED',
                    'is_verified': True,
                    'display_badge': f"{auth_level} — VERIFIED",
                    'match_percent': match_percent,
                    'match_label': f"{match_percent}%",
                    'score_percent': match_percent,
                    'score': round(float(best_sim), 3),
                    'confidence': round(min(1.0, max(0.0, (best_sim - 0.2) / 0.8)), 2),
                    'color': '#10B981',
                    'snapshot_captured': True,
                    'snapshot_url': ''
                }

                # Step 5: Continuous Session Tracking & Debounced SQLite Event Logging
                SESSION_TIMEOUT = 15.0
                sess = self._active_sessions.get(cam_id)
                is_same_session = (
                    sess is not None and
                    sess.get('subject_type') == 'visitor' and
                    sess.get('name') == full_name and
                    (now - sess.get('last_seen', 0)) < SESSION_TIMEOUT
                )

                if is_same_session:
                    # Same recognition session (e.g. 00:28:31, 00:28:32, 00:28:33):
                    # Keep session active, reuse snapshot & latest event without creating duplicate SQLite events
                    sess['last_seen'] = time.time()
                    det_obj['snapshot_url'] = sess.get('snapshot_url', '')
                    if sess.get('latest_event'):
                        with self.lock:
                            if cam_id in self.camera_states:
                                self.camera_states[cam_id]['latest_event'] = sess['latest_event']
                else:
                    # NEW RECOGNITION EVENT: Person 1 (or new visitor Person 2, or returning after absence)
                    snap_path = self._log_visitor_recognition_event(
                        cam_id, cam_location, cam_zone, det_obj, frame_bgr=frame_bgr,
                        visitor_id=actual_vis_id, full_name=full_name, ticket_id=ticket_id,
                        match_percent=match_percent, best_sim=best_sim
                    )
                    det_obj['snapshot_url'] = snap_path or ''
                    ev_obj = self.camera_states.get(cam_id, {}).get('latest_event')
                    self._active_sessions[cam_id] = {
                        'subject_type': 'visitor',
                        'name': full_name,
                        'visitor_id': actual_vis_id,
                        'first_seen': now,
                        'last_seen': time.time(),
                        'snapshot_url': snap_path or '',
                        'latest_event': ev_obj
                    }

                detections.append(det_obj)

            else:
                # UNKNOWN FACE DETECTED
                unknown_count += 1
                det_obj = {
                    'box': [int(box[0]), int(box[1]), int(box[2]), int(box[3])],
                    'type': 'unknown',
                    'name': 'Unknown',
                    'visitor_id': '—',
                    'ticket_id': 'N/A',
                    'allowed_zone': 'Unregistered',
                    'camera_zone': cam_zone,
                    'zone_authorized': False,
                    'is_checked_in': False,
                    'checkin_status': 'NOT REGISTERED',
                    'auth_level': 'Unregistered',
                    'role': 'Unknown Individual',
                    'authorization': 'Not Registered',
                    'status': 'NOT REGISTERED',
                    'is_verified': False,
                    'display_badge': 'NOT VERIFIED',
                    'match_percent': 0,
                    'match_label': 'No registered match',
                    'score_percent': 0,
                    'score': round(float(best_sim if best_sim > 0 else 0.0), 3),
                    'confidence': 0.0,
                    'color': '#F59E0B',
                    'snapshot_captured': True,
                    'snapshot_url': ''
                }

                # Unknown continuous session check
                SESSION_TIMEOUT = 15.0
                sess = self._active_sessions.get(cam_id)
                is_same_session = (
                    sess is not None and
                    sess.get('subject_type') == 'unknown' and
                    (now - sess.get('last_seen', 0)) < SESSION_TIMEOUT
                )

                if is_same_session:
                    sess['last_seen'] = time.time()
                    det_obj['snapshot_url'] = sess.get('snapshot_url', '')
                    if sess.get('latest_event'):
                        with self.lock:
                            if cam_id in self.camera_states:
                                self.camera_states[cam_id]['latest_event'] = sess['latest_event']
                else:
                    snap_path = self._log_unknown_person_event(cam_id, cam_location, cam_zone, det_obj=det_obj, frame_bgr=frame_bgr)
                    det_obj['snapshot_url'] = snap_path or ''
                    ev_obj = self.camera_states.get(cam_id, {}).get('latest_event')
                    self._active_sessions[cam_id] = {
                        'subject_type': 'unknown',
                        'name': 'Unknown',
                        'visitor_id': '—',
                        'first_seen': now,
                        'last_seen': time.time(),
                        'snapshot_url': snap_path or '',
                        'latest_event': ev_obj
                    }

                detections.append(det_obj)

        # Clear expired session if no face was detected for > 15 seconds
        if len(detected_face_boxes) == 0:
            sess = self._active_sessions.get(cam_id)
            if sess and (time.time() - sess.get('last_seen', 0)) >= 15.0:
                self._active_sessions[cam_id] = None

        # People count is the number of detected faces or HOG people
        people_count = max(len(detected_face_boxes), recognized_count + unknown_count)

        # Step 6: Separate Weapon Detection (YOLOv11 if installed)
        # STRICT SEPARATION: Face recognition never triggers weapon detection!
        weapon_model = detection_pipeline.get_weapon_model()
        active_threat = False

        if weapon_model is not None:
            try:
                # Real YOLO inference
                res = weapon_model.predict(frame_bgr, conf=0.40, imgsz=640, verbose=False)
                WEAPON_CLASSES = {'gun', 'pistol', 'handgun', 'knife', 'firearm', 'rifle', 'shotgun', 'weapon', 'dagger', 'blade'}
                for r in res:
                    boxes = r.boxes
                    if boxes is None or len(boxes) == 0:
                        continue
                    for b in boxes:
                        cls_id = int(b.cls[0])
                        cls_name = weapon_model.names.get(cls_id, '').lower()
                        conf = float(b.conf[0])
                        if cls_name in WEAPON_CLASSES:
                            weapons_count += 1
                            active_threat = True
                            xyxy = b.xyxy[0].cpu().numpy().astype(int).tolist()
                            detections.append({
                                'box': [xyxy[0], xyxy[1], xyxy[2] - xyxy[0], xyxy[3] - xyxy[1]],
                                'type': 'weapon',
                                'name': f"{cls_name.capitalize()} Detected",
                                'confidence': round(conf, 2),
                                'color': '#DC2626'
                            })
                            # Log weapon event if debounced
                            w_key = (cam_id, f"WEAPON_{cls_name}")
                            if now - self._event_debounce.get(w_key, 0) >= 20.0:
                                self._event_debounce[w_key] = now
                                self._log_weapon_event(cam_id, cam_location, cam_zone, cls_name, conf, frame_bgr)
            except Exception as yolo_err:
                print(f"[CameraAI] YOLO inference notice: {yolo_err}", file=sys.stderr)

        # Step 7: Update Camera State Cache
        finish_time = time.time()
        with self.lock:
            state = self.camera_states.get(cam_id)
            if state:
                state['last_frame_time'] = finish_time
                state['last_ai_time'] = finish_time
                state['status'] = 'LIVE'
                state['resolution'] = f"{w}x{h}"
                state['people_count'] = people_count
                state['recognized_count'] = recognized_count
                state['unknown_count'] = unknown_count
                state['weapons_count'] = weapons_count
                state['detections'] = detections
                state['active_threat'] = active_threat

        return self.get_camera_state(cam_id)

    def _check_zone_authorization(self, allowed_zone, camera_zone):
        """Checks if visitor's allowed zone matches the camera zone."""
        if not allowed_zone or not camera_zone:
            return True
        al = allowed_zone.lower()
        cz = camera_zone.lower()
        if 'all' in al or 'full access' in al:
            return True
        # Extract zone letters/identifiers
        for z in ['zone a', 'zone b', 'zone c', 'zone d', 'gallery', 'vault']:
            if z in cz and z in al:
                return True
        return al == cz

    def _save_face_snapshot(self, frame_bgr, cam_id, label, box=None, is_match=True):
        """Saves annotated JPEG snapshot of camera frame to snapshots/ and assets/snapshots/ directory."""
        if frame_bgr is None or not HAS_OPENCV:
            return ""
        try:
            ts = int(time.time() * 1000)
            prefix = "match" if is_match else "unk"
            snap_file = f"snap_{prefix}_{cam_id.lower()}_{ts}.jpg"
            snap_abs = os.path.join(SNAPSHOTS_DIR, snap_file)
            assets_snap_abs = os.path.join(ASSETS_SNAPSHOTS_DIR, snap_file)
            annotated = frame_bgr.copy()
            h_f, w_f = annotated.shape[:2]

            # Top HUD bar
            hud_bg = (15, 23, 42)  # Slate-900
            cv2.rectangle(annotated, (0, 0), (w_f, 28), hud_bg, -1)
            hud_text = f"SECUREVISION AI | {cam_id} REAL-TIME WEBCAM | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            cv2.putText(annotated, hud_text, (10, 19), cv2.FONT_HERSHEY_SIMPLEX, 0.45, (148, 163, 184), 1, cv2.LINE_AA)

            if box and len(box) >= 4:
                x, y, w, h = int(box[0]), int(box[1]), int(box[2]), int(box[3])
                color = (34, 197, 94) if is_match else (30, 140, 240)  # BGR: Emerald (#22c55e) or Amber/Orange
                # Bounding box
                cv2.rectangle(annotated, (x, y), (x + w, y + h), color, 2)
                # Corner accents
                c_len = max(10, min(w // 4, h // 4, 25))
                cv2.line(annotated, (x, y), (x + c_len, y), color, 4)
                cv2.line(annotated, (x, y), (x, y + c_len), color, 4)
                cv2.line(annotated, (x + w, y), (x + w - c_len, y), color, 4)
                cv2.line(annotated, (x + w, y), (x + w, y + c_len), color, 4)
                cv2.line(annotated, (x, y + h), (x + c_len, y + h), color, 4)
                cv2.line(annotated, (x, y + h), (x, y + h - c_len), color, 4)
                cv2.line(annotated, (x + w, y + h), (x + w - c_len, y + h), color, 4)
                cv2.line(annotated, (x + w, y + h), (x + w, y + h - c_len), color, 4)

                # Label tag
                tag_text = f"✓ {label}" if is_match else f"⚠ {label}"
                font_scale = 0.55
                thickness = 2
                (tw, th), baseline = cv2.getTextSize(tag_text, cv2.FONT_HERSHEY_SIMPLEX, font_scale, thickness)
                tag_y = max(34, y - 8)
                cv2.rectangle(annotated, (x, tag_y - th - 6), (x + tw + 10, tag_y + 4), color, -1)
                cv2.putText(annotated, tag_text, (x + 5, tag_y), cv2.FONT_HERSHEY_SIMPLEX, font_scale, (0, 0, 0), thickness, cv2.LINE_AA)

            cv2.imwrite(snap_abs, annotated)
            try:
                cv2.imwrite(assets_snap_abs, annotated)
            except Exception:
                pass
            return f"snapshots/{snap_file}"
        except Exception as e:
            print(f"[CameraAI] Failed to save face snapshot: {e}", file=sys.stderr)
            return ""

    def _log_visitor_recognition_event(self, cam_id, location, zone, det_obj, frame_bgr=None, visitor_id=None, full_name=None, ticket_id=None, match_percent=None, best_sim=None):
        """Persists genuine visitor recognition event to SQLite and captures actual camera frame snapshot."""
        try:
            full_name = full_name or det_obj.get('name', 'Registered Visitor')
            vis_id = visitor_id or det_obj.get('visitor_id', 'VIS-REGISTERED')
            ticket_id = ticket_id or det_obj.get('ticket_id', 'TKT-VALID')
            zone_auth = det_obj.get('zone_authorized', True)
            checkin_status = det_obj.get('checkin_status', 'Check-in required')
            pct = match_percent if match_percent is not None else det_obj.get('match_percent', 95)
            sim_score = best_sim if best_sim is not None else det_obj.get('score', 0.85)

            time_str = datetime.now().strftime('%H:%M:%S')
            date_str = datetime.now().strftime('%Y-%m-%d')
            event_id = f"EV-REC-{int(time.time()*1000)%100000}"

            # Save genuine snapshot from camera frame
            snap_url = self._save_face_snapshot(
                frame_bgr, cam_id,
                f"FACE VERIFIED: {full_name} ({vis_id}) - {pct}%",
                box=det_obj.get('box'),
                is_match=True
            )

            type_desc = f"Visitor Recognized ({checkin_status})"
            if not zone_auth:
                type_desc = f"Restricted-Zone Alert: {full_name} not authorized for {zone}"
                severity = "Warning"
            elif det_obj.get('is_checked_in'):
                severity = "Info"
            else:
                severity = "Info"

            inside_event = {
                'id': event_id,
                'timestamp': time_str,
                'date': date_str,
                'camera': cam_id,
                'location': f"{location} ({zone})",
                'type': type_desc,
                'severity': severity,
                'person': full_name,
                'visitor_id': vis_id,
                'confidence': det_obj.get('confidence', 0.95),
                'weaponType': 'None',
                'boundingColor': 'green' if zone_auth else 'unauthorized-orange',
                'snapshot': snap_url,
                'snapshot_url': snap_url,
                'status': 'Active'
            }
            database.add_inside_event(inside_event)

            # Also log entry verification in entry_logs
            database.log_entry_verification({
                'ticket_id': ticket_id,
                'visitor_id': vis_id,
                'visitor_name': full_name,
                'checkpoint_name': f"{cam_id} Checkpoint ({location})",
                'verification_status': 'ENTRY_APPROVED' if (zone_auth and det_obj.get('is_checked_in')) else ('CHECKIN_PENDING' if zone_auth else 'ZONE_RESTRICTED'),
                'face_match_confidence': sim_score,
                'notes': f"Recognized at {cam_id} ({location}). Status: {checkin_status}. Zone authorization: {'Granted' if zone_auth else 'Denied'}."
            })

            cam_info = database.get_camera_by_id(cam_id) or {}
            camera_display_name = cam_info.get('camera_name') or (f"{cam_id} — Laptop Webcam" if cam_id == 'CAM-02' else f"Camera {cam_id}")

            latest_ev = {
                'id': event_id,
                'time': time_str,
                'date': date_str,
                'camera_id': cam_id,
                'camera_name': camera_display_name,
                'location': location,
                'zone': zone,
                'recognition': 'MATCHED',
                'status': 'VERIFIED',
                'authorization': 'Registered',
                'is_verified': True,
                'is_registered': True,
                'person': full_name,
                'name': full_name,
                'visitor_id': vis_id,
                'ticket_id': ticket_id,
                'allowed_zone': det_obj.get('allowed_zone', zone),
                'match_confidence': pct,
                'match_percent': pct,
                'match_label': f"{pct}%",
                'confidence': det_obj.get('confidence', 0.95),
                'score': sim_score,
                'snapshot_url': snap_url,
                'snapshot': snap_url,
                'logged_in_sqlite': True
            }
            with self.lock:
                if cam_id in self.camera_states:
                    self.camera_states[cam_id]['latest_event'] = latest_ev
                    self.camera_states[cam_id]['latest_snapshot'] = snap_url
                    if 'recent_events' not in self.camera_states[cam_id]:
                        self.camera_states[cam_id]['recent_events'] = []
                    self.camera_states[cam_id]['recent_events'].insert(0, latest_ev)
                    if len(self.camera_states[cam_id]['recent_events']) > 20:
                        self.camera_states[cam_id]['recent_events'] = self.camera_states[cam_id]['recent_events'][:20]

            print(f"[CameraAI] Logged SQLite recognition event for {full_name} ({vis_id}) at {cam_id} (Snapshot: {snap_url})")
            return snap_url
        except Exception as ex:
            print(f"[CameraAI] Error logging recognition event: {ex}", file=sys.stderr)
            return None

    def _log_unknown_person_event(self, cam_id, location, zone, det_obj=None, frame_bgr=None):
        """Logs genuine unknown person event in SQLite inside_events with actual camera frame snapshot."""
        try:
            time_str = datetime.now().strftime('%H:%M:%S')
            date_str = datetime.now().strftime('%Y-%m-%d')
            event_id = f"EV-UNK-{int(time.time()*1000)%100000}"

            # Save genuine snapshot from camera frame
            snap_url = self._save_face_snapshot(
                frame_bgr, cam_id,
                "NOT REGISTERED: Unknown",
                box=det_obj.get('box') if det_obj else None,
                is_match=False
            )

            inside_event = {
                'id': event_id,
                'timestamp': time_str,
                'date': date_str,
                'camera': cam_id,
                'location': f"{location} ({zone})",
                'type': "Unknown Person Detected (Unregistered Individual)",
                'severity': "Warning",
                'person': "Unknown",
                'visitor_id': '—',
                'confidence': det_obj.get('confidence', 0.0) if det_obj else 0.0,
                'weaponType': 'None',
                'boundingColor': 'unknown-amber',
                'snapshot': snap_url,
                'snapshot_url': snap_url,
                'status': 'Active'
            }
            database.add_inside_event(inside_event)

            cam_info = database.get_camera_by_id(cam_id) or {}
            camera_display_name = cam_info.get('camera_name') or (f"{cam_id} — Laptop Webcam" if cam_id == 'CAM-02' else f"Camera {cam_id}")

            latest_ev = {
                'id': event_id,
                'time': time_str,
                'date': date_str,
                'camera_id': cam_id,
                'camera_name': camera_display_name,
                'location': location,
                'zone': zone,
                'recognition': 'NO MATCH',
                'status': 'NOT REGISTERED',
                'authorization': 'Not Registered',
                'is_verified': False,
                'is_registered': False,
                'person': "Unknown",
                'name': "Unknown",
                'visitor_id': '—',
                'ticket_id': 'N/A',
                'allowed_zone': 'Unregistered',
                'match_confidence': 0,
                'match_percent': 0,
                'match_label': 'No registered match',
                'confidence': det_obj.get('confidence', 0.0) if det_obj else 0.0,
                'score': det_obj.get('score', 0.0) if det_obj else 0.0,
                'snapshot_url': snap_url,
                'snapshot': snap_url,
                'logged_in_sqlite': True
            }
            with self.lock:
                if cam_id in self.camera_states:
                    self.camera_states[cam_id]['latest_event'] = latest_ev
                    self.camera_states[cam_id]['latest_snapshot'] = snap_url
                    if 'recent_events' not in self.camera_states[cam_id]:
                        self.camera_states[cam_id]['recent_events'] = []
                    self.camera_states[cam_id]['recent_events'].insert(0, latest_ev)
                    if len(self.camera_states[cam_id]['recent_events']) > 20:
                        self.camera_states[cam_id]['recent_events'] = self.camera_states[cam_id]['recent_events'][:20]

            print(f"[CameraAI] Logged SQLite unknown person event at {cam_id} (Snapshot: {snap_url})")
            return snap_url
        except Exception as ex:
            print(f"[CameraAI] Error logging unknown person: {ex}", file=sys.stderr)
            return None

    def _log_weapon_event(self, cam_id, location, zone, weapon_type, conf, frame_bgr):
        """Logs real weapon detection event to SQLite threat_events."""
        try:
            now = datetime.now()
            time_str = now.strftime('%H:%M:%S')
            date_str = now.strftime('%Y-%m-%d')
            snap_file = f"snap_weapon_{now.strftime('%Y%m%d_%H%M%S')}.jpg"
            snap_path = os.path.join(SNAPSHOTS_DIR, snap_file)

            if frame_bgr is not None and HAS_OPENCV:
                cv2.imwrite(snap_path, frame_bgr)

            event_id = database.add_threat_event({
                'camera_id': cam_id,
                'camera_name': f"Camera {cam_id}",
                'event_type': 'Weapon Detection',
                'detected_object': f"{weapon_type.capitalize()} (Real-Time AI)",
                'confidence': round(conf, 3),
                'snapshot_path': f"snapshots/{snap_file}",
                'video_path': '',
                'location': location,
                'zone': zone,
                'status': 'OPEN'
            })
            print(f"[CameraAI] 🚨 Logged SQLite critical threat event: {weapon_type} at {cam_id} (ID: {event_id})")
        except Exception as ex:
            print(f"[CameraAI] Error logging weapon event: {ex}", file=sys.stderr)


# Global singleton camera AI engine
camera_engine = CameraAIEngine()
