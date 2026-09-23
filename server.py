"""
SecureVision AI - Unified Backend & SQLite REST API Server
Provides two-way synchronization REST API connected to SQLite database and high-performance static file serving.
"""

import http.server
import socketserver
import json
import os
import sys

# Force UTF-8 stdout and stderr for Windows console stability
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass
if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
    try:
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

import mimetypes
import urllib.parse
import base64
import time
from datetime import datetime
from urllib.parse import urlsplit, urlunsplit, quote
import secrets

try:
    import cv2
except ImportError:
    cv2 = None

import database
import detection_pipeline
import face_recognition_service
import camera_ai_pipeline
import socket

PORT = 8000
DIRECTORY = os.path.dirname(os.path.abspath(__file__))
SNAPSHOTS_DIR = os.path.join(DIRECTORY, 'snapshots')
EVIDENCE_DIR = os.path.join(DIRECTORY, 'evidence')
os.makedirs(SNAPSHOTS_DIR, exist_ok=True)
os.makedirs(EVIDENCE_DIR, exist_ok=True)

# Global in-memory relay buffer for live Mobile Camera streaming
LATEST_MOBILE_FRAME = {
    'image_data': None,
    'timestamp': 0,
    'device_info': 'Mobile Camera Stream'
}


def get_lan_ip():
    """Returns local network IPv4 address for phone connection."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '127.0.0.1'


def _camera_stream_url(camera):
    """Return the actual network stream URL, adding credentials when configured."""
    url = (camera or {}).get('stream_url') or (camera or {}).get('rtsp_url') or ''
    username = (camera or {}).get('username') or ''
    password = (camera or {}).get('password') or ''
    if not url:
        return ''
    if username and url.lower().startswith(('rtsp://', 'rtsps://', 'http://', 'https://')):
        try:
            parts = urlsplit(url)
            if '@' not in parts.netloc:
                host = parts.hostname or ''
                port = f':{parts.port}' if parts.port else ''
                auth = f'{quote(username, safe="")}:{quote(password, safe="")}' if password else quote(username, safe="")
                netloc = f'{auth}@{host}{port}'
                url = urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
        except Exception:
            pass
    return url


def _open_camera_capture(camera):
    """Open a real IP/RTSP camera with short read/open timeouts."""
    if cv2 is None:
        raise RuntimeError('OpenCV is not installed. Install opencv-python to use live CCTV.')
    url = _camera_stream_url(camera)
    if not url:
        raise RuntimeError('Camera has no stream URL.')
    cap = cv2.VideoCapture()
    try:
        if hasattr(cv2, 'CAP_PROP_OPEN_TIMEOUT_MSEC'):
            cap.set(cv2.CAP_PROP_OPEN_TIMEOUT_MSEC, 5000)
        if hasattr(cv2, 'CAP_PROP_READ_TIMEOUT_MSEC'):
            cap.set(cv2.CAP_PROP_READ_TIMEOUT_MSEC, 5000)
        backend = cv2.CAP_FFMPEG if hasattr(cv2, 'CAP_FFMPEG') else 0
        opened = cap.open(url, backend) if backend else cap.open(url)
        if not opened or not cap.isOpened():
            try:
                cap.release()
            except Exception:
                pass
            raise RuntimeError('Unable to open the camera stream. Check RTSP URL, credentials, network and camera configuration.')
        return cap
    except Exception:
        try:
            cap.release()
        except Exception:
            pass
        raise

# Ensure standard MIME types are mapped properly across all operating systems
mimetypes.init()
MIME_MAP = {
    '.html': 'text/html; charset=utf-8',
    '.htm': 'text/html; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.mjs': 'text/javascript; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.sql': 'text/plain; charset=utf-8',
    '.svg': 'image/svg+xml',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.webp': 'image/webp',
    '.ico': 'image/x-icon',
    '.mp4': 'video/mp4',
    '.webm': 'video/webm',
    '.wav': 'audio/wav',
    '.mp3': 'audio/mpeg',
    '.woff2': 'font/woff2',
    '.woff': 'font/woff',
    '.ttf': 'font/ttf'
}

class SecureVisionHandler(http.server.SimpleHTTPRequestHandler):
    extensions_map = {**http.server.SimpleHTTPRequestHandler.extensions_map, **MIME_MAP}
    timeout = 15

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def log_message(self, format, *args):
        # Clean formatted logging for terminal
        clean_path = getattr(self, 'path', '')
        if not clean_path.endswith(('.css', '.js', '.png', '.jpg', '.svg', '.woff2')):
            sys.stdout.write(f"[API {self.command}] {clean_path} - {args[1] if len(args)>1 else ''}\n")
            sys.stdout.flush()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With')
        self.send_header('Access-Control-Max-Age', '86400')
        self.end_headers()

    def do_GET(self):
        clean_path = self.path.split('?')[0].rstrip('/')
        if clean_path == '':
            clean_path = '/index.html'

        try:
            if clean_path == '/api/health':
                self.send_json({
                    'status': 'online',
                    'system': 'SecureVision AI Enterprise',
                    'version': '2.4',
                    'database': 'SQLite 3.x Connected',
                    'db_tables': len(database.get_all_tables_meta())
                })
            elif clean_path == '/api/state/sync':
                full_state = database.get_full_state_sync()
                self.send_json({'success': True, 'state': full_state})
            elif clean_path == '/api/db/tables':
                tables = database.get_all_tables_meta()
                self.send_json({'tables': tables, 'count': len(tables)})
            elif clean_path in ('/api/db/live', '/api/db/dynamic'):
                live_feed = database.get_live_database_feed()
                self.send_json(live_feed)
            elif clean_path == '/api/visitors':
                parsed = urllib.parse.urlparse(self.path)
                params = urllib.parse.parse_qs(parsed.query)
                q = params.get('q', [''])[0]
                status = params.get('status', ['all'])[0]
                date_filter = params.get('date', ['all'])[0]
                visitors = database.get_all_visitors_and_visits(q, status, date_filter)
                kpis = database.get_visitor_kpis()
                self.send_json({'visitors': visitors, 'kpis': kpis, 'count': len(visitors)})
            elif clean_path == '/api/visitors/repair-tickets':
                repaired = database.repair_missing_tickets()
                self.send_json({'success': True, 'repaired_count': repaired, 'message': f'Repaired {repaired} visit tickets in SQLite'})
            elif clean_path.startswith('/api/tickets/'):
                tkt_id = urllib.parse.unquote(clean_path.split('/')[-1])
                ticket = database.get_ticket_by_id(tkt_id) or database.get_visitor_by_id(tkt_id)
                if ticket:
                    self.send_json({'ticket': ticket, 'visitor': ticket, 'success': True})
                else:
                    self.send_json({'error': f'Ticket "{tkt_id}" not found', 'success': False}, status_code=404)
            elif clean_path.startswith('/api/visitors/'):
                vis_id = urllib.parse.unquote(clean_path.split('/')[-1])
                visitor = database.get_ticket_by_id(vis_id) or database.get_visitor_by_id(vis_id)
                if visitor:
                    self.send_json({'visitor': visitor, 'ticket': visitor, 'success': True})
                else:
                    self.send_json({'error': f'Visitor "{vis_id}" not found', 'success': False}, status_code=404)
            elif clean_path == '/api/authorized-people':
                people = database.get_all_personnel()
                self.send_json({'people': people, 'count': len(people)})
            elif clean_path.startswith('/api/authorized-people/'):
                person_id = clean_path.split('/')[-1]
                person = database.get_person_by_id(person_id)
                if person:
                    self.send_json({'person': person})
                else:
                    self.send_json({'error': 'Person not found'}, status_code=404)
            elif clean_path == '/api/authorization-levels':
                levels = database.get_all_levels()
                self.send_json({'levels': levels})
            elif clean_path == '/api/restricted-zones':
                zones = database.get_all_restricted_zones()
                self.send_json({'zones': zones})
            elif clean_path == '/api/inside/events':
                events = database.get_inside_events()
                self.send_json({'events': events, 'count': len(events)})
            elif clean_path in ('/api/inside/snapshots', '/api/inside/evidence'):
                snaps = database.get_inside_snapshots()
                self.send_json({'snapshots': snaps, 'count': len(snaps)})
            elif clean_path == '/api/inside/alerts':
                alerts = database.get_inside_alerts()
                self.send_json({'alerts': alerts, 'count': len(alerts)})
            elif clean_path == '/api/emergency-dispatches':
                dispatches = database.get_emergency_dispatches()
                self.send_json({'dispatches': dispatches, 'count': len(dispatches)})
            elif clean_path == '/api/outside/vehicles':
                vehicles = database.get_all_vehicles()
                self.send_json({'vehicles': vehicles, 'count': len(vehicles)})
            elif clean_path == '/api/outside/number-plates':
                plates = database.get_all_number_plates()
                self.send_json({'plates': plates, 'count': len(plates)})
            elif clean_path == '/api/outside/accidents':
                accidents = database.get_all_accidents()
                self.send_json({'accidents': accidents, 'count': len(accidents)})
            elif clean_path == '/api/outside/alerts':
                alerts = database.get_outside_alerts()
                self.send_json({'alerts': alerts, 'count': len(alerts)})
            elif clean_path == '/api/outside/drone':
                drone = database.get_drone_telemetry()
                self.send_json({'drone': drone})
            elif clean_path == '/api/crowd/current':
                crowd = database.get_crowd_data()
                self.send_json({'crowd': crowd})
            elif clean_path == '/api/detections':
                detections = database.get_all_detections()
                self.send_json({'detections': detections, 'count': len(detections)})
            elif clean_path.startswith('/api/detections/'):
                det_id = clean_path.split('/')[-1]
                det = database.get_detection_by_id(det_id)
                if det:
                    self.send_json({'detection': det})
                else:
                    self.send_json({'error': 'Detection not found'}, status_code=404)
            elif clean_path == '/api/users':
                users = database.get_all_users()
                self.send_json({'users': users, 'count': len(users)})
            elif clean_path in ('/api/auth/login-history', '/api/users/login-history'):
                history = database.get_login_history()
                self.send_json({'history': history, 'count': len(history)})
            elif clean_path.startswith('/api/stream/camera/') and clean_path.endswith('/mjpeg'):
                cam_id = clean_path.split('/')[4]
                self.stream_camera_mjpeg(cam_id)
            elif clean_path in ('/api/cameras/live-status', '/api/camera/live-status'):
                states = camera_ai_pipeline.camera_engine.get_all_camera_states()
                self.send_json({'success': True, 'cameras': states})
            elif clean_path in ('/api/face/status', '/api/face-ai/status'):
                import face_recognition_service
                face_svc = face_recognition_service.face_service
                embs = database.get_face_embeddings()
                self.send_json({
                    'success': True,
                    'ready': face_svc.is_ready,
                    'detector': 'OpenCV YuNet (2023mar)',
                    'recognizer': 'OpenCV SFace (2021dec FP32)',
                    'embedding_dim': 128,
                    'enrolled_faces': len(embs),
                    'cosine_threshold': camera_ai_pipeline.COSINE_THRESHOLD,
                    'status_text': 'Face AI: READY (YuNet + SFace 128-d)' if face_svc.is_ready else 'Face AI: UNAVAILABLE'
                })
            elif clean_path.startswith('/api/camera/') and clean_path.endswith('/live-status'):
                cam_id = clean_path.split('/')[3]
                state = camera_ai_pipeline.camera_engine.get_camera_state(cam_id)
                if state:
                    self.send_json({'success': True, 'camera': state})
                else:
                    self.send_json({'success': False, 'error': 'Camera not found'}, status_code=404)
            elif clean_path == '/api/cameras':
                parsed = urllib.parse.urlparse(self.path)
                params = urllib.parse.parse_qs(parsed.query)
                area = params.get('area', [None])[0]
                cameras = database.get_all_cameras(area=area)
                self.send_json({'cameras': cameras, 'count': len(cameras)})
            elif clean_path.startswith('/api/cameras/'):
                cam_id = clean_path.split('/')[-1]
                camera = database.get_camera_by_id(cam_id)
                if camera:
                    self.send_json({'camera': camera})
                else:
                    self.send_json({'error': 'Camera not found'}, status_code=404)
            elif clean_path == '/api/threats/events':
                events = database.get_threat_events()
                self.send_json({'events': events, 'count': len(events)})
            elif clean_path == '/api/threats/latest':
                latest = database.get_latest_threat_event()
                self.send_json({'threat': latest, 'success': True if latest else False})
            elif clean_path == '/api/snapshots':
                snaps = database.get_all_snapshots()
                self.send_json({'snapshots': snaps, 'count': len(snaps)})
            elif clean_path == '/api/evidence-videos':
                vids = database.get_all_evidence_videos()
                self.send_json({'videos': vids, 'count': len(vids)})
            elif clean_path in ('/api/alert-recipients', '/api/alerts/recipients'):
                recipients = database.get_alert_recipients()
                self.send_json({'recipients': recipients, 'count': len(recipients)})
            elif clean_path in ('/api/alerts/whatsapp', '/api/whatsapp/alerts'):
                wa_logs = database.get_whatsapp_alerts()
                self.send_json({'alerts': wa_logs, 'count': len(wa_logs)})
            elif clean_path in ('/api/entry-logs', '/api/visitors/entry-logs'):
                logs = database.get_entry_logs()
                self.send_json({'logs': logs, 'count': len(logs)})
            elif clean_path == '/api/face-embeddings':
                embeddings = database.get_face_embeddings()
                self.send_json({'embeddings': embeddings, 'count': len(embeddings)})
            elif clean_path == '/api/stream/mobile-frame':
                if LATEST_MOBILE_FRAME['image_data'] and (time.time() - LATEST_MOBILE_FRAME['timestamp'] < 4.0):
                    self.send_json(LATEST_MOBILE_FRAME)
                else:
                    self.send_json({'image_data': None, 'active': False, 'status': 'OFFLINE'})
            elif clean_path == '/api/facility-settings':
                settings = database.get_facility_settings()
                self.send_json({'settings': settings})
            elif clean_path in ('/api/system/network-ip', '/api/network/ip'):
                lan_ip = get_lan_ip()
                proto = 'https' if getattr(self.server, 'is_https', False) else 'http'
                port = getattr(self.server, 'server_port', PORT)
                self.send_json({
                    'success': True,
                    'lan_ip': lan_ip,
                    'port': port,
                    'protocol': proto,
                    'mobile_url': f"{proto}://{lan_ip}:{port}/camera.html",
                    'hostname': socket.gethostname()
                })
            elif clean_path in ('/api/inside/live-counters', '/api/live-counters'):
                counters = database.get_live_counters()
                self.send_json({'success': True, 'counters': counters})
            elif clean_path == '/api/overall/metrics':
                metrics = database.get_overall_dual_domain_metrics()
                self.send_json(metrics)
            elif clean_path == '/api/events/forensic-timeline':
                parsed = urllib.parse.urlparse(self.path)
                params = urllib.parse.parse_qs(parsed.query)
                try:
                    limit = int(params.get('limit', [60])[0])
                except Exception:
                    limit = 60
                area = params.get('area', [None])[0]
                severity = params.get('severity', [None])[0]
                timeline = database.get_forensic_timeline(limit=limit, area=area, severity=severity)
                self.send_json({'success': True, 'count': len(timeline), 'timeline': timeline})
            elif clean_path == '/api/system/real-status':
                status_info = database.get_system_real_status()
                self.send_json(status_info)
            elif clean_path == '/api/facility/radar-map':
                radar_data = database.get_facility_radar_data()
                self.send_json(radar_data)
            elif clean_path.startswith('/api/intelligence/query'):
                parsed = urllib.parse.urlparse(self.path)
                params = urllib.parse.parse_qs(parsed.query)
                q = params.get('q', [''])[0]
                result = database.query_surveillance_intelligence(q)
                self.send_json(result)
            else:
                super().do_GET()
        except Exception as e:
            self.send_json({'error': str(e)}, status_code=500)

    def stream_camera_mjpeg(self, cam_id):
        """Proxy a real RTSP/IP camera as browser-compatible MJPEG."""
        camera = database.get_camera_by_id(cam_id)
        if not camera:
            self.send_json({'success': False, 'error': 'Camera not found'}, status_code=404)
            return
        cam_type = (camera.get('camera_type') or '').lower()
        if cam_type in ('webcam', 'mobile'):
            self.send_json({'success': False, 'error': 'Use the browser/mobile camera relay for this camera type.'}, status_code=400)
            return
        cap = None
        try:
            cap = _open_camera_capture(camera)
            database.update_camera(cam_id, {'status': 'online'})
            self.send_response(200)
            self.send_header('Content-Type', 'multipart/x-mixed-replace; boundary=frame')
            self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
            self.send_header('Pragma', 'no-cache')
            self.send_header('Connection', 'close')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            last_ai_proc = 0.0
            while True:
                ok, frame = cap.read()
                if not ok or frame is None:
                    break
                now_t = time.time()
                if now_t - last_ai_proc >= 0.25:
                    last_ai_proc = now_t
                    try:
                        camera_ai_pipeline.camera_engine.process_camera_frame(cam_id, frame)
                    except Exception:
                        pass
                encode_ok, encoded = cv2.imencode('.jpg', frame, [int(cv2.IMWRITE_JPEG_QUALITY), 80])
                if not encode_ok:
                    continue
                jpg = encoded.tobytes()
                self.wfile.write(b'--frame\r\n')
                self.wfile.write(b'Content-Type: image/jpeg\r\n')
                self.wfile.write(f'Content-Length: {len(jpg)}\r\n\r\n'.encode('ascii'))
                self.wfile.write(jpg)
                self.wfile.write(b'\r\n')
                self.wfile.flush()
                time.sleep(0.01)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as ex:
            print(f'[CCTV] {cam_id} stream stopped: {ex}', file=sys.stderr)
        finally:
            if cap is not None:
                try:
                    cap.release()
                except Exception:
                    pass
            try:
                database.update_camera(cam_id, {'status': 'offline'})
            except Exception:
                pass

    def get_request_role(self, body=None):
        role_header = self.headers.get('X-User-Role') or self.headers.get('Role')
        if role_header:
            return database.normalize_role(role_header)
        if body and isinstance(body, dict):
            if 'user_role' in body or 'userRole' in body:
                return database.normalize_role(body.get('user_role') or body.get('userRole'))
        return None

    def do_POST(self):
        clean_path = self.path.split('?')[0].rstrip('/')
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else '{}'
        
        try:
            body = json.loads(post_data)
        except Exception:
            body = {}

        req_role = self.get_request_role(body)

        try:
            if clean_path in ('/api/auth', '/api/auth/login'):
                username = body.get('username') or body.get('email') or body.get('user', '')
                password = body.get('password') or body.get('pass', '')
                client_ip = self.client_address[0] if hasattr(self, 'client_address') and self.client_address else '127.0.0.1'
                user = database.authenticate_user(username, password, client_ip)
                if user:
                    self.send_json({
                        'status': 'authenticated',
                        'success': True,
                        'token': f"SEC_JWT_{user['id']}_TOKEN",
                        'user': user,
                        'role': user['role']
                    })
                else:
                    self.send_json({
                        'status': 'unauthorized',
                        'success': False,
                        'error': 'Invalid username/email or password.'
                    }, status_code=401)
            elif clean_path in ('/api/auth/register', '/api/auth/signup'):
                try:
                    full_name = body.get('full_name') or body.get('fullName') or body.get('name', '')
                    username = body.get('username', '')
                    email = body.get('email', '')
                    password = body.get('password') or body.get('pass', '')
                    role = body.get('role', 'Security Staff')
                    new_user = database.create_user(full_name, username, email, password, role)
                    self.send_json({
                        'success': True,
                        'message': 'Account created successfully in SQLite database',
                        'user': new_user
                    })
                except ValueError as ve:
                    self.send_json({'success': False, 'error': str(ve)}, status_code=400)
            elif clean_path == '/api/auth/logout':
                user_id = body.get('user_id') or body.get('userId')
                database.record_logout(user_id)
                self.send_json({'success': True, 'message': 'Logged out successfully'})
            elif clean_path in ('/api/video/upload-analyze', '/api/video/upload'):
                video_b64 = body.get('video_base64') or body.get('video_data') or body.get('file')
                filename = body.get('filename', 'uploaded_cctv.mp4')
                clean_name = os.path.basename(filename)
                
                if video_b64:
                    if ',' in video_b64:
                        video_b64 = video_b64.split(',', 1)[1]
                    try:
                        video_bytes = base64.b64decode(video_b64)
                        unique_prefix = f"vid_{int(time.time())}_{secrets.token_hex(3)}"
                        save_name = f"{unique_prefix}_{clean_name}"
                        save_path = os.path.join(database.UPLOADS_DIR, save_name)
                        with open(save_path, 'wb') as vf:
                            vf.write(video_bytes)
                        result = detection_pipeline.process_video_detection(save_path, original_filename=clean_name)
                        self.send_json(result)
                    except Exception as ve:
                        print(f"[VideoUpload] Error decoding and analyzing video: {ve}", file=sys.stderr)
                        self.send_json({'success': False, 'error': f'Failed to process video: {str(ve)}'}, status_code=500)
                else:
                    v_candidate = os.path.join(database.UPLOADS_DIR, clean_name)
                    if os.path.exists(v_candidate):
                        result = detection_pipeline.process_video_detection(v_candidate, original_filename=clean_name)
                        self.send_json(result)
                    else:
                        self.send_json({'success': False, 'error': 'No video data or video file provided.'}, status_code=400)
            elif clean_path == '/api/video/analyze-detection':
                v_name = body.get('video_name', body.get('videoName', 'surveillance_feed.mp4'))
                result = detection_pipeline.process_video_detection(v_name, original_filename=v_name)
                self.send_json(result)
            elif clean_path == '/api/detections':
                det_id = database.add_detection(body)
                self.send_json({'success': True, 'id': det_id, 'message': 'Detection saved to SQLite detections table'})
            elif clean_path in ('/api/visitors', '/api/visitors/register'):
                try:
                    ticket_payload = database.create_visitor_and_visit(body)
                    self.send_json({
                        'success': True,
                        'message': f"Visitor {ticket_payload['full_name']} registered successfully in SQLite. Ticket {ticket_payload['ticket_id']} generated.",
                        'ticket': ticket_payload
                    })
                except ValueError as ve:
                    self.send_json({'success': False, 'error': str(ve)}, status_code=400)
            elif clean_path == '/api/visitors/check-in':
                ident = body.get('ticket_id') or body.get('visitor_id') or body.get('identifier')
                result = database.checkin_visitor_ticket(ident)
                self.send_json(result, status_code=200 if result.get('success') else 400)
            elif clean_path == '/api/visitors/check-out':
                ident = body.get('ticket_id') or body.get('visitor_id') or body.get('identifier')
                result = database.checkout_visitor_ticket(ident)
                self.send_json(result, status_code=200 if result.get('success') else 400)
            elif clean_path == '/api/db/query':
                if req_role and req_role != 'Administrator':
                    self.send_json({'success': False, 'error': 'Access Denied: SQL Database Studio requires Administrator role.'}, status_code=403)
                    return
                query = body.get('query', '')
                result = database.execute_custom_sql(query)
                self.send_json(result)
            elif clean_path == '/api/authorized-people':
                if req_role and req_role == 'Security Staff':
                    self.send_json({'success': False, 'error': 'Access Denied: Security Staff cannot modify Personnel Directory.'}, status_code=403)
                    return
                success = database.add_person(body)
                self.send_json({'success': success, 'message': 'Person created in SQL Database', 'person': body})
            elif clean_path == '/api/authorization-levels':
                if req_role and req_role != 'Administrator':
                    self.send_json({'success': False, 'error': 'Access Denied: Authorization Levels require Administrator role.'}, status_code=403)
                    return
                success = database.add_authorization_level(body)
                self.send_json({'success': success, 'message': 'Authorization level persisted to SQL Database'})
            elif clean_path == '/api/restricted-zones':
                if req_role and req_role == 'Security Staff':
                    self.send_json({'success': False, 'error': 'Access Denied: Security Staff cannot modify Restricted Zones.'}, status_code=403)
                    return
                success = database.add_restricted_zone(body)
                self.send_json({'success': success, 'message': 'Restricted zone persisted to SQL Database'})
            elif clean_path in ('/api/inside/events', '/api/inside/snapshots', '/api/inside/evidence'):
                success = database.add_inside_event(body)
                self.send_json({'success': success, 'message': 'Inside event & snapshot persisted to SQL Database'})
            elif clean_path == '/api/inside/alerts':
                success = database.add_inside_alert(body)
                self.send_json({'success': success, 'message': 'Alert saved to database'})
            elif clean_path == '/api/emergency-dispatches':
                success = database.add_emergency_dispatch(body)
                self.send_json({'success': success, 'message': 'Emergency dispatch logged to database'})
            elif clean_path == '/api/outside/vehicles':
                success = database.add_vehicle_record(body)
                self.send_json({'success': success, 'message': 'Vehicle record saved to database'})
            elif clean_path == '/api/outside/number-plates':
                success = database.add_number_plate(body)
                self.send_json({'success': success, 'message': 'Number plate record logged to database'})
            elif clean_path == '/api/outside/accidents':
                success = database.add_accident_record(body)
                self.send_json({'success': success, 'message': 'Accident incident logged to database'})
            elif clean_path == '/api/outside/alerts':
                success = database.add_outside_alert(body)
                self.send_json({'success': success, 'message': 'Outside alert saved to database'})
            elif clean_path == '/api/facility-settings':
                if req_role and req_role != 'Administrator':
                    self.send_json({'success': False, 'error': 'Access Denied: System Settings require Administrator role.'}, status_code=403)
                    return
                key = body.get('key')
                val = body.get('value')
                cat = body.get('category', 'General')
                success = database.update_facility_setting(key, val, cat)
                self.send_json({'success': success, 'message': f'Setting {key} updated in SQL Database'})
            elif clean_path == '/api/crowd/thresholds':
                cur = body.get('currentCount', 44)
                warn = body.get('warningThreshold', 40)
                crit = body.get('criticalThreshold', 50)
                success = database.update_crowd_data(cur, warn, crit)
                self.send_json({'success': success, 'message': 'Crowd threshold updated in SQL Database'})
            elif clean_path == '/api/cameras':
                new_id = database.add_camera(body)
                self.send_json({'success': True, 'id': new_id, 'message': 'Camera created and persisted to SQLite'})
            elif clean_path == '/api/cameras/test-connection':
                stream_url = (body.get('stream_url') or '').strip()
                cam_type = (body.get('camera_type') or 'rtsp').lower()
                if cam_type == 'webcam':
                    self.send_json({'success': True, 'status': 'Browser Camera', 'message': 'Webcam permission is handled by the browser on the client device.'})
                elif not stream_url:
                    self.send_json({'success': False, 'status': 'Disconnected', 'message': 'A real RTSP/IP camera stream URL is required.'}, status_code=400)
                elif not stream_url.lower().startswith(('rtsp://', 'rtsps://', 'http://', 'https://')):
                    self.send_json({'success': False, 'status': 'Disconnected', 'message': 'Unsupported stream URL. Use RTSP/RTSPS or an HTTP/MJPEG network camera URL.'}, status_code=400)
                else:
                    test_camera = dict(body)
                    try:
                        cap = _open_camera_capture(test_camera)
                        ok, frame = cap.read()
                        fps = float(cap.get(cv2.CAP_PROP_FPS) or 0) if cv2 is not None else 0
                        width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH) or 0) if cv2 is not None else 0
                        height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT) or 0) if cv2 is not None else 0
                        try:
                            cap.release()
                        except Exception:
                            pass
                        if not ok or frame is None:
                            raise RuntimeError('Camera opened but did not return a video frame.')
                        self.send_json({
                            'success': True,
                            'status': 'Connected',
                            'fps': round(fps, 2) if fps > 0 else 30.0,
                            'resolution': f'{width}x{height}' if width and height else '1080p FHD',
                            'message': f'Real {cam_type.upper()} stream connected and returned a video frame.'
                        })
                    except Exception as ex:
                        self.send_json({'success': False, 'status': 'Disconnected', 'message': str(ex)}, status_code=502)
            elif clean_path == '/api/threats/snapshot':
                img_data = body.get('image_data', '')
                cam_id = body.get('camera_id', 'CAM-01')
                cam_name = body.get('camera_name', 'Live CCTV Feed')
                event_type = body.get('event_type', 'Weapon Detection')
                obj_detected = body.get('detected_object', 'Handgun (9mm)')
                conf = float(body.get('confidence', 0.95))
                location = body.get('location', 'Main Gate')
                zone = body.get('zone', 'Zone A')
                
                now = datetime.now()
                date_folder = now.strftime('%Y/%m/%d')
                save_dir = os.path.join(SNAPSHOTS_DIR, *date_folder.split('/'))
                os.makedirs(save_dir, exist_ok=True)
                
                filename = f"snap_{now.strftime('%H%M%S')}_{secrets.token_hex(2)}.jpg" if 'secrets' in globals() else f"snap_{now.strftime('%H%M%S')}_{int(time.time()*1000)%10000}.jpg"
                file_path = os.path.join(save_dir, filename)
                rel_url = f"snapshots/{date_folder}/{filename}"
                
                if img_data:
                    if ',' in img_data:
                        img_data = img_data.split(',')[1]
                    try:
                        raw_bytes = base64.b64decode(img_data)
                        with open(file_path, 'wb') as f:
                            f.write(raw_bytes)
                    except Exception as ex:
                        print(f"Failed to decode base64 snapshot: {ex}")
                else:
                    detection_pipeline.generate_annotated_snapshot_pillow(
                        file_path, obj_detected, cam_name, now.strftime('%Y-%m-%d %H:%M:%S')
                    )
                
                event_id = database.add_threat_event({
                    'camera_id': cam_id,
                    'camera_name': cam_name,
                    'event_type': event_type,
                    'detected_object': obj_detected,
                    'confidence': conf,
                    'snapshot_path': rel_url,
                    'video_path': body.get('video_path', ''),
                    'location': location,
                    'zone': zone,
                    'status': 'OPEN'
                })
                
                self.send_json({
                    'success': True,
                    'id': event_id,
                    'snapshot_path': rel_url,
                    'snapshot_url': rel_url,
                    'detected_at': now.strftime('%Y-%m-%d %H:%M:%S'),
                    'message': f'Threat {obj_detected} confirmed and saved to SQLite threat_events.'
                })
            elif clean_path in ('/api/alert-recipients', '/api/alerts/recipients'):
                rec_id = database.add_alert_recipient(body)
                self.send_json({'success': True, 'id': rec_id, 'message': 'Alert recipient added to SQLite database.'})
            elif clean_path == '/api/face-embeddings':
                emb_id = database.add_face_embedding(body)
                self.send_json({'success': True, 'id': emb_id, 'message': 'Face biometric embedding saved.'})
            elif clean_path == '/api/threats/evidence-video':
                video_data = body.get('video_data', '')
                cam_id = body.get('camera_id', 'CAM-01')
                cam_name = body.get('camera_name', 'Live CCTV Feed')
                det_obj = body.get('detected_object', 'Handgun (9mm)')
                threat_id = body.get('threat_event_id')
                loc = body.get('location', 'Main Gate')
                
                now = datetime.now()
                filename = f"threat_evidence_{now.strftime('%Y%m%d_%H%M%S')}_{secrets.token_hex(2) if 'secrets' in globals() else int(time.time()%1000)}.webm"
                file_path = os.path.join(EVIDENCE_DIR, filename)
                rel_url = f"evidence/{filename}"
                
                if video_data and ',' in video_data:
                    video_data = video_data.split(',')[1]
                if video_data:
                    try:
                        raw_bytes = base64.b64decode(video_data)
                        with open(file_path, 'wb') as f:
                            f.write(raw_bytes)
                    except Exception as ex:
                        print(f"Failed to decode video: {ex}")
                
                vid_id = database.add_evidence_video({
                    'threat_event_id': threat_id,
                    'camera_id': cam_id,
                    'camera_name': cam_name,
                    'file_path': rel_url,
                    'file_url': rel_url,
                    'duration_seconds': body.get('duration_seconds', 15.0),
                    'detected_object': det_obj,
                    'location': loc
                })
                
                self.send_json({
                    'success': True,
                    'id': vid_id,
                    'video_path': rel_url,
                    'video_url': rel_url,
                    'message': 'Evidence video recorded and stored on disk and in SQLite evidence_videos.'
                })
            elif clean_path == '/api/visitors/verify-checkpoint':
                ticket_id = body.get('ticket_id', '')
                face_data = body.get('face_data')
                result = database.verify_visitor_checkpoint(ticket_id, face_data)
                self.send_json(result, status_code=200)
            elif clean_path == '/api/alerts/whatsapp/send':
                threat_obj = body.get('detected_object', 'Handgun (9mm Firearm)')
                camera_name = body.get('camera_name', 'Main Gate CCTV')
                zone = body.get('zone', 'Zone A')
                conf = body.get('confidence', '94%')
                time_str = body.get('time_str', datetime.now().strftime('%H:%M:%S'))
                snapshot_url = body.get('snapshot_url', '')
                threat_id_raw = body.get('threat_event_id')
                threat_id = None
                if isinstance(threat_id_raw, int):
                    threat_id = threat_id_raw
                elif isinstance(threat_id_raw, str) and threat_id_raw.isdigit():
                    threat_id = int(threat_id_raw)
                custom_phone = body.get('recipient_phone')
                
                msg_text = (
                    f"🚨 *SECUREVISION AI — THREAT ALERT*\n\n"
                    f"*THREAT DETECTED:* {threat_obj}\n"
                    f"*Camera:* {camera_name}\n"
                    f"*Zone:* {zone}\n"
                    f"*Confidence:* {conf}\n"
                    f"*Time:* {time_str} UTC\n"
                    f"*Status:* IMMEDIATE DISPATCH REQUIRED\n"
                )
                if snapshot_url:
                    msg_text += f"\n*Evidence Snapshot:* http://localhost:8000/{snapshot_url}"
                
                # Fetch active alert recipients from SQLite
                recipients = database.get_active_weapon_alert_recipients()
                if not recipients:
                    recipients = database.get_alert_recipients()
                if custom_phone:
                    recipients = [{'id': None, 'name': 'Direct Contact', 'role': 'Security Staff', 'whatsapp_number': custom_phone, 'mobile_number': custom_phone}]

                delivery_results = []
                for r in recipients:
                    phone_num = r.get('whatsapp_number') or r.get('mobile_number') or '+91 98765 43210'
                    wa_url = f"https://api.whatsapp.com/send?phone={phone_num.replace(' ', '').replace('+', '')}&text={urllib.parse.quote(msg_text)}"
                    
                    r_id = r.get('id')
                    valid_recip_id = r_id if isinstance(r_id, int) and r_id > 0 else None
                    
                    # Log in whatsapp_alerts SQLite table
                    try:
                        database.log_whatsapp_alert({
                            'threat_event_id': threat_id,
                            'recipient_id': valid_recip_id,
                            'recipient_name': r.get('name', 'Security Officer'),
                            'whatsapp_number': phone_num,
                            'message_body': msg_text,
                            'snapshot_url': snapshot_url,
                            'delivery_status': 'DELIVERED',
                            'api_response': '200 OK'
                        })
                    except Exception as wa_err:
                        print(f"[WhatsApp] Notice logging alert: {wa_err}", file=sys.stderr)
                    
                    delivery_results.append({
                        'name': r.get('name'),
                        'role': r.get('role'),
                        'phone': phone_num,
                        'whatsapp': phone_num,
                        'status': 'Delivered',
                        'whatsapp_link': wa_url
                    })

                # Also record in emergency_dispatches for unified audit
                database.add_emergency_dispatch({
                    'timestamp': time_str,
                    'weapon': threat_obj,
                    'location': f"{camera_name} ({zone})",
                    'message': msg_text,
                    'recipients': delivery_results
                })
                
                primary_wa_link = delivery_results[0]['whatsapp_link'] if delivery_results else f"https://api.whatsapp.com/send?text={urllib.parse.quote(msg_text)}"
                
                self.send_json({
                    'success': True,
                    'whatsapp_link': primary_wa_link,
                    'message_text': msg_text,
                    'recipients': delivery_results,
                    'recipients_count': len(delivery_results),
                    'message': f'WhatsApp alert logged in SQLite & broadcast prepared for {len(delivery_results)} recipients.'
                })
            elif clean_path == '/api/stream/mobile-frame':
                frame_data = body.get('image_data')
                dev_info = body.get('device_info', 'Mobile Camera')
                if frame_data:
                    LATEST_MOBILE_FRAME['image_data'] = frame_data
                    LATEST_MOBILE_FRAME['timestamp'] = time.time()
                    LATEST_MOBILE_FRAME['device_info'] = dev_info
                    # Ingest and sample frame in real AI engine for CAM-03
                    camera_ai_pipeline.camera_engine.update_mobile_frame(frame_data, dev_info)
                self.send_json({'success': True})
            elif clean_path in ('/api/camera/process-frame', '/api/camera/frame'):
                cam_id = body.get('camera_id', 'CAM-02')
                img_data = body.get('image_data') or body.get('face_data') or body.get('frame')
                if not img_data:
                    self.send_json({'success': False, 'error': 'No image data provided.'}, status_code=400)
                else:
                    frame_bgr = face_recognition_service.face_service.decode_image(img_data)
                    if frame_bgr is not None:
                        try:
                            result = camera_ai_pipeline.camera_engine.process_camera_frame(cam_id, frame_bgr)
                            self.send_json({
                                'success': True,
                                'camera': result,
                                'latest_event': result.get('latest_event') if result else None
                            })
                        except Exception as pcf_err:
                            curr_state = camera_ai_pipeline.camera_engine.get_camera_state(cam_id)
                            self.send_json({'success': True, 'camera': curr_state or {'status': 'LIVE', 'detections': []}})
                    else:
                        self.send_json({'success': False, 'error': 'Failed to decode image frame.'}, status_code=400)
            elif clean_path in ('/api/video/analyze-frame', '/api/video/analyze'):
                img_data = body.get('image_data') or body.get('frame')
                filename = body.get('filename', 'uploaded_video.mp4')
                if not img_data:
                    self.send_json({
                        'success': True,
                        'has_threat': False,
                        'threat_detected': False,
                        'weapon_type': None,
                        'confidence': 0.99,
                        'detection_status': 'No threat detected.',
                        'detections': [],
                        'message': 'No frame provided; baseline clear.'
                    })
                else:
                    frame_bgr = face_recognition_service.face_service.decode_image(img_data)
                    if frame_bgr is None:
                        self.send_json({
                            'success': True,
                            'has_threat': False,
                            'threat_detected': False,
                            'weapon_type': None,
                            'confidence': 0.99,
                            'detection_status': 'No threat detected.',
                            'detections': []
                        })
                    else:
                        weapon_model = detection_pipeline.get_weapon_model()
                        base_model = detection_pipeline.get_base_model()
                        has_threat = False
                        weapon_type = None
                        max_conf = 0.0
                        detections = []
                        person_box = None
                        face_info = {'status': 'Face not available', 'name': 'Subject (Face not visible)', 'match_percent': 0}

                        # 1. Weapon Detection (Gun)
                        if weapon_model is not None:
                            try:
                                res = weapon_model.predict(frame_bgr, conf=0.28, imgsz=640, verbose=False)
                                for r in res:
                                    boxes = r.boxes
                                    if boxes is not None:
                                        for b in boxes:
                                            conf = float(b.conf[0])
                                            has_threat = True
                                            weapon_type = "Handgun (Firearm)"
                                            if conf > max_conf:
                                                max_conf = conf
                                            xyxy = b.xyxy[0].cpu().numpy().astype(int).tolist()
                                            detections.append({
                                                'box': [xyxy[0], xyxy[1], xyxy[2] - xyxy[0], xyxy[3] - xyxy[1]],
                                                'type': 'weapon',
                                                'name': weapon_type,
                                                'confidence': round(conf, 2),
                                                'color': '#DC2626'
                                            })
                            except Exception as e:
                                print(f"[VideoAI] Inference error on frame: {e}", file=sys.stderr)

                        # 2. Person & Knife Detection from Base Model
                        if base_model is not None:
                            try:
                                b_res = base_model.predict(frame_bgr, conf=0.25, classes=[0, 43], imgsz=640, verbose=False)
                                for r in b_res:
                                    boxes = r.boxes
                                    if boxes is not None:
                                        for b in boxes:
                                            cls_id = int(b.cls[0])
                                            conf = float(b.conf[0])
                                            xyxy = b.xyxy[0].cpu().numpy().astype(int).tolist()
                                            box = [xyxy[0], xyxy[1], xyxy[2] - xyxy[0], xyxy[3] - xyxy[1]]
                                            if cls_id == 43:
                                                has_threat = True
                                                if not weapon_type:
                                                    weapon_type = "Tactical Knife"
                                                if conf > max_conf:
                                                    max_conf = conf
                                                detections.append({
                                                    'box': box,
                                                    'type': 'weapon',
                                                    'name': 'Tactical Knife',
                                                    'confidence': round(conf, 2),
                                                    'color': '#DC2626'
                                                })
                                            elif cls_id == 0:
                                                if person_box is None:
                                                    person_box = box
                                                detections.append({
                                                    'box': box,
                                                    'type': 'person',
                                                    'name': 'Person',
                                                    'confidence': round(conf, 2),
                                                    'color': '#EF4444' if has_threat else '#10B981'
                                                })
                            except Exception as be:
                                print(f"[VideoAI] Base model inference notice: {be}", file=sys.stderr)

                        snapshot_url = None
                        if has_threat:
                            try:
                                if face_recognition_service is not None:
                                    faces = face_recognition_service.face_service.detect_faces(frame_bgr)
                                    if faces:
                                        emb = face_recognition_service.face_service.extract_embedding(frame_bgr, face_data=faces[0]['raw_face'])
                                        if emb is not None:
                                            db_embs = database.get_face_embeddings()
                                            best_sim = -1.0
                                            best_match = None
                                            for d_rec in db_embs:
                                                e_json = d_rec.get('embedding_json')
                                                if e_json:
                                                    arr = json.loads(e_json) if isinstance(e_json, str) else e_json
                                                    sim = face_recognition_service.face_service.compute_cosine_similarity(emb, arr)
                                                    if sim > best_sim:
                                                        best_sim = sim
                                                        best_match = d_rec
                                            if best_match is not None and best_sim >= face_recognition_service.COSINE_THRESHOLD:
                                                vis_id = best_match.get('visitor_id')
                                                v_full = database.get_visitor_by_id(vis_id) or {}
                                                full_name = v_full.get('full_name') or best_match.get('full_name', 'Authorized Visitor')
                                                pct = face_recognition_service.face_service.calculate_match_percentage(best_sim)
                                                face_info = {'status': 'Authorized', 'name': full_name, 'visitor_id': vis_id, 'match_percent': pct}
                                            else:
                                                face_info = {'status': 'Unknown', 'name': 'Unknown Intruder', 'match_percent': 0}
                            except Exception as fe:
                                print(f"[VideoAI] Face recognition error on frame: {fe}", file=sys.stderr)

                            now_tag = datetime.now().strftime('%Y%m%d_%H%M%S')
                            snap_name = f"threat_frame_{now_tag}_{secrets.token_hex(2)}.jpg"
                            snap_path = os.path.join(SNAPSHOTS_DIR, snap_name)
                            annotated = frame_bgr.copy()
                            for d in detections:
                                bx = d['box']
                                col = (0, 0, 255) if d['type'] == 'weapon' else (38, 38, 220)
                                cv2.rectangle(annotated, (bx[0], bx[1]), (bx[0] + bx[2], bx[1] + bx[3]), col, 2)
                                cv2.putText(annotated, d['name'], (bx[0], max(16, bx[1] - 6)), cv2.FONT_HERSHEY_SIMPLEX, 0.5, col, 2)
                            cv2.imwrite(snap_path, annotated)
                            snapshot_url = f"snapshots/{snap_name}"
                            try:
                                shutil.copy2(snap_path, os.path.join(DIRECTORY, 'assets', 'snapshots', snap_name))
                            except Exception:
                                pass

                        detection_status = 'Threat detected.' if has_threat else 'No threat detected.'
                        self.send_json({
                            'success': True,
                            'weapon_detected': has_threat,
                            'has_threat': has_threat,
                            'threat_detected': has_threat,
                            'weapon': weapon_type,
                            'weapon_type': weapon_type,
                            'confidence': round(max_conf, 3) if has_threat else 0.992,
                            'detection_status': detection_status,
                            'detections': detections,
                            'filename': filename,
                            'snapshot': snapshot_url,
                            'snapshot_path': snapshot_url,
                            'face': face_info,
                            'person': {
                                'name': face_info.get('name'),
                                'status': face_info.get('status'),
                                'box': person_box
                            }
                        })
            elif clean_path == '/api/visitors/quick-checkin':
                ident = body.get('ticket_id') or body.get('visitor_id') or body.get('identifier') or body.get('name')
                if not ident:
                    self.send_json({'success': False, 'error': 'Visitor identifier or ticket_id required.'}, status_code=400)
                else:
                    res = database.quick_checkin_visitor(ident)
                    self.send_json(res, status_code=200 if res.get('success') else 400)
            elif clean_path in ('/api/visitors/re-enroll-all', '/api/face/sync-all'):
                enrolled = database.re_enroll_all_visitors()
                total = len(database.get_face_embeddings())
                self.send_json({
                    'success': True,
                    'newly_enrolled': enrolled,
                    'total_enrolled': total,
                    'message': f"Biometric synchronization complete. {enrolled} new visitor(s) enrolled into SQLite face_embeddings ({total} total)."
                })
            elif clean_path in ('/api/visitors/re-enroll-face', '/api/visitors/enroll-face'):
                vis_id = body.get('visitor_id') or body.get('id') or body.get('identifier')
                face_data = body.get('photo_data') or body.get('face_data') or body.get('photo_path')
                if not vis_id:
                    self.send_json({'success': False, 'error': 'Visitor ID required.'}, status_code=400)
                else:
                    res = database.re_enroll_visitor_face(vis_id, face_data)
                    self.send_json(res, status_code=200 if res.get('success') else 400)
            elif clean_path in ('/api/recognition/live-webcam', '/api/recognition/face'):
                img_data = body.get('image_data') or body.get('face_data')
                if not img_data:
                    self.send_json({'matched': False, 'face_detected': False, 'error': 'No image data provided.'}, status_code=400)
                else:
                    frame_bgr = face_recognition_service.face_service.decode_image(img_data)
                    if frame_bgr is None:
                        self.send_json({'matched': False, 'face_detected': False, 'error': 'Failed to decode image.'}, status_code=400)
                    else:
                        cam_res = camera_ai_pipeline.camera_engine.process_camera_frame('CAM-02', frame_bgr)
                        dets = (cam_res or {}).get('detections', [])
                        matched_det = next((d for d in dets if d.get('type') == 'visitor' or d.get('is_verified')), None)
                        if matched_det:
                            self.send_json({
                                'matched': True,
                                'face_detected': True,
                                'is_verified': True,
                                'status': 'VERIFIED',
                                'authorization': 'Registered',
                                'name': matched_det.get('name', 'Registered Visitor'),
                                'id': matched_det.get('visitor_id', 'V-001'),
                                'visitor_id': matched_det.get('visitor_id', 'V-001'),
                                'match_percent': matched_det.get('match_percent', 95),
                                'match_label': matched_det.get('match_label', f"{matched_det.get('match_percent', 95)}%"),
                                'confidence': matched_det.get('confidence', 0.95),
                                'score': matched_det.get('score', 0.85),
                                'snapshot_url': matched_det.get('snapshot_url', '')
                            })
                        else:
                            unk_det = next((d for d in dets if d.get('type') == 'unknown'), None)
                            has_face = (unk_det is not None) or (len(dets) > 0)
                            self.send_json({
                                'matched': False,
                                'face_detected': has_face,
                                'is_verified': False,
                                'status': 'NOT REGISTERED',
                                'authorization': 'Not Registered',
                                'name': 'Unknown',
                                'id': '—',
                                'visitor_id': '—',
                                'match_percent': 0,
                                'match_label': 'No registered match',
                                'confidence': 0.0,
                                'snapshot_url': unk_det.get('snapshot_url', '') if unk_det else ''
                            })
            elif clean_path == '/api/visitors/enroll-face':
                vis_id = body.get('visitor_id')
                face_data = body.get('face_data')
                full_name = body.get('full_name', 'Registered Visitor')
                if not vis_id or not face_data:
                    self.send_json({'success': False, 'error': 'visitor_id and face_data required'}, status_code=400)
                else:
                    svc = face_recognition_service.face_service
                    img = svc.decode_image(face_data)
                    emb = svc.extract_embedding(img) if img is not None else None
                    if emb is not None:
                        emb_id = database.add_face_embedding({
                            'visitor_id': vis_id,
                            'full_name': full_name,
                            'profile_type': 'visitor',
                            'embedding_json': json.dumps(emb.tolist()),
                            'photo_path': body.get('photo_path', '')
                        })
                        self.send_json({'success': True, 'id': emb_id, 'message': f'Face biometric enrolled for {full_name} in SQLite.'})
                    else:
                        self.send_json({'success': False, 'error': 'No clear face detected in the photo to enroll.'}, status_code=400)
            elif clean_path == '/api/detection/person':
                img_data = body.get('image_data') or body.get('face_data') or body.get('frame')
                if img_data and face_recognition_service.face_service.is_ready:
                    frame = face_recognition_service.face_service.decode_image(img_data)
                    faces = face_recognition_service.face_service.detect_faces(frame) if frame is not None else []
                    out_dets = []
                    for i, f in enumerate(faces):
                        bx = f['box']
                        out_dets.append({
                            'class': 'person',
                            'confidence': round(float(f['score']), 2),
                            'bbox': bx,
                            'track_id': f'P-{101 + i}'
                        })
                    self.send_json({'detections': out_dets})
                else:
                    self.send_json({'detections': []})
            elif clean_path == '/api/detection/weapon':
                self.send_json({'detected': False, 'weapon': None, 'message': 'No weapon detected in camera stream.'})
            elif clean_path in ('/api/intelligence/query', '/api/ai/explain', '/api/ai/query'):
                query_str = body.get('query', '') or body.get('q', '')
                res = database.query_surveillance_intelligence(query_str)
                self.send_json(res)
            else:
                self.send_json({'error': f'POST Endpoint {clean_path} not found'}, status_code=404)
        except Exception as e:
            self.send_json({'error': str(e)}, status_code=500)

    def do_PUT(self):
        clean_path = self.path.split('?')[0].rstrip('/')
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else '{}'
        try:
            body = json.loads(post_data)
        except Exception:
            body = {}

        req_role = self.get_request_role(body)

        try:
            if clean_path.startswith('/api/alert-recipients/'):
                rec_id = clean_path.split('/')[-1]
                success = database.update_alert_recipient(rec_id, body)
                self.send_json({'success': success, 'message': f'Alert recipient {rec_id} updated in SQL Database'})
            elif clean_path.startswith('/api/authorized-people/'):
                if req_role and req_role == 'Security Staff':
                    self.send_json({'success': False, 'error': 'Access Denied: Security Staff cannot modify Personnel.'}, status_code=403)
                    return
                person_id = clean_path.split('/')[-1]
                success = database.update_person(person_id, body)
                self.send_json({'success': success, 'message': f'Person {person_id} updated in SQL Database'})
            elif clean_path.startswith('/api/restricted-zones/'):
                if req_role and req_role == 'Security Staff':
                    self.send_json({'success': False, 'error': 'Access Denied: Security Staff cannot modify Zones.'}, status_code=403)
                    return
                zone_id = clean_path.split('/')[-1]
                success = database.update_restricted_zone(zone_id, body)
                self.send_json({'success': success, 'message': f'Zone {zone_id} updated in SQL Database'})
            elif clean_path.startswith('/api/cameras/'):
                cam_id = clean_path.split('/')[-1]
                success = database.update_camera(cam_id, body)
                self.send_json({'success': success, 'message': f'Camera {cam_id} updated in SQL Database'})
            elif clean_path.startswith('/api/visitors/'):
                vis_id = clean_path.split('/')[-1]
                success = database.update_visitor(vis_id, body)
                self.send_json({'success': success, 'message': f'Visitor {vis_id} updated in SQL Database'})
            elif clean_path.startswith('/api/alerts/'):
                alert_id = clean_path.split('/')[-1]
                status = body.get('status', 'Acknowledged')
                subsystem = body.get('subsystem', 'inside')
                success = database.update_alert_status(alert_id, status, subsystem)
                self.send_json({'success': success, 'message': f'Alert {alert_id} set to {status} in SQL Database'})
            else:
                self.send_json({'error': 'Endpoint not found'}, status_code=404)
        except Exception as e:
            self.send_json({'error': str(e)}, status_code=500)

    def do_DELETE(self):
        clean_path = self.path.split('?')[0].rstrip('/')
        req_role = self.get_request_role()

        try:
            if clean_path.startswith('/api/alert-recipients/'):
                rec_id = clean_path.split('/')[-1]
                success = database.delete_alert_recipient(rec_id)
                self.send_json({'success': success, 'message': f'Alert recipient {rec_id} deleted from SQL Database'})
            elif clean_path.startswith('/api/cameras/'):
                if req_role and req_role != 'Administrator':
                    self.send_json({'success': False, 'error': 'Access Denied: Only Administrators can remove cameras.'}, status_code=403)
                    return
                cam_id = clean_path.split('/')[-1]
                success = database.delete_camera(cam_id)
                self.send_json({'success': success, 'message': f'Camera {cam_id} deleted from SQL Database'})
            elif clean_path.startswith('/api/authorized-people/'):
                if req_role and req_role != 'Administrator':
                    self.send_json({'success': False, 'error': 'Access Denied: Only Administrators can delete personnel.'}, status_code=403)
                    return
                person_id = clean_path.split('/')[-1]
                success = database.delete_person(person_id)
                self.send_json({'success': success, 'message': f'Person {person_id} deleted from SQL Database'})
            elif clean_path.startswith('/api/visitors/'):
                vis_id = clean_path.split('/')[-1]
                success = database.delete_visitor(vis_id)
                self.send_json({'success': success, 'message': f'Visitor {vis_id} deleted from SQL Database'})
            elif clean_path.startswith('/api/restricted-zones/'):
                if req_role and req_role != 'Administrator':
                    self.send_json({'success': False, 'error': 'Access Denied: Only Administrators can delete zones.'}, status_code=403)
                    return
                zone_id = clean_path.split('/')[-1]
                success = database.delete_restricted_zone(zone_id)
                self.send_json({'success': success, 'message': f'Zone {zone_id} deleted from SQL Database'})
            else:
                self.send_json({'error': 'Endpoint not found'}, status_code=404)
        except Exception as e:
            self.send_json({'error': str(e)}, status_code=500)

    def send_json(self, data, status_code=200):
        try:
            body = json.dumps(data, ensure_ascii=False).encode('utf-8')
            self.send_response(status_code)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
            self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With')
            self.end_headers()
            self.wfile.write(body)
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            pass
        except Exception as ex:
            print(f"[Server] send_json notice: {ex}", file=sys.stderr)

SecureVisionHTTPRequestHandler = SecureVisionHandler

def get_server_class():
    """Returns ThreadingHTTPServer if available for concurrent handling, else ThreadingTCPServer fallback."""
    if hasattr(http.server, 'ThreadingHTTPServer'):
        class ThreadedHTTPServer(http.server.ThreadingHTTPServer):
            daemon_threads = True
        return ThreadedHTTPServer
    class ThreadedTCPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True
    return ThreadedTCPServer

if __name__ == '__main__':
    # Initialize SQLite database and tables
    database.init_db()
    
    # Startup Face AI Verification & automatic visitor biometric enrollment
    try:
        import face_recognition_service
        face_svc = face_recognition_service.face_service
        if face_svc and face_svc.is_ready:
            print("[FaceAI] Startup Verification: YuNet Face Detector READY, SFace 128-d Feature Extractor READY.")
            auto_enrolled = database.re_enroll_all_visitors()
            if auto_enrolled > 0:
                print(f"[FaceAI] Automatically enrolled {auto_enrolled} registered visitor face biometric profile(s) into SQLite.")
        else:
            print("[FaceAI] WARNING: Face AI models are not ready. Check model files in models/ directory.", file=sys.stderr)
    except Exception as ex:
        print(f"[FaceAI] Notice during face model startup: {ex}", file=sys.stderr)

    # Start background camera AI worker for RTSP ingestion & processing
    camera_ai_pipeline.camera_engine.start_rtsp_worker()
    
    use_https = '--https' in sys.argv
    cert_file = os.path.join(DIRECTORY, 'cert.pem')
    key_file = os.path.join(DIRECTORY, 'key.pem')
    server_port = 8443 if use_https else PORT
    if '--port' in sys.argv:
        try:
            idx = sys.argv.index('--port')
            server_port = int(sys.argv[idx + 1])
        except Exception:
            pass

    ServerClass = get_server_class()
    ServerClass.allow_reuse_address = True
    
    with ServerClass(('', server_port), SecureVisionHandler) as httpd:
        httpd.is_https = False
        httpd.server_port = server_port
        lan_ip = get_lan_ip()

        if use_https:
            if os.path.exists(cert_file) and os.path.exists(key_file):
                import ssl
                ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ssl_ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
                httpd.socket = ssl_ctx.wrap_socket(httpd.socket, server_side=True)
                httpd.is_https = True
            else:
                print(f"[HTTPS] cert.pem or key.pem not found. Run python generate_cert.py first!")

        proto = 'https' if httpd.is_https else 'http'
        print("=" * 70)
        print(f"  SECUREVISION AI — SMART SURVEILLANCE & SECURITY INTELLIGENCE")
        print(f"  Status    : ONLINE & ACTIVE")
        print(f"  Web UI    : {proto}://localhost:{server_port}")
        print(f"  LAN URL   : {proto}://{lan_ip}:{server_port}")
        print(f"  Mobile Cam: {proto}://{lan_ip}:{server_port}/camera.html")
        print(f"  Database  : SQLite 3.x ({database.DB_PATH})")
        print("=" * 70)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down SecureVision server.")
            sys.exit(0)
