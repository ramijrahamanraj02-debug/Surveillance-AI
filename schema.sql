-- =============================================================================
-- SecureVision AI - Enterprise Relational SQL Database Schema
-- Version: 2.4 | Engine: SQLite / PostgreSQL / MySQL Compatible
-- Description: Comprehensive database schema for Inside Secure Area, Outside 
--              Public Area, Biometrics, Weapon Threats, ANPR & Emergency Dispatches
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1. USERS & OPERATOR AUTHENTICATION (SQLite Relational Model)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name TEXT NOT NULL,
    username TEXT NOT NULL UNIQUE,
    email TEXT UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME
);

-- -----------------------------------------------------------------------------
-- 1b. LOGIN AUDIT HISTORY & ACCESS LOGS
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS login_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    username TEXT,
    role TEXT,
    login_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    logout_time DATETIME,
    status TEXT DEFAULT 'Success',
    ip_address TEXT DEFAULT '127.0.0.1',
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- -----------------------------------------------------------------------------
-- 1c. VISITORS REPOSITORY (Museum / Public / Gov Property Visitors)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS visitors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    visitor_id TEXT UNIQUE NOT NULL,
    full_name TEXT NOT NULL,
    photo_path TEXT,
    mobile_number TEXT,
    whatsapp_number TEXT,
    email TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- -----------------------------------------------------------------------------
-- 1d. VISITS & QR ENTRY PASS / TICKETING
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS visits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    visitor_id INTEGER NOT NULL,
    visit_date TEXT NOT NULL,
    visit_time TEXT,
    purpose TEXT,
    department TEXT,
    host_name TEXT,
    authorization_level TEXT DEFAULT 'Standard Visitor',
    allowed_zone TEXT DEFAULT 'Zone A (Main Gallery)',
    status TEXT DEFAULT 'Approved', -- Approved, Checked In, Completed, Cancelled
    ticket_id TEXT UNIQUE,
    ticket_path TEXT,
    ticket_sent INTEGER DEFAULT 0,
    entry_time DATETIME,
    exit_time DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (visitor_id) REFERENCES visitors(id) ON DELETE CASCADE
);

-- -----------------------------------------------------------------------------
-- 2. AUTHORIZATION LEVELS & RBAC PRIVILEGES
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS authorization_levels (
    id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    zones_json TEXT, -- JSON array of permitted zones: ["Zone A", "Zone B", "Zone C"]
    permissions_json TEXT, -- JSON array: ["All Zones", "Arms Carry", "Evidence Purge"]
    badge_color VARCHAR(20) DEFAULT '#2563EB',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- -----------------------------------------------------------------------------
-- 3. AUTHORIZED PERSONNEL & BIOMETRIC REPOSITORY
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS authorized_personnel (
    id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    role VARCHAR(100) NOT NULL,
    level_id VARCHAR(50) REFERENCES authorization_levels(id),
    department VARCHAR(100) NOT NULL,
    allowed_zones_json TEXT, -- JSON array: ["Zone A", "Zone B", "Zone C"]
    phone VARCHAR(30),
    whatsapp VARCHAR(30),
    status VARCHAR(20) NOT NULL DEFAULT 'Active', -- Active, Suspended, Revoked
    reg_date DATE DEFAULT (CURRENT_DATE),
    face_profile VARCHAR(100), -- 128D FaceNet Embedding Hash / Identifier
    avatar_color VARCHAR(20) DEFAULT '#10B981',
    photo_url TEXT, -- Base64 thumbnail or media storage path
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- -----------------------------------------------------------------------------
-- 4. RESTRICTED SECURITY ZONES (Inside Polygon & Geometric Definitions)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS restricted_zones (
    id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    allowed_levels_json TEXT, -- JSON array: ["Administrator", "Security Staff"]
    security_level VARCHAR(20) NOT NULL, -- Critical, High, Medium
    severity VARCHAR(20) NOT NULL DEFAULT 'Critical',
    color VARCHAR(20) DEFAULT '#EF4444',
    points_json TEXT NOT NULL, -- Normalized polygon vertices JSON: [{"x":0.15,"y":0.2}, ...]
    is_active INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- -----------------------------------------------------------------------------
-- 5. INSIDE CCTV CAMERAS
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS inside_cameras (
    id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    location VARCHAR(100) NOT NULL,
    rtsp_url TEXT NOT NULL,
    status VARCHAR(20) DEFAULT 'Online', -- Online, Offline, Connecting
    zone_id VARCHAR(50) REFERENCES restricted_zones(id),
    area VARCHAR(20) DEFAULT 'Inside',
    fps INTEGER DEFAULT 30,
    resolution VARCHAR(20) DEFAULT '4K UHD',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- -----------------------------------------------------------------------------
-- 5b. UNIFIED REAL-TIME CAMERAS & STREAMS PIPELINE (Option 3 Live CCTV/RTSP)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cameras (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    camera_id VARCHAR(50) UNIQUE NOT NULL,
    camera_name VARCHAR(100) NOT NULL,
    camera_type VARCHAR(50) NOT NULL, -- 'webcam', 'mobile', 'ip_cctv', 'rtsp', 'webrtc'
    stream_url TEXT,
    location VARCHAR(100),
    zone VARCHAR(50),
    username VARCHAR(100),
    password VARCHAR(100),
    status VARCHAR(20) DEFAULT 'online', -- 'online', 'offline', 'connecting'
    fps INTEGER DEFAULT 30,
    resolution VARCHAR(20) DEFAULT '1080p FHD',
    area VARCHAR(20) DEFAULT 'Inside', -- 'Inside', 'Outside'
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- -----------------------------------------------------------------------------
-- 6b. REAL THREAT EVENTS & FORENSIC EVIDENCE (Snapshots + Video Clips)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS threat_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    camera_id VARCHAR(50),
    camera_name VARCHAR(100),
    event_type VARCHAR(100) NOT NULL, -- 'Gun Detection', 'Knife Detection', 'Restricted Intrusion', 'Biometric Mismatch'
    detected_object VARCHAR(100), -- 'Handgun (9mm)', 'Tactical Knife', 'Intruder'
    confidence REAL DEFAULT 0.95,
    snapshot_path TEXT,
    video_path TEXT,
    location VARCHAR(100),
    zone VARCHAR(50),
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) DEFAULT 'OPEN'
);

-- -----------------------------------------------------------------------------
-- 6c. AUTOMATIC FORENSIC SNAPSHOTS REPOSITORY
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_event_id INTEGER,
    camera_id VARCHAR(50),
    camera_name VARCHAR(100),
    file_path TEXT NOT NULL,
    file_url TEXT NOT NULL,
    detected_object VARCHAR(100),
    confidence REAL DEFAULT 0.95,
    location VARCHAR(100),
    zone VARCHAR(50),
    captured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (threat_event_id) REFERENCES threat_events(id) ON DELETE CASCADE
);

-- -----------------------------------------------------------------------------
-- 6d. LIVE RECORDED EVIDENCE VIDEOS (Pre & Post Event Circular Buffer)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS evidence_videos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_event_id INTEGER,
    camera_id VARCHAR(50),
    camera_name VARCHAR(100),
    file_path TEXT NOT NULL,
    file_url TEXT NOT NULL,
    duration_seconds REAL DEFAULT 15.0,
    detected_object VARCHAR(100),
    location VARCHAR(100),
    recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (threat_event_id) REFERENCES threat_events(id) ON DELETE CASCADE
);

-- -----------------------------------------------------------------------------
-- 6e. AUTHORIZED EMERGENCY ALERT RECIPIENTS (WhatsApp / SMS Engine)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS alert_recipients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(100) NOT NULL,
    role VARCHAR(100) NOT NULL,
    mobile_number VARCHAR(30) NOT NULL,
    whatsapp_number VARCHAR(30) NOT NULL,
    receive_weapon_alert INTEGER DEFAULT 1,
    active INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- -----------------------------------------------------------------------------
-- 6f. WHATSAPP ALERT DELIVERY AUDIT TRAIL
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS whatsapp_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_event_id INTEGER,
    recipient_id INTEGER,
    recipient_name VARCHAR(100),
    whatsapp_number VARCHAR(30) NOT NULL,
    message_body TEXT NOT NULL,
    snapshot_url TEXT,
    delivery_status VARCHAR(30) DEFAULT 'SENT', -- 'QUEUED', 'SENT', 'DELIVERED', 'FAILED'
    api_response TEXT,
    dispatched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (threat_event_id) REFERENCES threat_events(id) ON DELETE SET NULL,
    FOREIGN KEY (recipient_id) REFERENCES alert_recipients(id) ON DELETE SET NULL
);

-- -----------------------------------------------------------------------------
-- 6g. VISITOR ENTRY LOGS & CHECKPOINT BIOMETRIC AUDIT
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS entry_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id VARCHAR(50),
    visitor_id INTEGER,
    visitor_name VARCHAR(100) NOT NULL,
    checkpoint_name VARCHAR(100) DEFAULT 'Main Gate Checkpoint',
    verification_status VARCHAR(50) NOT NULL, -- 'ENTRY_APPROVED', 'BIOMETRIC_MISMATCH', 'INVALID_TICKET'
    face_match_confidence REAL,
    matched_profile VARCHAR(100),
    entry_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    notes TEXT,
    FOREIGN KEY (visitor_id) REFERENCES visitors(id) ON DELETE CASCADE
);

-- -----------------------------------------------------------------------------
-- 6h. FACENET FACE BIOMETRIC EMBEDDINGS REPOSITORY
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS face_embeddings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    visitor_id INTEGER,
    personnel_id VARCHAR(50),
    full_name VARCHAR(100) NOT NULL,
    profile_type VARCHAR(30) DEFAULT 'visitor', -- 'visitor', 'personnel'
    embedding_json TEXT NOT NULL, -- JSON array of 128-D or 512-D float vectors
    photo_path TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (visitor_id) REFERENCES visitors(id) ON DELETE CASCADE
);

-- -----------------------------------------------------------------------------
-- 6. INSIDE SECURITY EVENTS & INCIDENT AUDIT LOG
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS inside_events (
    id VARCHAR(50) PRIMARY KEY,
    timestamp_str VARCHAR(20) NOT NULL,
    date_str DATE DEFAULT (CURRENT_DATE),
    camera_id VARCHAR(50) REFERENCES inside_cameras(id),
    location VARCHAR(100) NOT NULL,
    event_type VARCHAR(100) NOT NULL, -- Restricted-Zone Intrusion, Weapon Detection, Authorized Entry
    severity VARCHAR(20) NOT NULL, -- Critical, High, Info
    person VARCHAR(100),
    confidence REAL DEFAULT 0.95,
    weapon_type VARCHAR(100), -- Tactical Knife, Handgun (9mm), None
    bounding_color VARCHAR(20) DEFAULT 'red',
    snapshot_url TEXT,
    status VARCHAR(20) DEFAULT 'Active', -- Active, Resolved, Acknowledged
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- -----------------------------------------------------------------------------
-- 7. INSIDE ALERTS & EXPLAINABLE AI ATTRIBUTIONS
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS inside_alerts (
    id VARCHAR(50) PRIMARY KEY,
    event_id VARCHAR(50) REFERENCES inside_events(id),
    title VARCHAR(200) NOT NULL,
    alert_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    time_str VARCHAR(20) NOT NULL,
    date_str DATE DEFAULT (CURRENT_DATE),
    camera_id VARCHAR(50),
    location VARCHAR(100) NOT NULL,
    zone VARCHAR(100),
    status VARCHAR(20) DEFAULT 'Active',
    sound_triggered INTEGER DEFAULT 1,
    xai_what TEXT,
    xai_why_detected TEXT,
    xai_why_unauthorized TEXT,
    xai_why_critical TEXT,
    xai_confidence VARCHAR(20),
    xai_bounding_class VARCHAR(50),
    xai_evidence_ref VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- -----------------------------------------------------------------------------
-- 8. EMERGENCY WHATSAPP & SMS DISPATCH AUDIT LOG
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS emergency_dispatches (
    id VARCHAR(50) PRIMARY KEY,
    timestamp_str VARCHAR(20) NOT NULL,
    date_str DATE DEFAULT (CURRENT_DATE),
    weapon_type VARCHAR(100) NOT NULL,
    location VARCHAR(100) NOT NULL,
    message TEXT NOT NULL,
    recipients_json TEXT NOT NULL, -- JSON array of recipients, roles, phone numbers, and WhatsApp delivery receipts
    status VARCHAR(50) DEFAULT 'Broadcast Complete',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- -----------------------------------------------------------------------------
-- 9. OUTSIDE CCTV CAMERAS
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS outside_cameras (
    id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    location VARCHAR(100) NOT NULL,
    rtsp_url TEXT NOT NULL,
    status VARCHAR(20) DEFAULT 'Online',
    area VARCHAR(20) DEFAULT 'Outside',
    fps INTEGER DEFAULT 30,
    resolution VARCHAR(20) DEFAULT '4K UHD',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- -----------------------------------------------------------------------------
-- 10. VEHICLE TRACKING & BYTETRACK LOGS
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS vehicle_tracking (
    track_id VARCHAR(50) PRIMARY KEY,
    vehicle_class VARCHAR(50) NOT NULL,
    license_plate VARCHAR(30),
    speed_kmh VARCHAR(20),
    direction VARCHAR(50),
    camera_id VARCHAR(50) REFERENCES outside_cameras(id),
    entry_time VARCHAR(20) NOT NULL,
    status VARCHAR(20) DEFAULT 'Tracked', -- Tracked, Exited
    confidence REAL DEFAULT 0.95,
    snapshot_url TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- -----------------------------------------------------------------------------
-- 11. ANPR NUMBER PLATE OCR RECORDS
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS number_plates (
    id VARCHAR(50) PRIMARY KEY,
    plate_number VARCHAR(30) NOT NULL,
    vehicle_type VARCHAR(50) NOT NULL,
    timestamp_str VARCHAR(20) NOT NULL,
    date_str DATE DEFAULT (CURRENT_DATE),
    camera_id VARCHAR(50) REFERENCES outside_cameras(id),
    location VARCHAR(100) NOT NULL,
    confidence REAL DEFAULT 0.98,
    tracking_id VARCHAR(50),
    snapshot_url TEXT,
    flag_type VARCHAR(50) DEFAULT 'Standard', -- Standard, Authorized Delivery, Public Transit, Flagged
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- -----------------------------------------------------------------------------
-- 12. ACCIDENT & TRAFFIC INCIDENT LOGS
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS accident_records (
    id VARCHAR(50) PRIMARY KEY,
    accident_type VARCHAR(100) NOT NULL, -- Vehicle-to-Vehicle Collision, Overturned Two-Wheeler
    severity VARCHAR(20) NOT NULL,
    timestamp_str VARCHAR(20) NOT NULL,
    date_str DATE DEFAULT (CURRENT_DATE),
    camera_id VARCHAR(50) REFERENCES outside_cameras(id),
    location VARCHAR(100) NOT NULL,
    vehicles_involved_json TEXT, -- JSON array: ["Sedan (KA01AB1234)", "Motorcycle (DL04CA8821)"]
    persons_involved INTEGER DEFAULT 1,
    confidence REAL DEFAULT 0.93,
    snapshot_url TEXT,
    evidence_ref VARCHAR(50),
    status VARCHAR(20) DEFAULT 'Active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- -----------------------------------------------------------------------------
-- 13. CROWD MONITORING & DENSITY SENSORS
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS crowd_monitoring (
    id VARCHAR(50) PRIMARY KEY,
    timestamp_str VARCHAR(20) NOT NULL,
    date_str DATE DEFAULT (CURRENT_DATE),
    current_count INTEGER NOT NULL,
    warning_threshold INTEGER NOT NULL DEFAULT 40,
    critical_threshold INTEGER NOT NULL DEFAULT 50,
    peak_count INTEGER DEFAULT 68,
    peak_time VARCHAR(20) DEFAULT '12:45 PM',
    average_count INTEGER DEFAULT 32,
    density_status VARCHAR(20) DEFAULT 'Warning',
    hourly_trend_json TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- -----------------------------------------------------------------------------
-- 14. DRONE SURVEILLANCE & GPS TELEMETRY
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS drone_telemetry (
    id VARCHAR(50) PRIMARY KEY,
    drone_name VARCHAR(100) NOT NULL,
    status VARCHAR(50) DEFAULT 'Active Patrol',
    battery_pct INTEGER DEFAULT 84,
    altitude_m VARCHAR(20) DEFAULT '120 m',
    speed_kmh VARCHAR(20) DEFAULT '24 km/h',
    gps_coords VARCHAR(50) DEFAULT '28.6139° N, 77.2090° E',
    detected_vehicles INTEGER DEFAULT 6,
    detected_people INTEGER DEFAULT 18,
    stream_url TEXT,
    patrol_zone VARCHAR(100) DEFAULT 'North & East Outer Perimeters',
    last_ping TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- -----------------------------------------------------------------------------
-- 15. OUTSIDE ALERTS & INCIDENT ATTRIBUTIONS
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS outside_alerts (
    id VARCHAR(50) PRIMARY KEY,
    event_id VARCHAR(50),
    title VARCHAR(200) NOT NULL,
    alert_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    time_str VARCHAR(20) NOT NULL,
    date_str DATE DEFAULT (CURRENT_DATE),
    camera_id VARCHAR(50),
    location VARCHAR(100) NOT NULL,
    status VARCHAR(20) DEFAULT 'Active',
    sound_triggered INTEGER DEFAULT 1,
    xai_what TEXT,
    xai_why_detected TEXT,
    xai_why_unauthorized TEXT,
    xai_why_critical TEXT,
    xai_confidence VARCHAR(20),
    xai_bounding_class VARCHAR(50),
    xai_evidence_ref VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- -----------------------------------------------------------------------------
-- 16. FACILITY SETTINGS & SYSTEM CONFIGURATION
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS facility_settings (
    setting_key VARCHAR(100) PRIMARY KEY,
    setting_value TEXT NOT NULL,
    category VARCHAR(50) DEFAULT 'General',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- -----------------------------------------------------------------------------
-- 17. DAILY SECURITY AUDIT REPORTS
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS daily_reports (
    id VARCHAR(50) PRIMARY KEY,
    report_date DATE NOT NULL,
    subsystem VARCHAR(50) NOT NULL, -- Inside, Outside, Combined
    total_people INTEGER DEFAULT 0,
    total_vehicles INTEGER DEFAULT 0,
    total_incidents INTEGER DEFAULT 0,
    report_json TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- -----------------------------------------------------------------------------
-- 18. AI VIDEO ANALYSIS DETECTIONS & WEAPON THREAT AUDIT
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    video_name TEXT NOT NULL,
    detection_status TEXT NOT NULL,
    weapon_type TEXT,
    snapshot_path TEXT,
    evidence_path TEXT,
    confidence REAL,
    detected_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- =============================================================================
-- SEED DATA INSERTS
-- =============================================================================

-- Users (3 Default Operational Accounts)
INSERT OR IGNORE INTO users (id, full_name, username, email, password_hash, role) VALUES
(1, 'Ahmed Khan', 'admin', 'admin@securevision.gov', 'pbkdf2_sha256$8f9d12a4c0e54b67$3b7a58c9735d46fb05d933e7ce71bb76ec85c9de5ee307d8d21c7e97d1b32bb7', 'Administrator'),
(2, 'John Smith', 'john', 'john@securevision.gov', 'pbkdf2_sha256$6a2b84e1d90c7f32$7e5b293d09a8039c3fbd8a87b5a6c382f7c0d2938475a892b3c4d5e6f7a8b9c0', 'Security Staff'),
(3, 'Elena Rostova', 'elena', 'elena@securevision.gov', 'pbkdf2_sha256$1c4d92f8a5e37b90$4a8b7c6d5e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b', 'Museum Staff / Lead Curator');

-- Login Audit History Seed
INSERT OR IGNORE INTO login_history (id, user_id, username, role, login_time, ip_address, status) VALUES
(1, 1, 'admin', 'Administrator', datetime('now', '-2 hours'), '127.0.0.1', 'Success'),
(2, 2, 'john', 'Security Staff', datetime('now', '-45 minutes'), '127.0.0.1', 'Success');

-- Authorization Levels (Strictly 3 Operational Roles)
INSERT OR IGNORE INTO authorization_levels (id, name, description, zones_json, permissions_json, badge_color) VALUES
('lvl-admin', 'Administrator', 'Full facility access & system configuration rights', '["Zone A", "Zone B", "Zone C", "Zone D"]', '["All Zones", "Config", "Evidence Purge", "User Management"]', '#8B5CF6'),
('lvl-sec', 'Security Staff', 'Active perimeter & restricted vaults armed response', '["Zone A", "Zone B", "Zone C"]', '["Access Vaults", "Arms Carry", "Emergency Override"]', '#2563EB'),
('lvl-cur', 'Museum Staff / Lead Curator', 'Curatorial wings, artefact vaults and preservation rooms', '["Zone A", "Zone C"]', '["Curatorial Entry", "Inventory Audit", "Artefact Handling"]', '#10B981');

-- Authorized Personnel (Directory of Credentialed Staff)
INSERT OR IGNORE INTO authorized_personnel (id, name, role, level_id, department, allowed_zones_json, phone, whatsapp, status, reg_date, face_profile, avatar_color, photo_url) VALUES
('EMP101', 'Ahmed Khan', 'Administrator', 'lvl-admin', 'Executive Operations & IT Security', '["Zone A", "Zone B", "Zone C", "Zone D"]', '+91 98765 43210', '+91 98765 43210', 'Active', '2025-01-15', 'EMB_88921_AK', '#8B5CF6', NULL),
('EMP102', 'John Smith', 'Security Staff', 'lvl-sec', 'Physical Security Division', '["Zone A", "Zone B", "Zone C"]', '+91 98111 22334', '+91 98111 22334', 'Active', '2025-02-10', 'EMB_44102_JS', '#2563EB', NULL),
('EMP103', 'Dr. Elena Rostova', 'Museum Staff / Lead Curator', 'lvl-cur', 'Antiquities Conservation & Vaults', '["Zone A", "Zone C"]', '+91 99000 88776', '+91 99000 88776', 'Active', '2024-11-01', 'EMB_11094_ER', '#10B981', NULL);

-- Restricted Zones (RBAC Alignment)
INSERT OR IGNORE INTO restricted_zones (id, name, allowed_levels_json, security_level, severity, color, points_json, is_active) VALUES
('zone-a', 'Zone A — Main Vault & Artefacts', '["Administrator", "Security Staff", "Museum Staff / Lead Curator"]', 'Critical', 'Critical', '#EF4444', '[{"x":0.15,"y":0.2},{"x":0.45,"y":0.2},{"x":0.45,"y":0.65},{"x":0.15,"y":0.65}]', 1),
('zone-b', 'Zone B — Cyber Core / Server Room', '["Administrator", "Security Staff"]', 'High', 'Critical', '#DC2626', '[{"x":0.55,"y":0.15},{"x":0.9,"y":0.15},{"x":0.9,"y":0.55},{"x":0.55,"y":0.55}]', 1),
('zone-c', 'Zone C — Curatorial Archive & Artefacts', '["Administrator", "Security Staff", "Museum Staff / Lead Curator"]', 'Medium', 'High', '#F59E0B', '[{"x":0.3,"y":0.7},{"x":0.8,"y":0.7},{"x":0.8,"y":0.95},{"x":0.3,"y":0.95}]', 1);

-- Inside Cameras
INSERT OR IGNORE INTO inside_cameras (id, name, location, rtsp_url, status, zone_id, area, fps, resolution) VALUES
('CAM-IN-01', 'Main Gallery Hall A', 'Wing 1, Level 1', 'rtsp://192.168.1.101:554/stream1', 'Online', 'zone-a', 'Inside', 30, '4K UHD'),
('CAM-IN-02', 'Vault Security Corridor', 'Sub-level Vault Core', 'rtsp://192.168.1.102:554/stream1', 'Online', 'zone-a', 'Inside', 30, '1080p'),
('CAM-IN-03', 'Server Room Entry', 'Tech Annex 2', 'rtsp://192.168.1.103:554/stream1', 'Online', 'zone-b', 'Inside', 30, '1080p'),
('CAM-IN-04', 'Curatorial Archive South', 'Wing 2, Level 2', 'rtsp://192.168.1.104:554/stream1', 'Connecting', 'zone-c', 'Inside', 25, '1080p');

-- Outside Cameras
INSERT OR IGNORE INTO outside_cameras (id, name, location, rtsp_url, status, area, fps, resolution) VALUES
('CAM-OUT-01', 'North Perimeter Gate', 'Outer Gate 1', 'rtsp://192.168.1.201:554/stream1', 'Online', 'Outside', 30, '4K UHD'),
('CAM-OUT-02', 'East Parking Plaza', 'Plaza Sector 4', 'rtsp://192.168.1.202:554/stream1', 'Online', 'Outside', 30, '1080p'),
('CAM-OUT-03', 'Public Promenade', 'Museum Forecourt', 'rtsp://192.168.1.203:554/stream1', 'Online', 'Outside', 30, '1080p');

-- Number Plates
INSERT OR IGNORE INTO number_plates (id, plate_number, vehicle_type, timestamp_str, date_str, camera_id, location, confidence, tracking_id, flag_type) VALUES
('NP-01', 'KA01AB1234', 'Sedan (Black)', '14:20:11', '2026-08-25', 'CAM-OUT-01', 'North Perimeter Gate', 0.98, 'V101', 'Standard'),
('NP-02', 'DL04CA8821', 'Motorcycle (Red)', '14:25:40', '2026-08-25', 'CAM-OUT-02', 'East Parking Plaza', 0.95, 'V102', 'Standard'),
('NP-03', 'MH12XY9900', 'City Bus #14', '14:10:05', '2026-08-25', 'CAM-OUT-03', 'Public Promenade Gate', 0.99, 'V103', 'Public Transit'),
('NP-04', 'WB02K7711', 'Heavy Truck', '14:28:15', '2026-08-25', 'CAM-OUT-01', 'North Logistics Gate', 0.94, 'V104', 'Authorized Delivery');

-- Drone Telemetry
INSERT OR IGNORE INTO drone_telemetry (id, drone_name, status, battery_pct, altitude_m, speed_kmh, gps_coords, detected_vehicles, detected_people, stream_url, patrol_zone) VALUES
('DRONE-SKYEYE-01', 'Perimeter SkyEye-01', 'Active Patrol', 84, '120 m', '24 km/h', '28.6139° N, 77.2090° E', 6, 18, 'demo://drone-feed-sim', 'North & East Outer Perimeters');

-- Facility Settings
INSERT OR IGNORE INTO facility_settings (setting_key, setting_value, category) VALUES
('facility_name', 'National Heritage & Executive Complex', 'General'),
('system_version', 'SecureVision AI Enterprise v2.4', 'General'),
('sound_alarm_enabled', 'true', 'Alerts'),
('emergency_whatsapp_enabled', 'true', 'Alerts'),
('emergency_sms_enabled', 'true', 'Alerts'),
('alarm_volume', '0.75', 'Alerts'),
('daily_report_time', '18:00', 'Reports'),
('recipient_email', 'security-director@govfacility.gov', 'Reports');

-- Vehicle Tracking (ByteTrack)
INSERT OR IGNORE INTO vehicle_tracking (track_id, vehicle_class, license_plate, speed_kmh, direction, camera_id, entry_time, status, confidence, snapshot_url) VALUES
('V101', 'Car / Sedan', 'KA01AB1234', '38 km/h', 'Northbound', 'CAM-OUT-01', '14:20:11', 'Tracked', 0.98, 'assets/snapshots/snap_car_ka01.jpg'),
('V102', 'Motorcycle', 'DL04CA8821', '44 km/h', 'Eastbound', 'CAM-OUT-02', '14:25:40', 'Tracked', 0.95, 'assets/snapshots/snap_bike_dl04.jpg'),
('V103', 'City Bus', 'MH12XY9900', '22 km/h', 'Southbound', 'CAM-OUT-03', '14:10:05', 'Exited', 0.99, 'assets/snapshots/snap_bus_mh12.jpg');

-- Accident Records
INSERT OR IGNORE INTO accident_records (id, accident_type, severity, timestamp_str, date_str, camera_id, location, vehicles_involved_json, persons_involved, confidence, snapshot_url, evidence_ref, status) VALUES
('ACC-OUT-401', 'Vehicle-to-Vehicle Collision', 'Critical', '14:12:33', '2026-08-25', 'CAM-OUT-02', 'East Parking Plaza Intersection', '["Sedan (KA01AB1234)", "Motorcycle (DL04CA8821)"]', 2, 0.93, 'assets/snapshots/snap_accident_1.jpg', 'EVID-OUT-20260825-401', 'Active'),
('ACC-OUT-402', 'Overturned Two-Wheeler Hazard', 'High', '11:40:15', '2026-08-25', 'CAM-OUT-01', 'North Perimeter Slipway', '["Motorcycle (DL04CA8821)"]', 1, 0.91, 'assets/snapshots/snap_bike_dl04.jpg', 'EVID-OUT-20260825-402', 'Resolved');

-- Crowd Monitoring
INSERT OR IGNORE INTO crowd_monitoring (id, timestamp_str, date_str, current_count, warning_threshold, critical_threshold, peak_count, peak_time, average_count, density_status, hourly_trend_json) VALUES
('CROWD-01', '14:30:00', '2026-08-25', 44, 40, 50, 68, '12:45 PM', 32, 'Warning', '[14, 22, 38, 48, 68, 52, 44, 39, 44]');

-- Outside Alerts
INSERT OR IGNORE INTO outside_alerts (id, event_id, title, alert_type, severity, time_str, date_str, camera_id, location, status, sound_triggered, xai_what, xai_why_detected, xai_why_unauthorized, xai_why_critical, xai_confidence, xai_bounding_class, xai_evidence_ref) VALUES
('ALT-OUT-001', 'ACC-OUT-401', 'Major Traffic Collision Detected', 'Vehicle-to-Vehicle Collision', 'Critical', '14:12:33', '2026-08-25', 'CAM-OUT-02', 'East Parking Plaza Intersection', 'Active', 1, 'High-impact collision detected between sedan KA01AB1234 and motorcycle DL04CA8821.', 'Sudden deceleration vector anomaly and bounding box overlap with crash acoustic pattern.', 'N/A - Safety Hazard Event.', 'Potential rider injury and traffic blockage on emergency exit corridor.', '93.5%', 'Collision Hazard', 'EVID-OUT-20260825-401');

-- Daily Reports
INSERT OR IGNORE INTO daily_reports (id, report_date, subsystem, total_people, total_vehicles, total_incidents, report_json) VALUES
('REP-20260825-IN', '2026-08-25', 'Inside', 148, 0, 2, '{"authorized":62,"unknown":86,"violations":3,"weapons":1}'),
('REP-20260825-OUT', '2026-08-25', 'Outside', 520, 312, 1, '{"unique_vehicles":284,"plates":290,"accidents":1,"crowd_warnings":4}');

-- Real Live CCTV & Stream Pipeline Cameras (Option 3: CAM-01, CAM-02, CAM-03)
INSERT OR IGNORE INTO cameras (id, camera_id, camera_name, camera_type, stream_url, location, zone, status, fps, resolution, area) VALUES
(1, 'CAM-01', 'CAM-01 — Main Gate CCTV', 'rtsp', 'rtsp://192.168.1.101:554/stream1', 'Main Entry Gate 1', 'Zone A (Main Gallery)', 'online', 30, '4K UHD', 'Inside'),
(2, 'CAM-02', 'CAM-02 — Laptop Webcam', 'webcam', 'device://default-webcam', 'Security Terminal Alpha', 'Command Desk', 'online', 30, '1080p FHD', 'Inside'),
(3, 'CAM-03', 'CAM-03 — Mobile Camera Stream', 'mobile', 'http://localhost:8000/camera.html', 'Mobile Patrol Unit 1', 'Zone B (Vault Entry)', 'online', 30, '720p HD', 'Inside');

-- Authorized Alert Recipients (WhatsApp / SMS Engine)
INSERT OR IGNORE INTO alert_recipients (id, name, role, mobile_number, whatsapp_number, receive_weapon_alert, active) VALUES
(1, 'Ahmed Khan', 'Administrator', '+91 98765 43210', '+91 98765 43210', 1, 1),
(2, 'John Smith', 'Security Staff', '+91 98111 22334', '+91 98111 22334', 1, 1),
(3, 'Dr. Elena Rostova', 'Museum Staff / Lead Curator', '+91 99000 88776', '+91 99000 88776', 1, 1),
(4, 'Central Emergency Response Unit', 'Security Staff', '+91 98450 99887', '+91 98450 99887', 1, 1);

-- Threat Events & Real Forensic Detections
INSERT OR IGNORE INTO threat_events (id, camera_id, camera_name, event_type, detected_object, confidence, snapshot_path, video_path, location, zone, detected_at, status) VALUES
(1, 'CAM-01', 'CAM-01 — Main Gate CCTV', 'Weapon Detection', 'Handgun (9mm Firearm)', 0.94, 'snapshots/2026/08/25/snap_143512_g44.jpg', 'evidence/threat_evidence_20260825_143512.webm', 'Main Entry Gate 1', 'Zone A (Main Gallery)', '2026-08-25 14:35:12', 'RESOLVED'),
(2, 'CAM-04', 'CAM-04 — Vault Core IP Camera', 'Weapon Detection', 'Tactical Knife (6-inch Serrated)', 0.97, 'snapshots/2026/08/25/snap_164022_k92.jpg', 'evidence/threat_evidence_20260825_164022.webm', 'Sub-Level Vault Core', 'Zone A (Main Vault)', '2026-08-25 16:40:22', 'RESOLVED');

-- Forensic Snapshots Repository
INSERT OR IGNORE INTO snapshots (id, threat_event_id, camera_id, camera_name, file_path, file_url, detected_object, confidence, location, zone, captured_at) VALUES
(1, 1, 'CAM-01', 'CAM-01 — Main Gate CCTV', 'snapshots/2026/08/25/snap_143512_g44.jpg', 'snapshots/2026/08/25/snap_143512_g44.jpg', 'Handgun (9mm Firearm)', 0.94, 'Main Entry Gate 1', 'Zone A (Main Gallery)', '2026-08-25 14:35:12'),
(2, 2, 'CAM-04', 'CAM-04 — Vault Core IP Camera', 'snapshots/2026/08/25/snap_164022_k92.jpg', 'snapshots/2026/08/25/snap_164022_k92.jpg', 'Tactical Knife (6-inch Serrated)', 0.97, 'Sub-Level Vault Core', 'Zone A (Main Vault)', '2026-08-25 16:40:22');

-- Recorded Evidence Videos
INSERT OR IGNORE INTO evidence_videos (id, threat_event_id, camera_id, camera_name, file_path, file_url, duration_seconds, detected_object, location, recorded_at) VALUES
(1, 1, 'CAM-01', 'CAM-01 — Main Gate CCTV', 'evidence/threat_evidence_20260825_143512.webm', 'evidence/threat_evidence_20260825_143512.webm', 15.0, 'Handgun (9mm Firearm)', 'Main Entry Gate 1', '2026-08-25 14:35:12'),
(2, 2, 'CAM-04', 'CAM-04 — Vault Core IP Camera', 'evidence/threat_evidence_20260825_164022.webm', 'evidence/threat_evidence_20260825_164022.webm', 18.5, 'Tactical Knife (6-inch Serrated)', 'Sub-Level Vault Core', '2026-08-25 16:40:22');

-- WhatsApp Alert Deliveries Audit
INSERT OR IGNORE INTO whatsapp_alerts (id, threat_event_id, recipient_id, recipient_name, whatsapp_number, message_body, snapshot_url, delivery_status, dispatched_at) VALUES
(1, 1, 1, 'Ahmed Khan', '+91 98765 43210', '🚨 SECUREVISION AI ALERT: Handgun detected at CAM-01 (Main Gate CCTV). Confidence: 94%. Immediate response dispatched.', 'snapshots/2026/08/25/snap_143512_g44.jpg', 'DELIVERED', '2026-08-25 14:35:13'),
(2, 1, 2, 'John Smith', '+91 98111 22334', '🚨 SECUREVISION AI ALERT: Handgun detected at CAM-01 (Main Gate CCTV). Confidence: 94%. Immediate response dispatched.', 'snapshots/2026/08/25/snap_143512_g44.jpg', 'DELIVERED', '2026-08-25 14:35:13');

-- Checkpoint Visitor Entry Logs
INSERT OR IGNORE INTO entry_logs (id, ticket_id, visitor_id, visitor_name, checkpoint_name, verification_status, face_match_confidence, matched_profile, entry_timestamp, notes) VALUES
(1, 'TKT-2026-8841', 1, 'Tariq Al-Mansoor', 'Main Gate Checkpoint', 'ENTRY_APPROVED', 0.99, 'Tariq Al-Mansoor (VIS-2026-001)', datetime('now', '-2 hours'), 'Face matched with 99% FaceNet similarity. Access granted.'),
(2, 'TKT-2026-8842', 2, 'Sarah Jenkins', 'Main Gate Checkpoint', 'ENTRY_APPROVED', 0.98, 'Sarah Jenkins (VIS-2026-002)', datetime('now', '-1 hour'), 'VIP pass verified. Face biometrics validated.'),
(3, 'TKT-2026-8843', 3, 'David Wilson', 'Main Gate Checkpoint', 'ENTRY_APPROVED', 0.97, 'David Wilson (VIS-2026-003)', datetime('now', '-30 minutes'), 'Standard visitor checked in.');

-- FaceNet Embeddings Repository (Pre-registered biometrics)
INSERT OR IGNORE INTO face_embeddings (id, visitor_id, full_name, profile_type, embedding_json, photo_path) VALUES
(1, 1, 'Tariq Al-Mansoor', 'visitor', '[0.124, -0.048, 0.312, 0.089, -0.192, 0.441, -0.023, 0.115]', 'https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=150&auto=format&fit=crop&q=80'),
(2, 2, 'Sarah Jenkins', 'visitor', '[0.088, 0.214, -0.105, 0.301, 0.177, -0.042, 0.289, -0.155]', 'https://images.unsplash.com/photo-1494790108377-be9c29b29330?w=150&auto=format&fit=crop&q=80'),
(3, 3, 'David Wilson', 'visitor', '[-0.142, 0.095, 0.231, -0.081, 0.315, 0.122, -0.198, 0.064]', 'https://images.unsplash.com/photo-1500648767791-00dcc994a43e?w=150&auto=format&fit=crop&q=80');



