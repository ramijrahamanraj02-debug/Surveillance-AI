"""
SecureVision AI - Real-World Biometric Face Recognition Service
Powered by OpenCV YuNet (Face Detection) + SFace (Face Recognition Feature Extractor).
Threshold: Cosine similarity >= 0.363 (OpenCV SFace standard).
"""

import os
import sys
import base64
import urllib.request
import numpy as np

try:
    import cv2
    HAS_OPENCV = True
except ImportError:
    cv2 = None
    HAS_OPENCV = False

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, 'models')
os.makedirs(MODELS_DIR, exist_ok=True)

# Official OpenCV Model Zoo URLs
YUNET_MODEL_NAME = 'face_detection_yunet_2023mar.onnx'
SFACE_MODEL_NAME = 'face_recognition_sface_2021dec.onnx'

YUNET_URL = f"https://github.com/opencv/opencv_zoo/raw/main/models/face_detection_yunet/{YUNET_MODEL_NAME}"
SFACE_URL = f"https://github.com/opencv/opencv_zoo/raw/main/models/face_recognition_sface/{SFACE_MODEL_NAME}"

YUNET_PATH = os.path.join(MODELS_DIR, YUNET_MODEL_NAME)
SFACE_PATH = os.path.join(MODELS_DIR, SFACE_MODEL_NAME)

# OpenCV SFace Cosine Threshold
COSINE_THRESHOLD = 0.363
L2_THRESHOLD = 1.128


def download_model_if_missing(url, dest_path, description="Model"):
    """Downloads an ONNX model from OpenCV Zoo if not locally present."""
    if os.path.exists(dest_path) and os.path.getsize(dest_path) > 10000:
        return True
    try:
        print(f"[FaceAI] Downloading {description} from {url}...")
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 SecureVisionAI/2.6'})
        with urllib.request.urlopen(req, timeout=30) as resp, open(dest_path, 'wb') as out_f:
            total_bytes = 0
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                out_f.write(chunk)
                total_bytes += len(chunk)
        print(f"[FaceAI] Successfully downloaded {description} ({total_bytes} bytes) to {dest_path}")
        return True
    except Exception as ex:
        print(f"[FaceAI] Warning: Failed to download {description}: {ex}", file=sys.stderr)
        if os.path.exists(dest_path) and os.path.getsize(dest_path) < 10000:
            try:
                os.remove(dest_path)
            except Exception:
                pass
        return False


def ensure_models_available():
    """Ensures YuNet and SFace ONNX models are present in the models/ directory."""
    yunet_ok = os.path.exists(YUNET_PATH) and os.path.getsize(YUNET_PATH) > 10000
    if not yunet_ok:
        yunet_ok = download_model_if_missing(YUNET_URL, YUNET_PATH, "YuNet Face Detector")

    sface_ok = os.path.exists(SFACE_PATH) and os.path.getsize(SFACE_PATH) > 10000
    if not sface_ok:
        sface_ok = download_model_if_missing(SFACE_URL, SFACE_PATH, "SFace Face Recognizer")

    return yunet_ok and sface_ok


class FaceRecognitionService:
    def __init__(self):
        self.detector = None
        self.recognizer = None
        self._models_loaded = False
        self.cosine_threshold = COSINE_THRESHOLD
        self._init_models()

    def _init_models(self):
        if not HAS_OPENCV:
            print("[FaceAI] OpenCV is not available in current Python environment.", file=sys.stderr)
            return

        if not hasattr(cv2, 'FaceDetectorYN') or not hasattr(cv2, 'FaceRecognizerSF'):
            print("[FaceAI] cv2.FaceDetectorYN or cv2.FaceRecognizerSF not found in OpenCV build.", file=sys.stderr)
            return

        # Check local files
        if not (os.path.exists(YUNET_PATH) and os.path.exists(SFACE_PATH)):
            # Attempt download
            ensure_models_available()

        if os.path.exists(YUNET_PATH) and os.path.exists(SFACE_PATH):
            try:
                # YuNet detector instance: input size will be dynamically updated in detect_faces
                self.detector = cv2.FaceDetectorYN.create(
                    model=YUNET_PATH,
                    config="",
                    input_size=(320, 320),
                    score_threshold=0.5,
                    nms_threshold=0.3,
                    top_k=5000
                )
                self.recognizer = cv2.FaceRecognizerSF.create(
                    model=SFACE_PATH,
                    config=""
                )
                self._models_loaded = True
                print("[FaceAI] OpenCV YuNet & SFace models successfully initialized.")
            except Exception as ex:
                print(f"[FaceAI] Error loading FaceDetectorYN/FaceRecognizerSF: {ex}", file=sys.stderr)
                self._models_loaded = False
        else:
            print(f"[FaceAI] Models missing from {MODELS_DIR}. Run download helper or place ONNX files.", file=sys.stderr)

    @property
    def is_ready(self):
        return self._models_loaded and self.detector is not None and self.recognizer is not None

    def decode_image(self, img_input):
        """Converts base64 string, data URL, file path, or bytes into a BGR OpenCV image."""
        if img_input is None:
            return None
        if isinstance(img_input, np.ndarray):
            return img_input

        if isinstance(img_input, str):
            # Check if file path
            if os.path.isfile(img_input):
                return cv2.imread(img_input)
            # Data URL or base64
            if ',' in img_input:
                img_input = img_input.split(',', 1)[1]
            try:
                raw_bytes = base64.b64decode(img_input)
                arr = np.frombuffer(raw_bytes, dtype=np.uint8)
                return cv2.imdecode(arr, cv2.IMREAD_COLOR)
            except Exception:
                return None

        if isinstance(img_input, (bytes, bytearray)):
            try:
                arr = np.frombuffer(img_input, dtype=np.uint8)
                return cv2.imdecode(arr, cv2.IMREAD_COLOR)
            except Exception:
                return None

        return None

    def detect_faces(self, frame_bgr):
        """
        Detects faces in frame using YuNet with scale-aware preprocessing.
        Returns list of dicts: {'box': [x, y, w, h], 'score': float, 'raw_face': array}
        """
        if not self.is_ready or frame_bgr is None:
            return []

        h, w = frame_bgr.shape[:2]
        if h == 0 or w == 0:
            return []

        # Preprocess frame size: YuNet operates optimally in 320x320 to 640x640 range
        scale = 1.0
        proc_frame = frame_bgr
        if w < 320 or h < 320:
            scale = max(320.0 / w, 320.0 / h)
            new_w = int(w * scale)
            new_h = int(h * scale)
            proc_frame = cv2.resize(frame_bgr, (new_w, new_h), interpolation=cv2.INTER_LINEAR)
            self.detector.setInputSize((new_w, new_h))
        elif w > 640 or h > 640:
            scale = min(640.0 / w, 640.0 / h)
            new_w = int(w * scale)
            new_h = int(h * scale)
            proc_frame = cv2.resize(frame_bgr, (new_w, new_h), interpolation=cv2.INTER_LINEAR)
            self.detector.setInputSize((new_w, new_h))
        else:
            self.detector.setInputSize((w, h))

        ret, faces = self.detector.detect(proc_frame)
        if faces is None or ret == 0:
            return []

        results = []
        for face in faces:
            raw_face = face.copy()
            if scale != 1.0:
                raw_face[0:4] = raw_face[0:4] / scale
                raw_face[4:14] = raw_face[4:14] / scale
            box = raw_face[0:4].astype(int).tolist()
            score = float(raw_face[-1])
            results.append({
                'box': box,
                'score': score,
                'raw_face': raw_face
            })
        return results

    def extract_embedding(self, frame_bgr, face_data=None):
        """
        Aligns face and extracts 128-dimensional SFace feature embedding vector.
        If face_data is not passed, detects the primary face first.
        Returns numpy array (128,) or None.
        """
        if not self.is_ready or frame_bgr is None:
            return None

        if face_data is None:
            faces = self.detect_faces(frame_bgr)
            if not faces:
                return None
            # Pick highest score face
            faces.sort(key=lambda f: f['score'], reverse=True)
            face_data = faces[0]['raw_face']

        try:
            # Align face crop using landmarks
            aligned_face = self.recognizer.alignCrop(frame_bgr, face_data)
            if aligned_face is None or aligned_face.size == 0:
                return None
            if aligned_face.shape[0] != 112 or aligned_face.shape[1] != 112:
                aligned_face = cv2.resize(aligned_face, (112, 112), interpolation=cv2.INTER_LINEAR)
            aligned_face = np.ascontiguousarray(aligned_face, dtype=np.uint8)
            feature = self.recognizer.feature(aligned_face)
            feature_flat = feature.flatten().astype(np.float32)
            # L2 normalize feature
            norm = np.linalg.norm(feature_flat)
            if norm > 0:
                feature_flat = feature_flat / norm
            return feature_flat
        except Exception:
            return None

    def calculate_match_percentage(self, cosine_sim):
        """Maps SFace cosine similarity (-1.0 to 1.0, threshold ~0.363) to user-friendly percentage (50% to 99.5%)."""
        if cosine_sim is None or cosine_sim < COSINE_THRESHOLD:
            return 0
        pct = round(((float(cosine_sim) - 0.20) / 0.80) * 100.0, 1)
        if pct == int(pct):
            pct = int(pct)
        return min(99.4, max(50.0, pct))

    def compute_cosine_similarity(self, emb1, emb2):
        """Computes cosine similarity between two 128-d vectors (range -1.0 to 1.0)."""
        if emb1 is None or emb2 is None:
            return 0.0
        v1 = np.asarray(emb1, dtype=np.float32).flatten()
        v2 = np.asarray(emb2, dtype=np.float32).flatten()
        if v1.shape != v2.shape or v1.size == 0:
            return 0.0
        dot = np.dot(v1, v2)
        norm1 = np.linalg.norm(v1)
        norm2 = np.linalg.norm(v2)
        if norm1 == 0 or norm2 == 0:
            return 0.0
        return float(dot / (norm1 * norm2))

    def verify_faces(self, img1_input, img2_input, threshold=COSINE_THRESHOLD):
        """
        Compares two face images using YuNet detection + SFace embeddings.
        Returns:
            {
                'matched': bool,
                'score': float, # Cosine similarity
                'threshold': float,
                'message': str
            }
        """
        img1 = self.decode_image(img1_input)
        img2 = self.decode_image(img2_input)

        if img1 is None or img2 is None:
            return {
                'matched': False,
                'score': 0.0,
                'threshold': threshold,
                'message': 'Failed to decode input images.'
            }

        if not self.is_ready:
            return {
                'matched': False,
                'score': 0.0,
                'threshold': threshold,
                'message': 'Face recognition models (YuNet/SFace) are not installed or loaded.'
            }

        emb1 = self.extract_embedding(img1)
        emb2 = self.extract_embedding(img2)

        if emb1 is None:
            return {
                'matched': False,
                'score': 0.0,
                'threshold': threshold,
                'message': 'No detectable face found in first image.'
            }
        if emb2 is None:
            return {
                'matched': False,
                'score': 0.0,
                'threshold': threshold,
                'message': 'No detectable face found in second image (camera/photo).'
            }

        score = self.compute_cosine_similarity(emb1, emb2)
        matched = score >= threshold

        return {
            'matched': matched,
            'score': round(score, 4),
            'threshold': threshold,
            'confidence': round(min(1.0, max(0.0, (score - 0.2) / 0.8)), 3),
            'message': f"Face match {'confirmed' if matched else 'denied'}: similarity {round(score, 3)} (threshold: {threshold})"
        }

    def match_against_database(self, query_frame, db_embeddings_list, threshold=COSINE_THRESHOLD):
        """
        Compares query frame against a list of known database embeddings.
        db_embeddings_list: list of dicts with 'id', 'visitor_id', 'visitor_name', 'embedding'
        """
        if not self.is_ready:
            return None

        query_img = self.decode_image(query_frame)
        if query_img is None:
            return None

        query_emb = self.extract_embedding(query_img)
        if query_emb is None:
            return None

        best_match = None
        best_score = -1.0

        for item in db_embeddings_list:
            raw_emb = item.get('embedding')
            if raw_emb is None:
                continue
            if isinstance(raw_emb, str):
                try:
                    # Stored as json list or comma-separated
                    import json
                    raw_emb = json.loads(raw_emb)
                except Exception:
                    continue
            sim = self.compute_cosine_similarity(query_emb, raw_emb)
            if sim > best_score:
                best_score = sim
                best_match = item

        if best_match and best_score >= threshold:
            return {
                'matched': True,
                'visitor': best_match,
                'score': round(best_score, 4),
                'confidence': round(min(1.0, max(0.0, (best_score - 0.2) / 0.8)), 3)
            }

        return {
            'matched': False,
            'visitor': None,
            'score': round(best_score, 4) if best_score > 0 else 0.0,
            'confidence': 0.0
        }


# Global singleton instance
face_service = FaceRecognitionService()
