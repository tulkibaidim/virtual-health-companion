import firebase_admin
from firebase_admin import credentials, firestore, auth
import os
import threading

_firebase_initialized = False
_db = None

def init_firebase():
    global _firebase_initialized, _db
    if _firebase_initialized:
        return _db
    try:
        cred_path = os.environ.get("FIREBASE_KEY_PATH", os.path.join(os.path.dirname(__file__), "serviceAccountKey.json"))
        if not os.path.exists(cred_path):
            print("[Firebase] No service account key found, Firebase disabled.")
            return None
        cred = credentials.Certificate(cred_path)
        firebase_admin.initialize_app(cred)
        _db = firestore.client()
        _firebase_initialized = True
        print("[Firebase] Connected successfully!")
        return _db
    except Exception as e:
        print(f"[Firebase] Init error: {e}")
        return None

def get_firebase():
    return _db if _firebase_initialized else init_firebase()

def sync_async(func):
    t = threading.Thread(target=func, daemon=True)
    t.start()

def sync_user(user_id, data):
    db = get_firebase()
    if not db: return
    def _do():
        try:
            email = data.get("email", "")
            password = data.get("password", "")
            first_name = str(data.get("first_name", ""))
            last_name = str(data.get("last_name", ""))
            display_name = first_name + " " + last_name

            firebase_uid = None
            try:
                fb_user = auth.create_user(
                    email=email,
                    password=password,
                    display_name=display_name,
                )
                firebase_uid = fb_user.uid
                print(f"[Firebase] Auth account created: {email}")
            except auth.EmailAlreadyExistsError:
                fb_user = auth.get_user_by_email(email)
                firebase_uid = fb_user.uid
                # Update password so mobile can login with new password
                auth.update_user(firebase_uid, password=password, display_name=display_name)
                print(f"[Firebase] Auth account updated: {email}")
            except Exception as e:
                print(f"[Firebase] Auth create error: {e}")

            doc_id = firebase_uid if firebase_uid else str(user_id)
            db.collection("users").document(doc_id).set({
                "id": doc_id,
                "websiteId": str(user_id),
                "name": display_name,
                "email": email,
                "dob": data.get("dob", ""),
                "gender": data.get("gender", ""),
                "blood_type": data.get("blood_type", ""),
                "height_cm": data.get("height_cm", 0),
                "weight_kg": data.get("weight_kg", 0),
                "steps": 0,
                "heartRate": 72,
                "sleep": 0,
                "calories": 0,
                "glucose": 95,
                "healthScore": 0,
                "source": "website",
                "updatedAt": firestore.SERVER_TIMESTAMP,
            }, merge=True)
            print(f"[Firebase] User {user_id} synced to Firestore")
        except Exception as e:
            print(f"[Firebase] sync_user error: {e}")
    sync_async(_do)

def sync_reading(user_id, reading):
    db = get_firebase()
    if not db: return
    def _do():
        try:
            db.collection("health_readings").add({
                "userId": str(user_id),
                "heart_rate": reading.get("heart_rate"),
                "systolic_bp": reading.get("systolic_bp"),
                "diastolic_bp": reading.get("diastolic_bp"),
                "glucose": reading.get("glucose"),
                "weight_kg": reading.get("weight_kg"),
                "steps": reading.get("steps"),
                "sleep_hours": reading.get("sleep_hours"),
                "calories": reading.get("calories"),
                "recorded_at": reading.get("recorded_at"),
                "source": "website",
                "createdAt": firestore.SERVER_TIMESTAMP,
            })
            print(f"[Firebase] Reading synced for user {user_id}")
        except Exception as e:
            print(f"[Firebase] sync_reading error: {e}")
    sync_async(_do)

def sync_report(user_id, report):
    db = get_firebase()
    if not db: return
    def _do():
        try:
            db.collection("reports").add({
                "userId": str(user_id),
                "title": report.get("title"),
                "summary": report.get("summary"),
                "score": report.get("score"),
                "created_at": report.get("created_at"),
                "source": "website",
                "createdAt": firestore.SERVER_TIMESTAMP,
            })
            print(f"[Firebase] Report synced for user {user_id}")
        except Exception as e:
            print(f"[Firebase] sync_report error: {e}")
    sync_async(_do)
