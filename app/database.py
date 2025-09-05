import firebase_admin
from firebase_admin import credentials, firestore
from werkzeug.security import generate_password_hash, check_password_hash
import os
import sys
import re
from dotenv import load_dotenv
import datetime

# Load environment variables from .env file
load_dotenv()

# Global Firebase app and db variables
_firebase_app = None
_db = None

def get_db():
    
    global _firebase_app, _db
    
    if _db is not None:
        return _db
    
    try:
        # Get Firebase configuration from environment variables
        firebase_config = {
            "type": os.environ.get('FIREBASE_TYPE', 'service_account'),
            "project_id": os.environ.get('FIREBASE_PROJECT_ID'),
            "private_key_id": os.environ.get('FIREBASE_PRIVATE_KEY_ID'),
            "private_key": os.environ.get('FIREBASE_PRIVATE_KEY', '').replace('\\n', '\n'),
            "client_email": os.environ.get('FIREBASE_CLIENT_EMAIL'),
            "client_id": os.environ.get('FIREBASE_CLIENT_ID'),
            "auth_uri": os.environ.get('FIREBASE_AUTH_URI', 'https://accounts.google.com/o/oauth2/auth'),
            "token_uri": os.environ.get('FIREBASE_TOKEN_URI', 'https://oauth2.googleapis.com/token'),
            "auth_provider_x509_cert_url": os.environ.get('FIREBASE_AUTH_PROVIDER_X509_CERT_URL', 'https://www.googleapis.com/oauth2/v1/certs'),
            "client_x509_cert_url": os.environ.get('FIREBASE_CLIENT_X509_CERT_URL')
        }
        
        # Check if required fields are present
        required_fields = ['project_id', 'private_key', 'client_email']
        missing_fields = [field for field in required_fields if not firebase_config.get(field)]
        
        if missing_fields:
            raise ValueError(f"Missing required Firebase configuration: {', '.join(missing_fields)}")
        
        # Initialize Firebase Admin SDK
        if not firebase_admin._apps:
            cred = credentials.Certificate(firebase_config)
            _firebase_app = firebase_admin.initialize_app(cred)
        else:
            _firebase_app = firebase_admin.get_app()
        
        # Get Firestore client
        _db = firestore.client()
        
        # Test the connection by attempting to read from a collection
        _db.collection('test').limit(1).get()
        
        print("\033[92m[SUCCESS]\033[0m Firebase Firestore connection established successfully!")
        return _db
    
    except Exception as e:
        print(f"\033[91m[ERROR]\033[0m Firebase connection failed: {str(e)}")
        print("Make sure Firebase configuration is correct in your .env file.")
        sys.exit(1)  # Exit the application if database connection fails

def validate_password(password):
    
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    # if not any(char.isupper() for char in password):
    #     return False, "Password must contain at least one uppercase letter"
    
    # if not any(char.islower() for char in password):
    #     return False, "Password must contain at least one lowercase letter"
    
    # if not any(char.isdigit() for char in password):
    #     return False, "Password must contain at least one numerical digit"
    
    return True, "Password meets requirements"

# User functions
def create_user(username, password, email):
  
    db = get_db()
    
    try:
        # Check if user already exists by username
        users_ref = db.collection('users')
        username_query = users_ref.where('username', '==', username).limit(1).get()
        if username_query:
            return False, "Username already exists"
        
        # Check if user already exists by email
        email_query = users_ref.where('email', '==', email).limit(1).get()
        if email_query:
            return False, "Email already exists"
        
        # Validate password
        is_valid, message = validate_password(password)
        if not is_valid:
            return False, message
        
        # Create new user with hashed password
        user_data = {
            "username": username,
            "password": generate_password_hash(password),
            "email": email,
            "auth_type": "local",  # Regular local account
            "created_at": firestore.SERVER_TIMESTAMP
        }
        
        # Add user to Firestore
        users_ref.add(user_data)
        print(f"\033[92m[SUCCESS]\033[0m User '{username}' created successfully")
        return True, "User created successfully"
        
    except Exception as e:
        print(f"\033[91m[ERROR]\033[0m Error creating user: {str(e)}")
        return False, "Error creating user"

def create_google_user(username, password, email):
   
    db = get_db()
    
    try:
        users_ref = db.collection('users')
        
        # Check if user already exists by email
        email_query = users_ref.where('email', '==', email).limit(1).get()
        
        if email_query:
            existing_user = email_query[0].to_dict()
            if existing_user.get("auth_type") == "google":
                # User already exists with Google auth
                return True, "User already exists"
            else:
                # Update existing user to link Google account
                email_query[0].reference.update({"auth_type": "google"})
                return True, "Account linked to Google"
        
        # Create new user with Google auth
        user_data = {
            "username": username,
            "password": generate_password_hash(password),  # Store a random password
            "email": email,
            "auth_type": "google",  # Mark as Google authenticated
            "created_at": firestore.SERVER_TIMESTAMP
        }
        
        users_ref.add(user_data)
        print(f"\033[92m[SUCCESS]\033[0m Google user '{username}' created successfully")
        return True, "User created successfully"
        
    except Exception as e:
        print(f"\033[91m[ERROR]\033[0m Error creating Google user: {str(e)}")
        return False, "Error creating user"

def validate_user(username, password):
    
    # credential bypass - modular and can be easily removed
    if username == "guest" and password == "guest":
        print(f"\033[92m[SUCCESS]\033[0m Credential bypass login for '{username}'")
        # Create a minimal user object with just enough data
        guest_user = {
            "username": "guest",
            "email": "guest@example.com"
        }
        return True, guest_user
    
    # Regular authentication flow   
    db = get_db()
    
    try:
        users_ref = db.collection('users')
        user_doc = None
        
        # Check if username is an email (contains @ symbol)
        if '@' in username:
            email_query = users_ref.where('email', '==', username).limit(1).get()
            if email_query:
                user_doc = email_query[0]
        else:
            username_query = users_ref.where('username', '==', username).limit(1).get()
            if username_query:
                user_doc = username_query[0]
        
        if user_doc:
            user_data = user_doc.to_dict()
            if check_password_hash(user_data["password"], password):
                print(f"\033[92m[SUCCESS]\033[0m Login successful for user '{user_data['username']}'")
                return True, user_data
        
        print(f"\033[93m[WARNING]\033[0m Failed login attempt for username/email '{username}'")
        return False, None
        
    except Exception as e:
        print(f"\033[91m[ERROR]\033[0m Error validating user: {str(e)}")
        return False, None

# User memory functions
def get_user_memory(username):
    
    db = get_db()
    
    try:
        memory_ref = db.collection('user_memory').document(username)
        memory_doc = memory_ref.get()
        
        if not memory_doc.exists:
            # Initialize empty memory if none exists
            memory_data = {
                "username": username,
                "name": "",
                "place": "",
                "friends": [],
                "priorities": [],
                "preferences": {},
                "other_info": {},
                "created_at": firestore.SERVER_TIMESTAMP,
                "updated_at": firestore.SERVER_TIMESTAMP
            }
            memory_ref.set(memory_data)
            print(f"\033[92m[INFO]\033[0m Created new memory for user '{username}'")
            return memory_data
        
        return memory_doc.to_dict()
        
    except Exception as e:
        print(f"\033[91m[ERROR]\033[0m Error getting user memory: {str(e)}")
        return None

def update_user_memory(username, memory_type, value):
    
    db = get_db()
    
    try:
        # Debug print
        print(f"\033[96m[DEBUG]\033[0m Updating memory for {username}: {memory_type} = {value}")
        
        memory_ref = db.collection('user_memory').document(username)
        
        # Get current memory
        memory = get_user_memory(username)
        if not memory:
            return None
        
        # Update the specific memory type
        if memory_type == "name":
            memory_ref.update({
                "name": value,
                "updated_at": firestore.SERVER_TIMESTAMP
            })
            print(f"\033[92m[SUCCESS]\033[0m Updated name for {username} to '{value}'")
            return f"name: {value}"
        
        elif memory_type == "place":
            memory_ref.update({
                "place": value,
                "updated_at": firestore.SERVER_TIMESTAMP
            })
            print(f"\033[92m[SUCCESS]\033[0m Updated place for {username} to '{value}'")
            return f"place: {value}"
        
        elif memory_type == "friends":
            # Add to friends list if not already present
            current_friends = memory.get("friends", [])
            if value not in current_friends:
                memory_ref.update({
                    "friends": firestore.ArrayUnion([value]),
                    "updated_at": firestore.SERVER_TIMESTAMP
                })
                print(f"\033[92m[SUCCESS]\033[0m Added friend '{value}' for {username}")
            return f"friend: {value}"
        
        elif memory_type == "priorities":
            # Add to priorities list if not already present
            current_priorities = memory.get("priorities", [])
            if value not in current_priorities:
                memory_ref.update({
                    "priorities": firestore.ArrayUnion([value]),
                    "updated_at": firestore.SERVER_TIMESTAMP
                })
                print(f"\033[92m[SUCCESS]\033[0m Added priority '{value}' for {username}")
            return f"priority: {value}"
        
        elif memory_type.startswith("preferences."):
            # Extract the preference key
            pref_key = memory_type.split(".", 1)[1]
            memory_ref.update({
                f"preferences.{pref_key}": value,
                "updated_at": firestore.SERVER_TIMESTAMP
            })
            print(f"\033[92m[SUCCESS]\033[0m Updated preference {pref_key}='{value}' for {username}")
            return f"preference: {pref_key} = {value}"
        
        elif memory_type.startswith("other_info."):
            # Extract the info key
            info_key = memory_type.split(".", 1)[1]
            memory_ref.update({
                f"other_info.{info_key}": value,
                "updated_at": firestore.SERVER_TIMESTAMP
            })
            print(f"\033[92m[SUCCESS]\033[0m Updated information {info_key}='{value}' for {username}")
            return f"information: {info_key} = {value}"
        
        return None
        
    except Exception as e:
        print(f"\033[91m[ERROR]\033[0m Error updating user memory: {str(e)}")
        return None

# Conversation history functions
def get_conversation_history(username):
    """Get conversation history for a user"""
    db = get_db()
    
    try:
        history_ref = db.collection('conversation_history').document(username)
        history_doc = history_ref.get()
        
        if not history_doc.exists:
            # Initialize empty history if none exists
            history_data = {
                "username": username,
                "messages": [],
                "created_at": firestore.SERVER_TIMESTAMP,
                "updated_at": firestore.SERVER_TIMESTAMP
            }
            history_ref.set(history_data)
            return []
        
        return history_doc.to_dict().get("messages", [])
        
    except Exception as e:
        print(f"\033[91m[ERROR]\033[0m Error getting conversation history: {str(e)}")
        return []

def add_to_conversation_history(username, message):
    """Add a message to the conversation history"""
    db = get_db()
    
    try:
        history_ref = db.collection('conversation_history').document(username)
        
        # Get current history
        history_doc = history_ref.get()
        
        if history_doc.exists:
            current_messages = history_doc.to_dict().get("messages", [])
        else:
            current_messages = []
        
        # Add new message
        current_messages.append(message)
        
        # Limit history to 100 messages
        if len(current_messages) > 100:
            current_messages = current_messages[-100:]
        
        # Update or create the document
        history_ref.set({
            "username": username,
            "messages": current_messages,
            "updated_at": firestore.SERVER_TIMESTAMP
        }, merge=True)
        
    except Exception as e:
        print(f"\033[91m[ERROR]\033[0m Error adding to conversation history: {str(e)}")

def extract_user_info(text):
    """
    Extract user information from text using regex patterns
    Returns a list of (memory_type, value) tuples
    """
    info = []
    
    # Debug print
    print(f"\033[96m[DEBUG]\033[0m Extracting user info from: {text}")
    
    # Convert to lowercase for case-insensitive matching
    text_lower = text.lower()
    
    # Name pattern: "my name is X" or "I am X" or "I'm X"
    name_patterns = [
        r"my name is (?:called\s+)?([A-Za-z]+(?:\s+[A-Za-z]+)*)",
        r"(?:i am|i'm) (?:called\s+)?([A-Za-z]+(?:\s+[A-Za-z]+)*)"
    ]
    
    for pattern in name_patterns:
        match = re.search(pattern, text_lower)
        if match:
            name_value = match.group(1)
            # Capitalize the first letter of each word
            name_value = ' '.join(word.capitalize() for word in name_value.split())
            info.append(("name", name_value))
            print(f"\033[96m[DEBUG]\033[0m Found name: {name_value}")
            break
    
    # Place pattern: "I live in X" or "I am from X" or "I'm from X" or "my place is X"
    place_patterns = [
        r"i live in ([A-Za-z]+(?:\s+[A-Za-z]+)*)",
        r"(?:i am|i'm) from ([A-Za-z]+(?:\s+[A-Za-z]+)*)",
        r"my place is ([A-Za-z]+(?:\s+[A-Za-z]+)*)"
    ]
    
    for pattern in place_patterns:
        match = re.search(pattern, text_lower)
        if match:
            place_value = match.group(1)
            # Capitalize the first letter of each word
            place_value = ' '.join(word.capitalize() for word in place_value.split())
            info.append(("place", place_value))
            print(f"\033[96m[DEBUG]\033[0m Found place: {place_value}")
            break
    
    # Friends pattern: "my friend X" or "my friends X, Y, and Z"
    friends_patterns = [
        r"my friend(?:s)? (?:is|are)? ([A-Za-z]+(?:\s+[A-Za-z]+)*(?:,\s+[A-Za-z]+(?:\s+[A-Za-z]+)*)*(?:,? and [A-Za-z]+(?:\s+[A-Za-z]+)*)?)",
        r"my friend(?:s)? name(?:s)? (?:is|are)? ([A-Za-z]+(?:\s+[A-Za-z]+)*(?:,\s+[A-Za-z]+(?:\s+[A-Za-z]+)*)*(?:,? and [A-Za-z]+(?:\s+[A-Za-z]+)*)?)"
    ]
    
    for pattern in friends_patterns:
        match = re.search(pattern, text_lower)
        if match:
            # Split the friends list
            friends_text = match.group(1)
            friends = re.split(r',\s*|\s+and\s+', friends_text)
            for friend in friends:
                if friend.strip():
                    friend_value = ' '.join(word.capitalize() for word in friend.strip().split())
                    info.append(("friends", friend_value))
                    print(f"\033[96m[DEBUG]\033[0m Found friend: {friend_value}")
            break
    
    # Priorities pattern: "my priority is X" or "my priorities are X, Y, and Z"
    priorities_pattern = r"my priorit(?:y|ies) (?:is|are) ([A-Za-z0-9]+(?:\s+[A-Za-z0-9]+)*(?:,\s+[A-Za-z0-9]+(?:\s+[A-Za-z0-9]+)*)*(?:,? and [A-Za-z0-9]+(?:\s+[A-Za-z0-9]+)*)?)"
    match = re.search(priorities_pattern, text_lower)
    if match:
        # Split the priorities list
        priorities_text = match.group(1)
        priorities = re.split(r',\s*|\s+and\s+', priorities_text)
        for priority in priorities:
            if priority.strip():
                info.append(("priorities", priority.strip()))
                print(f"\033[96m[DEBUG]\033[0m Found priority: {priority.strip()}")
    
    # Preferences pattern: "I like X" or "I prefer X" or "I love X" or "I hate X" or "I dislike X"
    preference_patterns = [
        (r"i (?:like|prefer|love) ([A-Za-z0-9]+(?:\s+[A-Za-z0-9]+)*)", "like"),
        (r"i (?:hate|dislike) ([A-Za-z0-9]+(?:\s+[A-Za-z0-9]+)*)", "dislike")
    ]
    
    for pattern, sentiment in preference_patterns:
        for match in re.finditer(pattern, text_lower):
            preference = match.group(1).strip()
            info.append((f"preferences.{preference}", sentiment))
            print(f"\033[96m[DEBUG]\033[0m Found preference: {preference} = {sentiment}")
    
    return info

def log_user_activity(username, action_type, filename, timestamp=None):
    """
    Log user activity in the database
    action_type: 'encrypt' or 'decrypt'
    """
    db = get_db()
    
    try:
        # Use current time if timestamp not provided
        if timestamp is None:
            timestamp = datetime.datetime.now()
        
        activity_data = {
            "username": username,
            "action_type": action_type,
            "filename": filename,
            "timestamp": timestamp
        }
        
        # Add activity to Firestore
        db.collection('activity_logs').add(activity_data)
        print(f"\033[92m[SUCCESS]\033[0m Logged {action_type} activity for user '{username}'")
        return True
        
    except Exception as e:
        print(f"\033[91m[ERROR]\033[0m Error logging user activity: {str(e)}")
        return False

def get_user_activities(username=None, limit=50):
    """
    Retrieve user activities from database
    If username is None, get activities for all users
    """
    db = get_db()
    
    try:
        activities_ref = db.collection('activity_logs')
        
        # Query based on username or get all activities
        if username:
            query = activities_ref.where('username', '==', username)
        else:
            query = activities_ref
        
        # Get activities sorted by timestamp (newest first)
        activities_docs = query.order_by('timestamp', direction=firestore.Query.DESCENDING).limit(limit).get()
        
        # Convert to list of dictionaries
        activities = []
        for doc in activities_docs:
            activity_data = doc.to_dict()
            activities.append(activity_data)
        
        return activities
        
    except Exception as e:
        print(f"\033[91m[ERROR]\033[0m Error getting user activities: {str(e)}")
        return []