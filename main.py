import os
import sys
from dotenv import load_dotenv

# -----------------------------
# Project setup
# -----------------------------
# Absolute path of the project root
project_root = os.path.dirname(os.path.abspath(__file__))

# Add project root and app folder to Python path
sys.path.insert(0, project_root)
sys.path.insert(0, os.path.join(project_root, 'app'))
os.environ['PYTHONPATH'] = project_root

# Load environment variables from .env
load_dotenv(os.path.join(project_root, '.env'))

# -----------------------------
# Import and create Flask app
# -----------------------------
from app import create_app

# Create app at module level so Gunicorn can see it
app = create_app()

# -----------------------------
# Run locally
# -----------------------------
if __name__ == "__main__":
    # This runs only when executing "python run.py" locally
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
