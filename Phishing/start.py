import subprocess
import sys
import os
import time

def install_requirements():
    print("Installing dependencies...")
    if not os.path.exists("requirements.txt"):
        print("requirements.txt not found. Skipping dependency installation.")
        return

    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
    except subprocess.CalledProcessError as e:
        print(f"Error installing dependencies: {e}")
        input("Press Enter to exit...")
        sys.exit(1)

def run_phishing():
    print("Starting Phishing Server...")
    try:
        subprocess.run([sys.executable, "phishing.py"])
    except KeyboardInterrupt:
        print("\nStopping server...")
    except Exception as e:
        print(f"Error running phishing.py: {e}")
        input("Press Enter to exit...")

if __name__ == "__main__":
    try:
        install_requirements()
        run_phishing()
    except KeyboardInterrupt:
        print("\nExiting...")
    
    # Keep window open if run from double-click and it crashes immediately
    # functionality handled in sub-functions, but a final pause might be nice if it wasn't a clean exit
