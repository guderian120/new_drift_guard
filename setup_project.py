import subprocess
import sys
import os

def run(cmd):
    with open("setup_log.txt", "a") as f:
        f.write(f"Running: {cmd}\n")
        try:
            # Use shell=True for windows commands
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            f.write("STDOUT:\n")
            f.write(result.stdout)
            f.write("\nSTDERR:\n")
            f.write(result.stderr)
            f.write(f"\nReturn Code: {result.returncode}\n")
            f.write("-" * 20 + "\n")
        except Exception as e:
            f.write(f"Exception: {e}\n")

if __name__ == "__main__":
    # Ensure we are in the right directory
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    run("python -m pip install -r requirements.txt")
    run("python -m django startproject driftguard_project .")
    run("python manage.py startapp core")
    run("python manage.py startapp accounts")
    run("python manage.py startapp dashboard")
    run("python manage.py startapp drifts")
    run("python manage.py startapp chat")
    run("python manage.py startapp integrations")
