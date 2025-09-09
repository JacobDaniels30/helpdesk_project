import os
import subprocess
import sys

# Activate virtual environment (adjust path if different)
venv_path = os.path.join(os.getcwd(), "helpdesk_env")
if sys.platform.startswith("win"):
    activate_script = os.path.join(venv_path, "Scripts", "activate.bat")
else:
    activate_script = os.path.join(venv_path, "bin", "activate")

print(f"Using virtual environment at: {venv_path}")

# Install necessary packages
packages = ["black", "isort", "flake8", "pylint"]
print("Installing packages:", packages)
subprocess.run([sys.executable, "-m", "pip", "install"] + packages, check=True)

# Format code with black
print("Formatting Python files with Black...")
subprocess.run([sys.executable, "-m", "black", "."], check=True)

# Sort imports
print("Sorting imports with isort...")
subprocess.run([sys.executable, "-m", "isort", "."], check=True)

# Lint code with flake8
print("Running flake8 style check...")
subprocess.run([sys.executable, "-m", "flake8", "."], check=True)

# Lint code with pylint
print("Running pylint for errors and warnings...")
subprocess.run([sys.executable, "-m", "pylint", "."], check=True)

print("✅ Cleanup completed! Check VS Code for updated markers.")
