#!/bin/bash

# Ensure that the required tools are installed
echo "Checking for Python and pip..."
command -v python3 >/dev/null 2>&1 || { echo >&2 "Python is not installed. Please install Python 3."; exit 1; }
command -v pip3 >/dev/null 2>&1 || { echo >&2 "pip is not installed. Please install pip."; exit 1; }

# Create a virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
else
    echo "Virtual environment already exists."
fi

# Activate the virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Install dependencies from requirements.txt
echo "Installing Python packages from requirements.txt..."
pip install --upgrade pip
pip install -r requirements.txt

# Success message
echo "Virtual environment setup and packages installed successfully."
echo "To activate the virtual environment, run: source venv/bin/activate"
