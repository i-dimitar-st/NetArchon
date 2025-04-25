#!/bin/bash

echo "Installing system dependencies..."
sudo apt update
sudo apt install -y python3.12 python3.12-venv python3.12-dev influxdb grafana

echo "Creating Python 3.12 virtual environment..."
python3.12 -m venv venv
source venv/bin/activate

echo "Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

echo "Setting up folders..."
mkdir -p logs config storage services
touch logs/network-gateway.log

echo "Making main.py executable..."
chmod +x main.py

echo "Allowing sudo execution of main.py without password (optional)..."
echo "$USER ALL=(ALL) NOPASSWD: $(pwd)/main.py" | sudo tee /etc/sudoers.d/network-gateway

echo "Starting InfluxDB and Grafana..."
sudo systemctl enable --now influxdb
sudo systemctl enable --now grafana-server

echo "Installation complete."
echo "To start, run: sudo $(pwd)/main.py"
