FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Copy project files
COPY . /app/

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose port for Flask app
EXPOSE 5000

# Start the Flask application
CMD ["python", "app/main.py"]
