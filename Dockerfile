# Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3-tk \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . .

# Create output directory
RUN mkdir -p output

# Set environment variables
ENV PYTHONPATH=/app
ENV DISPLAY=:0

# Expose port for potential web interface
EXPOSE 8080

# Command to run the application
CMD ["python", "main_gui.py"]
