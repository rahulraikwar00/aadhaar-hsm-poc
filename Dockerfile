FROM python:3.11-slim

# Install SoftHSM and dependencies
RUN apt-get update && apt-get install -y \
    softhsm2 \
    opensc \
    gcc \
    g++ \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install Python packages
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ /app/
COPY config.yaml /config.yaml

# Create log directory
RUN mkdir -p /var/log/aadhaar_hsm

# Expose ports
EXPOSE 8000 8080

# Run application
CMD ["python3", "main.py"]