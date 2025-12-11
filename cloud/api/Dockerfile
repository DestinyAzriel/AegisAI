# AegisAI Cloud API Dockerfile

# Use Python 3.9 slim image as base
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install system dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        gcc \
        g++ \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements file
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Create non-root user
RUN adduser --disabled-password --gecos '' appuser
USER appuser

# Copy application code
COPY . .

# Copy certificates
COPY certs/ /app/certs/

# Expose ports
EXPOSE 8080
EXPOSE 8443

# Run the application with HTTPS support
CMD ["python", "main.py", "--port", "8443", "--ssl-cert", "certs/server.crt", "--ssl-key", "certs/server.key", "--mtls-ca", "certs/ca.crt"]