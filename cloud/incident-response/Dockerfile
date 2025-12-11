# AegisAI Incident Response Module Dockerfile
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create evidence directory
RUN mkdir -p /var/evidence

# Create non-root user
RUN useradd --create-home --shell /bin/bash aegisai
RUN chown -R aegisai:aegisai /app /var/evidence
USER aegisai

# Expose port (if needed for API)
EXPOSE 8000

# Command to run the application
CMD ["python", "incident_response.py"]