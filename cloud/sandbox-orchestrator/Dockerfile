# AegisAI Sandbox Orchestrator
# Secure isolated environment for malware analysis

FROM ubuntu:20.04

# Avoid prompts from apt
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
    build-essential \
    libffi-dev \
    libssl-dev \
    curl \
    wget \
    git \
    vim \
    tcpdump \
    net-tools \
    procps \
    sysstat \
    strace \
    ltrace \
    gdb \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt /tmp/requirements.txt
RUN pip3 install -r /tmp/requirements.txt

# Create sandbox user
RUN useradd -m -s /bin/bash sandbox

# Create analysis directories
RUN mkdir -p /analysis/samples \
    /analysis/results \
    /analysis/tools \
    /analysis/logs

# Set permissions
RUN chown -R sandbox:sandbox /analysis

# Copy sandbox orchestrator
COPY . /sandbox-orchestrator
WORKDIR /sandbox-orchestrator

# Expose API port
EXPOSE 8002

# Run as sandbox user
USER sandbox

# Start the orchestrator
CMD ["python3", "orchestrator.py"]