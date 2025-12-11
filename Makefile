# AegisAI Makefile
# ================

# Variables
PROJECT_NAME = AegisAI
VERSION = 1.0.0
DOCKER_REGISTRY = aegisai

# Default target
.PHONY: help
help:
	@echo "AegisAI Build System"
	@echo "==================="
	@echo "Available targets:"
	@echo "  help          - Show this help message"
	@echo "  build         - Build all components"
	@echo "  build-agent   - Build Windows agent"
	@echo "  build-cloud   - Build cloud services"
	@echo "  build-web     - Build web console"
	@echo "  test          - Run all tests"
	@echo "  test-unit     - Run unit tests"
	@echo "  test-int      - Run integration tests"
	@echo "  clean         - Clean build artifacts"
	@echo "  docker-build  - Build Docker images"
	@echo "  docker-push   - Push Docker images to registry"
	@echo "  deploy        - Deploy to local environment"
	@echo "  deploy-k8s    - Deploy to Kubernetes"
	@echo "  run           - Run locally with Docker Compose"
	@echo "  stop          - Stop local Docker Compose environment"

# Build targets
.PHONY: build
build: build-agent build-cloud build-web

.PHONY: build-agent
build-agent:
	@echo "Building Windows agent..."
	cd agent/windows && ./build.bat

.PHONY: build-cloud
build-cloud:
	@echo "Building cloud services..."
	# Cloud services are Python-based, no compilation needed
	@echo "Cloud services ready"

.PHONY: build-web
build-web:
	@echo "Building web console..."
	cd web-console && npm install && npm run build

# Test targets
.PHONY: test
test: test-unit test-int

.PHONY: test-unit
test-unit:
	@echo "Running unit tests..."
	python -m pytest tests/test_*.py -v

.PHONY: test-int
test-int:
	@echo "Running integration tests..."
	python -m pytest tests/test_threat_intel.py -v
	python -m pytest tests/test_static_analyzer.py -v
	python -m pytest tests/test_cloud_security.py -v

# Clean target
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	rm -rf agent/windows/build/
	rm -rf web-console/build/
	rm -rf web-console/node_modules/
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -delete

# Docker targets
.PHONY: docker-build
docker-build:
	@echo "Building Docker images..."
	docker build -t $(DOCKER_REGISTRY)/cloud-api:$(VERSION) ./cloud/api
	docker build -t $(DOCKER_REGISTRY)/ml-service:$(VERSION) ./cloud/ml
	docker build -t $(DOCKER_REGISTRY)/static-analyzer:$(VERSION) ./cloud/static-analyzer
	docker build -t $(DOCKER_REGISTRY)/web-console:$(VERSION) ./web-console
	docker build -t $(DOCKER_REGISTRY)/api-gateway:$(VERSION) ./cloud/api-gateway

.PHONY: docker-push
docker-push:
	@echo "Pushing Docker images to registry..."
	docker push $(DOCKER_REGISTRY)/cloud-api:$(VERSION)
	docker push $(DOCKER_REGISTRY)/ml-service:$(VERSION)
	docker push $(DOCKER_REGISTRY)/static-analyzer:$(VERSION)
	docker push $(DOCKER_REGISTRY)/web-console:$(VERSION)
	docker push $(DOCKER_REGISTRY)/api-gateway:$(VERSION)

# Deployment targets
.PHONY: deploy
deploy:
	@echo "Deploying to local environment..."
	docker-compose up -d

.PHONY: deploy-k8s
deploy-k8s:
	@echo "Deploying to Kubernetes..."
	kubectl apply -f infra/kubernetes/

.PHONY: run
run:
	@echo "Starting local environment with Docker Compose..."
	docker-compose up

.PHONY: stop
stop:
	@echo "Stopping local environment..."
	docker-compose down

# Install development dependencies
.PHONY: install-dev
install-dev:
	@echo "Installing development dependencies..."
	pip install -r requirements-dev.txt

# Install runtime dependencies
.PHONY: install
install:
	@echo "Installing runtime dependencies..."
	pip install -r requirements.txt