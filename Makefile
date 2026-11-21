


REGISTRY ?= ghcr.io/your-org
TAG ?= v3.5.0
NAMESPACE ?= ishastra-system
RELEASE ?= ishastra
PLATFORM ?= linux/amd64,linux/arm64

.PHONY: help build push build-and-push deploy verify clean test

help:
	@grep -E '^[a-zA-Z_-]+:.*?##' Makefile | awk 'BEGIN {FS = ":.*?##"}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## Build multi-arch Docker image locally
	docker buildx create --name ishastra-builder --use 2>/dev/null || docker buildx use ishastra-builder
	docker buildx build --platform $(PLATFORM) -t $(REGISTRY)/ishastra:$(TAG) -f Dockerfile --load .

push: ## Build and push multi-arch Docker images to registry
	docker buildx create --name ishastra-builder --use 2>/dev/null || docker buildx use ishastra-builder
	docker buildx build --platform $(PLATFORM) -t $(REGISTRY)/ishastra:$(TAG) -f Dockerfile --push .
	docker tag $(REGISTRY)/ishastra:$(TAG) $(REGISTRY)/ishastra-operator:$(TAG)
	docker tag $(REGISTRY)/ishastra:$(TAG) $(REGISTRY)/ishastra-api:$(TAG)
	docker tag $(REGISTRY)/ishastra:$(TAG) $(REGISTRY)/ishastra-worker:$(TAG)
	docker tag $(REGISTRY)/ishastra:$(TAG) $(REGISTRY)/ishastra-scheduler:$(TAG)
	docker push $(REGISTRY)/ishastra-operator:$(TAG) $(REGISTRY)/ishastra-api:$(TAG) $(REGISTRY)/ishastra-worker:$(TAG) $(REGISTRY)/ishastra-scheduler:$(TAG)

build-and-push: push ## Alias for push

deploy: ## Deploy to Kubernetes using Helm
	@./scripts/deploy-ishastra.sh $(NAMESPACE) $(RELEASE)

deploy-dev: ## Deploy development stack with embedded Postgres/Redis
	helm upgrade --install $(RELEASE) deploy/helm/ishastra \
	  --namespace $(NAMESPACE) --create-namespace \
	  --set postgresql.enabled=true \
	  --set redis.enabled=true \
	  --set operator.enabled=false \
	  --wait --timeout=5m

undeploy: ## Remove deployment and namespace
	helm uninstall $(RELEASE) -n $(NAMESPACE) || true
	kubectl delete namespace $(NAMESPACE) --ignore-not-found=true

verify: ## Verify deployment status and health
	@echo "=== Pods ==="
	kubectl get pods -n $(NAMESPACE) -o wide
	@echo ""
	@echo "=== CRDs ==="
	kubectl get crd | grep ishastra.io
	@echo ""
	@echo "=== Operator logs (last 50) ==="
	kubectl logs -n $(NAMESPACE) -l app.kubernetes.io/component=operator --tail=50
	@echo ""
	@echo "=== Health checks ==="
	kubectl exec -n $(NAMESPACE) deploy/$(RELEASE)-operator -- ishastra dr health 2>/dev/null || echo "DR health check failed"

verify-resources: ## List all Ishastra CR resources
	@echo "=== Tenants ==="
	kubectl get tenants -A
	@echo ""
	@echo "=== Policies ==="
	kubectl get policies -A
	@echo ""
	@echo "=== AssessmentJobs ==="
	kubectl get assessmentjobs -A
	@echo ""
	@echo "=== ScanResults ==="
	kubectl get scanresults -A

create-tenant: ## Create example Tenant, Policy, AssessmentJob
	kubectl apply -f deploy/examples/production-resources.yaml

run-assessment: ## Run example assessment
	kubectl apply -f deploy/examples/production-resources.yaml

dr-health: ## Check DR health status
	kubectl exec -n $(NAMESPACE) deploy/$(RELEASE)-operator -- ishastra dr health

dr-backup: ## Create verified database backup
	kubectl exec -n $(NAMESPACE) deploy/$(RELEASE)-operator -- ishastra backup --verify

dr-failover: ## Initiate DR failover (with confirmation)
	@read -p "This will initiate failover. Continue? [y/N] " confirm && [ "$$confirm" = "y" ]
	kubectl exec -n $(NAMESPACE) deploy/$(RELEASE)-operator -- ishastra standby-promote --verify

test: ## Run full test suite with coverage
	python3 -m pytest tests/ --cov=src --cov-report=term-missing --cov-fail-under=50

test-unit: ## Run unit tests only
	python3 -m pytest tests/unit/ -v

lint: ## Run linter, type checker and secret scan
	ruff check src/ tests/
	mypy src/
	python3 scripts/check_secrets.py

format: ## Format code with ruff
	ruff format src/ tests/

benchmark: ## Run detection + scope-gate benchmarks (records results in benchmarks/)
	python3 scripts/detection_benchmark.py --allow-unmeasured --output benchmarks/detection-benchmark-results.json
	python3 scripts/benchmark_scope_gate.py --requests 5000

clean: ## Clean build artifacts
	docker buildx rm ishastra-builder 2>/dev/null || true
	rm -rf .pytest_cache coverage.json htmlcov/ dist/ build/ *.egg-info/

release-dry-run: ## Build and verify package
	python3 -m build
	python3 -m twine check dist/*

release: ## Publish package to PyPI
	python3 -m build
	python3 -m twine upload dist/*