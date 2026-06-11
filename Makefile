.PHONY: deploy plan plan-json test destroy fmt fmt-check policy-test policy-gate verify-evidence creds

# Set AWS_PROFILE in your shell before running, or pass on the command line:
#   make deploy AWS_PROFILE=my-sandbox
AWS_PROFILE ?= default

# If your profile is AWS SSO-based, the Terraform provider can't always
# read the profile directly. Export credentials into env vars first.
CREDS = eval "$$(aws configure export-credentials --profile $(AWS_PROFILE) --format env)"

deploy: ## Deploy the starter (terraform init + apply)
	@$(CREDS) && cd terraform && terraform init -input=false && terraform apply -auto-approve

plan: ## Show what deploy would do
	@$(CREDS) && cd terraform && terraform init -input=false && terraform plan

plan-json: ## Generate plan JSON for conftest (output: terraform/tfplan.json)
	@$(CREDS) && cd terraform && \
		terraform init -input=false && \
		terraform plan -out=tfplan.binary -input=false && \
		terraform show -json tfplan.binary > tfplan.json && \
		echo "Plan written to terraform/tfplan.json"

test: ## Smoke test the deployed API
	@$(CREDS) && cd terraform && API_URL=$$(terraform output -raw api_url) && \
		echo "POST $$API_URL" && \
		curl -sS -X POST "$$API_URL" \
			-H 'content-type: application/json' \
			-d '{"patient_id":"P-0001","fields":{"reason":"smoke-test"}}' \
		| python3 -m json.tool

destroy: ## Tear it all down
	@$(CREDS) && cd terraform && terraform destroy -auto-approve

fmt: ## Format all Terraform files
	cd terraform && terraform fmt -recursive

fmt-check: ## Check Terraform formatting (non-destructive, exits 1 if unformatted)
	cd terraform && terraform fmt -recursive -check

policy-test: ## Run OPA unit tests against all policies
	opa test ./policies --verbose

policy-gate: ## Run conftest against the current plan JSON
	@if [ ! -f terraform/tfplan.json ]; then \
		echo "No plan JSON found. Run: make plan-json AWS_PROFILE=<profile>"; exit 1; fi
	conftest test terraform/tfplan.json --policy policies/ --all-namespaces

creds: ## Print the active AWS identity (sanity check)
	@$(CREDS) && aws sts get-caller-identity
