SIGMA := sigma
PIPELINES := -p kql-conversions/pipelines/azuread-table-mappings.yml -p sentinel_asim

.PHONY: convert
convert:
	@mkdir -p kql-conversions/generated
	@for f in sigma-rules/*.yml; do \
		name=$$(basename $$f .yml); \
		$(SIGMA) convert -t kusto $(PIPELINES) -o kql-conversions/generated/$$name.kql $$f; \
	done

.PHONY: test
test:
	@python3 log-correlation/correlate.py

# Note: `sigma check` hangs indefinitely in this environment (seems to reach
# out to attack.mitre.org for tag validation and stalls) — validate syntax
# via `make convert` instead, which parses every rule as a side effect.
