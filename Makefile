SIGMA := sigma
PIPELINES := -p kql-conversions/pipelines/signinlogs-table.yml -p sentinel_asim

.PHONY: convert
convert:
	@mkdir -p kql-conversions/generated
	@for f in sigma-rules/*.yml; do \
		name=$$(basename $$f .yml); \
		$(SIGMA) convert -t kusto $(PIPELINES) -o kql-conversions/generated/$$name.kql $$f; \
	done

.PHONY: check
check:
	$(SIGMA) check sigma-rules/*.yml
