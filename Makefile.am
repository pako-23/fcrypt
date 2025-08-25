ACLOCAL_AMFLAGS = -I m4

doc_DATA = AUTHORS ChangeLog COPYING INSTALL NEWS README

SUBDIRS = src tests

if HAVE_INDENT
format-c:
	@indent -linux $$(find $(abs_srcdir) -name '*.c' -o -name '*.h')

format: format-c
else
format:
endif

.PHONY: format


CLEANFILES = google-java-format-1.27.0-all-deps.jar


.PHONY: clean-gcno clean-gcda \
	generate-coverage-html clean-coverage-html \
	check-coverage check-valgrind

clean-local: clean-gcno clean-coverage-html

if HAVE_COVERAGE_REPORT

clean-gcno:
	@echo Removing old coverage instrumentation
	-find -name '*.gcno' -delete

clean-gcda:
	@echo Removing old coverage results
	-find -name '*.gcda' -delete

check-coverage: clean-gcda
	-$(MAKE) $(AM_MAKEFLAGS) -k check
	$(MAKE) $(AM_MAKEFLAGS) generate-coverage-html

generate-coverage-html:
	@echo Collecting coverage data
	@$(LCOV) --directory $(top_builddir) --ignore-errors empty --capture --output-file coverage.info --no-checksum --compat-libtool
	@if test -s coverage.info; then \
		LANG=C $(GENHTML) --prefix $(top_builddir) --output-directory coverage --title "Code Coverage" --legend --show-details coverage.info; \
	fi

clean-coverage-html: clean-gcda
	-$(LCOV) --directory $(top_builddir) -z
	-rm -rf coverage.info coveragereport

endif
