## Process this file with automake to produce Makefile.in

AUTOMAKE_OPTIONS = serial-tests
bin_PROGRAMS = stellar-core

include $(top_srcdir)/common.mk
include $(srcdir)/src.mk

noinst_HEADERS = $(SRC_H_FILES)

if BUILD_TESTS
stellar_core_SOURCES = main/StellarCoreVersion.cpp main/XDRFilesSha256.cpp $(SRC_CXX_FILES) $(SRC_TEST_CXX_FILES)
else # !BUILD_TESTS
stellar_core_SOURCES = main/StellarCoreVersion.cpp main/XDRFilesSha256.cpp $(SRC_CXX_FILES)
endif # !BUILD_TESTS

CARGO_FEATURES =
if USE_TRACY
CARGO_FEATURES += --features tracy
endif

if ENABLE_NEXT_PROTOCOL_VERSION_UNSAFE_FOR_PRODUCTION
CARGO_FEATURES += --features core-vnext
main/XDRFilesSha256.cpp: $(SRC_X_FILES) Makefile $(top_srcdir)/hash-xdrs.sh
	$(top_srcdir)/hash-xdrs.sh protocol-next >$@
else
main/XDRFilesSha256.cpp: $(SRC_X_FILES) Makefile $(top_srcdir)/hash-xdrs.sh
	$(top_srcdir)/hash-xdrs.sh protocol-curr >$@
endif

stellar_core_LDADD = $(soci_LIBS) $(libmedida_LIBS)		\
	$(top_builddir)/lib/lib3rdparty.a $(sqlite3_LIBS)	\
	$(libpq_LIBS) $(xdrpp_LIBS) $(libsodium_LIBS) $(libunwind_LIBS)

TESTDATA_DIR = testdata
TEST_FILES = $(TESTDATA_DIR)/stellar-core_example.cfg $(TESTDATA_DIR)/stellar-core_standalone.cfg \
             $(TESTDATA_DIR)/stellar-core_testnet.cfg $(TESTDATA_DIR)/stellar-core_testnet_legacy.cfg \
             $(TESTDATA_DIR)/stellar-history.testnet.6714239.json $(TESTDATA_DIR)/stellar-history.livenet.15686975.json \
             $(TESTDATA_DIR)/stellar-core_testnet_validator.cfg $(TESTDATA_DIR)/stellar-core_example_validators.cfg \
             $(TESTDATA_DIR)/stellar-history.testnet.6714239.networkPassphrase.json

BUILT_SOURCES = $(SRC_X_FILES:.x=.h) main/StellarCoreVersion.cpp main/XDRFilesSha256.cpp $(TEST_FILES)

$(SRC_X_FILES:.x=.h): $(XDRC)
SUFFIXES = .x .h .rs
.x.h:
	$(XDRC) -hh -pedantic -o $@ $<

BISON=bison
FLEX=flex

util/xdrquery/XDRQueryScanner.cpp: util/xdrquery/XDRQueryScanner.ll
	$(FLEX) --outfile=$@ $<

util/xdrquery/XDRQueryParser.cpp: util/xdrquery/XDRQueryParser.yy
	$(BISON) --defines=util/xdrquery/XDRQueryParser.h  --output=$@ $<

util/xdrquery/XDRQueryParser.h: util/xdrquery/XDRQueryParser.cpp
	touch $@

BUILT_SOURCES += util/xdrquery/XDRQueryScanner.cpp util/xdrquery/XDRQueryParser.h util/xdrquery/XDRQueryParser.cpp
stellar_core_SOURCES += util/xdrquery/XDRQueryScanner.cpp util/xdrquery/XDRQueryParser.h util/xdrquery/XDRQueryParser.cpp

# Old automakes have buggy dependency tracking for conditional generated
# sources. We work around this here by making rust/RustBridge.{cpp,h} generated
# in all cases, and just empty in the non-rust case. Also because of the way old
# automake relies on horrible path-munging code in config.status to extract the
# names of depfiles from the Makefile itself, we can't use any variables in the
# SOURCES addition we're doing here, have to list unadorned paths.

BUILT_SOURCES += rust/RustBridge.h rust/RustBridge.cpp
stellar_core_SOURCES += rust/RustBridge.h rust/RustBridge.cpp

RUST_BUILD_DIR=$(top_builddir)/src/rust
RUST_BIN_DIR=$(RUST_BUILD_DIR)/bin
RUST_TARGET_DIR=$(top_builddir)/target
RUST_CXXBRIDGE=$(RUST_BIN_DIR)/cxxbridge
RUST_PROFILE=release
RUST_HOST_DEPFILES=rust/Cargo.toml $(top_srcdir)/Cargo.toml $(top_srcdir)/Cargo.lock $(wildcard rust/soroban-host-crates/*/*.*)
RUST_TARGET_PROFILE_DIR=$(RUST_TARGET_DIR)/$(RUST_PROFILE)
LIBSOROBAN_ENV_HOST_P21=$(RUST_TARGET_PROFILE_DIR)/libsoroban_env_host_p21.rlib
LIBSOROBAN_ENV_HOST_P22=$(RUST_TARGET_PROFILE_DIR)/libsoroban_env_host_p22.rlib
ALL_SOROBAN_HOST_RLIBS=$(LIBSOROBAN_ENV_HOST_P21) $(LIBSOROBAN_ENV_HOST_P22)
LIBRUST_STELLAR_CORE=$(RUST_TARGET_DIR)/$(RUST_PROFILE)/librust_stellar_core.a
stellar_core_LDADD += $(LIBRUST_STELLAR_CORE) -ldl

# This is a little awkward, but we want each ".../deps/libsoroban_env_host_p21.rlib"
# to turn into "--extern soroban_env_host_p21=.../deps/libsoroban_env_host_p21.rlib"
define extern_flag
$(shell printf -- '--extern %s=%s\n' $(1) $(abspath $(2)))
endef
ALL_SOROBAN_EXTERN_ARGS=$(foreach lib,$(ALL_SOROBAN_HOST_RLIBS),$(call extern_flag,$(patsubst $(RUST_TARGET_PROFILE_DIR)/lib%.rlib,%,$(lib)),$(lib)))

$(RUST_CXXBRIDGE):
	mkdir -p $(RUST_BIN_DIR)
	CARGO_HTTP_MULTIPLEXING=false $(CARGO) install --locked --root $(RUST_BUILD_DIR) cxxbridge-cmd --version 1.0.68

rust/RustBridge.h: rust/src/lib.rs $(SRC_RUST_FILES) Makefile $(RUST_CXXBRIDGE)
	$(RUST_CXXBRIDGE) $< --cfg test=false --header --output $@.tmp
	if cmp -s $@.tmp $@; then rm -v $@.tmp; else mv -v $@.tmp $@; fi

rust/RustBridge.cpp: rust/src/lib.rs $(SRC_RUST_FILES) Makefile $(RUST_CXXBRIDGE)
	$(RUST_CXXBRIDGE) $< --cfg test=false --output $@.tmp
	if cmp -s $@.tmp $@; then rm -v $@.tmp; else mv -v $@.tmp $@; fi

# This is a helper target that will re-fetch a lockfile committed to soroban-env-host
# from upstream when you change the git rev that each Cargo.toml points to. You do
# not need to run this normally and we will be committing the Cargo.lock files here
# as well to improve reproducibility.
rust/soroban-host-crates/%/Cargo.lock: rust/soroban-host-crates/%/Cargo.toml Makefile
	curl -o $@ $(shell perl -ne 'print "https://raw.githubusercontent.com/stellar/rs-soroban-env/$$1/Cargo.lock" if /rev = "([a-f0-9]+)"/' $<)

$(RUST_TARGET_PROFILE_DIR)/libsoroban_env_host_%.rlib: rust/soroban-host-crates/%/Cargo.toml Makefile 
	cd $(dir $<) && \
		CARGO_NET_GIT_FETCH_WITH_CLI=true cargo build \
		--$(RUST_PROFILE) \
		--target-dir $(abspath $(RUST_TARGET_DIR)) \
		$(CARGO_FEATURES)

$(LIBRUST_STELLAR_CORE): $(RUST_HOST_DEPFILES) $(SRC_RUST_FILES) Makefile $(ALL_SOROBAN_HOST_RLIBS)
	CARGO_NET_GIT_FETCH_WITH_CLI=true cargo rustc \
		--package stellar-core \
		--$(RUST_PROFILE) \
		--target-dir $(abspath $(RUST_TARGET_DIR)) \
		$(CARGO_FEATURES) \
		-- \
		$(ALL_SOROBAN_EXTERN_ARGS) \
		-L dependency=$(RUST_TARGET_PROFILE_DIR)/deps
	ranlib $@

$(srcdir)/src.mk: $(top_srcdir)/make-mks
	cd $(top_srcdir) && ./make-mks

$(TESTDATA_DIR)/%.cfg : $(top_srcdir)/docs/%.cfg
	mkdir -p $(@D) && cp $< $@

$(TESTDATA_DIR)/%.json : $(top_srcdir)/src/history/serialize-tests/%.json
	mkdir -p $(@D) && cp $< $@

.PHONY: always
always:
	@:

# Always rebuild because .git/HEAD is a symbolic ref one can't depend on
main/StellarCoreVersion.cpp: always
	@vers=$$(cd "$(srcdir)" \
		&& git describe --always --dirty --tags 2>/dev/null \
		|| echo "$(PACKAGE) $(VERSION)"); \
		sed -e "s@%%VERSION%%@$$vers@" \
			< "$(srcdir)/main/StellarCoreVersion.cpp.in" > $@~
	@if cmp -s $@~ $@; then rm -f $@~; else \
	    mv -f $@~ $@ && printf "echo '%s' > $@\n" "$$(cat $@)"; fi

if USE_POSTGRES
TESTS=test/selftest-pg
else # !USE_POSTGRES
TESTS=test/selftest-nopg
endif # !USE_POSTGRES
TESTS += test/check-nondet

format: always
if USE_CLANG_FORMAT
	cd $(srcdir) && $(CLANG_FORMAT) -style=file -i $(SRC_CXX_FILES) $(SRC_H_FILES) $(SRC_TEST_CXX_FILES) $(SRC_TEST_H_FILES)
endif # USE_CLANG_FORMAT
	cd $(srcdir) && $(CARGO) fmt --all

if USE_AFL_FUZZ
FUZZER_MODE ?= overlay

fuzz-testcases: stellar-core
	mkdir -p fuzz-testcases
	for i in `seq 1 10000`; do \
	    ./stellar-core gen-fuzz --mode=${FUZZER_MODE} fuzz-testcases/fuzz$$i.xdr ; \
	done
	mkdir -p min-testcases
	afl-cmin -i fuzz-testcases -o min-testcases -m 500 -t 250 ./stellar-core fuzz --ll ERROR --mode=${FUZZER_MODE} @@
	rm -Rf fuzz-testcases

# when running in parallel,
# run the same command than below replacing `-M main` with `-S worker_N`
# and `--process-id 0` with `--process-id N`

fuzz: fuzz-testcases stellar-core
	mkdir -p fuzz-findings
	afl-fuzz -m 500 -M main -t 250 -i min-testcases -o fuzz-findings \
	    ./stellar-core fuzz --ll ERROR --process-id 0 --mode=${FUZZER_MODE} @@

fuzz-clean: always
	rm -Rf fuzz-testcases fuzz-findings

distclean-local: fuzz-clean
endif # USE_AFL_FUZZ

CLEANFILES = $(BUILT_SOURCES) *~ */*~ stellar*.log
MAINTAINERCLEANFILES = $(srcdir)/Makefile.in $(srcdir)/*~ $(srcdir)/*/*~

EXTRA_DIST = $(SRC_X_FILES) test/selftest-nopg test/selftest-pg
