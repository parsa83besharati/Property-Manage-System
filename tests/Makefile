# Test Makefile for Property Management System
# SDET Best Practice: Separate test targets per module
# Cross-platform: Windows (MinGW) and Unix (Linux/macOS)

CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -Isrc/include -Itests

# Platform detection
ifeq ($(OS),Windows_NT)
    LDFLAGS = -lws2_32
    EXE = .exe
    RM = del /Q
else
    LDFLAGS = -lpthread
    EXE =
    RM = rm -f
endif

# Source directories
SRC_DIR = src
MODULES_DIR = $(SRC_DIR)/modules
UTILS_DIR = $(SRC_DIR)/utils
TEST_DIR = tests

# All test source files
TEST_SOURCES = \
    run_sha256.c \
    run_database.c \
    run_validation.c \
    run_edge_cases.c \
    run_export.c \
    run_audit.c \
    run_config.c \
    run_user.c \
    run_property.c \
    test_lease.c \
    run_negative.c

# Project source files needed for tests
PROJECT_SRCS = \
    $(UTILS_DIR)/sha256.c \
    $(UTILS_DIR)/common.c \
    $(UTILS_DIR)/sqlite3.c \
    $(UTILS_DIR)/config.c \
    $(UTILS_DIR)/export.c \
    $(UTILS_DIR)/audit.c \
    $(UTILS_DIR)/ui.c \
    $(MODULES_DIR)/database.c \
    $(MODULES_DIR)/user.c \
    $(MODULES_DIR)/property.c \
    $(MODULES_DIR)/menu.c

# Test executables (without .exe extension for cross-platform)
TEST_EXE = test_all$(EXE)
TEST_BINARIES = $(TEST_SOURCES:%.c=test_%$(EXE))

.PHONY: all clean test test-all test-sha256 test-database test-validation test-edge-cases test-export test-audit test-config test-user test-property test-lease test-negative

# Build all test executables
all: $(TEST_BINARIES)
	@echo "All test binaries built."

# Build individual test executables
test_%$(EXE): run_%.c unity.c $(PROJECT_SRCS)
	$(CC) $(CFLAGS) -o $@ $< unity.c $(PROJECT_SRCS) $(LDFLAGS)

test_lease$(EXE): test_lease.c unity.c $(PROJECT_SRCS)
	$(CC) $(CFLAGS) -o $@ $< unity.c $(PROJECT_SRCS) $(LDFLAGS)

test_negative$(EXE): run_negative.c unity.c $(PROJECT_SRCS)
	$(CC) $(CFLAGS) -o $@ $< unity.c $(PROJECT_SRCS) $(LDFLAGS)

# Run all tests
test-all: $(TEST_BINARIES)
	@echo "========================================="
	@echo "Running all unit tests..."
	@echo "========================================="
	@for test in $(TEST_BINARIES); do \
		echo "Running $$test..."; \
		./$$test || exit 1; \
	done
	@echo "========================================="
	@echo "All tests passed!"
	@echo "========================================="

# Individual test targets
test-sha256: test_sha256$(EXE)
	@echo "Running SHA256 tests..."
	./test_sha256$(EXE)

test-database: test_database$(EXE)
	@echo "Running Database tests..."
	./test_database$(EXE)

test-validation: test_validation$(EXE)
	@echo "Running Validation tests..."
	./test_validation$(EXE)

test-edge-cases: test_edge_cases$(EXE)
	@echo "Running Edge Cases tests..."
	./test_edge_cases$(EXE)

test-export: test_export$(EXE)
	@echo "Running Export tests..."
	./test_export$(EXE)

test-audit: test_audit$(EXE)
	@echo "Running Audit tests..."
	./test_audit$(EXE)

test-config: test_config$(EXE)
	@echo "Running Config tests..."
	./test_config$(EXE)

test-user: test_user$(EXE)
	@echo "Running User tests..."
	./test_user$(EXE)

test-property: test_property$(EXE)
	@echo "Running Property tests..."
	./test_property$(EXE)

test-lease: test_lease$(EXE)
	@echo "Running Lease tests..."
	./test_lease$(EXE)

test-negative: test_negative$(EXE)
	@echo "Running Negative tests..."
	./test_negative$(EXE)

# Coverage build
coverage: CFLAGS += --coverage -fprofile-arcs -ftest-coverage
coverage: LDFLAGS += --coverage
coverage: test-all

# AddressSanitizer build
asan: CFLAGS += -fsanitize=address,undefined -fno-omit-frame-pointer -g
asan: LDFLAGS += -fsanitize=address,undefined
asan: test-all

# ThreadSanitizer build (Unix only)
tsan: CFLAGS += -fsanitize=thread -fno-omit-frame-pointer -g
tsan: LDFLAGS += -fsanitize=thread
tsan: test-all

# Clean test artifacts
clean:
	$(RM) *$(EXE) *.o
	$(RM) data/test_*.db
	$(RM) coverage.info
	$(RM) -r coverage_html
	@echo "Test artifacts cleaned."