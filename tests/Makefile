# Test Makefile for Property Management System
# SDET Best Practice: Separate test targets per module

CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -Isrc/include -Itests
LDFLAGS = -lws2_32  # Windows sockets for sqlite3

# Source directories
SRC_DIR = src
MODULES_DIR = $(SRC_DIR)/modules
UTILS_DIR = $(SRC_DIR)/utils
TEST_DIR = tests

# Test source files
TEST_RUNNER = $(TEST_DIR)/test_runner.c
TEST_SHA256 = $(TEST_DIR)/test_sha256.c
TEST_USER = $(TEST_DIR)/test_user.c
TEST_PROPERTY = $(TEST_DIR)/test_property.c
TEST_DATABASE = $(TEST_DIR)/test_database.c
UNITY = $(TEST_DIR)/unity.c

# Project source files needed for tests
PROJECT_SRCS = \
    $(UTILS_DIR)/sha256.c \
    $(UTILS_DIR)/common.c \
    $(UTILS_DIR)/sqlite3.c \
    $(MODULES_DIR)/user.c \
    $(MODULES_DIR)/property.c \
    $(MODULES_DIR)/database.c

# Test executables
TEST_EXE = $(TEST_DIR)/test_all.exe
TEST_SHA256_EXE = $(TEST_DIR)/test_sha256.exe
TEST_USER_EXE = $(TEST_DIR)/test_user.exe
TEST_PROPERTY_EXE = $(TEST_DIR)/test_property.exe
TEST_DATABASE_EXE = $(TEST_DIR)/test_database.exe

.PHONY: all clean test test-sha256 test-user test-property test-database

# Build all tests
all: $(TEST_EXE)
	@echo "All tests built. Run: $(TEST_EXE)"

# Build all tests executable
$(TEST_EXE): $(TEST_RUNNER) $(UNITY) $(TEST_SHA256) $(TEST_USER) $(TEST_PROPERTY) $(TEST_DATABASE) $(PROJECT_SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Build SHA256 test only
test-sha256: $(TEST_SHA256_EXE)
	@echo "Running SHA256 tests..."
	./$(TEST_SHA256_EXE)

$(TEST_SHA256_EXE): $(TEST_SHA256) $(UNITY) $(UTILS_DIR)/sha256.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Build User test only
test-user: $(TEST_USER_EXE)
	@echo "Running User tests..."
	./$(TEST_USER_EXE)

$(TEST_USER_EXE): $(TEST_USER) $(UNITY) $(MODULES_DIR)/user.c $(MODULES_DIR)/database.c $(UTILS_DIR)/sha256.c $(UTILS_DIR)/sqlite3.c $(UTILS_DIR)/common.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Build Property test only
test-property: $(TEST_PROPERTY_EXE)
	@echo "Running Property tests..."
	./$(TEST_PROPERTY_EXE)

$(TEST_PROPERTY_EXE): $(TEST_PROPERTY) $(UNITY) $(MODULES_DIR)/property.c $(MODULES_DIR)/database.c $(UTILS_DIR)/sqlite3.c $(UTILS_DIR)/common.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Build Database test only
test-database: $(TEST_DATABASE_EXE)
	@echo "Running Database tests..."
	./$(TEST_DATABASE_EXE)

$(TEST_DATABASE_EXE): $(TEST_DATABASE) $(UNITY) $(MODULES_DIR)/database.c $(MODULES_DIR)/user.c $(MODULES_DIR)/property.c $(UTILS_DIR)/sha256.c $(UTILS_DIR)/sqlite3.c $(UTILS_DIR)/common.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Run all tests
test: $(TEST_EXE)
	@echo "========================================="
	@echo "Running all unit tests..."
	@echo "========================================="
	./$(TEST_EXE)

# Clean test artifacts
clean:
	rm -f $(TEST_DIR)/*.exe $(TEST_DIR)/*.o
	rm -f data/test_*.db
	@echo "Test artifacts cleaned."