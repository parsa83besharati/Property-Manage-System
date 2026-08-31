CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -Iinclude -O2
LDFLAGS = 
TARGET = property_manage.exe

SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin
TEST_DIR = tests

SOURCES = $(SRC_DIR)/main.c \
          $(SRC_DIR)/utils/common.c \
          $(SRC_DIR)/utils/sha256.c \
          $(SRC_DIR)/utils/ui.c \
          $(SRC_DIR)/utils/sqlite3.c \
          $(SRC_DIR)/utils/config.c \
          $(SRC_DIR)/utils/export.c \
          $(SRC_DIR)/utils/audit.c \
          $(SRC_DIR)/modules/user.c \
          $(SRC_DIR)/modules/property.c \
          $(SRC_DIR)/modules/menu.c \
          $(SRC_DIR)/modules/database.c

OBJECTS = $(SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

TEST_SOURCES = $(TEST_DIR)/run_sha256.c \
               $(TEST_DIR)/run_user.c \
               $(TEST_DIR)/run_property.c \
               $(TEST_DIR)/run_database.c \
               $(TEST_DIR)/run_validation.c \
               $(TEST_DIR)/run_edge_cases.c \
               $(TEST_DIR)/run_export.c \
               $(TEST_DIR)/run_audit.c \
               $(TEST_DIR)/run_config.c

TEST_OBJECTS = $(TEST_SOURCES:$(TEST_DIR)/%.c=$(TEST_DIR)/%.o)
TEST_BINARIES = $(TEST_SOURCES:$(TEST_DIR)/%.c=$(TEST_DIR)/test_%.exe)

all: $(BIN_DIR)/$(TARGET)

$(BIN_DIR)/$(TARGET): $(OBJECTS)
	@mkdir -p $(BIN_DIR)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR) $(TEST_DIR)/test_*.exe

run: $(BIN_DIR)/$(TARGET)
	./$(BIN_DIR)/$(TARGET)

debug: CFLAGS += -g -DDEBUG
debug: all

# Test targets
test: $(TEST_BINARIES)
	@for test in $(TEST_BINARIES); do \
		cd $(TEST_DIR) && ./$$(basename $$test) || exit 1; \
	done

test-sha256: $(TEST_DIR)/test_sha256.exe
	cd $(TEST_DIR) && ./test_sha256.exe

test-user: $(TEST_DIR)/test_user.exe
	cd $(TEST_DIR) && ./test_user.exe

test-property: $(TEST_DIR)/test_property.exe
	cd $(TEST_DIR) && ./test_property.exe

test-database: $(TEST_DIR)/test_database.exe
	cd $(TEST_DIR) && ./test_database.exe

test-validation: $(TEST_DIR)/test_validation.exe
	cd $(TEST_DIR) && ./test_validation.exe

test-edge-cases: $(TEST_DIR)/test_edge_cases.exe
	cd $(TEST_DIR) && ./test_edge_cases.exe

test-export: $(TEST_DIR)/test_export.exe
	cd $(TEST_DIR) && ./test_export.exe

test-audit: $(TEST_DIR)/test_audit.exe
	cd $(TEST_DIR) && ./test_audit.exe

test-config: $(TEST_DIR)/test_config.exe
	cd $(TEST_DIR) && ./test_config.exe

$(TEST_DIR)/test_%.exe: $(TEST_DIR)/run_%.c $(TEST_DIR)/unity.c $(OBJECTS)
	$(CC) $(CFLAGS) -Iinclude -Itests -o $@ $< $(TEST_DIR)/unity.c $(filter-out $(OBJ_DIR)/main.o, $(OBJECTS))

.PHONY: all clean run debug test test-sha256 test-user test-property test-database test-validation test-edge-cases test-export test-audit test-config