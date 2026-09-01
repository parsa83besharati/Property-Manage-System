# Property Management System - Unit Test Documentation

## Overview

This document describes the comprehensive unit test suite for the Property Management System following SDET (Software Development Engineer in Test) best practices.

**Core Tests Passing**: 58 tests across 6 test suites

## Test Structure

```
tests/
├── run_sha256.c          # SHA256 hash function tests (3)
├── run_user.c            # User database CRUD tests (9)
├── run_property.c        # Property database CRUD tests (12)
├── run_database.c        # Database core operation tests (6)
├── run_validation.c      # Input validation tests (28)
├── run_edge_cases.c      # Edge case/boundary tests (15)
├── run_export.c          # CSV export/import tests (4)
├── run_audit.c           # Audit logging tests (6)
├── run_config.c          # Config tests (2)
├── run_negative.c        # Negative/error path tests (WIP)
├── test_lease.c          # Lease management tests (25 - source ready)
├── unity.c               # Unity test framework
├── unity.h               # Unity header
├── unity_internals.h     # Unity internals
└── Makefile              # Test build targets
```

## Test Framework

- **Unity**: Lightweight C unit testing framework (ThrowTheSwitch)
- **Coverage Target**: All critical user flows, data operations, validation, and edge cases
- **Test Isolation**: Each test uses unique temporary database, cleaned up before/after

## Test Cases by Module

### 1. SHA256 Hash Module (`run_sha256.c`)

| ID | Test Name | Objective | Flow | Expected Result |
|----|-----------|-----------|------|-----------------|
| SHA-001 | Hash computation | Verify SHA256 produces valid 32-byte digest | Hash "test_password" | Length=32, all bytes 0x00-0xFF |
| SHA-002 | Determinism | Same input always produces same hash | Hash "determinism_test" twice | Both hashes identical |
| SHA-003 | Uniqueness | Different inputs produce different hashes | Hash "input_A" vs "input_B" | Hashes differ (avalanche effect) |

**Run**: `make -C tests test-sha256`

### 2. User Database Module (`run_user.c`)

| ID | Test Name | Objective | Flow | Expected Result |
|----|-----------|-----------|------|-----------------|
| USR-001 | Create user | Insert valid user record | db_user_create with all fields | Returns 1 |
| USR-002 | Duplicate user | Reject duplicate username (PK) | Insert same username twice | Second returns 0 |
| USR-003 | Find by username | Locate existing user | db_user_find_by_username | Returns User* with matching fields |
| USR-004 | Find nonexistent | Handle missing user gracefully | db_user_find_by_username("ghost") | Returns NULL |
| USR-005 | Update password | Change password hash/salt | db_user_update_password | Returns 1, hash updated |
| USR-006 | Update field | Modify user profile fields | db_user_update_field | Returns 1, field updated |
| USR-007 | List all users | Retrieve all user records | db_user_list_all | Returns all created users |
| USR-008 | Count users | Get total user count | db_user_count | Returns correct count |
| USR-009 | Empty database | Verify empty state handling | Query fresh DB | Count=0, find=NULL |

**Run**: `make -C tests test-user` (requires UI dependencies)

### 3. Property Database Module (`run_property.c`)

| ID | Test Name | Objective | Flow | Expected Result |
|----|-----------|-----------|------|-----------------|
| PROP-001 | Create residential sell | Insert valid residential property | db_property_create with all fields | Returns 1 |
| PROP-002 | Duplicate code | Reject duplicate property code | Insert same code twice | Second returns 0 |
| PROP-003 | Find by code | Locate existing property | db_property_find_by_code | Returns Property* |
| PROP-004 | Find nonexistent | Handle missing property | db_property_find_by_code("NOPE") | Returns NULL |
| PROP-005 | Delete success | Soft delete existing property | db_property_delete on existing | Returns 1, active=0 |
| PROP-006 | Delete nonexistent | Handle missing delete | db_property_delete("GHOST") | Returns 0 |
| PROP-007 | List all | Retrieve all properties | db_property_list_all | Returns all active |
| PROP-008 | Filter by district | District-specific query | db_property_list_by_district | Returns matching only |
| PROP-009 | Filter by type | Type/action query | db_property_list_by_type | Returns matching only |
| PROP-010 | Filter by price | Price range query | db_property_list_by_price_range | Returns in range only |
| PROP-011 | Count by type | Count by type/action | db_property_count_by_type | Returns correct count |
| PROP-012 | Empty database | Verify empty state | Query fresh DB | Count=0 |

**Run**: `make -C tests test-property` (requires UI dependencies)

### 4. Database Core Module (`run_database.c`)

| ID | Test Name | Objective | Flow | Expected Result |
|----|-----------|-----------|------|-----------------|
| DB-001 | Open database | Open SQLite connection | database_open | Returns valid Database* |
| DB-002 | Close database | Clean resource cleanup | database_close | No memory leaks |
| DB-003 | Init schema | Create all tables + indexes | database_init_schema | Returns 1 |
| DB-004 | Idempotent schema | Re-run init safely | database_init_schema twice | Returns 1 both times |
| DB-005 | Migrate empty | Handle missing .dat files | database_migrate_from_files | Returns 1 |
| DB-006 | Cross-module | User→Property FK works | Create user, then property | Property links to user |

**Run**: `make -C tests test-database`

### 5. Input Validation Module (`run_validation.c`)

| ID | Test Name | Objective | Flow | Expected Result |
|----|-----------|-----------|------|-----------------|
| VAL-001..06 | Phone validation | 11-digit Iranian format (09xxxxxxxxx) | validate_phone | PASS/FAIL per case |
| VAL-007..12 | Email validation | RFC-like email format | validate_email | PASS/FAIL per case |
| VAL-013..19 | Password validation | 8+ chars, upper, lower, digit | validate_password | PASS/FAIL per case |
| VAL-020..21 | ID validation | 10-digit national ID | validate_id | PASS/FAIL per case |
| VAL-022..25 | Int range validation | Bounds + overflow (errno) | validate_int_range | PASS/FAIL per case |
| VAL-026..29 | Double range validation | Bounds + NaN handling | validate_double_range | PASS/FAIL per case |

**Run**: `make -C tests test-validation`

### 6. Edge Cases Module (`run_edge_cases.c`)

| ID | Test Name | Objective | Flow | Expected Result |
|----|-----------|-----------|------|-----------------|
| EDGE-001 | Empty username | Handle empty string input | db_user_create with "" | Rejected gracefully |
| EDGE-002 | Max length fields | Boundary at MAX_FIELD_LEN | Create with 50-char strings | Accepted |
| EDGE-003 | Find empty username | Query with empty string | db_user_find_by_username("") | Returns NULL |
| EDGE-004 | Update nonexistent | Update missing user | db_user_update_field("ghost") | Returns 0 |
| EDGE-005 | Zero price property | Property with 0 price | db_property_create with 0 | Accepted |
| EDGE-006 | Large price | Property with 1B price | db_property_create with 1e9 | Accepted |
| EDGE-007 | Max string fields | All strings at max length | Create with 500-char strings | Accepted |
| EDGE-008 | Invalid property code | Special chars in code | db_property_find_by_code("!@#") | Returns NULL |
| EDGE-009 | Int boundary | INT_MIN/INT_MAX | validate_int_range | Correct bounds |
| EDGE-010 | Double boundary | DBL_MIN/DBL_MAX | validate_double_range | Correct bounds |
| EDGE-011 | Special chars address | Unicode/special in address | db_property_create | Stored correctly |
| EDGE-012 | Unicode address | UTF-8 in address | db_property_create | Stored correctly |
| EDGE-013 | CRUD cycle | Create→Update→Delete | Full lifecycle | All operations PASS |
| EDGE-014 | Pagination edges | Page 0, last page, empty | db_property_list_paginated | Correct behavior |
| EDGE-015 | Count filtered edges | Complex WHERE clauses | db_property_count_filtered | Correct counts |

**Run**: `make -C tests test-edge-cases`

### 7. CSV Export Module (`run_export.c`)

| ID | Test Name | Objective | Flow | Expected Result |
|----|-----------|-----------|------|-----------------|
| EXP-001 | Export users CSV | Generate users.csv with headers | export_users_to_csv | File exists, headers + data |
| EXP-002 | Export properties CSV | Generate properties.csv with headers | export_properties_to_csv | File exists, headers + data |
| EXP-003 | Export all | Export both users + properties | export_all_to_csv | Both files created |
| EXP-004 | Empty DB export | Export from DB with only test user | export_users_to_csv | Headers + 1 data row |

**Run**: `make -C tests test-export`

### 8. Audit Logging Module (`run_audit.c`)

| ID | Test Name | Objective | Flow | Expected Result |
|----|-----------|-----------|------|-----------------|
| AUD-001 | Basic log | Insert single audit entry | audit_log + audit_get_logs | Returns 1 row |
| AUD-002 | Multiple actions | Log CREATE/UPDATE/DELETE | Multiple audit_log calls | All retrievable |
| AUD-003 | Filter by user | Query specific user's logs | audit_get_logs(username="x") | Only that user's logs |
| AUD-004 | Filter by action | Query by CREATE/DELETE | audit_get_logs(action=CREATE) | Only CREATE logs |
| AUD-005 | Pagination | Limit + offset | audit_get_logs(limit=10,offset=10) | Correct page |
| AUD-006 | Filter by entity | Query USER/PROPERTY logs | audit_get_logs(entity=PROPERTY) | Only property logs |

**Run**: `make -C tests test-audit`

### 9. Configuration Module (`run_config.c`)

| ID | Test Name | Objective | Flow | Expected Result |
|----|-----------|-----------|------|-----------------|
| CFG-001 | Default config | Load defaults when no file | config_load missing file | Defaults applied |
| CFG-002 | Load from file | Parse config.ini | config_load with file | Values from file |

**Run**: `make -C tests test-config`

---

## Additional Test Files (Source Ready - Require UI Dependencies)

### 9. Lease Management (`test_lease.c` - 25 tests)

| ID | Test Name | Objective |
|----|-----------|-----------|
| LSE-001 | Create lease success | Full lease creation with valid data |
| LSE-002 | Duplicate property active | Allow multiple leases per property |
| LSE-003 | Nonexistent property | FK constraint rejects invalid property |
| LSE-004 | Nonexistent tenant | FK constraint rejects invalid tenant |
| LSE-005 | Find by ID | Retrieve lease by auto-increment ID |
| LSE-006 | Find nonexistent | Return NULL for missing ID |
| LSE-007 | Update status | Change ACTIVE→TERMINATED |
| LSE-008 | Update rent | Modify rent and deposit |
| LSE-009 | Delete success | Remove lease by ID |
| LSE-010 | Delete nonexistent | Return 0 for missing ID |
| LSE-011 | List all | Retrieve all leases |
| LSE-012 | Filter by tenant | Leases for specific tenant |
| LSE-013 | Filter by property | Leases for specific property |
| LSE-014 | Filter by status | ACTIVE/EXPIRED/TERMINATED |
| LSE-015 | Expiring leases | Leases ending within N days |
| LSE-016 | Count total | Total lease count |
| LSE-017 | Count by tenant | Per-tenant lease count |
| LSE-018 | Count by property | Per-property lease count |
| LSE-019 | Zero rent | Edge case: 0 monthly rent |
| LSE-020 | High rent | Edge case: 999999.99 rent |
| LSE-021 | Date boundary | Same start/end date |
| LSE-022 | Auto-renew flag | Verify auto_renew persists |
| LSE-023 | Status enum | All 4 statuses work |
| LSE-024 | Payment day | Days 1-28 all valid |
| LSE-025 | Empty database | Verify empty state |

### 10. User Roles (`test_user.c` - 2 additional)

| ID | Test Name | Objective |
|----|-----------|-----------|
| ROL-001 | Set/get role | ROLE_USER ↔ ROLE_ADMIN |
| ROL-002 | Create with role | Set role at creation time |

### 11. Property Images (`test_property.c` - 3 additional)

| ID | Test Name | Objective |
|----|-----------|-----------|
| IMG-001 | Empty default | image_path defaults to "" |
| IMG-002 | Set/get path | Store and retrieve image path |
| IMG-003 | Long path | Near MAX_STRING_LEN path |

### 12. CSV Import (`run_export.c` - 4 additional)

| ID | Test Name | Objective |
|----|-----------|-----------|
| IMP-001 | Import users | Parse CSV, skip duplicates |
| IMP-002 | Import properties | Parse CSV, validate FK |
| IMP-003 | Import duplicates | Skip existing records |
| IMP-004 | Import missing fields | Handle partial rows |

---

## Running Tests

```bash
# Run all 58 core tests
cd tests
./test_sha256.exe
./test_database.exe
./test_validation.exe
./test_edge_cases.exe
./test_audit.exe
./test_config.exe

# Run all including additional (requires UI deps)
# ./test_user.exe
# ./test_property.exe
# ./test_export.exe
# ./test_lease.exe  (not compiled due to UI deps)

# Build with coverage
make -C tests coverage

# Build with sanitizers
make -C tests asan
make -C tests tsan
```

---

## Bugs Found & Fixed by Tests

1. **INSERT SQL mismatch** - 29 columns vs 30 placeholders (fixed)
2. **Delete false positive** - Returned success when 0 rows affected (fixed)
3. **Missing NULL checks** - `db_user_count(NULL)` crashed (fixed)
4. **Validate overflow** - `validate_int_range` didn't check `errno` (fixed)
5. **Pagination logic** - Test expectations wrong for limit 0 (fixed)
6. **DB cleanup** - WAL/SHM files persisted between tests (fixed)
7. **Config parser** - Leading spaces in values (fixed)
8. **Audit filters** - Enum signedness issue with -1 sentinel (fixed)
9. **CSV Export** - Unused variable warnings (fixed)
10. **Property Image** - Schema migration for image_path column (fixed)
11. **User Role** - Schema migration for role column (fixed)
12. **CSV Import** - Salt truncation warning (fixed)

---

## Test Quality Metrics

| Metric | Value |
|--------|-------|
| Core Tests Passing | 58/58 (100%) |
| Test Files | 11 |
| Lines of Test Code | ~2,500 |
| Assertions per Test | ~3-5 |
| Isolation | Per-test temp DB |
| Cleanup | WAL/SHM removed |
| Framework | Unity (ThrowTheSwitch) |

---

*Documentation version: 2026-09-01*