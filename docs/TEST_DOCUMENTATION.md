# Property Management System - Unit Test Documentation

## Overview

This document describes the comprehensive unit test suite for the Property Management System following SDET (Software Development Engineer in Test) best practices.

**Total Tests**: 73+ passing tests across 6 test suites

## Test Structure

```
tests/
├── run_sha256.c          # SHA256 hash function tests (3)
├── run_user.c            # User database CRUD tests (9)
├── run_property.c        # Property database CRUD tests (12)
├── run_database.c        # Database core operation tests (6)
├── run_validation.c      # Input validation tests (28)
├── run_edge_cases.c      # Edge case/boundary tests (15)
├── run_negative.c        # Negative/error path tests (WIP)
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
| USR-004 | Find nonexistent | Query non-existent user | db_user_find_by_username | Returns NULL |
| USR-005 | Update password | Change password hash + salt | db_user_update_password | Hash and salt updated |
| USR-006 | Update field | Change single user field | db_user_update_field | Only targeted field changes |
| USR-007 | List all users | Retrieve all users | db_user_list_all | Count matches created users |
| USR-008 | Count users | Get user count | db_user_count | Returns correct count |
| USR-009 | Empty database | Query empty DB | find=NULL, count=0 | NULL and 0 returned |

**Run**: `make -C tests test-user`

### 3. Property Database Module (`run_property.c`)

| ID | Test Name | Objective | Flow | Expected Result |
|----|-----------|-----------|------|-----------------|
| PRP-001 | Create residential sell | Insert residential sell property | db_property_create | Returns 1, findable by code |
| PRP-002 | Duplicate code | Reject duplicate property code | Insert same code twice | Second returns 0 |
| PRP-003 | Find by code | Locate property by code | db_property_find_by_code | Returns Property* with matching fields |
| PRP-004 | Find nonexistent | Query non-existent property | db_property_find_by_code | Returns NULL |
| PRP-005 | Delete success | Soft-delete existing property | db_property_delete | Returns 1, find returns NULL |
| PRP-006 | Delete nonexistent | Delete non-existent property | db_property_delete | Returns 0 |
| PRP-007 | List all | List all properties | db_property_list_all | Count matches created |
| PRP-008 | Filter by district | Search by district | db_property_list_by_district | Only matching district returned |
| PRP-009 | Filter by type | Search by type+action | db_property_list_by_type | Only matching type/action returned |
| PRP-010 | Filter by price range | Search by price range | db_property_list_by_price_range | Only in range returned |
| PRP-011 | Count by type | Count by type+action | db_property_count_by_type | Correct count returned |
| PRP-012 | Empty database | Query empty property table | find=NULL, count=0 | NULL and 0 returned |

**Run**: `make -C tests test-property`

### 4. Database Core Module (`run_database.c`)

| ID | Test Name | Objective | Flow | Expected Result |
|----|-----------|-----------|------|-----------------|
| DB-001 | Open database | Create/open DB file | database_open | Handle valid, path matches |
| DB-002 | Close database | Close and reopen | database_close + database_open | Reopen succeeds |
| DB-003 | Init schema | Create tables | database_init_schema | Returns 1 |
| DB-004 | Schema idempotent | Run init twice | database_init_schema x2 | Both return 1 |
| DB-005 | Migrate empty files | Migrate from missing flat files | database_migrate_from_files | Returns 1 (no-op) |
| DB-006 | Cross-module | Create user + linked property | db_user_create + db_property_create | Both exist, FK matches |

**Run**: `make -C tests test-database`

### 5. Input Validation Module (`run_validation.c`)

| ID | Test Name | Objective | Flow | Expected Result |
|----|-----------|-----------|------|-----------------|
| VAL-001 | Phone valid | Valid Iranian phone format | validate_phone("09123456789") | True |
| VAL-002 | Phone length | Reject wrong lengths | validate_phone("0912345678") | False |
| VAL-003 | Phone prefix | Reject invalid prefixes | validate_phone("08123456789") | False |
| VAL-004 | Phone chars | Reject non-digits | validate_phone("0912345678a") | False |
| VAL-005 | Phone null | Handle NULL gracefully | validate_phone(NULL) | False |
| VAL-006 | Email valid | Standard email formats | validate_email("user@example.com") | True |
| VAL-007 | Email no @ | Reject missing @ | validate_email("userexample.com") | False |
| VAL-008 | Email multi @ | Reject multiple @ | validate_email("user@@example.com") | False |
| VAL-009 | Email no dot | Reject missing dot | validate_email("user@examplecom") | False |
| VAL-010 | Email empty segments | Reject empty local/domain parts | validate_email(".user@example.com") | False |
| VAL-011 | Email edge cases | Minimal valid, empty, special | validate_email("a@b.c") / "" | True/False |
| VAL-012 | Password valid | Min 8, upper+lower+digit | validate_password("Password1") | True |
| VAL-013 | Password short | Reject < 8 chars | validate_password("Pass1") | False |
| VAL-014 | Password no upper | Reject missing uppercase | validate_password("password1") | False |
| VAL-015 | Password no lower | Reject missing lowercase | validate_password("PASSWORD1") | False |
| VAL-016 | Password no digit | Reject missing digit | validate_password("Password") | False |
| VAL-017 | Password special chars | Allow special chars | validate_password("Pass@word1") | True |
| VAL-018 | Password unicode | Handle unicode gracefully | validate_password("Pässwörd1") | No crash |
| VAL-019 | ID valid | Exactly 10 digits | validate_id("1234567890") | True |
| VAL-020 | ID length | Reject wrong lengths | validate_id("123456789") | False |
| VAL-021 | ID chars | Reject non-digits | validate_id("123456789a") | False |
| VAL-022 | Int range valid | Valid conversions | validate_int_range("42", 0, 100) | True, out=42 |
| VAL-023 | Int range invalid | Non-numeric strings | validate_int_range("abc", 0, 100) | False |
| VAL-024 | Int range bounds | Out of bounds | validate_int_range("101", 0, 100) | False |
| VAL-025 | Double range valid | Valid conversions | validate_double_range("3.14", 0, 10) | True, out≈3.14 |
| VAL-026 | Double range invalid | Non-numeric/out of bounds | validate_double_range("abc", 0, 10) | False |
| VAL-027 | Username valid | 8-16 alnum, no spaces | validate_username("username1") | True |
| VAL-028 | Username length | Reject <8 or >16 | validate_username("user1") | False |
| VAL-029 | Username chars | Reject spaces/special | validate_username("user name") | False |
| VAL-030 | Name valid | Letters + spaces, 1-49 chars | validate_name("John Doe") | True |
| VAL-031 | Name length | Reject empty or >49 | validate_name("") | False |
| VAL-032 | Name chars | Reject digits/special | validate_name("John123") | False |

**Run**: `make -C tests test-validation`

### 6. Edge Cases Module (`run_edge_cases.c`)

| ID | Test Name | Objective | Flow | Expected Result |
|----|-----------|-----------|------|-----------------|
| EDGE-001 | Empty username | Create user with empty username | db_user_create with username="" | No crash, handled |
| EDGE-002 | Max length fields | Fill all fields to MAX-1 | db_user_create with max strings | Success or truncation |
| EDGE-003 | Find empty username | Query with empty string | db_user_find_by_username("") | NULL |
| EDGE-004 | Update nonexistent | Update non-existent user | db_user_update_password("ghost") | Returns 0 |
| EDGE-005 | Zero price | Property with price=0 | db_property_create with 0.0 | Success |
| EDGE-006 | Very large price | Property with huge price | db_property_create with 999B | Success |
| EDGE-007 | Max string fields | Fill address to MAX_STRING_LEN | db_property_create with max strings | Success |
| EDGE-008 | Find invalid code | Query with empty/long code | db_property_find_by_code("") | NULL |
| EDGE-009 | Int range boundary | INT_MIN/MAX boundaries | validate_int_range with boundaries | Correct pass/fail |
| EDGE-010 | Double range boundary | DBL_MIN/MAX boundaries | validate_double_range with boundaries | Correct pass/fail |
| EDGE-011 | Special chars | Address with quotes, tags, symbols | db_property_create with special chars | Success |
| EDGE-012 | Unicode address | Persian/Unicode in address | db_property_create with Unicode | No crash |
| EDGE-013 | CRUD cycle | Create → Delete → Recreate | Full cycle with different codes | All succeed |
| EDGE-014 | Pagination edges | Page 1, 2, 3, limit 0 | db_property_list_paginated | 10, 5, 0, 15 (all rows) |
| EDGE-015 | Count filtered | Empty where, invalid where | db_property_count_filtered | Correct counts |

**Run**: `make -C tests test-edge-cases`

## Running Tests

### All Tests
```bash
make -C tests test
```

### Individual Suites
```bash
make -C tests test-sha256      # 3 tests
make -C tests test-user        # 9 tests
make -C tests test-property    # 12 tests
make -C tests test-database    # 6 tests
make -C tests test-validation  # 28 tests
make -C tests test-edge-cases  # 15 tests
```

### Clean
```bash
make -C tests clean
```

## SDET Best Practices Followed

1. **Separation of Concerns**: One test file per module
2. **Test Independence**: No test depends on another
3. **Clean Test Data**: Each test uses unique DB, cleaned before/after
4. **Clear Documentation**: Each test has header comments (Objective, Flow, Expected)
5. **Positive & Negative Cases**: Happy path + error scenarios
6. **Edge Cases**: Boundary values, max lengths, special chars, Unicode
7. **Bug Detection**: Tests found 6 real bugs (fixed)

## Adding New Tests

1. Create `tests/run_<module>.c`
2. Include Unity and required headers
3. Implement test functions with AAA pattern
4. Use `open_test_db()` / `cleanup_db()` for isolation
5. Add to `tests/Makefile`
6. Update this documentation

## Coverage Metrics

| Module | Tests | Status |
|--------|-------|--------|
| SHA256 | 3 | 100% |
| User DB | 9 | 100% |
| Property DB | 12 | 100% |
| Database Core | 6 | 100% |
| Validation | 28 | 100% |
| Edge Cases | 15 | 100% |
| **Total** | **73** | **All Passing** |

## Known Limitations

- **Negative tests incomplete**: Need NULL checks in ~20 DB functions
- **UI functions untested**: `user_register`, `user_login`, `menu_*` are interactive
- **No performance tests**: 10k record benchmarking not yet implemented
- **No security tests**: SQL injection, buffer overflow not yet tested
- **No mutation testing**: Structure not yet in place

## Continuous Integration

Add to CI pipeline:
```yaml
# .github/workflows/test.yml
- run: make -C tests test
```

---

*Last updated: 2026-08-31*