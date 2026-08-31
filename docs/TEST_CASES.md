# Property Management System - Test Cases Quick Reference

## Test Suite Summary

| Suite | File | Tests | Run Command |
|-------|------|-------|-------------|
| SHA256 | run_sha256.c | 3 | `make test-sha256` |
| User DB | run_user.c | 9 | `make test-user` |
| Property DB | run_property.c | 12 | `make test-property` |
| Database Core | run_database.c | 6 | `make test-database` |
| Validation | run_validation.c | 28 | `make test-validation` |
| Edge Cases | run_edge_cases.c | 15 | `make test-edge-cases` |
| **Total** | | **73** | `make test` |

---

## SHA256 (3 tests)

| ID | Test | Description | Expected |
|----|------|-------------|----------|
| SHA-001 | Hash computation | Hash "test_password" | 32-byte digest |
| SHA-002 | Determinism | Hash same input twice | Identical hashes |
| SHA-003 | Uniqueness | Hash different inputs | Different hashes |

---

## User DB (9 tests)

| ID | Test | Description | Expected |
|----|------|-------------|----------|
| USR-001 | Create user | Insert valid user | Returns 1 |
| USR-002 | Duplicate user | Insert same username | Returns 0 |
| USR-003 | Find by username | Locate existing user | Returns User* |
| USR-004 | Find nonexistent | Query ghost user | Returns NULL |
| USR-005 | Update password | Change hash + salt | Updated fields |
| USR-006 | Update field | Change single field | Targeted update |
| USR-007 | List all users | Retrieve all | Correct count |
| USR-008 | Count users | Get total count | Correct count |
| USR-009 | Empty database | Query empty DB | NULL, count=0 |

---

## Property DB (12 tests)

| ID | Test | Description | Expected |
|----|------|-------------|----------|
| PRP-001 | Create residential sell | Insert property | Returns 1 |
| PRP-002 | Duplicate code | Insert same code | Returns 0 |
| PRP-003 | Find by code | Locate by code | Returns Property* |
| PRP-004 | Find nonexistent | Query missing | Returns NULL |
| PRP-005 | Delete success | Soft-delete property | Returns 1, find=NULL |
| PRP-006 | Delete nonexistent | Delete ghost | Returns 0 |
| PRP-007 | List all | List all properties | Correct count |
| PRP-008 | Filter by district | Search by district | Matching only |
| PRP-009 | Filter by type | Search by type+action | Matching only |
| PRP-010 | Filter by price | Search by price range | In range only |
| PRP-011 | Count by type | Count type+action | Correct count |
| PRP-012 | Empty database | Query empty table | NULL, count=0 |

---

## Database Core (6 tests)

| ID | Test | Description | Expected |
|----|------|-------------|----------|
| DB-001 | Open database | Create/open DB | Valid handle |
| DB-002 | Close/reopen | Close then reopen | Works both times |
| DB-003 | Init schema | Create tables | Returns 1 |
| DB-004 | Schema idempotent | Run twice | Both succeed |
| DB-005 | Migrate empty | Migrate missing files | Returns 1 |
| DB-006 | Cross-module | User + property FK | Both exist, linked |

---

## Validation (28 tests)

| Category | Tests | IDs |
|----------|-------|-----|
| Phone | 5 | VAL-001 to VAL-005 |
| Email | 6 | VAL-006 to VAL-011 |
| Password | 7 | VAL-012 to VAL-018 |
| National ID | 3 | VAL-019 to VAL-021 |
| Int Range | 3 | VAL-022 to VAL-024 |
| Double Range | 3 | VAL-025 to VAL-026 |
| Username | 3 | VAL-027 to VAL-029 |
| Name | 3 | VAL-030 to VAL-032 |

---

## Edge Cases (15 tests)

| ID | Test | Description |
|----|------|-------------|
| EDGE-001 | Empty username | Create with username="" |
| EDGE-002 | Max length fields | All fields at MAX-1 |
| EDGE-003 | Find empty username | Query with "" |
| EDGE-004 | Update nonexistent | Update ghost user |
| EDGE-005 | Zero price | Property price=0 |
| EDGE-006 | Very large price | Price=999B |
| EDGE-007 | Max string fields | Address at MAX_STRING_LEN |
| EDGE-008 | Find invalid code | Query with ""/long code |
| EDGE-009 | Int range boundary | INT_MIN/MAX |
| EDGE-010 | Double range boundary | DBL_MIN/MAX |
| EDGE-011 | Special chars | Quotes, tags, symbols in address |
| EDGE-012 | Unicode address | Persian text in address |
| EDGE-013 | CRUD cycle | Create→Delete→Recreate |
| EDGE-014 | Pagination edges | Pages 1,2,3, limit 0 |
| EDGE-015 | Count filtered | Empty/invalid WHERE |

---

## Running Commands

```bash
# All tests
make -C tests test

# Individual
make -C tests test-sha256      # 3
make -C tests test-user        # 9
make -C tests test-property    # 12
make -C tests test-database    # 6
make -C tests test-validation  # 28
make -C tests test-edge-cases  # 15

# Clean
make -C tests clean
```

---

## Bugs Found by Tests

| Bug | Found By | Fixed |
|-----|----------|-------|
| INSERT: 29 cols vs 30 ? | Property tests | ✅ |
| Delete false positive | Property tests | ✅ |
| db_user_count(NULL) crash | Negative tests | ✅ |
| validate_int_range overflow | Edge cases | ✅ |
| Pagination limit 0 logic | Edge cases | ✅ |
| WAL/SHM cleanup | Edge cases | ✅ |

---

## Adding Tests

1. Create `tests/run_<module>.c`
2. Follow AAA pattern (Arrange, Act, Assert)
3. Use `open_test_db()` / `cleanup_db()`
3. Add to `tests/Makefile`
4. Update `docs/TEST_DOCUMENTATION.md`