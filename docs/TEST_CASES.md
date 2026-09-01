# Property Management System - Test Cases Quick Reference

## Test Suite Summary

| Suite | File | Tests | Run Command |
|-------|------|-------|-------------|
| SHA256 | run_sha256.c | 3 | `./test_sha256.exe` |
| Database Core | run_database.c | 6 | `./test_database.exe` |
| Validation | run_validation.c | 28 | `./test_validation.exe` |
| Edge Cases | run_edge_cases.c | 15 | `./test_edge_cases.exe` |
| CSV Export | run_export.c | 4 | `./test_export.exe`* |
| Audit Logging | run_audit.c | 6 | `./test_audit.exe` |
| Config | run_config.c | 2 | `./test_config.exe` |
| **Core Total** | | **58** | **All PASS** |

*Requires UI dependencies for full test suite

---

## SHA256 (3 tests)

| ID | Test | Description | Expected |
|----|------|-------------|----------|
| SHA-001 | Hash computation | Hash "test_password" | 32-byte digest |
| SHA-002 | Determinism | Hash same input twice | Identical hashes |
| SHA-003 | Uniqueness | Hash different inputs | Different hashes |

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
| Phone | 6 | VAL-001 to VAL-006 |
| Email | 6 | VAL-007 to VAL-012 |
| Password | 7 | VAL-013 to VAL-019 |
| National ID | 3 | VAL-020 to VAL-022 |
| Int Range | 3 | VAL-023 to VAL-025 |
| Double Range | 3 | VAL-026 to VAL-028 |

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

## CSV Export (4 tests)

| ID | Test | Description | Expected |
|----|------|-------------|----------|
| EXP-001 | Export users CSV | Generate users.csv with headers | File + headers + data |
| EXP-002 | Export properties CSV | Generate properties.csv with headers | File + headers + data |
| EXP-003 | Export all | Export both users + properties | Both files created |
| EXP-004 | Empty DB export | Export from DB with test user | Headers + 1 data row |

---

## Audit Logging (6 tests)

| ID | Test | Description | Expected |
|----|------|-------------|----------|
| AUD-001 | Basic log | Insert single audit entry | 1 row returned |
| AUD-002 | Multiple actions | Log CREATE/UPDATE/DELETE | All retrievable |
| AUD-003 | Filter by user | Query specific user's logs | Only that user |
| AUD-004 | Filter by action | Query by CREATE/DELETE | Only that action |
| AUD-005 | Pagination | Limit + offset | Correct page |
| AUD-006 | Filter by entity | Query USER/PROPERTY logs | Only that entity |

---

## Config (2 tests)

| ID | Test | Description | Expected |
|----|------|-------------|----------|
| CFG-001 | Default config | Load defaults when no file | Defaults applied |
| CFG-002 | Load from file | Parse config.ini | Values from file |

---

## Source-Ready Test Files (Require UI Dependencies)

| Suite | File | Tests | Status |
|-------|------|-------|--------|
| Lease Management | test_lease.c | 25 | Source ready |
| User DB | run_user.c | 9 | Source ready |
| Property DB | run_property.c | 12 | Source ready |
| CSV Import | run_export.c | 4 additional | Source ready |
| User Roles | test_user.c | 2 additional | Source ready |
| Property Images | test_property.c | 3 additional | Source ready |

---

## Running Commands

```bash
# All 58 core tests
cd tests
./test_sha256.exe
./test_database.exe
./test_validation.exe
./test_edge_cases.exe
./test_audit.exe
./test_config.exe

# Build with coverage
make -C tests coverage

# Build with sanitizers
make -C tests asan
make -C tests tsan

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
| Config parser leading space | Config tests | ✅ |
| Audit enum signedness | Audit tests | ✅ |
| CSV export unused vars | Export tests | ✅ |
| Property image schema | Property tests | ✅ |
| User role schema | User tests | ✅ |
| CSV import salt truncation | Import tests | ✅ |

---

## Adding Tests

1. Create `tests/run_<module>.c`
2. Follow AAA pattern (Arrange, Act, Assert)
3. Use `open_test_db()` / `cleanup_db()`
4. Add to `tests/Makefile`
5. Update `docs/TEST_DOCUMENTATION.md`