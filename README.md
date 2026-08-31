# Property Management System

A console-based property management application written in C, featuring user authentication, property listings (sell/rent), SQLite database backend, modern terminal UI, and comprehensive test suite.

## Features

- **User Authentication**: Secure registration and login with SHA-256 password hashing and salt
- **Property Management**: Add, delete, and search properties with modern UI
- **Property Types**: Residential (Apartment/Villa), Commercial (Official/Position), Land (Farm/City)
- **Transaction Types**: Sell and Rent
- **Advanced Search & Reports**: Filter by district, location, price range, property type with pagination
- **Admin Panel**: View all users, manage all properties, system statistics
- **Profile Management**: Edit personal info, change password
- **Modern Terminal UI**: Color-coded styles, box drawing, forms with validation, spinners, progress bars, tables
- **SQLite Database**: WAL mode, foreign keys, migrations from flat files
- **Comprehensive Test Suite**: 73+ unit tests following SDET best practices

## Quick Start

### Prerequisites

- GCC compiler (MinGW on Windows, or GCC/Clang on Linux/macOS)
- Make (optional, for Makefile)

### Building

```bash
# Using Makefile
make

# Or manually with GCC
gcc -Wall -Wextra -std=c11 -Isrc/include -o property_manage.exe \
    src/main.c src/utils/common.c src/utils/sha256.c src/utils/ui.c src/utils/sqlite3.c \
    src/modules/user.c src/modules/property.c src/modules/menu.c src/modules/database.c
```

### Running

```bash
./property_manage.exe
```

On Windows, you can also double-click the executable.

## Running Tests

### All Tests (73+ tests)
```bash
# From project root
make -C tests test

# Or from tests directory
cd tests && make test
```

### Individual Module Tests
```bash
# SHA256 tests (3 tests)
make -C tests test-sha256

# User DB tests (9 tests)
make -C tests test-user

# Property DB tests (12 tests)
make -C tests test-property

# Database Core tests (6 tests)
make -C tests test-database

# Validation tests (28 tests)
make -C tests test-validation

# Edge case tests (15 tests)
make -C tests test-edge-cases
```

### Clean Test Artifacts
```bash
make -C tests clean
```

## Usage

### First Run
1. Select **Sign Up** to create an account
2. Enter required information (username, name, ID, phone, email, password)
3. Login with your credentials

### Main Menu Options
1. **Add Property** - Register a new property for sale or rent
2. **Delete Property** - Remove your own property listings
3. **Search Properties** - Advanced search with filters + pagination
4. **User Settings** - Edit profile, change password
5. **Logout** - Return to entry menu

### Admin Access
Login with username `Admin` and password `Admin1234` to access:
- View all registered users
- View all properties (including inactive)
- Delete any property
- System statistics

## Project Structure

```
Property-Manage-System/
├── src/
│   ├── main.c                 # Application entry point
│   ├── include/               # Public APIs
│   │   ├── common.h           # Shared types, constants, utilities
│   │   ├── sha256.h           # Password hashing interface
│   │   ├── user.h             # User management API
│   │   ├── property.h         # Property management API
│   │   ├── menu.h             # Menu system API
│   │   ├── database.h         # SQLite database API
│   │   └── ui.h               # Terminal UI components
│   ├── utils/                 # Utility implementations
│   │   ├── common.c           # Input validation, string utils, date/time
│   │   ├── sha256.c           # SHA-256 implementation
│   │   ├── ui.c               # Terminal UI (colors, boxes, forms, tables)
│   │   └── sqlite3.c          # SQLite amalgamation
│   └── modules/               # Core business logic
│       ├── user.c             # Registration, login, profile management
│       ├── property.c         # Property input/validation
│       ├── menu.c             # Menu navigation, search, admin
│       └── database.c         # SQLite CRUD, migrations
├── tests/                      # Unit test suite
│   ├── run_sha256.c           # SHA256 hash tests (3)
│   ├── run_user.c             # User DB tests (9)
│   ├── run_property.c         # Property DB tests (12)
│   ├── run_database.c         # Database core tests (6)
│   ├── run_validation.c       # Input validation tests (28)
│   ├── run_edge_cases.c       # Edge case tests (15)
│   ├── run_negative.c         # Negative/error tests (WIP)
│   ├── unity.c/.h             # Unity test framework
│   └── Makefile               # Test build targets
├── docs/                       # Documentation
│   ├── TEST_DOCUMENTATION.md  # Complete test case documentation
│   └── TEST_CASES.md          # Test case reference
├── data/                       # Runtime data (created automatically)
│   ├── property_manage.db     # SQLite database
│   └── *.dat                  # Legacy flat files (migrated)
├── Makefile                    # Build configuration
└── README.md                   # This file
```

## Test Suite Overview (73+ Tests)

| Suite | Tests | Status |
|-------|-------|--------|
| SHA256 Hash | 3 | ✅ PASS |
| User DB CRUD | 9 | ✅ PASS |
| Property DB CRUD | 12 | ✅ PASS |
| Database Core | 6 | ✅ PASS |
| Input Validation | 28 | ✅ PASS |
| Edge Cases | 15 | ✅ PASS |
| Negative/Error | Partial | ⚠️ Exposing bugs |

### Bugs Found by Tests:
1. **INSERT SQL mismatch** - 29 columns vs 30 placeholders (fixed)
2. **Delete false positive** - Returned success when 0 rows affected (fixed)
3. **Missing NULL checks** - `db_user_count(NULL)` crashed (fixed)
4. **Validate overflow** - `validate_int_range` didn't check `errno` (fixed)
5. **Pagination logic** - Test expectations wrong for limit 0 (fixed)
6. **DB cleanup** - WAL/SHM files persisted between tests (fixed)

## Documentation

- [Test Documentation](docs/TEST_DOCUMENTATION.md) - Complete test case details with objectives, flows, and requirements
- [Test Cases Reference](docs/TEST_CASES.md) - Quick reference table format

## Data Format

### SQLite Database (`data/property_manage.db`)
- **users** table: username (PK), first_name, last_name, id, phone, email, password_hash, salt, created_at
- **properties** table: code (PK), district, address, location, ptype, action, subtype, ... active, created_at
- Foreign key: properties.username → users.username

### Legacy Flat Files (migrated)
- `users.dat` - Pipe-delimited user records
- `properties.dat` - Pipe-delimited property records

## Security Notes

- Passwords hashed with SHA-256 + unique 16-char salt per user
- Salts stored alongside hashes
- No plaintext passwords ever stored
- Foreign key constraints enforce data integrity
- WAL mode for better concurrency

## Architecture Highlights

### Unified Property Model
Single `Property` struct with enums for type/action:
- `PropertyType`: Residential/Commercial/Land
- `PropertyAction`: Sell/Rent
- `subtype` union for type-specific fields
- Optional fields set to 0/NULL when not applicable

### Modular Design
- Clear separation: User, Property, Menu, Database, UI
- Header/implementation separation
- SQLite abstraction layer

### Memory Safety
- No `gets()` or unsafe functions
- Dynamic arrays with capacity tracking
- Proper cleanup on exit

## Development

### Code Style
- C11 standard
- `-Wall -Wextra` clean
- Consistent naming: `snake_case` functions/variables, `PascalCase` types

### Adding Features
1. Define types in appropriate header
2. Implement in corresponding `.c` file
3. Add menu entries in `menu.c`
4. Write tests in `tests/`
5. Update documentation in `docs/`

### Adding Tests
1. Create `tests/run_<module>.c` with Unity framework
2. Include test in `tests/Makefile`
3. Follow AAA pattern (Arrange, Act, Assert)
4. Use `open_test_db()` / `cleanup_db()` for isolation
5. Update `docs/TEST_DOCUMENTATION.md`

## License

Open source. Feel free to use and modify.

## Troubleshooting

### "gcc not found"
Install MinGW-w64 on Windows, or use WSL with `sudo apt install build-essential`

### Compilation errors
- Ensure all source files are in correct locations
- Check that `src/include/` headers are accessible
- Verify C11 support: `gcc --version` should be 5+

### Runtime issues
- Delete `data/` folder to reset to clean state
- Check console output for error messages
- Ensure write permissions in application directory