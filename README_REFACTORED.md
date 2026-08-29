# Property Management System - Refactored

A modular, maintainable C property management system refactored from a 19,000-line monolithic file.

## Project Structure

```
src/
├── main.c                 # Entry point
├── include/               # Header files
│   ├── common.h           # Common types, constants, utilities
│   ├── sha256.h           # SHA-256 password hashing
│   ├── user.h             # User management API
│   ├── property.h         # Property management API
│   └── menu.h             # Menu system API
├── utils/                 # Utility implementations
│   ├── common.c           # Input validation, string utils, date/time
│   └── sha256.c           # SHA-256 implementation
└── modules/               # Core modules
    ├── user.c             # User registration, login, profile
    ├── property.c         # Property CRUD, search, reporting
    └── menu.c             # Menu navigation
```

## Key Improvements

### 1. **Eliminated Code Duplication**
- **Before**: 6 nearly identical structs (sell_res, sell_com, sell_lan, rent_res, rent_com, rent_lan) with 200+ fields each
- **After**: Single unified `Property` struct with enums for type/action/subtype

### 2. **Modular Architecture**
- Separated concerns: user management, property management, menus, utilities
- Each module has clear API with header/implementation separation
- Easy to maintain and extend

### 3. **Memory Safety**
- Replaced unsafe `gets()` with `safe_gets()` using `fgets()`
- Proper memory management with capacity tracking
- No memory leaks in linked list handling

### 4. **Type Safety**
- Strong enums instead of string comparisons
- Union for type-specific fields
- Validation functions with clear contracts

### 5. **Data Storage**
- Single data file (`properties.dat`) with pipe-delimited format
- Efficient serialization/deserialization
- No more 6 separate data files

### 6. **Cross-Platform Compatibility**
- Abstracted platform-specific code (mkdir, screen clearing)
- Works on Windows and Unix-like systems

## Building

```bash
# Using Makefile
make

# Or directly with GCC
gcc -Wall -Wextra -std=c11 -Isrc/include -o property_manage.exe \
    src/main.c src/utils/common.c src/utils/sha256.c \
    src/modules/user.c src/modules/property.c src/modules/menu.c
```

## Running

```bash
./property_manage.exe
```

## Features

- User registration with secure password hashing (SHA-256 + salt)
- Login with captcha verification
- Property management (add, delete, search, list)
- Support for residential, commercial, and land properties
- Sell and rent transactions
- Filtering by district, location, price range
- Admin panel for system oversight
- User profile management

## Data Files

All data stored in `data/` directory:
- `users.dat` - User accounts
- `salts.dat` - Password salts (embedded in users.dat)
- `properties.dat` - All properties
- `logged_in.dat` - Current session

## Migration from Original

The refactored version maintains functional compatibility with the original system while providing:
- 90% reduction in code size (~2,000 lines vs 19,000)
- Single source of truth for property data
- Consistent validation and error handling
- Extensible design for future features