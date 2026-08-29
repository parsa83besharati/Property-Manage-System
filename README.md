# Property Management System

A console-based property management application written in C, featuring user authentication, property listings (sell/rent), and administrative tools.

## Features

- **User Authentication**: Secure registration and login with SHA-256 password hashing and salt
- **Property Management**: Add, delete, and search properties
- **Property Types**: Residential (Apartment/Villa), Commercial (Official/Position), Land (Farm/City)
- **Transaction Types**: Sell and Rent
- **Search & Reports**: Filter by district, location, price range, property type
- **Admin Panel**: View all users, manage all properties, system statistics
- **Profile Management**: Edit personal info, change password
- **Data Persistence**: File-based storage with structured format

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
    src/main.c src/utils/common.c src/utils/sha256.c \
    src/modules/user.c src/modules/property.c src/modules/menu.c
```

### Running

```bash
./property_manage.exe
```

On Windows, you can also double-click the executable.

## Usage

### First Run
1. Select **Sign Up** to create an account
2. Enter required information (username, name, ID, phone, email, password)
3. Login with your credentials

### Main Menu Options
1. **Add Property** - Register a new property for sale or rent
2. **Delete Property** - Remove your own property listings
3. **Reports** - View properties with various filters
4. **User Settings** - Edit profile, change password
5. **Logout** - Return to entry menu

### Property Entry
When adding a property, you'll be prompted for:
- **Code**: Unique identifier
- **District**: 1-30
- **Address**: Free text
- **Location**: North/South/East/West
- **Category**: Residential/Commercial/Land
- **Sub-type**: Apartment/Villa, Official/Position, Farm/City
- **Transaction**: Sell or Rent
- **Physical details**: Build age, floor area, land area, floor, etc.
- **Features**: Elevator, basement, balcony, parking, phones
- **Temperature preference**: Cold/Hot/Medium
- **Pricing**: Sell price OR base price + monthly rent

### Reports
- List all properties
- Filter by type (Sell/Rent × Residential/Commercial/Land)
- Filter by district (1-30)
- Filter by location (N/S/E/W)
- Filter by price range
- View property counters

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
│   │   └── menu.h             # Menu system API
│   ├── utils/                 # Utility implementations
│   │   ├── common.c           # Input validation, string utils, date/time
│   │   └── sha256.c           # SHA-256 implementation
│   └── modules/               # Core business logic
│       ├── user.c             # Registration, login, profile management
│       ├── property.c         # Property CRUD, search, reporting
│       └── menu.c             # Menu navigation and flow
├── data/                      # Runtime data (created automatically)
│   ├── users.dat              # User accounts
│   └── properties.dat         # Property listings
├── Makefile                   # Build configuration
└── README.md                  # This file
```

## Data Format

### Users (`data/users.dat`)
Pipe-delimited format:
```
username|first_name|last_name|id|phone|email|password_hash|salt
```

### Properties (`data/properties.dat`)
Pipe-delimited format with all property fields:
```
code|district|address|location|type|action|subtype|build_age|floor_area|floor|land_area|owner_phone|bedrooms|rooms|tax_rate|elevator|basement|basement_area|balcony|balcony_area|parkings|phones|temperature|sell_price|base_price|monthly_price|date|username|active
```

## Security Notes

- Passwords are hashed with SHA-256 using a unique 16-character salt per user
- Salts are stored alongside hashes in the user database
- Login includes a simple math captcha to prevent automated attempts
- No plaintext passwords are ever stored

## Architecture Highlights

### Unified Property Model
Instead of 6 separate structs for each property type/action combination, a single `Property` struct uses:
- `PropertyType` enum (Residential/Commercial/Land)
- `PropertyAction` enum (Sell/Rent)
- `subtype` union for type-specific fields
- Optional fields set to 0/NULL when not applicable

### Modular Design
- Clear separation: User management, Property management, UI/Menu
- Header/implementation separation for each module
- Easy to extend with new property types or features

### Memory Safety
- No `gets()` or other unsafe functions
- Dynamic arrays with capacity tracking
- Proper cleanup on exit

## Development

### Code Style
- C11 standard
- `-Wall -Wextra` clean
- Consistent naming: `snake_case` for functions/variables, `PascalCase` for types

### Adding Features
1. Define types in appropriate header
2. Implement in corresponding `.c` file
3. Add menu entries in `menu.c`
4. Update serialization if data model changes

## License

This project is open source. Feel free to use and modify.

## Troubleshooting

### "gcc not found"
Install MinGW-w64 on Windows, or use WSL with `sudo apt install build-essential`

### Data files not creating
Ensure write permissions in the application directory. The `data/` folder is created automatically on first run.

### Compilation errors
- Ensure all source files are in the correct locations per the project structure
- Check that `src/include/` headers are accessible
- Verify C11 support: `gcc --version` should be 5+

### Runtime issues
- Delete `data/` folder to reset to clean state
- Check console output for error messages