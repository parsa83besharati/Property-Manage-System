#include "database.h"
#include "sha256.h"
#include "audit.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const char *SCHEMA_SQL = 
    "CREATE TABLE IF NOT EXISTS users ("
    "    username TEXT PRIMARY KEY,"
    "    first_name TEXT NOT NULL,"
    "    last_name TEXT NOT NULL,"
    "    id TEXT NOT NULL,"
    "    phone TEXT NOT NULL,"
    "    email TEXT NOT NULL,"
    "    password_hash TEXT NOT NULL,"
    "    salt TEXT NOT NULL,"
    "    role INTEGER DEFAULT 0,"
    "    created_at DATETIME DEFAULT CURRENT_TIMESTAMP"
    ");"
    "CREATE TABLE IF NOT EXISTS properties ("
    "    code TEXT PRIMARY KEY,"
    "    district INTEGER NOT NULL,"
    "    address TEXT NOT NULL,"
    "    location INTEGER NOT NULL,"
    "    ptype INTEGER NOT NULL,"
    "    action INTEGER NOT NULL,"
    "    subtype INTEGER NOT NULL,"
    "    build_age INTEGER DEFAULT 0,"
    "    floor_area REAL DEFAULT 0,"
    "    floor INTEGER DEFAULT 0,"
    "    land_area REAL DEFAULT 0,"
    "    owner_phone TEXT NOT NULL,"
    "    bedrooms INTEGER DEFAULT 0,"
    "    rooms INTEGER DEFAULT 0,"
    "    tax_rate REAL DEFAULT 0,"
    "    elevator INTEGER DEFAULT 0,"
    "    basement INTEGER DEFAULT 0,"
    "    basement_area REAL DEFAULT 0,"
    "    balcony INTEGER DEFAULT 0,"
    "    balcony_area REAL DEFAULT 0,"
    "    parkings INTEGER DEFAULT 0,"
    "    phones INTEGER DEFAULT 0,"
    "    temperature INTEGER DEFAULT 0,"
    "    sell_price REAL DEFAULT 0,"
    "    base_price REAL DEFAULT 0,"
    "    monthly_price REAL DEFAULT 0,"
    "    date TEXT NOT NULL,"
    "    image_path TEXT DEFAULT '',"
    "    username TEXT NOT NULL,"
    "    active INTEGER DEFAULT 1,"
    "    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,"
    "    FOREIGN KEY (username) REFERENCES users(username)"
    ");"
    "CREATE TABLE IF NOT EXISTS leases ("
    "    id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "    property_code TEXT NOT NULL,"
    "    tenant_username TEXT NOT NULL,"
    "    start_date TEXT NOT NULL,"
    "    end_date TEXT NOT NULL,"
    "    monthly_rent REAL NOT NULL,"
    "    deposit REAL NOT NULL,"
    "    payment_day INTEGER NOT NULL,"
    "    status INTEGER DEFAULT 0,"
    "    auto_renew INTEGER DEFAULT 0,"
    "    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,"
    "    FOREIGN KEY (property_code) REFERENCES properties(code),"
    "    FOREIGN KEY (tenant_username) REFERENCES users(username)"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_properties_type_action ON properties(ptype, action);"
    "CREATE INDEX IF NOT EXISTS idx_properties_district ON properties(district);"
    "CREATE INDEX IF NOT EXISTS idx_properties_location ON properties(location);"
    "CREATE INDEX IF NOT EXISTS idx_properties_username ON properties(username);"
    "CREATE INDEX IF NOT EXISTS idx_properties_active ON properties(active);"
    "CREATE INDEX IF NOT EXISTS idx_leases_tenant ON leases(tenant_username);"
    "CREATE INDEX IF NOT EXISTS idx_leases_property ON leases(property_code);"
    "CREATE INDEX IF NOT EXISTS idx_leases_status ON leases(status);"
    "CREATE INDEX IF NOT EXISTS idx_leases_dates ON leases(start_date, end_date);";

Database *database_open(const char *path) {
    Database *db = malloc(sizeof(Database));
    if (!db) return NULL;
    
    strncpy(db->db_path, path, sizeof(db->db_path) - 1);
    db->db_path[sizeof(db->db_path) - 1] = '\0';
    
    int rc = sqlite3_open(path, &db->db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db->db));
        sqlite3_close(db->db);
        free(db);
        return NULL;
    }
    
    sqlite3_exec(db->db, "PRAGMA foreign_keys = ON;", NULL, NULL, NULL);
    sqlite3_exec(db->db, "PRAGMA journal_mode = WAL;", NULL, NULL, NULL);
    
    return db;
}

void database_close(Database *db) {
    if (db) {
        if (db->db) sqlite3_close(db->db);
        free(db);
    }
}

int database_init_schema(Database *db) {
    if (!db) return 0;
    char *err_msg = NULL;
    int rc = sqlite3_exec(db->db, SCHEMA_SQL, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Schema creation failed: %s\n", err_msg);
        sqlite3_free(err_msg);
        return 0;
    }
    if (!audit_log_init_schema(db)) return 0;
    return 1;
}

static int bind_user_stmt(sqlite3_stmt *stmt, const User *user) {
    sqlite3_bind_text(stmt, 1, user->username, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, user->first_name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, user->last_name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, user->id, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, user->phone, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 6, user->email, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 7, user->password_hash, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 8, user->salt, -1, SQLITE_STATIC);
    return SQLITE_OK;
}

static int bind_property_stmt(sqlite3_stmt *stmt, const Property *prop) {
    sqlite3_bind_text(stmt, 1, prop->code, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, prop->district);
    sqlite3_bind_text(stmt, 3, prop->address, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 4, prop->location);
    sqlite3_bind_int(stmt, 5, prop->ptype);
    sqlite3_bind_int(stmt, 6, prop->action);
    sqlite3_bind_int(stmt, 7, prop->subtype.res_type);
    sqlite3_bind_int(stmt, 8, prop->build_age);
    sqlite3_bind_double(stmt, 9, prop->floor_area);
    sqlite3_bind_int(stmt, 10, prop->floor);
    sqlite3_bind_double(stmt, 11, prop->land_area);
    sqlite3_bind_text(stmt, 12, prop->owner_phone, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 13, prop->bedrooms);
    sqlite3_bind_int(stmt, 14, prop->rooms);
    sqlite3_bind_double(stmt, 15, prop->tax_rate);
    sqlite3_bind_int(stmt, 16, prop->elevator);
    sqlite3_bind_int(stmt, 17, prop->basement);
    sqlite3_bind_double(stmt, 18, prop->basement_area);
    sqlite3_bind_int(stmt, 19, prop->balcony);
    sqlite3_bind_double(stmt, 20, prop->balcony_area);
    sqlite3_bind_int(stmt, 21, prop->parkings);
    sqlite3_bind_int(stmt, 22, prop->phones);
    sqlite3_bind_int(stmt, 23, prop->temperature);
    sqlite3_bind_double(stmt, 24, prop->sell_price);
    sqlite3_bind_double(stmt, 25, prop->base_price);
    sqlite3_bind_double(stmt, 26, prop->monthly_price);
    sqlite3_bind_text(stmt, 27, prop->date, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 28, prop->image_path, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 29, prop->username, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 30, prop->active);
    return SQLITE_OK;
}

static void row_to_user(sqlite3_stmt *stmt, User *user) {
    strncpy(user->username, (const char*)sqlite3_column_text(stmt, 0), MAX_FIELD_LEN - 1);
    strncpy(user->first_name, (const char*)sqlite3_column_text(stmt, 1), MAX_FIELD_LEN - 1);
    strncpy(user->last_name, (const char*)sqlite3_column_text(stmt, 2), MAX_FIELD_LEN - 1);
    strncpy(user->id, (const char*)sqlite3_column_text(stmt, 3), MAX_FIELD_LEN - 1);
    strncpy(user->phone, (const char*)sqlite3_column_text(stmt, 4), MAX_FIELD_LEN - 1);
    strncpy(user->email, (const char*)sqlite3_column_text(stmt, 5), MAX_FIELD_LEN - 1);
    strncpy(user->password_hash, (const char*)sqlite3_column_text(stmt, 6), SHA256_DIGEST_LENGTH * 2);
    strncpy(user->salt, (const char*)sqlite3_column_text(stmt, 7), SALT_LENGTH);
    user->role = (UserRole)sqlite3_column_int(stmt, 8);
}

static void row_to_property(sqlite3_stmt *stmt, Property *prop) {
    strncpy(prop->code, (const char*)sqlite3_column_text(stmt, 0), MAX_FIELD_LEN - 1);
    prop->district = sqlite3_column_int(stmt, 1);
    strncpy(prop->address, (const char*)sqlite3_column_text(stmt, 2), MAX_STRING_LEN - 1);
    prop->location = (Location)sqlite3_column_int(stmt, 3);
    prop->ptype = (PropertyType)sqlite3_column_int(stmt, 4);
    prop->action = (PropertyAction)sqlite3_column_int(stmt, 5);
    prop->subtype.res_type = (ResidentialType)sqlite3_column_int(stmt, 6);
    prop->build_age = sqlite3_column_int(stmt, 7);
    prop->floor_area = sqlite3_column_double(stmt, 8);
    prop->floor = sqlite3_column_int(stmt, 9);
    prop->land_area = sqlite3_column_double(stmt, 10);
    strncpy(prop->owner_phone, (const char*)sqlite3_column_text(stmt, 11), MAX_FIELD_LEN - 1);
    prop->bedrooms = sqlite3_column_int(stmt, 12);
    prop->rooms = sqlite3_column_int(stmt, 13);
    prop->tax_rate = sqlite3_column_double(stmt, 14);
    prop->elevator = (YesNo)sqlite3_column_int(stmt, 15);
    prop->basement = (YesNo)sqlite3_column_int(stmt, 16);
    prop->basement_area = sqlite3_column_double(stmt, 17);
    prop->balcony = (YesNo)sqlite3_column_int(stmt, 18);
    prop->balcony_area = sqlite3_column_double(stmt, 19);
    prop->parkings = sqlite3_column_int(stmt, 20);
    prop->phones = sqlite3_column_int(stmt, 21);
    prop->temperature = (Temperature)sqlite3_column_int(stmt, 22);
    prop->sell_price = sqlite3_column_double(stmt, 23);
    prop->base_price = sqlite3_column_double(stmt, 24);
    prop->monthly_price = sqlite3_column_double(stmt, 25);
    strncpy(prop->date, (const char*)sqlite3_column_text(stmt, 26), MAX_FIELD_LEN - 1);
    strncpy(prop->image_path, (const char*)sqlite3_column_text(stmt, 27), MAX_STRING_LEN - 1);
    strncpy(prop->username, (const char*)sqlite3_column_text(stmt, 28), MAX_FIELD_LEN - 1);
    prop->active = sqlite3_column_int(stmt, 29);
}

static void row_to_lease(sqlite3_stmt *stmt, Lease *lease) {
    lease->id = sqlite3_column_int(stmt, 0);
    strncpy(lease->property_code, (const char*)sqlite3_column_text(stmt, 1), MAX_FIELD_LEN - 1);
    strncpy(lease->tenant_username, (const char*)sqlite3_column_text(stmt, 2), MAX_FIELD_LEN - 1);
    strncpy(lease->start_date, (const char*)sqlite3_column_text(stmt, 3), MAX_FIELD_LEN - 1);
    strncpy(lease->end_date, (const char*)sqlite3_column_text(stmt, 4), MAX_FIELD_LEN - 1);
    lease->monthly_rent = sqlite3_column_double(stmt, 5);
    lease->deposit = sqlite3_column_double(stmt, 6);
    lease->payment_day = sqlite3_column_int(stmt, 7);
    lease->status = (LeaseStatus)sqlite3_column_int(stmt, 8);
    lease->auto_renew = sqlite3_column_int(stmt, 9);
    strncpy(lease->created_at, (const char*)sqlite3_column_text(stmt, 10), MAX_FIELD_LEN - 1);
}

int db_user_create(Database *db, const User *user) {
    if (!db || !user) return 0;
    const char *sql = "INSERT INTO users (username, first_name, last_name, id, phone, email, password_hash, salt) "
                      "VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;
    
    bind_user_stmt(stmt, user);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

User *db_user_find_by_username(Database *db, const char *username) {
    if (!db || !username) return NULL;
    const char *sql = "SELECT username, first_name, last_name, id, phone, email, password_hash, salt "
                      "FROM users WHERE username = ?";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return NULL;
    
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    
    User *user = NULL;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        user = malloc(sizeof(User));
        row_to_user(stmt, user);
    }
    sqlite3_finalize(stmt);
    return user;
}

int db_user_update_password(Database *db, const char *username, const char *hash, const char *salt) {
    if (!db || !username || !hash || !salt) return 0;
    const char *sql = "UPDATE users SET password_hash = ?, salt = ? WHERE username = ?";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;
    
    sqlite3_bind_text(stmt, 1, hash, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, salt, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, username, -1, SQLITE_STATIC);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE && sqlite3_changes(db->db) > 0;
}

int db_user_update_field(Database *db, const char *username, int field, const char *value) {
    if (!db || !username || !value) return 0;
    const char *columns[] = {"", "first_name", "last_name", "id", "phone", "email"};
    if (field < 1 || field > 5) return 0;
    
    char sql[256];
    snprintf(sql, sizeof(sql), "UPDATE users SET %s = ? WHERE username = ?", columns[field]);
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;
    
    sqlite3_bind_text(stmt, 1, value, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, username, -1, SQLITE_STATIC);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE && sqlite3_changes(db->db) > 0;
}

int db_user_list_all(Database *db, User **users, int *count) {
    if (!db || !users || !count) return 0;
    const char *sql = "SELECT username, first_name, last_name, id, phone, email, password_hash, salt FROM users";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;
    
    int capacity = 100;
    *users = malloc(capacity * sizeof(User));
    *count = 0;
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (*count >= capacity) {
            capacity *= 2;
            *users = realloc(*users, capacity * sizeof(User));
        }
        row_to_user(stmt, &(*users)[(*count)++]);
    }
    
    sqlite3_finalize(stmt);
    return 1;
}

int db_user_count(Database *db) {
    if (!db) return 0;
    const char *sql = "SELECT COUNT(*) FROM users";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;
    
    int count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return count;
}

int db_user_set_role(Database *db, const char *username, UserRole role) {
    if (!db || !username) return 0;
    const char *sql = "UPDATE users SET role = ? WHERE username = ?";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;
    
    sqlite3_bind_int(stmt, 1, (int)role);
    sqlite3_bind_text(stmt, 2, username, -1, SQLITE_STATIC);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE && sqlite3_changes(db->db) > 0;
}

UserRole db_user_get_role(Database *db, const char *username) {
    if (!db || !username) return ROLE_USER;
    const char *sql = "SELECT role FROM users WHERE username = ?";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return ROLE_USER;
    
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    
    UserRole role = ROLE_USER;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        role = (UserRole)sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return role;
}

// ============================================================================
// LEASE OPERATIONS
// ============================================================================

int db_lease_create(Database *db, const Lease *lease) {
    if (!db || !lease) return 0;
    const char *sql = "INSERT INTO leases (property_code, tenant_username, start_date, end_date, "
                      "monthly_rent, deposit, payment_day, status, auto_renew) "
                      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;
    
    sqlite3_bind_text(stmt, 1, lease->property_code, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, lease->tenant_username, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, lease->start_date, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, lease->end_date, -1, SQLITE_STATIC);
    sqlite3_bind_double(stmt, 5, lease->monthly_rent);
    sqlite3_bind_double(stmt, 6, lease->deposit);
    sqlite3_bind_int(stmt, 7, lease->payment_day);
    sqlite3_bind_int(stmt, 8, lease->status);
    sqlite3_bind_int(stmt, 9, lease->auto_renew);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

Lease *db_lease_find_by_id(Database *db, int id) {
    if (!db) return NULL;
    const char *sql = "SELECT id, property_code, tenant_username, start_date, end_date, "
                      "monthly_rent, deposit, payment_day, status, auto_renew, created_at "
                      "FROM leases WHERE id = ?";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return NULL;
    
    sqlite3_bind_int(stmt, 1, id);
    
    Lease *lease = NULL;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        lease = malloc(sizeof(Lease));
        row_to_lease(stmt, lease);
    }
    sqlite3_finalize(stmt);
    return lease;
}

int db_lease_update(Database *db, const Lease *lease) {
    if (!db || !lease) return 0;
    const char *sql = "UPDATE leases SET property_code = ?, tenant_username = ?, start_date = ?, "
                      "end_date = ?, monthly_rent = ?, deposit = ?, payment_day = ?, "
                      "status = ?, auto_renew = ? WHERE id = ?";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;
    
    sqlite3_bind_text(stmt, 1, lease->property_code, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, lease->tenant_username, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, lease->start_date, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, lease->end_date, -1, SQLITE_STATIC);
    sqlite3_bind_double(stmt, 5, lease->monthly_rent);
    sqlite3_bind_double(stmt, 6, lease->deposit);
    sqlite3_bind_int(stmt, 7, lease->payment_day);
    sqlite3_bind_int(stmt, 8, lease->status);
    sqlite3_bind_int(stmt, 9, lease->auto_renew);
    sqlite3_bind_int(stmt, 10, lease->id);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE && sqlite3_changes(db->db) > 0;
}

int db_lease_delete(Database *db, int id) {
    if (!db) return 0;
    const char *sql = "DELETE FROM leases WHERE id = ?";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;
    
    sqlite3_bind_int(stmt, 1, id);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE && sqlite3_changes(db->db) > 0;
}

int db_lease_list_all(Database *db, Lease **leases, int *count) {
    if (!db || !leases || !count) return 0;
    const char *sql = "SELECT id, property_code, tenant_username, start_date, end_date, "
                      "monthly_rent, deposit, payment_day, status, auto_renew, created_at "
                      "FROM leases ORDER BY id DESC";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;
    
    int capacity = 100;
    *leases = malloc(capacity * sizeof(Lease));
    *count = 0;
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (*count >= capacity) {
            capacity *= 2;
            *leases = realloc(*leases, capacity * sizeof(Lease));
        }
        row_to_lease(stmt, &(*leases)[(*count)++]);
    }
    
    sqlite3_finalize(stmt);
    return 1;
}

int db_lease_list_by_tenant(Database *db, const char *username, Lease **leases, int *count) {
    if (!db || !username || !leases || !count) return 0;
    const char *sql = "SELECT id, property_code, tenant_username, start_date, end_date, "
                      "monthly_rent, deposit, payment_day, status, auto_renew, created_at "
                      "FROM leases WHERE tenant_username = ? ORDER BY id DESC";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;
    
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    
    int capacity = 100;
    *leases = malloc(capacity * sizeof(Lease));
    *count = 0;
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (*count >= capacity) {
            capacity *= 2;
            *leases = realloc(*leases, capacity * sizeof(Lease));
        }
        row_to_lease(stmt, &(*leases)[(*count)++]);
    }
    
    sqlite3_finalize(stmt);
    return 1;
}

int db_lease_list_by_property(Database *db, const char *property_code, Lease **leases, int *count) {
    if (!db || !property_code || !leases || !count) return 0;
    const char *sql = "SELECT id, property_code, tenant_username, start_date, end_date, "
                      "monthly_rent, deposit, payment_day, status, auto_renew, created_at "
                      "FROM leases WHERE property_code = ? ORDER BY id DESC";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;
    
    sqlite3_bind_text(stmt, 1, property_code, -1, SQLITE_STATIC);
    
    int capacity = 100;
    *leases = malloc(capacity * sizeof(Lease));
    *count = 0;
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (*count >= capacity) {
            capacity *= 2;
            *leases = realloc(*leases, capacity * sizeof(Lease));
        }
        row_to_lease(stmt, &(*leases)[(*count)++]);
    }
    
    sqlite3_finalize(stmt);
    return 1;
}

int db_lease_list_by_status(Database *db, LeaseStatus status, Lease **leases, int *count) {
    if (!db || !leases || !count) return 0;
    const char *sql = "SELECT id, property_code, tenant_username, start_date, end_date, "
                      "monthly_rent, deposit, payment_day, status, auto_renew, created_at "
                      "FROM leases WHERE status = ? ORDER BY id DESC";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;
    
    sqlite3_bind_int(stmt, 1, (int)status);
    
    int capacity = 100;
    *leases = malloc(capacity * sizeof(Lease));
    *count = 0;
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (*count >= capacity) {
            capacity *= 2;
            *leases = realloc(*leases, capacity * sizeof(Lease));
        }
        row_to_lease(stmt, &(*leases)[(*count)++]);
    }
    
    sqlite3_finalize(stmt);
    return 1;
}

int db_lease_list_expiring(Database *db, int days_ahead, Lease **leases, int *count) {
    if (!db || !leases || !count) return 0;
    char sql[512];
    snprintf(sql, sizeof(sql),
        "SELECT id, property_code, tenant_username, start_date, end_date, "
        "monthly_rent, deposit, payment_day, status, auto_renew, created_at "
        "FROM leases "
        "WHERE status = %d "
        "AND date(end_date) BETWEEN date('now') AND date('now', '+%d days') "
        "ORDER BY end_date ASC", LEASE_STATUS_ACTIVE, days_ahead);
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;
    
    int capacity = 100;
    *leases = malloc(capacity * sizeof(Lease));
    *count = 0;
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (*count >= capacity) {
            capacity *= 2;
            *leases = realloc(*leases, capacity * sizeof(Lease));
        }
        row_to_lease(stmt, &(*leases)[(*count)++]);
    }
    
    sqlite3_finalize(stmt);
    return 1;
}

int db_lease_count(Database *db) {
    if (!db) return 0;
    const char *sql = "SELECT COUNT(*) FROM leases";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;
    
    int count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return count;
}

int db_lease_count_by_tenant(Database *db, const char *username) {
    if (!db || !username) return 0;
    const char *sql = "SELECT COUNT(*) FROM leases WHERE tenant_username = ?";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;
    
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    
    int count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return count;
}

int db_lease_count_by_property(Database *db, const char *property_code) {
    if (!db || !property_code) return 0;
    const char *sql = "SELECT COUNT(*) FROM leases WHERE property_code = ?";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;
    
    sqlite3_bind_text(stmt, 1, property_code, -1, SQLITE_STATIC);
    
    int count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return count;
}

int db_property_create(Database *db, const Property *prop) {
    if (!db || !prop) return 0;
    const char *sql = "INSERT INTO properties (code, district, address, location, ptype, action, subtype, "
                      "build_age, floor_area, floor, land_area, owner_phone, bedrooms, rooms, tax_rate, "
                      "elevator, basement, basement_area, balcony, balcony_area, parkings, phones, temperature, "
                      "sell_price, base_price, monthly_price, date, username, active) "
                      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "db_property_create prepare failed: %s\n", sqlite3_errmsg(db->db));
        return 0;
    }
    
    bind_property_stmt(stmt, prop);
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "db_property_create step failed: %s\n", sqlite3_errmsg(db->db));
    }
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

Property *db_property_find_by_code(Database *db, const char *code) {
    if (!db || !code) return NULL;
    const char *sql = "SELECT code, district, address, location, ptype, action, subtype, build_age, "
                      "floor_area, floor, land_area, owner_phone, bedrooms, rooms, tax_rate, elevator, "
                      "basement, basement_area, balcony, balcony_area, parkings, phones, temperature, "
                      "sell_price, base_price, monthly_price, date, username, active "
                      "FROM properties WHERE code = ? AND active = 1";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return NULL;
    
    sqlite3_bind_text(stmt, 1, code, -1, SQLITE_STATIC);
    
    Property *prop = NULL;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        prop = malloc(sizeof(Property));
        row_to_property(stmt, prop);
    }
    sqlite3_finalize(stmt);
    return prop;
}

int db_property_delete(Database *db, const char *code) {
    if (!db || !code) return 0;
    const char *sql = "UPDATE properties SET active = 0 WHERE code = ?";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;
    
    sqlite3_bind_text(stmt, 1, code, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE && sqlite3_changes(db->db) > 0;
}

static int property_query_with_filters(Database *db, const char *where_clause, const char *order_by, 
                                       int limit, int offset, Property **props, int *count) {
    if (!db || !props || !count) return 0;
    char sql[1024];
    snprintf(sql, sizeof(sql), 
        "SELECT code, district, address, location, ptype, action, subtype, build_age, "
        "floor_area, floor, land_area, owner_phone, bedrooms, rooms, tax_rate, elevator, "
        "basement, basement_area, balcony, balcony_area, parkings, phones, temperature, "
        "sell_price, base_price, monthly_price, date, username, active "
        "FROM properties WHERE active = 1");
    
    if (where_clause && strlen(where_clause) > 0) {
        strncat(sql, " AND ", sizeof(sql) - strlen(sql) - 1);
        strncat(sql, where_clause, sizeof(sql) - strlen(sql) - 1);
    }
    
    if (order_by && strlen(order_by) > 0) {
        snprintf(sql + strlen(sql), sizeof(sql) - strlen(sql), " ORDER BY %s", order_by);
    } else {
        strncat(sql, " ORDER BY date DESC", sizeof(sql) - strlen(sql) - 1);
    }
    
    if (limit > 0) {
        snprintf(sql + strlen(sql), sizeof(sql) - strlen(sql), " LIMIT %d", limit);
        if (offset > 0) {
            snprintf(sql + strlen(sql), sizeof(sql) - strlen(sql), " OFFSET %d", offset);
        }
    }
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;
    
    int capacity = 100;
    *props = malloc(capacity * sizeof(Property));
    *count = 0;
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (*count >= capacity) {
            capacity *= 2;
            *props = realloc(*props, capacity * sizeof(Property));
        }
        row_to_property(stmt, &(*props)[(*count)++]);
    }
    
    sqlite3_finalize(stmt);
    return 1;
}

int db_property_list_all(Database *db, Property **props, int *count) {
    return property_query_with_filters(db, NULL, "date DESC", 0, 0, props, count);
}

int db_property_list_by_type(Database *db, PropertyType ptype, PropertyAction action, Property **props, int *count) {
    if (!db || !props || !count) return 0;
    char where[128];
    snprintf(where, sizeof(where), "ptype = %d AND action = %d", ptype, action);
    return property_query_with_filters(db, where, "date DESC", 0, 0, props, count);
}

int db_property_list_by_district(Database *db, int district, Property **props, int *count) {
    if (!db || !props || !count) return 0;
    char where[128];
    snprintf(where, sizeof(where), "district = %d", district);
    return property_query_with_filters(db, where, "date DESC", 0, 0, props, count);
}

int db_property_list_by_location(Database *db, Location location, Property **props, int *count) {
    if (!db || !props || !count) return 0;
    char where[128];
    snprintf(where, sizeof(where), "location = %d", location);
    return property_query_with_filters(db, where, "date DESC", 0, 0, props, count);
}

int db_property_list_by_price_range(Database *db, double min, double max, Property **props, int *count) {
    if (!db || !props || !count) return 0;
    char where[256];
    snprintf(where, sizeof(where), 
        "(action = %d AND sell_price BETWEEN %.2f AND %.2f) OR "
        "(action = %d AND monthly_price BETWEEN %.2f AND %.2f)",
        PROP_ACTION_SELL, min, max, PROP_ACTION_RENT, min, max);
    return property_query_with_filters(db, where, "date DESC", 0, 0, props, count);
}

int db_property_count_by_type(Database *db, PropertyType ptype, PropertyAction action) {
    if (!db) return 0;
    char sql[256];
    snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM properties WHERE active = 1 AND ptype = %d AND action = %d", ptype, action);
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;
    
    int count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return count;
}

int db_property_list_paginated(Database *db, const char *where_clause, const char *order_by, 
                               int limit, int offset, Property **props, int *count) {
    if (!db || !props || !count) return 0;
    return property_query_with_filters(db, where_clause, order_by, limit, offset, props, count);
}

int db_property_count_filtered(Database *db, const char *where_clause) {
    if (!db) return 0;
    char sql[1024];
    snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM properties WHERE active = 1");
    if (where_clause && strlen(where_clause) > 0) {
        strncat(sql, " AND ", sizeof(sql) - strlen(sql) - 1);
        strncat(sql, where_clause, sizeof(sql) - strlen(sql) - 1);
    }
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;
    
    int count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return count;
}

int database_migrate_from_files(Database *db, const char *users_file, const char *properties_file) {
    if (!db || !users_file || !properties_file) return 0;
    FILE *uf = fopen(users_file, "r");
    if (uf) {
        char line[2048];
        while (fgets(line, sizeof(line), uf)) {
            trim_newline(line);
            char *tokens[8];
            int tc = 0;
            char *t = strtok(line, "|");
            while (t && tc < 8) { tokens[tc++] = t; t = strtok(NULL, "|"); }
            if (tc >= 8) {
                User u = {0};
                strncpy(u.username, tokens[0], MAX_FIELD_LEN - 1);
                strncpy(u.first_name, tokens[1], MAX_FIELD_LEN - 1);
                strncpy(u.last_name, tokens[2], MAX_FIELD_LEN - 1);
                strncpy(u.id, tokens[3], MAX_FIELD_LEN - 1);
                strncpy(u.phone, tokens[4], MAX_FIELD_LEN - 1);
                strncpy(u.email, tokens[5], MAX_FIELD_LEN - 1);
                strncpy(u.password_hash, tokens[6], SHA256_DIGEST_LENGTH * 2);
                strncpy(u.salt, tokens[7], SALT_LENGTH);
                db_user_create(db, &u);
            }
        }
        fclose(uf);
    }
    
    FILE *pf = fopen(properties_file, "r");
    if (pf) {
        char line[4096];
        while (fgets(line, sizeof(line), pf)) {
            trim_newline(line);
            char *tokens[30];
            int tc = 0;
            char *t = strtok(line, "|");
            while (t && tc < 30) { tokens[tc++] = t; t = strtok(NULL, "|"); }
            if (tc >= 29) {
                Property p = {0};
                int idx = 0;
                strncpy(p.code, tokens[idx++], MAX_FIELD_LEN - 1);
                p.district = atoi(tokens[idx++]);
                strncpy(p.address, tokens[idx++], MAX_STRING_LEN - 1);
                p.location = atoi(tokens[idx++]);
                p.ptype = atoi(tokens[idx++]);
                p.action = atoi(tokens[idx++]);
                p.subtype.res_type = atoi(tokens[idx++]);
                p.build_age = atoi(tokens[idx++]);
                p.floor_area = atof(tokens[idx++]);
                p.floor = atoi(tokens[idx++]);
                p.land_area = atof(tokens[idx++]);
                strncpy(p.owner_phone, tokens[idx++], MAX_FIELD_LEN - 1);
                p.bedrooms = atoi(tokens[idx++]);
                p.rooms = atoi(tokens[idx++]);
                p.tax_rate = atof(tokens[idx++]);
                p.elevator = atoi(tokens[idx++]);
                p.basement = atoi(tokens[idx++]);
                p.basement_area = atof(tokens[idx++]);
                p.balcony = atoi(tokens[idx++]);
                p.balcony_area = atof(tokens[idx++]);
                p.parkings = atoi(tokens[idx++]);
                p.phones = atoi(tokens[idx++]);
                p.temperature = atoi(tokens[idx++]);
                p.sell_price = atof(tokens[idx++]);
                p.base_price = atof(tokens[idx++]);
                p.monthly_price = atof(tokens[idx++]);
                strncpy(p.date, tokens[idx++], MAX_FIELD_LEN - 1);
                strncpy(p.username, tokens[idx++], MAX_FIELD_LEN - 1);
                p.active = atoi(tokens[idx++]);
                db_property_create(db, &p);
            }
        }
        fclose(pf);
    }
    return 1;
}