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
    "CREATE TABLE IF NOT EXISTS payments ("
    "    id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "    lease_id INTEGER NOT NULL,"
    "    amount REAL NOT NULL,"
    "    payment_date TEXT NOT NULL,"
    "    due_date TEXT NOT NULL,"
    "    is_late INTEGER DEFAULT 0,"
    "    late_fee REAL DEFAULT 0,"
    "    notes TEXT DEFAULT '',"
    "    recorded_by TEXT NOT NULL,"
    "    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,"
    "    FOREIGN KEY (lease_id) REFERENCES leases(id),"
    "    FOREIGN KEY (recorded_by) REFERENCES users(username)"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_properties_type_action ON properties(ptype, action);"
    "CREATE INDEX IF NOT EXISTS idx_properties_district ON properties(district);"
    "CREATE INDEX IF NOT EXISTS idx_properties_location ON properties(location);"
    "CREATE INDEX IF NOT EXISTS idx_properties_username ON properties(username);"
    "CREATE INDEX IF NOT EXISTS idx_properties_active ON properties(active);"
    "CREATE INDEX IF NOT EXISTS idx_leases_tenant ON leases(tenant_username);"
    "CREATE INDEX IF NOT EXISTS idx_leases_property ON leases(property_code);"
    "CREATE INDEX IF NOT EXISTS idx_leases_status ON leases(status);"
    "CREATE INDEX IF NOT EXISTS idx_leases_dates ON leases(start_date, end_date);"
    "CREATE TABLE IF NOT EXISTS expenses ("
    "    id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "    property_code TEXT NOT NULL,"
    "    type INTEGER NOT NULL,"
    "    amount REAL NOT NULL,"
    "    date TEXT NOT NULL,"
    "    description TEXT DEFAULT '',"
    "    vendor TEXT DEFAULT '',"
    "    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,"
    "    FOREIGN KEY (property_code) REFERENCES properties(code)"
    ");"
    "CREATE TABLE IF NOT EXISTS work_orders ("
    "    id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "    property_code TEXT NOT NULL,"
    "    reported_by TEXT NOT NULL,"
    "    assigned_to TEXT DEFAULT '',"
    "    type INTEGER NOT NULL,"
    "    priority INTEGER NOT NULL,"
    "    status INTEGER DEFAULT 0,"
    "    title TEXT NOT NULL,"
    "    description TEXT DEFAULT '',"
    "    estimated_cost REAL DEFAULT 0,"
    "    actual_cost REAL DEFAULT 0,"
    "    reported_date TEXT NOT NULL,"
    "    scheduled_date TEXT DEFAULT '',"
    "    completed_date TEXT DEFAULT '',"
    "    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,"
    "    FOREIGN KEY (property_code) REFERENCES properties(code),"
    "    FOREIGN KEY (reported_by) REFERENCES users(username),"
    "    FOREIGN KEY (assigned_to) REFERENCES users(username)"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_properties_type_action ON properties(ptype, action);"
    "CREATE INDEX IF NOT EXISTS idx_properties_district ON properties(district);"
    "CREATE INDEX IF NOT EXISTS idx_properties_location ON properties(location);"
    "CREATE INDEX IF NOT EXISTS idx_properties_username ON properties(username);"
    "CREATE INDEX IF NOT EXISTS idx_properties_active ON properties(active);"
    "CREATE INDEX IF NOT EXISTS idx_leases_tenant ON leases(tenant_username);"
    "CREATE INDEX IF NOT EXISTS idx_leases_property ON leases(property_code);"
    "CREATE INDEX IF NOT EXISTS idx_leases_status ON leases(status);"
    "CREATE INDEX IF NOT EXISTS idx_leases_dates ON leases(start_date, end_date);"
    "CREATE INDEX IF NOT EXISTS idx_expenses_property ON expenses(property_code);"
    "CREATE INDEX IF NOT EXISTS idx_expenses_date ON expenses(date);"
    "CREATE INDEX IF NOT EXISTS idx_expenses_type ON expenses(type);"
    "CREATE INDEX IF NOT EXISTS idx_work_orders_property ON work_orders(property_code);"
    "CREATE INDEX IF NOT EXISTS idx_work_orders_status ON work_orders(status);"
    "CREATE INDEX IF NOT EXISTS idx_work_orders_assigned ON work_orders(assigned_to);"
    "CREATE INDEX IF NOT EXISTS idx_work_orders_dates ON work_orders(scheduled_date, completed_date);";

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
    const char *sql = "INSERT INTO users (username, first_name, last_name, id, phone, email, password_hash, salt, role) "
                      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;
    
    bind_user_stmt(stmt, user);
    sqlite3_bind_int(stmt, 9, (int)user->role);
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

// ============================================================================
// PAYMENT OPERATIONS
// ============================================================================

static void row_to_payment(sqlite3_stmt *stmt, Payment *payment) {
    payment->id = sqlite3_column_int(stmt, 0);
    payment->lease_id = sqlite3_column_int(stmt, 1);
    payment->amount = sqlite3_column_double(stmt, 2);
    strncpy(payment->payment_date, (const char*)sqlite3_column_text(stmt, 3), MAX_FIELD_LEN - 1);
    strncpy(payment->due_date, (const char*)sqlite3_column_text(stmt, 4), MAX_FIELD_LEN - 1);
    payment->is_late = sqlite3_column_int(stmt, 5);
    payment->late_fee = sqlite3_column_double(stmt, 6);
    strncpy(payment->notes, (const char*)sqlite3_column_text(stmt, 7), MAX_STRING_LEN - 1);
    strncpy(payment->recorded_by, (const char*)sqlite3_column_text(stmt, 8), MAX_FIELD_LEN - 1);
    strncpy(payment->created_at, (const char*)sqlite3_column_text(stmt, 9), MAX_FIELD_LEN - 1);
}

int db_payment_create(Database *db, const Payment *payment) {
    if (!db || !payment) return 0;
    const char *sql = "INSERT INTO payments (lease_id, amount, payment_date, due_date, is_late, late_fee, notes, recorded_by) "
                      "VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;
    
    sqlite3_bind_int(stmt, 1, payment->lease_id);
    sqlite3_bind_double(stmt, 2, payment->amount);
    sqlite3_bind_text(stmt, 3, payment->payment_date, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, payment->due_date, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 5, payment->is_late);
    sqlite3_bind_double(stmt, 6, payment->late_fee);
    sqlite3_bind_text(stmt, 7, payment->notes, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 8, payment->recorded_by, -1, SQLITE_STATIC);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

Payment *db_payment_find_by_id(Database *db, int id) {
    if (!db) return NULL;
    const char *sql = "SELECT id, lease_id, amount, payment_date, due_date, is_late, late_fee, notes, recorded_by, created_at "
                      "FROM payments WHERE id = ?";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return NULL;
    
    sqlite3_bind_int(stmt, 1, id);
    
    Payment *payment = NULL;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        payment = malloc(sizeof(Payment));
        row_to_payment(stmt, payment);
    }
    sqlite3_finalize(stmt);
    return payment;
}

int db_payment_list_by_lease(Database *db, int lease_id, Payment **payments, int *count) {
    if (!db || !payments || !count) return 0;
    const char *sql = "SELECT id, lease_id, amount, payment_date, due_date, is_late, late_fee, notes, recorded_by, created_at "
                      "FROM payments WHERE lease_id = ? ORDER BY payment_date DESC";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;
    
    sqlite3_bind_int(stmt, 1, lease_id);
    
    int capacity = 100;
    *payments = malloc(capacity * sizeof(Payment));
    *count = 0;
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (*count >= capacity) {
            capacity *= 2;
            *payments = realloc(*payments, capacity * sizeof(Payment));
        }
        row_to_payment(stmt, &(*payments)[(*count)++]);
    }
    
    sqlite3_finalize(stmt);
    return 1;
}

int db_payment_list_by_date_range(Database *db, const char *start_date, const char *end_date, Payment **payments, int *count) {
    if (!db || !start_date || !end_date || !payments || !count) return 0;
    const char *sql = "SELECT id, lease_id, amount, payment_date, due_date, is_late, late_fee, notes, recorded_by, created_at "
                      "FROM payments WHERE payment_date BETWEEN ? AND ? ORDER BY payment_date DESC";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;
    
    sqlite3_bind_text(stmt, 1, start_date, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, end_date, -1, SQLITE_STATIC);
    
    int capacity = 100;
    *payments = malloc(capacity * sizeof(Payment));
    *count = 0;
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (*count >= capacity) {
            capacity *= 2;
            *payments = realloc(*payments, capacity * sizeof(Payment));
        }
        row_to_payment(stmt, &(*payments)[(*count)++]);
    }
    
    sqlite3_finalize(stmt);
    return 1;
}

int db_payment_list_late(Database *db, Payment **payments, int *count) {
    if (!db || !payments || !count) return 0;
    const char *sql = "SELECT id, lease_id, amount, payment_date, due_date, is_late, late_fee, notes, recorded_by, created_at "
                      "FROM payments WHERE is_late = 1 ORDER BY payment_date DESC";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;
    
    int capacity = 100;
    *payments = malloc(capacity * sizeof(Payment));
    *count = 0;
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (*count >= capacity) {
            capacity *= 2;
            *payments = realloc(*payments, capacity * sizeof(Payment));
        }
        row_to_payment(stmt, &(*payments)[(*count)++]);
    }
    
    sqlite3_finalize(stmt);
    return 1;
}

double db_payment_sum_by_lease(Database *db, int lease_id) {
    if (!db) return 0.0;
    const char *sql = "SELECT COALESCE(SUM(amount), 0) FROM payments WHERE lease_id = ?";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0.0;
    
    sqlite3_bind_int(stmt, 1, lease_id);
    
    double sum = 0.0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        sum = sqlite3_column_double(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return sum;
}

int db_payment_count(Database *db) {
    if (!db) return 0;
    const char *sql = "SELECT COUNT(*) FROM payments";
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

// ============================================================================
// EXPENSE OPERATIONS
// ============================================================================

static void row_to_expense(sqlite3_stmt *stmt, Expense *expense) {
    expense->id = sqlite3_column_int(stmt, 0);
    strncpy(expense->property_code, (const char*)sqlite3_column_text(stmt, 1), MAX_FIELD_LEN - 1);
    expense->type = (ExpenseType)sqlite3_column_int(stmt, 2);
    expense->amount = sqlite3_column_double(stmt, 3);
    strncpy(expense->date, (const char*)sqlite3_column_text(stmt, 4), MAX_FIELD_LEN - 1);
    strncpy(expense->description, (const char*)sqlite3_column_text(stmt, 5), MAX_STRING_LEN - 1);
    strncpy(expense->vendor, (const char*)sqlite3_column_text(stmt, 6), MAX_FIELD_LEN - 1);
    strncpy(expense->created_at, (const char*)sqlite3_column_text(stmt, 7), MAX_FIELD_LEN - 1);
}

static int bind_expense_stmt(sqlite3_stmt *stmt, const Expense *expense) {
    sqlite3_bind_text(stmt, 1, expense->property_code, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, (int)expense->type);
    sqlite3_bind_double(stmt, 3, expense->amount);
    sqlite3_bind_text(stmt, 4, expense->date, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, expense->description, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 6, expense->vendor, -1, SQLITE_STATIC);
    return SQLITE_OK;
}

int db_expense_create(Database *db, const Expense *expense) {
    if (!db || !expense) return 0;
    const char *sql = "INSERT INTO expenses (property_code, type, amount, date, description, vendor) "
                      "VALUES (?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;
    
    bind_expense_stmt(stmt, expense);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

Expense *db_expense_find_by_id(Database *db, int id) {
    if (!db) return NULL;
    const char *sql = "SELECT id, property_code, type, amount, date, description, vendor, created_at "
                      "FROM expenses WHERE id = ?";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return NULL;
    
    sqlite3_bind_int(stmt, 1, id);
    
    Expense *expense = NULL;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        expense = malloc(sizeof(Expense));
        row_to_expense(stmt, expense);
    }
    sqlite3_finalize(stmt);
    return expense;
}

int db_expense_update(Database *db, const Expense *expense) {
    if (!db || !expense) return 0;
    const char *sql = "UPDATE expenses SET property_code = ?, type = ?, amount = ?, date = ?, "
                      "description = ?, vendor = ? WHERE id = ?";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;
    
    bind_expense_stmt(stmt, expense);
    sqlite3_bind_int(stmt, 7, expense->id);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE && sqlite3_changes(db->db) > 0;
}

int db_expense_delete(Database *db, int id) {
    if (!db) return 0;
    const char *sql = "DELETE FROM expenses WHERE id = ?";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;
    
    sqlite3_bind_int(stmt, 1, id);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE && sqlite3_changes(db->db) > 0;
}

int db_expense_list_all(Database *db, Expense **expenses, int *count) {
    if (!db || !expenses || !count) return 0;
    const char *sql = "SELECT id, property_code, type, amount, date, description, vendor, created_at "
                      "FROM expenses ORDER BY date DESC";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;
    
    int capacity = 100;
    *expenses = malloc(capacity * sizeof(Expense));
    *count = 0;
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (*count >= capacity) {
            capacity *= 2;
            *expenses = realloc(*expenses, capacity * sizeof(Expense));
        }
        row_to_expense(stmt, &(*expenses)[(*count)++]);
    }
    
    sqlite3_finalize(stmt);
    return 1;
}

int db_expense_list_by_property(Database *db, const char *property_code, Expense **expenses, int *count) {
    if (!db || !property_code || !expenses || !count) return 0;
    const char *sql = "SELECT id, property_code, type, amount, date, description, vendor, created_at "
                      "FROM expenses WHERE property_code = ? ORDER BY date DESC";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;
    
    sqlite3_bind_text(stmt, 1, property_code, -1, SQLITE_STATIC);
    
    int capacity = 100;
    *expenses = malloc(capacity * sizeof(Expense));
    *count = 0;
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (*count >= capacity) {
            capacity *= 2;
            *expenses = realloc(*expenses, capacity * sizeof(Expense));
        }
        row_to_expense(stmt, &(*expenses)[(*count)++]);
    }
    
    sqlite3_finalize(stmt);
    return 1;
}

int db_expense_list_by_type(Database *db, ExpenseType type, Expense **expenses, int *count) {
    if (!db || !expenses || !count) return 0;
    const char *sql = "SELECT id, property_code, type, amount, date, description, vendor, created_at "
                      "FROM expenses WHERE type = ? ORDER BY date DESC";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;
    
    sqlite3_bind_int(stmt, 1, (int)type);
    
    int capacity = 100;
    *expenses = malloc(capacity * sizeof(Expense));
    *count = 0;
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (*count >= capacity) {
            capacity *= 2;
            *expenses = realloc(*expenses, capacity * sizeof(Expense));
        }
        row_to_expense(stmt, &(*expenses)[(*count)++]);
    }
    
    sqlite3_finalize(stmt);
    return 1;
}

int db_expense_list_by_date_range(Database *db, const char *start_date, const char *end_date, Expense **expenses, int *count) {
    if (!db || !start_date || !end_date || !expenses || !count) return 0;
    const char *sql = "SELECT id, property_code, type, amount, date, description, vendor, created_at "
                      "FROM expenses WHERE date BETWEEN ? AND ? ORDER BY date DESC";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;
    
    sqlite3_bind_text(stmt, 1, start_date, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, end_date, -1, SQLITE_STATIC);
    
    int capacity = 100;
    *expenses = malloc(capacity * sizeof(Expense));
    *count = 0;
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (*count >= capacity) {
            capacity *= 2;
            *expenses = realloc(*expenses, capacity * sizeof(Expense));
        }
        row_to_expense(stmt, &(*expenses)[(*count)++]);
    }
    
    sqlite3_finalize(stmt);
    return 1;
}

int db_expense_list_by_property_date_range(Database *db, const char *property_code, const char *start_date, const char *end_date, Expense **expenses, int *count) {
    if (!db || !property_code || !start_date || !end_date || !expenses || !count) return 0;
    const char *sql = "SELECT id, property_code, type, amount, date, description, vendor, created_at "
                      "FROM expenses WHERE property_code = ? AND date BETWEEN ? AND ? ORDER BY date DESC";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;
    
    sqlite3_bind_text(stmt, 1, property_code, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, start_date, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, end_date, -1, SQLITE_STATIC);
    
    int capacity = 100;
    *expenses = malloc(capacity * sizeof(Expense));
    *count = 0;
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (*count >= capacity) {
            capacity *= 2;
            *expenses = realloc(*expenses, capacity * sizeof(Expense));
        }
        row_to_expense(stmt, &(*expenses)[(*count)++]);
    }
    
    sqlite3_finalize(stmt);
    return 1;
}

double db_expense_sum_by_property(Database *db, const char *property_code) {
    if (!db || !property_code) return 0.0;
    const char *sql = "SELECT COALESCE(SUM(amount), 0) FROM expenses WHERE property_code = ?";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0.0;
    
    sqlite3_bind_text(stmt, 1, property_code, -1, SQLITE_STATIC);
    
    double sum = 0.0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        sum = sqlite3_column_double(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return sum;
}

double db_expense_sum_by_type(Database *db, ExpenseType type) {
    if (!db) return 0.0;
    const char *sql = "SELECT COALESCE(SUM(amount), 0) FROM expenses WHERE type = ?";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0.0;
    
    sqlite3_bind_int(stmt, 1, (int)type);
    
    double sum = 0.0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        sum = sqlite3_column_double(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return sum;
}

double db_expense_sum_by_property_type(Database *db, const char *property_code, ExpenseType type) {
    if (!db || !property_code) return 0.0;
    const char *sql = "SELECT COALESCE(SUM(amount), 0) FROM expenses WHERE property_code = ? AND type = ?";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0.0;
    
    sqlite3_bind_text(stmt, 1, property_code, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, (int)type);
    
    double sum = 0.0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        sum = sqlite3_column_double(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return sum;
}

int db_expense_count(Database *db) {
    if (!db) return 0;
    const char *sql = "SELECT COUNT(*) FROM expenses";
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

int db_expense_count_by_property(Database *db, const char *property_code) {
    if (!db || !property_code) return 0;
    const char *sql = "SELECT COUNT(*) FROM expenses WHERE property_code = ?";
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

// ============================================================================
// RENEWAL OPERATIONS
// ============================================================================

int db_lease_check_expiring(Database *db, int days_ahead, Lease **leases, int *count) {
    return db_lease_list_expiring(db, days_ahead, leases, count);
}

int db_lease_auto_renew(Database *db, int lease_id) {
    if (!db) return 0;
    
    Lease *lease = db_lease_find_by_id(db, lease_id);
    if (!lease) return 0;
    
    if (lease->auto_renew == 0) {
        free(lease);
        return 0;
    }
    
    if (lease->status != LEASE_STATUS_ACTIVE && lease->status != LEASE_STATUS_EXPIRED) {
        free(lease);
        return 0;
    }
    
    // Calculate new dates (extend by same duration)
    // For simplicity, extend by 1 year
    int start_year, start_month, start_day;
    int end_year, end_month, end_day;
    sscanf(lease->start_date, "%d-%d-%d", &start_year, &start_month, &start_day);
    sscanf(lease->end_date, "%d-%d-%d", &end_year, &end_month, &end_day);
    
    int duration_days = (end_year - start_year) * 365 + (end_month - start_month) * 30 + (end_day - start_day);
    if (duration_days <= 0) duration_days = 365;
    
    int new_start_year = end_year, new_start_month = end_month, new_start_day = end_day + 1;
    int new_end_year = end_year, new_end_month = end_month, new_end_day = end_day;
    
    // Add duration
    int days_added = 0;
    while (days_added < duration_days) {
        new_end_day++;
        days_added++;
        if (new_end_day > 28) { // Simplified month handling
            new_end_day = 1;
            new_end_month++;
            if (new_end_month > 12) {
                new_end_month = 1;
                new_end_year++;
            }
        }
    }
    
    char new_start[MAX_FIELD_LEN], new_end[MAX_FIELD_LEN];
    snprintf(new_start, sizeof(new_start), "%04d-%02d-%02d", new_start_year, new_start_month, new_start_day);
    snprintf(new_end, sizeof(new_end), "%04d-%02d-%02d", new_end_year, new_end_month, new_end_day);
    
    // Create new lease
    Lease new_lease;
    memset(&new_lease, 0, sizeof(Lease));
    strcpy(new_lease.property_code, lease->property_code);
    strcpy(new_lease.tenant_username, lease->tenant_username);
    strcpy(new_lease.start_date, new_start);
    strcpy(new_lease.end_date, new_end);
    new_lease.monthly_rent = lease->monthly_rent;
    new_lease.deposit = lease->deposit;
    new_lease.payment_day = lease->payment_day;
    new_lease.status = LEASE_STATUS_ACTIVE;
    new_lease.auto_renew = lease->auto_renew;
    
    int result = db_lease_create(db, &new_lease);
    
    // Mark old lease as expired
    lease->status = LEASE_STATUS_EXPIRED;
    db_lease_update(db, lease);
    
    free(lease);
    return result;
}

int db_lease_process_renewals(Database *db, int days_ahead) {
    if (!db) return 0;
    
    Lease *leases = NULL;
    int count = 0;
    if (!db_lease_list_expiring(db, days_ahead, &leases, &count)) return 0;
    
    int renewed = 0;
    for (int i = 0; i < count; i++) {
        if (leases[i].auto_renew) {
            if (db_lease_auto_renew(db, leases[i].id)) {
                renewed++;
            }
        }
    }
    
    if (leases) free(leases);
    return renewed;
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

// ============================================================================
// WORK ORDER OPERATIONS
// ============================================================================

static void row_to_work_order(sqlite3_stmt *stmt, WorkOrder *wo) {
    wo->id = sqlite3_column_int(stmt, 0);
    strncpy(wo->property_code, (const char*)sqlite3_column_text(stmt, 1), MAX_FIELD_LEN - 1);
    strncpy(wo->reported_by, (const char*)sqlite3_column_text(stmt, 2), MAX_FIELD_LEN - 1);
    strncpy(wo->assigned_to, (const char*)sqlite3_column_text(stmt, 3), MAX_FIELD_LEN - 1);
    wo->type = (WorkOrderType)sqlite3_column_int(stmt, 4);
    wo->priority = (WorkOrderPriority)sqlite3_column_int(stmt, 5);
    wo->status = (WorkOrderStatus)sqlite3_column_int(stmt, 6);
    strncpy(wo->title, (const char*)sqlite3_column_text(stmt, 7), MAX_STRING_LEN - 1);
    strncpy(wo->description, (const char*)sqlite3_column_text(stmt, 8), MAX_STRING_LEN - 1);
    wo->estimated_cost = sqlite3_column_double(stmt, 9);
    wo->actual_cost = sqlite3_column_double(stmt, 10);
    strncpy(wo->reported_date, (const char*)sqlite3_column_text(stmt, 11), MAX_FIELD_LEN - 1);
    strncpy(wo->scheduled_date, (const char*)sqlite3_column_text(stmt, 12), MAX_FIELD_LEN - 1);
    strncpy(wo->completed_date, (const char*)sqlite3_column_text(stmt, 13), MAX_FIELD_LEN - 1);
    strncpy(wo->created_at, (const char*)sqlite3_column_text(stmt, 14), MAX_FIELD_LEN - 1);
}

static int bind_work_order_stmt(sqlite3_stmt *stmt, const WorkOrder *wo) {
    sqlite3_bind_text(stmt, 1, wo->property_code, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, wo->reported_by, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, wo->assigned_to, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 4, (int)wo->type);
    sqlite3_bind_int(stmt, 5, (int)wo->priority);
    sqlite3_bind_int(stmt, 6, (int)wo->status);
    sqlite3_bind_text(stmt, 7, wo->title, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 8, wo->description, -1, SQLITE_STATIC);
    sqlite3_bind_double(stmt, 9, wo->estimated_cost);
    sqlite3_bind_double(stmt, 10, wo->actual_cost);
    sqlite3_bind_text(stmt, 11, wo->reported_date, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 12, wo->scheduled_date, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 13, wo->completed_date, -1, SQLITE_STATIC);
    return SQLITE_OK;
}

int db_work_order_create(Database *db, const WorkOrder *wo) {
    if (!db || !wo) return 0;
    const char *sql = "INSERT INTO work_orders (property_code, reported_by, assigned_to, type, priority, status, title, description, estimated_cost, actual_cost, reported_date, scheduled_date, completed_date) "
                      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;
    
    bind_work_order_stmt(stmt, wo);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

WorkOrder *db_work_order_find_by_id(Database *db, int id) {
    if (!db) return NULL;
    const char *sql = "SELECT id, property_code, reported_by, assigned_to, type, priority, status, title, description, estimated_cost, actual_cost, reported_date, scheduled_date, completed_date, created_at "
                      "FROM work_orders WHERE id = ?";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return NULL;
    
    sqlite3_bind_int(stmt, 1, id);
    
    WorkOrder *wo = NULL;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        wo = malloc(sizeof(WorkOrder));
        row_to_work_order(stmt, wo);
    }
    sqlite3_finalize(stmt);
    return wo;
}

int db_work_order_update(Database *db, const WorkOrder *wo) {
    if (!db || !wo) return 0;
    const char *sql = "UPDATE work_orders SET property_code = ?, reported_by = ?, assigned_to = ?, type = ?, priority = ?, status = ?, title = ?, description = ?, estimated_cost = ?, actual_cost = ?, reported_date = ?, scheduled_date = ?, completed_date = ? WHERE id = ?";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;
    
    bind_work_order_stmt(stmt, wo);
    sqlite3_bind_int(stmt, 14, wo->id);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE && sqlite3_changes(db->db) > 0;
}

int db_work_order_delete(Database *db, int id) {
    if (!db) return 0;
    const char *sql = "DELETE FROM work_orders WHERE id = ?";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;
    
    sqlite3_bind_int(stmt, 1, id);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE && sqlite3_changes(db->db) > 0;
}

int db_work_order_list_all(Database *db, WorkOrder **wos, int *count) {
    if (!db || !wos || !count) return 0;
    const char *sql = "SELECT id, property_code, reported_by, assigned_to, type, priority, status, title, description, estimated_cost, actual_cost, reported_date, scheduled_date, completed_date, created_at "
                      "FROM work_orders ORDER BY created_at DESC";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;
    
    int capacity = 100;
    *wos = malloc(capacity * sizeof(WorkOrder));
    *count = 0;
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (*count >= capacity) {
            capacity *= 2;
            *wos = realloc(*wos, capacity * sizeof(WorkOrder));
        }
        row_to_work_order(stmt, &(*wos)[(*count)++]);
    }
    
    sqlite3_finalize(stmt);
    return 1;
}

int db_work_order_list_by_property(Database *db, const char *property_code, WorkOrder **wos, int *count) {
    if (!db || !property_code || !wos || !count) return 0;
    const char *sql = "SELECT id, property_code, reported_by, assigned_to, type, priority, status, title, description, estimated_cost, actual_cost, reported_date, scheduled_date, completed_date, created_at "
                      "FROM work_orders WHERE property_code = ? ORDER BY created_at DESC";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;
    
    sqlite3_bind_text(stmt, 1, property_code, -1, SQLITE_STATIC);
    
    int capacity = 100;
    *wos = malloc(capacity * sizeof(WorkOrder));
    *count = 0;
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (*count >= capacity) {
            capacity *= 2;
            *wos = realloc(*wos, capacity * sizeof(WorkOrder));
        }
        row_to_work_order(stmt, &(*wos)[(*count)++]);
    }
    
    sqlite3_finalize(stmt);
    return 1;
}

int db_work_order_list_by_status(Database *db, WorkOrderStatus status, WorkOrder **wos, int *count) {
    if (!db || !wos || !count) return 0;
    const char *sql = "SELECT id, property_code, reported_by, assigned_to, type, priority, status, title, description, estimated_cost, actual_cost, reported_date, scheduled_date, completed_date, created_at "
                      "FROM work_orders WHERE status = ? ORDER BY created_at DESC";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;
    
    sqlite3_bind_int(stmt, 1, (int)status);
    
    int capacity = 100;
    *wos = malloc(capacity * sizeof(WorkOrder));
    *count = 0;
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (*count >= capacity) {
            capacity *= 2;
            *wos = realloc(*wos, capacity * sizeof(WorkOrder));
        }
        row_to_work_order(stmt, &(*wos)[(*count)++]);
    }
    
    sqlite3_finalize(stmt);
    return 1;
}

int db_work_order_list_by_assigned(Database *db, const char *username, WorkOrder **wos, int *count) {
    if (!db || !username || !wos || !count) return 0;
    const char *sql = "SELECT id, property_code, reported_by, assigned_to, type, priority, status, title, description, estimated_cost, actual_cost, reported_date, scheduled_date, completed_date, created_at "
                      "FROM work_orders WHERE assigned_to = ? ORDER BY created_at DESC";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;
    
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    
    int capacity = 100;
    *wos = malloc(capacity * sizeof(WorkOrder));
    *count = 0;
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (*count >= capacity) {
            capacity *= 2;
            *wos = realloc(*wos, capacity * sizeof(WorkOrder));
        }
        row_to_work_order(stmt, &(*wos)[(*count)++]);
    }
    
    sqlite3_finalize(stmt);
    return 1;
}

int db_work_order_list_by_reported(Database *db, const char *username, WorkOrder **wos, int *count) {
    if (!db || !username || !wos || !count) return 0;
    const char *sql = "SELECT id, property_code, reported_by, assigned_to, type, priority, status, title, description, estimated_cost, actual_cost, reported_date, scheduled_date, completed_date, created_at "
                      "FROM work_orders WHERE reported_by = ? ORDER BY created_at DESC";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;
    
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    
    int capacity = 100;
    *wos = malloc(capacity * sizeof(WorkOrder));
    *count = 0;
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (*count >= capacity) {
            capacity *= 2;
            *wos = realloc(*wos, capacity * sizeof(WorkOrder));
        }
        row_to_work_order(stmt, &(*wos)[(*count)++]);
    }
    
    sqlite3_finalize(stmt);
    return 1;
}

int db_work_order_list_by_priority(Database *db, WorkOrderPriority priority, WorkOrder **wos, int *count) {
    if (!db || !wos || !count) return 0;
    const char *sql = "SELECT id, property_code, reported_by, assigned_to, type, priority, status, title, description, estimated_cost, actual_cost, reported_date, scheduled_date, completed_date, created_at "
                      "FROM work_orders WHERE priority = ? ORDER BY created_at DESC";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;
    
    sqlite3_bind_int(stmt, 1, (int)priority);
    
    int capacity = 100;
    *wos = malloc(capacity * sizeof(WorkOrder));
    *count = 0;
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (*count >= capacity) {
            capacity *= 2;
            *wos = realloc(*wos, capacity * sizeof(WorkOrder));
        }
        row_to_work_order(stmt, &(*wos)[(*count)++]);
    }
    
    sqlite3_finalize(stmt);
    return 1;
}

int db_work_order_list_overdue(Database *db, WorkOrder **wos, int *count) {
    if (!db || !wos || !count) return 0;
    const char *sql = "SELECT id, property_code, reported_by, assigned_to, type, priority, status, title, description, estimated_cost, actual_cost, reported_date, scheduled_date, completed_date, created_at "
                      "FROM work_orders WHERE status IN (0, 1) AND scheduled_date != '' AND date(scheduled_date) < date('now') ORDER BY scheduled_date ASC";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;
    
    int capacity = 100;
    *wos = malloc(capacity * sizeof(WorkOrder));
    *count = 0;
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (*count >= capacity) {
            capacity *= 2;
            *wos = realloc(*wos, capacity * sizeof(WorkOrder));
        }
        row_to_work_order(stmt, &(*wos)[(*count)++]);
    }
    
    sqlite3_finalize(stmt);
    return 1;
}

int db_work_order_count(Database *db) {
    if (!db) return 0;
    const char *sql = "SELECT COUNT(*) FROM work_orders";
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

int db_work_order_count_by_property(Database *db, const char *property_code) {
    if (!db || !property_code) return 0;
    const char *sql = "SELECT COUNT(*) FROM work_orders WHERE property_code = ?";
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

int db_work_order_count_by_status(Database *db, WorkOrderStatus status) {
    if (!db) return 0;
    const char *sql = "SELECT COUNT(*) FROM work_orders WHERE status = ?";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;
    
    sqlite3_bind_int(stmt, 1, (int)status);
    
    int count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return count;
}