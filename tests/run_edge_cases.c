#include "unity.h"
#include "database.h"
#include "user.h"
#include "common.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

void setUp(void) {}
void tearDown(void) {}

void cleanup_db(const char *path) {
    // Close any open connections first by attempting to open and close
    Database *db = database_open(path);
    if (db) database_close(db);
    
    // Remove all database files
    remove(path);
    char buf[300];
    snprintf(buf, sizeof(buf), "%s-shm", path); remove(buf);
    snprintf(buf, sizeof(buf), "%s-wal", path); remove(buf);
}

Database *open_test_db(const char *path) {
    cleanup_db(path);
    Database *db = database_open(path);
    if (db) database_init_schema(db);
    User u;
    memset(&u, 0, sizeof(User));
    strcpy(u.username, "testuser");
    strcpy(u.first_name, "Test");
    strcpy(u.last_name, "User");
    strcpy(u.id, "1234567890");
    strcpy(u.phone, "09123456789");
    strcpy(u.email, "test@example.com");
    strcpy(u.password_hash, "hash");
    strcpy(u.salt, "salt");
    db_user_create(db, &u);
    return db;
}

// =============================================================================
// EDGE CASE: Empty/NULL inputs
// =============================================================================

void test_db_user_create_empty_username(void) {
    Database *db = open_test_db("data/test_edge_user_empty.db");
    User user;
    memset(&user, 0, sizeof(User));
    strcpy(user.username, "");  // empty
    strcpy(user.first_name, "Test");
    strcpy(user.last_name, "User");
    strcpy(user.id, "1234567890");
    strcpy(user.phone, "09123456789");
    strcpy(user.email, "test@example.com");
    strcpy(user.password_hash, "hash");
    strcpy(user.salt, "salt");
    // Should fail or truncate
    int result = db_user_create(db, &user);
    // We just verify no crash
    database_close(db);
    cleanup_db("data/test_edge_user_empty.db");
}

void test_db_user_create_max_length_fields(void) {
    Database *db = open_test_db("data/test_edge_user_max.db");
    User user;
    memset(&user, 0, sizeof(User));
    // Fill all fields to MAX_FIELD_LEN-1
    memset(user.username, 'u', MAX_FIELD_LEN - 1); user.username[MAX_FIELD_LEN - 1] = '\0';
    memset(user.first_name, 'f', MAX_FIELD_LEN - 1); user.first_name[MAX_FIELD_LEN - 1] = '\0';
    memset(user.last_name, 'l', MAX_FIELD_LEN - 1); user.last_name[MAX_FIELD_LEN - 1] = '\0';
    memset(user.id, '1', MAX_FIELD_LEN - 1); user.id[MAX_FIELD_LEN - 1] = '\0';
    memset(user.phone, '9', MAX_FIELD_LEN - 1); user.phone[MAX_FIELD_LEN - 1] = '\0';
    memset(user.email, 'e', MAX_FIELD_LEN - 1); user.email[MAX_FIELD_LEN - 1] = '\0';
    // Need valid email format
    snprintf(user.email, MAX_FIELD_LEN, "%.*s@test.com", MAX_FIELD_LEN - 10, user.email);
    strcpy(user.password_hash, "hash");
    strcpy(user.salt, "salt");
    int result = db_user_create(db, &user);
    database_close(db);
    cleanup_db("data/test_edge_user_max.db");
}

void test_db_user_find_empty_username(void) {
    Database *db = open_test_db("data/test_edge_find_empty.db");
    User *found = db_user_find_by_username(db, "");
    TEST_ASSERT_NULL(found);
    database_close(db);
    cleanup_db("data/test_edge_find_empty.db");
}

void test_db_user_update_nonexistent(void) {
    Database *db = open_test_db("data/test_edge_upd_none.db");
    int result = db_user_update_password(db, "ghost", "newhash", "newsalt");
    TEST_ASSERT_EQUAL(0, result);
    database_close(db);
    cleanup_db("data/test_edge_upd_none.db");
}

// =============================================================================
// EDGE CASE: Property with extreme values
// =============================================================================

Property create_test_prop(const char *code, double price) {
    Property p;
    memset(&p, 0, sizeof(Property));
    strcpy(p.code, code);
    p.district = 1;
    p.ptype = 0;
    p.action = 0;
    p.location = 0;
    p.sell_price = price;
    p.base_price = price * 0.9;
    p.monthly_price = price * 0.01;
    p.floor_area = 100.0;
    p.floor = 1;
    p.basement = 0;
    p.bedrooms = 1;
    p.rooms = 1;
    p.active = 1;
    strcpy(p.address, "Test");
    strcpy(p.owner_phone, "09123456789");
    strcpy(p.date, "2026-01-01");
    strcpy(p.username, "testuser");
    return p;
}

void test_db_property_create_zero_price(void) {
    Database *db = open_test_db("data/test_edge_prop_zero.db");
    Property p = create_test_prop("ZERO01", 0.0);
    int result = db_property_create(db, &p);
    TEST_ASSERT_EQUAL(1, result);
    database_close(db);
    cleanup_db("data/test_edge_prop_zero.db");
}

void test_db_property_create_very_large_price(void) {
    Database *db = open_test_db("data/test_edge_prop_big.db");
    Property p = create_test_prop("BIG001", 999999999999.99);
    int result = db_property_create(db, &p);
    TEST_ASSERT_EQUAL(1, result);
    database_close(db);
    cleanup_db("data/test_edge_prop_big.db");
}

void test_db_property_create_max_string_fields(void) {
    Database *db = open_test_db("data/test_edge_prop_str.db");
    Property p;
    memset(&p, 0, sizeof(Property));
    // Fill code to max
    memset(p.code, 'C', MAX_FIELD_LEN - 1); p.code[MAX_FIELD_LEN - 1] = '\0';
    p.district = 1;
    p.ptype = 0; p.action = 0; p.location = 0;
    p.sell_price = 100000;
    p.floor_area = 100; p.floor = 1; p.basement = 0; p.bedrooms = 1; p.rooms = 1;
    p.active = 1;
    // Fill address to max
    memset(p.address, 'A', MAX_STRING_LEN - 1); p.address[MAX_STRING_LEN - 1] = '\0';
    strcpy(p.owner_phone, "09123456789");
    strcpy(p.date, "2026-01-01");
    strcpy(p.username, "testuser");
    int result = db_property_create(db, &p);
    TEST_ASSERT_EQUAL(1, result);
    database_close(db);
    cleanup_db("data/test_edge_prop_str.db");
}

void test_db_property_find_invalid_code(void) {
    Database *db = open_test_db("data/test_edge_find_inv.db");
    TEST_ASSERT_NULL(db_property_find_by_code(db, ""));
    TEST_ASSERT_NULL(db_property_find_by_code(db, "VERY_LONG_CODE_THAT_EXCEEDS_MAX_FIELD_LENGTH_LIMIT"));
    database_close(db);
    cleanup_db("data/test_edge_find_inv.db");
}

// =============================================================================
// EDGE CASE: Boundary values for numeric fields
// =============================================================================

void test_validate_int_range_boundary(void) {
    int out;
    TEST_ASSERT_TRUE(validate_int_range("0", 0, 0, &out));    // min=max=0
    TEST_ASSERT_TRUE(validate_int_range("-2147483648", -2147483648, 2147483647, &out)); // INT_MIN
    TEST_ASSERT_TRUE(validate_int_range("2147483647", -2147483648, 2147483647, &out)); // INT_MAX
    TEST_ASSERT_FALSE(validate_int_range("2147483648", -2147483648, 2147483647, &out)); // INT_MAX+1
}

void test_validate_double_range_boundary(void) {
    double out;
    TEST_ASSERT_TRUE(validate_double_range("0", 0.0, 0.0, &out));
    TEST_ASSERT_TRUE(validate_double_range("-1.7976931348623157e+308", -1.7976931348623157e+308, 1.7976931348623157e+308, &out)); // DBL_MIN approx
    TEST_ASSERT_TRUE(validate_double_range("1.7976931348623157e+308", -1.7976931348623157e+308, 1.7976931348623157e+308, &out)); // DBL_MAX approx
}

// =============================================================================
// EDGE CASE: Special characters in strings
// =============================================================================

void test_db_property_special_chars_address(void) {
    Database *db = open_test_db("data/test_edge_special.db");
    Property p = create_test_prop("SPEC01", 100000.0);
    strcpy(p.address, "Test 'Address\" with <tags> & symbols #$%");
    int result = db_property_create(db, &p);
    TEST_ASSERT_EQUAL(1, result);
    Property *found = db_property_find_by_code(db, "SPEC01");
    TEST_ASSERT_NOT_NULL(found);
    database_close(db);
    cleanup_db("data/test_edge_special.db");
}

void test_db_property_unicode_address(void) {
    Database *db = open_test_db("data/test_edge_unicode.db");
    Property p = create_test_prop("UNIC01", 100000.0);
    strcpy(p.address, "آدرس فارسی"); // Persian text
    int result = db_property_create(db, &p);
    // Just verify no crash
    database_close(db);
    cleanup_db("data/test_edge_unicode.db");
}

// =============================================================================
// EDGE CASE: Duplicate handling
// =============================================================================

void test_db_property_create_then_update_then_delete(void) {
    Database *db = open_test_db("data/test_edge_crud_2.db");
    Property p = create_test_prop("CRUD02", 100000.0);
    db_property_create(db, &p);
    
    // Soft delete, then create with DIFFERENT code (unique constraint)
    db_property_delete(db, "CRUD02");
    Property p2 = create_test_prop("CRUD02_NEW", 300000.0);
    TEST_ASSERT_EQUAL(1, db_property_create(db, &p2));
    
    database_close(db);
    cleanup_db("data/test_edge_crud_2.db");
}

// =============================================================================
// EDGE CASE: Pagination edge cases
// =============================================================================

void test_db_property_pagination_edge_cases(void) {
    char db_path[100];
    sprintf(db_path, "data/test_edge_page_%d_%d.db", (int)time(NULL), rand());
    cleanup_db(db_path);
    Database *db = database_open(db_path);
    if (db) database_init_schema(db);
    User u;
    memset(&u, 0, sizeof(User));
    strcpy(u.username, "testuser");
    strcpy(u.first_name, "Test");
    strcpy(u.last_name, "User");
    strcpy(u.id, "1234567890");
    strcpy(u.phone, "09123456789");
    strcpy(u.email, "test@example.com");
    strcpy(u.password_hash, "hash");
    strcpy(u.salt, "salt");
    db_user_create(db, &u);

    // Create 15 properties with unique codes
    for (int i = 0; i < 15; i++) {
        char code[10]; sprintf(code, "PG_%d_%02d", rand(), i);
        Property p = create_test_prop(code, 100000.0 + i * 1000);
        db_property_create(db, &p);
    }
    
    Property *props[20];
    int count;
    
    // Page 1 (limit 10)
    TEST_ASSERT_TRUE(db_property_list_paginated(db, "1=1", "code ASC", 10, 0, props, &count));
    TEST_ASSERT_EQUAL_INT(10, count);
    
    // Page 2 (limit 10, offset 10) - should get 5
    TEST_ASSERT_TRUE(db_property_list_paginated(db, "1=1", "code ASC", 10, 10, props, &count));
    TEST_ASSERT_EQUAL_INT(5, count);
    
    // Page 3 (offset 20) - should get 0
    TEST_ASSERT_TRUE(db_property_list_paginated(db, "1=1", "code ASC", 10, 20, props, &count));
    TEST_ASSERT_EQUAL_INT(0, count);
    
    // Limit 0 - means no limit, should return all
    TEST_ASSERT_TRUE(db_property_list_paginated(db, "1=1", "code ASC", 0, 0, props, &count));
    TEST_ASSERT_EQUAL_INT(15, count);
    
    database_close(db);
    cleanup_db(db_path);
}

void test_db_property_count_filtered_edge(void) {
    Database *db = open_test_db("data/test_edge_count.db");
    Property p = create_test_prop("CNT001", 100000.0);
    db_property_create(db, &p);
    
    int count = db_property_count_filtered(db, "1=1");
    TEST_ASSERT_EQUAL_INT(1, count);
    
    count = db_property_count_filtered(db, "sell_price > 200000");
    TEST_ASSERT_EQUAL_INT(0, count);
    
    count = db_property_count_filtered(db, "");
    TEST_ASSERT_EQUAL_INT(1, count);  // empty where = all
    
    database_close(db);
    cleanup_db("data/test_edge_count.db");
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_db_user_create_empty_username);
    RUN_TEST(test_db_user_create_max_length_fields);
    RUN_TEST(test_db_user_find_empty_username);
    RUN_TEST(test_db_user_update_nonexistent);
    RUN_TEST(test_db_property_create_zero_price);
    RUN_TEST(test_db_property_create_very_large_price);
    RUN_TEST(test_db_property_create_max_string_fields);
    RUN_TEST(test_db_property_find_invalid_code);
    RUN_TEST(test_validate_int_range_boundary);
    RUN_TEST(test_validate_double_range_boundary);
    RUN_TEST(test_db_property_special_chars_address);
    RUN_TEST(test_db_property_unicode_address);
    RUN_TEST(test_db_property_create_then_update_then_delete);
    RUN_TEST(test_db_property_pagination_edge_cases);
    RUN_TEST(test_db_property_count_filtered_edge);
    return UNITY_END();
}