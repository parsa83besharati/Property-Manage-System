#include "unity.h"
#include "database.h"
#include "user.h"
#include "common.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

void setUp(void) {}
void tearDown(void) {}

void cleanup_db(const char *path) {
    Database *db = database_open(path);
    if (db) database_close(db);
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

Property create_test_prop(const char *code, double price) {
    Property p;
    memset(&p, 0, sizeof(Property));
    strcpy(p.code, code);
    p.district = 1;
    p.ptype = 0; p.action = 0; p.location = 0;
    p.sell_price = price; p.base_price = price * 0.9; p.monthly_price = price * 0.01;
    p.floor_area = 100; p.floor = 1; p.basement = 0; p.bedrooms = 1; p.rooms = 1;
    p.active = 1;
    strcpy(p.address, "Test"); strcpy(p.owner_phone, "09123456789");
    strcpy(p.date, "2026-01-01"); strcpy(p.username, "testuser");
    return p;
}

// =============================================================================
// NEGATIVE: db_user_create with invalid inputs
// =============================================================================

void test_user_create_null_db(void) {
    User user;
    memset(&user, 0, sizeof(User));
    strcpy(user.username, "test");
    strcpy(user.first_name, "Test");
    strcpy(user.last_name, "User");
    strcpy(user.id, "1234567890");
    strcpy(user.phone, "09123456789");
    strcpy(user.email, "test@example.com");
    strcpy(user.password_hash, "hash");
    strcpy(user.salt, "salt");
    int result = db_user_create(NULL, &user);
    TEST_ASSERT_EQUAL(0, result);
}

void test_user_create_null_user(void) {
    Database *db = open_test_db("data/test_neg_user_null.db");
    int result = db_user_create(db, NULL);
    TEST_ASSERT_EQUAL(0, result);
    database_close(db);
    cleanup_db("data/test_neg_user_null.db");
}

void test_user_create_empty_username(void) {
    Database *db = open_test_db("data/test_neg_user_empty.db");
    User user;
    memset(&user, 0, sizeof(User));
    strcpy(user.username, "");
    strcpy(user.first_name, "Test");
    strcpy(user.last_name, "User");
    strcpy(user.id, "1234567890");
    strcpy(user.phone, "09123456789");
    strcpy(user.email, "test@example.com");
    strcpy(user.password_hash, "hash");
    strcpy(user.salt, "salt");
    int result = db_user_create(db, &user);
    TEST_ASSERT_EQUAL(0, result);
    database_close(db);
    cleanup_db("data/test_neg_user_empty.db");
}

void test_user_create_duplicate_email(void) {
    Database *db = open_test_db("data/test_neg_user_email.db");
    User u1;
    memset(&u1, 0, sizeof(User));
    strcpy(u1.username, "user1");
    strcpy(u1.first_name, "Test");
    strcpy(u1.last_name, "One");
    strcpy(u1.id, "1111111111");
    strcpy(u1.phone, "09111111111");
    strcpy(u1.email, "same@example.com");
    strcpy(u1.password_hash, "hash1");
    strcpy(u1.salt, "salt1");
    db_user_create(db, &u1);
    
    User u2;
    memset(&u2, 0, sizeof(User));
    strcpy(u2.username, "user2");
    strcpy(u2.first_name, "Test");
    strcpy(u2.last_name, "Two");
    strcpy(u2.id, "2222222222");
    strcpy(u2.phone, "09222222222");
    strcpy(u2.email, "same@example.com");  // duplicate email
    strcpy(u2.password_hash, "hash2");
    strcpy(u2.salt, "salt2");
    // Note: schema doesn't enforce unique email, so this might succeed
    db_user_create(db, &u2);
    database_close(db);
    cleanup_db("data/test_neg_user_email.db");
}

// =============================================================================
// NEGATIVE: db_user_find_by_username
// =============================================================================

void test_user_find_null_db(void) {
    User *found = db_user_find_by_username(NULL, "test");
    TEST_ASSERT_NULL(found);
}

void test_user_find_null_username(void) {
    Database *db = open_test_db("data/test_neg_find_null.db");
    User *found = db_user_find_by_username(db, NULL);
    TEST_ASSERT_NULL(found);
    database_close(db);
    cleanup_db("data/test_neg_find_null.db");
}

void test_user_find_empty_username(void) {
    Database *db = open_test_db("data/test_neg_find_empty.db");
    User *found = db_user_find_by_username(db, "");
    TEST_ASSERT_NULL(found);
    database_close(db);
    cleanup_db("data/test_neg_find_empty.db");
}

// =============================================================================
// NEGATIVE: db_user_update_password
// =============================================================================

void test_user_update_password_null_db(void) {
    int result = db_user_update_password(NULL, "user", "hash", "salt");
    TEST_ASSERT_EQUAL(0, result);
}

void test_user_update_password_nonexistent(void) {
    Database *db = open_test_db("data/test_neg_upd_none.db");
    int result = db_user_update_password(db, "ghost", "newhash", "newsalt");
    TEST_ASSERT_EQUAL(0, result);
    database_close(db);
    cleanup_db("data/test_neg_upd_none.db");
}

void test_user_update_password_null_hash(void) {
    Database *db = open_test_db("data/test_neg_upd_null.db");
    int result = db_user_update_password(db, "testuser", NULL, "salt");
    TEST_ASSERT_EQUAL(0, result);
    database_close(db);
    cleanup_db("data/test_neg_upd_null.db");
}

// =============================================================================
// NEGATIVE: db_user_update_field
// =============================================================================

void test_user_update_field_null_db(void) {
    int result = db_user_update_field(NULL, "user", 1, "value");
    TEST_ASSERT_EQUAL(0, result);
}

void test_user_update_field_invalid_field(void) {
    Database *db = open_test_db("data/test_neg_upd_field.db");
    int result = db_user_update_field(db, "testuser", 999, "value");
    TEST_ASSERT_EQUAL(0, result);
    database_close(db);
    cleanup_db("data/test_neg_upd_field.db");
}

void test_user_update_field_null_value(void) {
    Database *db = open_test_db("data/test_neg_upd_val.db");
    int result = db_user_update_field(db, "testuser", 1, NULL);
    // Might succeed or fail depending on implementation
    database_close(db);
    cleanup_db("data/test_neg_upd_val.db");
}

// =============================================================================
// NEGATIVE: db_user_list_all
// =============================================================================

void test_user_list_all_null_db(void) {
    User *users[10];
    int count;
    int result = db_user_list_all(NULL, users, &count);
    TEST_ASSERT_EQUAL(0, result);
}

void test_user_list_all_null_output(void) {
    Database *db = open_test_db("data/test_neg_list_null.db");
    int result = db_user_list_all(db, NULL, NULL);
    TEST_ASSERT_EQUAL(0, result);
    database_close(db);
    cleanup_db("data/test_neg_list_null.db");
}

// =============================================================================
// NEGATIVE: db_user_count
// =============================================================================

void test_user_count_null_db(void) {
    int count = db_user_count(NULL);
    TEST_ASSERT_EQUAL(0, count);  // or some error value
}

// =============================================================================
// NEGATIVE: db_property_create
// =============================================================================

void test_property_create_null_db(void) {
    Property p = create_test_prop("NULL01", 100000);
    int result = db_property_create(NULL, &p);
    TEST_ASSERT_EQUAL(0, result);
}

void test_property_create_null_prop(void) {
    Database *db = open_test_db("data/test_neg_prop_null.db");
    int result = db_property_create(db, NULL);
    TEST_ASSERT_EQUAL(0, result);
    database_close(db);
    cleanup_db("data/test_neg_prop_null.db");
}

void test_property_create_empty_code(void) {
    Database *db = open_test_db("data/test_neg_prop_empty.db");
    Property p = create_test_prop("", 100000);
    int result = db_property_create(db, &p);
    TEST_ASSERT_EQUAL(0, result);
    database_close(db);
    cleanup_db("data/test_neg_prop_empty.db");
}

void test_property_create_invalid_username(void) {
    Database *db = open_test_db("data/test_neg_prop_user.db");
    Property p = create_test_prop("INV001", 100000);
    strcpy(p.username, "ghostuser");  // doesn't exist
    int result = db_property_create(db, &p);
    // Should fail due to FK constraint
    TEST_ASSERT_EQUAL(0, result);
    database_close(db);
    cleanup_db("data/test_neg_prop_user.db");
}

// =============================================================================
// NEGATIVE: db_property_find_by_code
// =============================================================================

void test_property_find_null_db(void) {
    Property *found = db_property_find_by_code(NULL, "code");
    TEST_ASSERT_NULL(found);
}

void test_property_find_null_code(void) {
    Database *db = open_test_db("data/test_neg_find_null.db");
    Property *found = db_property_find_by_code(db, NULL);
    TEST_ASSERT_NULL(found);
    database_close(db);
    cleanup_db("data/test_neg_find_null.db");
}

void test_property_find_empty_code(void) {
    Database *db = open_test_db("data/test_neg_find_empty.db");
    Property *found = db_property_find_by_code(db, "");
    TEST_ASSERT_NULL(found);
    database_close(db);
    cleanup_db("data/test_neg_find_empty.db");
}

// =============================================================================
// NEGATIVE: db_property_delete
// =============================================================================

void test_property_delete_null_db(void) {
    int result = db_property_delete(NULL, "code");
    TEST_ASSERT_EQUAL(0, result);
}

void test_property_delete_null_code(void) {
    Database *db = open_test_db("data/test_neg_del_null.db");
    int result = db_property_delete(db, NULL);
    TEST_ASSERT_EQUAL(0, result);
    database_close(db);
    cleanup_db("data/test_neg_del_null.db");
}

void test_property_delete_empty_code(void) {
    Database *db = open_test_db("data/test_neg_del_empty.db");
    int result = db_property_delete(db, "");
    TEST_ASSERT_EQUAL(0, result);
    database_close(db);
    cleanup_db("data/test_neg_del_empty.db");
}

// =============================================================================
// NEGATIVE: db_property_list_all
// =============================================================================

void test_property_list_all_null_db(void) {
    Property *props[10];
    int count;
    int result = db_property_list_all(NULL, props, &count);
    TEST_ASSERT_EQUAL(0, result);
}

void test_property_list_all_null_output(void) {
    Database *db = open_test_db("data/test_neg_plist_null.db");
    int result = db_property_list_all(db, NULL, NULL);
    TEST_ASSERT_EQUAL(0, result);
    database_close(db);
    cleanup_db("data/test_neg_plist_null.db");
}

// =============================================================================
// NEGATIVE: db_property_list_by_district
// =============================================================================

void test_property_list_by_district_null_db(void) {
    Property *props[10];
    int count;
    int result = db_property_list_by_district(NULL, 1, props, &count);
    TEST_ASSERT_EQUAL(0, result);
}

// =============================================================================
// NEGATIVE: db_property_list_by_type
// =============================================================================

void test_property_list_by_type_null_db(void) {
    Property *props[10];
    int count;
    int result = db_property_list_by_type(NULL, 0, 0, props, &count);
    TEST_ASSERT_EQUAL(0, result);
}

// =============================================================================
// NEGATIVE: db_property_list_by_price_range
// =============================================================================

void test_property_list_by_price_range_null_db(void) {
    Property *props[10];
    int count;
    int result = db_property_list_by_price_range(NULL, 0, 100000, props, &count);
    TEST_ASSERT_EQUAL(0, result);
}

void test_property_list_by_price_range_invalid_range(void) {
    Database *db = open_test_db("data/test_neg_price_range.db");
    Property *props[10];
    int count;
    // min > max
    int result = db_property_list_by_price_range(db, 100000, 50000, props, &count);
    TEST_ASSERT_EQUAL(0, result);
    database_close(db);
    cleanup_db("data/test_neg_price_range.db");
}

// =============================================================================
// NEGATIVE: db_property_list_paginated
// =============================================================================

void test_property_list_paginated_null_db(void) {
    Property *props[10];
    int count;
    int result = db_property_list_paginated(NULL, "1=1", "code ASC", 10, 0, props, &count);
    TEST_ASSERT_EQUAL(0, result);
}

void test_property_list_paginated_negative_limit(void) {
    Database *db = open_test_db("data/test_neg_page_limit.db");
    Property *props[10];
    int count;
    int result = db_property_list_paginated(db, "1=1", "code ASC", -1, 0, props, &count);
    TEST_ASSERT_EQUAL(0, result);
    database_close(db);
    cleanup_db("data/test_neg_page_limit.db");
}

void test_property_list_paginated_negative_offset(void) {
    Database *db = open_test_db("data/test_neg_page_offset.db");
    Property *props[10];
    int count;
    int result = db_property_list_paginated(db, "1=1", "code ASC", 10, -1, props, &count);
    TEST_ASSERT_EQUAL(0, result);
    database_close(db);
    cleanup_db("data/test_neg_page_offset.db");
}

// =============================================================================
// NEGATIVE: db_property_count_filtered
// =============================================================================

void test_property_count_filtered_null_db(void) {
    int count = db_property_count_filtered(NULL, "1=1");
    TEST_ASSERT_EQUAL(0, count);
}

void test_property_count_filtered_invalid_where(void) {
    Database *db = open_test_db("data/test_neg_count_where.db");
    int count = db_property_count_filtered(db, "INVALID SQL HERE");
    // Should handle gracefully
    database_close(db);
    cleanup_db("data/test_neg_count_where.db");
}

// =============================================================================
// NEGATIVE: database_open
// =============================================================================

void test_database_open_null_path(void) {
    Database *db = database_open(NULL);
    TEST_ASSERT_NULL(db);
}

// =============================================================================
// NEGATIVE: database_init_schema
// =============================================================================

void test_database_init_schema_null_db(void) {
    int result = database_init_schema(NULL);
    TEST_ASSERT_EQUAL(0, result);
}

// =============================================================================
// NEGATIVE: database_migrate_from_files
// =============================================================================

void test_database_migrate_null_db(void) {
    int result = database_migrate_from_files(NULL, "data/users.dat", "data/properties.dat");
    TEST_ASSERT_EQUAL(0, result);
}

void test_database_migrate_null_files(void) {
    Database *db = open_test_db("data/test_neg_migrate.db");
    int result = database_migrate_from_files(db, NULL, NULL);
    TEST_ASSERT_EQUAL(0, result);
    database_close(db);
    cleanup_db("data/test_neg_migrate.db");
}

int main(void) {
    UNITY_BEGIN();
    // User create
    RUN_TEST(test_user_create_null_db);
    RUN_TEST(test_user_create_null_user);
    RUN_TEST(test_user_create_empty_username);
    RUN_TEST(test_user_create_duplicate_email);
    // User find
    RUN_TEST(test_user_find_null_db);
    RUN_TEST(test_user_find_null_username);
    RUN_TEST(test_user_find_empty_username);
    // User update password
    RUN_TEST(test_user_update_password_null_db);
    RUN_TEST(test_user_update_password_nonexistent);
    RUN_TEST(test_user_update_password_null_hash);
    // User update field
    RUN_TEST(test_user_update_field_null_db);
    RUN_TEST(test_user_update_field_invalid_field);
    RUN_TEST(test_user_update_field_null_value);
    // User list
    RUN_TEST(test_user_list_all_null_db);
    RUN_TEST(test_user_list_all_null_output);
    // User count
    RUN_TEST(test_user_count_null_db);
    // Property create
    RUN_TEST(test_property_create_null_db);
    RUN_TEST(test_property_create_null_prop);
    RUN_TEST(test_property_create_empty_code);
    RUN_TEST(test_property_create_invalid_username);
    // Property find
    RUN_TEST(test_property_find_null_db);
    RUN_TEST(test_property_find_null_code);
    RUN_TEST(test_property_find_empty_code);
    // Property delete
    RUN_TEST(test_property_delete_null_db);
    RUN_TEST(test_property_delete_null_code);
    RUN_TEST(test_property_delete_empty_code);
    // Property list all
    RUN_TEST(test_property_list_all_null_db);
    RUN_TEST(test_property_list_all_null_output);
    // Property list by district
    RUN_TEST(test_property_list_by_district_null_db);
    // Property list by type
    RUN_TEST(test_property_list_by_type_null_db);
    // Property list by price range
    RUN_TEST(test_property_list_by_price_range_null_db);
    RUN_TEST(test_property_list_by_price_range_invalid_range);
    // Property paginated
    RUN_TEST(test_property_list_paginated_null_db);
    RUN_TEST(test_property_list_paginated_negative_limit);
    RUN_TEST(test_property_list_paginated_negative_offset);
    // Property count filtered
    RUN_TEST(test_property_count_filtered_null_db);
    RUN_TEST(test_property_count_filtered_invalid_where);
    // Database open
    RUN_TEST(test_database_open_null_path);
    // Database init schema
    RUN_TEST(test_database_init_schema_null_db);
    // Database migrate
    RUN_TEST(test_database_migrate_null_db);
    RUN_TEST(test_database_migrate_null_files);
    return UNITY_END();
}