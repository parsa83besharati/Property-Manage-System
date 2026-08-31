#include "unity.h"
#include "database.h"
#include "common.h"
#include <stdio.h>
#include <string.h>

void setUp(void) {}
void tearDown(void) {}

// =============================================================================
// DATABASE OPEN/CLOSE
// =============================================================================
void test_database_open(void) {
    Database *db = database_open("data/test_db_open.db");
    TEST_ASSERT_NOT_NULL(db);
    TEST_ASSERT_NOT_NULL(db->db);
    TEST_ASSERT_EQUAL_STRING("data/test_db_open.db", db->db_path);

    database_close(db);
    remove("data/test_db_open.db");
}

void test_database_close(void) {
    Database *db = database_open("data/test_db_close.db");
    TEST_ASSERT_NOT_NULL(db);
    database_close(db);
    // After close, we should be able to reopen
    Database *db2 = database_open("data/test_db_close.db");
    TEST_ASSERT_NOT_NULL(db2);
    database_close(db2);
    remove("data/test_db_close.db");
}

// =============================================================================
// SCHEMA INIT
// =============================================================================
void test_database_init_schema(void) {
    Database *db = database_open("data/test_db_schema.db");
    TEST_ASSERT_NOT_NULL(db);

    int result = database_init_schema(db);
    TEST_ASSERT_EQUAL(1, result);

    database_close(db);
    remove("data/test_db_schema.db");
}

void test_database_init_schema_idempotent(void) {
    Database *db = database_open("data/test_db_schema2.db");
    TEST_ASSERT_NOT_NULL(db);

    int result1 = database_init_schema(db);
    TEST_ASSERT_EQUAL(1, result1);

    int result2 = database_init_schema(db);
    TEST_ASSERT_EQUAL(1, result2);

    database_close(db);
    remove("data/test_db_schema2.db");
}

// =============================================================================
// MIGRATION
// =============================================================================
void test_database_migrate_empty_files(void) {
    Database *db = database_open("data/test_db_migrate.db");
    TEST_ASSERT_NOT_NULL(db);
    TEST_ASSERT_TRUE(database_init_schema(db));

    int result = database_migrate_from_files(db, "data/users.dat", "data/properties.dat");
    TEST_ASSERT_EQUAL(1, result);

    database_close(db);
    remove("data/test_db_migrate.db");
}

// =============================================================================
// CROSS-MODULE: User + Property in same database
// =============================================================================
void test_database_cross_module(void) {
    Database *db = database_open("data/test_db_cross.db");
    TEST_ASSERT_NOT_NULL(db);
    TEST_ASSERT_TRUE(database_init_schema(db));

    User user;
    memset(&user, 0, sizeof(User));
    strcpy(user.username, "crossuser");
    strcpy(user.first_name, "Cross");
    strcpy(user.last_name, "Module");
    strcpy(user.id, "8888888888");
    strcpy(user.phone, "09888888888");
    strcpy(user.email, "cross@example.com");
    strcpy(user.password_hash, "chash");
    strcpy(user.salt, "csalt");
    db_user_create(db, &user);

    Property prop;
    memset(&prop, 0, sizeof(Property));
    strcpy(prop.code, "CRS001");
    prop.district = 10;
    prop.ptype = PROP_TYPE_RESIDENTIAL;
    prop.action = PROP_ACTION_SELL;
    prop.location = LOCATION_NORTH;
    prop.sell_price = 400000.0;
    prop.base_price = 360000.0;
    prop.monthly_price = 4000.0;
    prop.floor_area = 120.0;
    prop.floor = 4;
    prop.basement = 1;
    prop.bedrooms = 3;
    prop.rooms = 2;
    prop.active = 1;
    strcpy(prop.address, "Cross Module Address");
    strcpy(prop.owner_phone, "09888888888");
    strcpy(prop.date, "2026-01-20");
    strcpy(prop.username, "crossuser");
    db_property_create(db, &prop);

    User *found_user = db_user_find_by_username(db, "crossuser");
    Property *found_prop = db_property_find_by_code(db, "CRS001");
    TEST_ASSERT_NOT_NULL(found_user);
    TEST_ASSERT_NOT_NULL(found_prop);
    TEST_ASSERT_EQUAL_STRING("crossuser", found_prop->username);

    database_close(db);
    remove("data/test_db_cross.db");
}