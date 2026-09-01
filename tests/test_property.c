#include "unity.h"
#include "database.h"
#include "common.h"
#include <stdio.h>
#include <string.h>

void setUp(void) {}
void tearDown(void) {}

Property create_test_property(const char *code, int district, PropertyType ptype,
                              PropertyAction action, double sell_price) {
    Property prop;
    memset(&prop, 0, sizeof(Property));
    strcpy(prop.code, code);
    prop.district = district;
    prop.ptype = ptype;
    prop.action = action;
    prop.location = LOCATION_NORTH;
    prop.sell_price = sell_price;
    prop.base_price = sell_price * 0.9;
    prop.monthly_price = sell_price * 0.01;
    prop.floor_area = 100.0;
    prop.floor = 3;
    prop.basement = 1;
    prop.bedrooms = 3;
    prop.rooms = 2;
    prop.active = 1;
    strcpy(prop.address, "Test Address");
    strcpy(prop.owner_phone, "09123456789");
    strcpy(prop.date, "2026-01-15");
    strcpy(prop.username, "testuser");
    return prop;
}

// =============================================================================
// CREATE
// =============================================================================
void test_property_create_residential_sell(void) {
    Database *db = database_open("data/test_prop_create.db");
    TEST_ASSERT_NOT_NULL(db);
    TEST_ASSERT_TRUE(database_init_schema(db));

    Property prop = create_test_property("P001", 10, PROP_TYPE_RESIDENTIAL, PROP_ACTION_SELL, 500000.0);
    int result = db_property_create(db, &prop);
    TEST_ASSERT_EQUAL(1, result);

    Property *found = db_property_find_by_code(db, "P001");
    TEST_ASSERT_NOT_NULL(found);
    TEST_ASSERT_EQUAL_STRING("P001", found->code);
    TEST_ASSERT_EQUAL_INT(10, found->district);
    TEST_ASSERT_EQUAL_DOUBLE(500000.0, found->sell_price);

    database_close(db);
    remove("data/test_prop_create.db");
}

void test_property_create_duplicate_code(void) {
    Database *db = database_open("data/test_prop_dup.db");
    TEST_ASSERT_NOT_NULL(db);
    TEST_ASSERT_TRUE(database_init_schema(db));

    Property prop1 = create_test_property("DUP001", 5, PROP_TYPE_RESIDENTIAL, PROP_ACTION_SELL, 100000.0);
    Property prop2 = create_test_property("DUP001", 6, PROP_TYPE_COMMERCIAL, PROP_ACTION_RENT, 200000.0);

    db_property_create(db, &prop1);
    int result = db_property_create(db, &prop2);
    TEST_ASSERT_EQUAL(0, result);

    database_close(db);
    remove("data/test_prop_dup.db");
}

// =============================================================================
// READ
// =============================================================================
void test_property_find_by_code(void) {
    Database *db = database_open("data/test_prop_find.db");
    TEST_ASSERT_NOT_NULL(db);
    TEST_ASSERT_TRUE(database_init_schema(db));

    Property prop = create_test_property("FIND001", 15, PROP_TYPE_LAND, PROP_ACTION_SELL, 300000.0);
    db_property_create(db, &prop);

    Property *found = db_property_find_by_code(db, "FIND001");
    TEST_ASSERT_NOT_NULL(found);
    TEST_ASSERT_EQUAL_STRING("FIND001", found->code);
    TEST_ASSERT_EQUAL_INT(PROP_TYPE_LAND, found->ptype);
    TEST_ASSERT_EQUAL_DOUBLE(300000.0, found->sell_price);

    database_close(db);
    remove("data/test_prop_find.db");
}

void test_property_find_nonexistent(void) {
    Database *db = database_open("data/test_prop_notfound.db");
    TEST_ASSERT_NOT_NULL(db);
    TEST_ASSERT_TRUE(database_init_schema(db));

    Property *found = db_property_find_by_code(db, "NOPE");
    TEST_ASSERT_NULL(found);

    database_close(db);
    remove("data/test_prop_notfound.db");
}

// =============================================================================
// DELETE
// =============================================================================
void test_property_delete_success(void) {
    Database *db = database_open("data/test_prop_del.db");
    TEST_ASSERT_NOT_NULL(db);
    TEST_ASSERT_TRUE(database_init_schema(db));

    Property prop = create_test_property("DEL001", 20, PROP_TYPE_RESIDENTIAL, PROP_ACTION_RENT, 1500.0);
    db_property_create(db, &prop);

    int result = db_property_delete(db, "DEL001");
    TEST_ASSERT_EQUAL(1, result);

    Property *found = db_property_find_by_code(db, "DEL001");
    TEST_ASSERT_NULL(found);

    database_close(db);
    remove("data/test_prop_del.db");
}

void test_property_delete_nonexistent(void) {
    Database *db = database_open("data/test_prop_delnone.db");
    TEST_ASSERT_NOT_NULL(db);
    TEST_ASSERT_TRUE(database_init_schema(db));

    int result = db_property_delete(db, "GHOST");
    TEST_ASSERT_EQUAL(0, result);

    database_close(db);
    remove("data/test_prop_delnone.db");
}

// =============================================================================
// LIST ALL
// =============================================================================
void test_property_list_all(void) {
    Database *db = database_open("data/test_prop_list.db");
    TEST_ASSERT_NOT_NULL(db);
    TEST_ASSERT_TRUE(database_init_schema(db));

    for (int i = 0; i < 3; i++) {
        char code[10];
        sprintf(code, "LST%03d", i);
        Property prop = create_test_property(code, 1 + i, PROP_TYPE_RESIDENTIAL, PROP_ACTION_SELL, 100000 * (i + 1));
        db_property_create(db, &prop);
    }

    Property *props[10];
    int count;
    int result = db_property_list_all(db, props, &count);
    TEST_ASSERT_EQUAL(1, result);
    TEST_ASSERT_EQUAL_INT(3, count);

    database_close(db);
    remove("data/test_prop_list.db");
}

// =============================================================================
// FILTER BY DISTRICT
// =============================================================================
void test_property_list_by_district(void) {
    Database *db = database_open("data/test_prop_district.db");
    TEST_ASSERT_NOT_NULL(db);
    TEST_ASSERT_TRUE(database_init_schema(db));

    Property p1 = create_test_property("DIS001", 1, PROP_TYPE_RESIDENTIAL, PROP_ACTION_SELL, 100000.0);
    Property p2 = create_test_property("DIS002", 2, PROP_TYPE_RESIDENTIAL, PROP_ACTION_SELL, 200000.0);
    Property p3 = create_test_property("DIS003", 1, PROP_TYPE_COMMERCIAL, PROP_ACTION_RENT, 300000.0);
    db_property_create(db, &p1);
    db_property_create(db, &p2);
    db_property_create(db, &p3);

    Property *found[10];
    int count;
    db_property_list_by_district(db, 1, found, &count);
    TEST_ASSERT_EQUAL_INT(2, count);

    database_close(db);
    remove("data/test_prop_district.db");
}

// =============================================================================
// FILTER BY TYPE
// =============================================================================
void test_property_list_by_type(void) {
    Database *db = database_open("data/test_prop_type.db");
    TEST_ASSERT_NOT_NULL(db);
    TEST_ASSERT_TRUE(database_init_schema(db));

    Property p1 = create_test_property("TYP001", 1, PROP_TYPE_RESIDENTIAL, PROP_ACTION_SELL, 100000.0);
    Property p2 = create_test_property("TYP002", 2, PROP_TYPE_RESIDENTIAL, PROP_ACTION_SELL, 200000.0);
    Property p3 = create_test_property("TYP003", 3, PROP_TYPE_COMMERCIAL, PROP_ACTION_SELL, 300000.0);
    db_property_create(db, &p1);
    db_property_create(db, &p2);
    db_property_create(db, &p3);

    Property *found[10];
    int count;
    db_property_list_by_type(db, PROP_TYPE_RESIDENTIAL, PROP_ACTION_SELL, found, &count);
    TEST_ASSERT_EQUAL_INT(2, count);

    database_close(db);
    remove("data/test_prop_type.db");
}

// =============================================================================
// FILTER BY PRICE RANGE
// =============================================================================
void test_property_list_by_price_range(void) {
    Database *db = database_open("data/test_prop_price.db");
    TEST_ASSERT_NOT_NULL(db);
    TEST_ASSERT_TRUE(database_init_schema(db));

    Property p1 = create_test_property("PRC001", 1, PROP_TYPE_RESIDENTIAL, PROP_ACTION_SELL, 50000.0);
    Property p2 = create_test_property("PRC002", 2, PROP_TYPE_RESIDENTIAL, PROP_ACTION_SELL, 150000.0);
    Property p3 = create_test_property("PRC003", 3, PROP_TYPE_RESIDENTIAL, PROP_ACTION_SELL, 250000.0);
    Property p4 = create_test_property("PRC004", 4, PROP_TYPE_RESIDENTIAL, PROP_ACTION_SELL, 500000.0);
    db_property_create(db, &p1);
    db_property_create(db, &p2);
    db_property_create(db, &p3);
    db_property_create(db, &p4);

    Property *found[10];
    int count;
    db_property_list_by_price_range(db, 100000.0, 300000.0, found, &count);
    TEST_ASSERT_EQUAL_INT(2, count);

    database_close(db);
    remove("data/test_prop_price.db");
}

// =============================================================================
// COUNT BY TYPE
// =============================================================================
void test_property_count_by_type(void) {
    Database *db = database_open("data/test_prop_count.db");
    TEST_ASSERT_NOT_NULL(db);
    TEST_ASSERT_TRUE(database_init_schema(db));

    Property p1 = create_test_property("CNT001", 1, PROP_TYPE_RESIDENTIAL, PROP_ACTION_SELL, 100000.0);
    Property p2 = create_test_property("CNT002", 2, PROP_TYPE_RESIDENTIAL, PROP_ACTION_SELL, 200000.0);
    Property p3 = create_test_property("CNT003", 3, PROP_TYPE_COMMERCIAL, PROP_ACTION_RENT, 300000.0);
    db_property_create(db, &p1);
    db_property_create(db, &p2);
    db_property_create(db, &p3);

    int count = db_property_count_by_type(db, PROP_TYPE_RESIDENTIAL, PROP_ACTION_SELL);
    TEST_ASSERT_EQUAL_INT(2, count);

    database_close(db);
    remove("data/test_prop_count.db");
}

// =============================================================================
// EMPTY DATABASE
// =============================================================================
void test_property_empty_database(void) {
    Database *db = database_open("data/test_prop_empty.db");
    TEST_ASSERT_NOT_NULL(db);
    TEST_ASSERT_TRUE(database_init_schema(db));

    Property *found = db_property_find_by_code(db, "EMPTY");
    TEST_ASSERT_NULL(found);

    Property *props[10];
    int count;
    db_property_list_all(db, props, &count);
    TEST_ASSERT_EQUAL_INT(0, count);

    database_close(db);
    remove("data/test_prop_empty.db");
}

// =============================================================================
// IMAGE PATH
// =============================================================================
void test_property_image_path_empty_by_default(void) {
    Database *db = database_open("data/test_prop_img_empty.db");
    TEST_ASSERT_NOT_NULL(db);
    TEST_ASSERT_TRUE(database_init_schema(db));

    Property prop = create_test_property("IMG001", 1, PROP_TYPE_RESIDENTIAL, PROP_ACTION_SELL, 100000.0);
    // Don't set image_path - should default to empty
    db_property_create(db, &prop);

    Property *found = db_property_find_by_code(db, "IMG001");
    TEST_ASSERT_NOT_NULL(found);
    TEST_ASSERT_EQUAL_STRING("", found->image_path);

    database_close(db);
    remove("data/test_prop_img_empty.db");
}

void test_property_image_path_set_and_get(void) {
    Database *db = database_open("data/test_prop_img_set.db");
    TEST_ASSERT_NOT_NULL(db);
    TEST_ASSERT_TRUE(database_init_schema(db));

    Property prop = create_test_property("IMG002", 1, PROP_TYPE_RESIDENTIAL, PROP_ACTION_SELL, 200000.0);
    strcpy(prop.image_path, "/images/property1.jpg");
    db_property_create(db, &prop);

    Property *found = db_property_find_by_code(db, "IMG002");
    TEST_ASSERT_NOT_NULL(found);
    TEST_ASSERT_EQUAL_STRING("/images/property1.jpg", found->image_path);

    database_close(db);
    remove("data/test_prop_img_set.db");
}

void test_property_image_path_long_path(void) {
    Database *db = database_open("data/test_prop_img_long.db");
    TEST_ASSERT_NOT_NULL(db);
    TEST_ASSERT_TRUE(database_init_schema(db));

    Property prop = create_test_property("IMG003", 1, PROP_TYPE_RESIDENTIAL, PROP_ACTION_SELL, 300000.0);
    // Test with a long path (near MAX_STRING_LEN)
    char long_path[MAX_STRING_LEN];
    memset(long_path, 'a', MAX_STRING_LEN - 1);
    long_path[MAX_STRING_LEN - 1] = '\0';
    strcpy(prop.image_path, long_path);
    db_property_create(db, &prop);

    Property *found = db_property_find_by_code(db, "IMG003");
    TEST_ASSERT_NOT_NULL(found);
    TEST_ASSERT_EQUAL_STRING(long_path, found->image_path);

    database_close(db);
    remove("data/test_prop_img_long.db");
}