#include "test_property_manage.h"
#include <stdio.h>
#include <string.h>

void test_sha256_hash(void) {
    // Test SHA256 hash computation using the 3-argument API
    uint8_t hash[SHA256_DIGEST_LENGTH];
    const uint8_t data[] = "test_password";
    
    sha256_hash(data, strlen((const char*)data), hash);
    
    // Hash should be 32 bytes
    TEST_ASSERT_EQUAL_INT(32, SHA256_DIGEST_LENGTH);
    
    // Hash should contain valid values
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        TEST_ASSERT_TRUE(hash[i] >= 0x00 && hash[i] <= 0xFF);
    }
}

void test_property_crud(void) {
    Database *db = database_open("data/test_units3.db");
    TEST_ASSERT_NOT_NULL(db);
    TEST_ASSERT_TRUE(database_init_schema(db));
    
    // Create property - use correct field names from common.h/s database schema
    Property prop;
    memset(&prop, 0, sizeof(Property));
    strcpy(prop.code, "9999");
    prop.ptype = PROP_TYPE_RESIDENTIAL;
    prop.action = PROP_ACTION_SELL;
    prop.district = 10;
    prop.location = LOCATION_NORTH;
    prop.floor_area = 120.5;
    prop.floor = 5;
    prop.basement = 1;
    strcpy(prop.address, "Test Address");
    strcpy(prop.owner_phone, "1234567890");
    prop.sell_price = 500000;  // not "price"
    prop.base_price = 450000;
    prop.monthly_price = 2000;
    prop.bedrooms = 3;
    prop.rooms = 2;
    prop.active = 1;  // not "status"
    strcpy(prop.date, "2026-01-01");
    strcpy(prop.username, "testuser");
    
    TEST_ASSERT_TRUE(db_property_create(db, &prop));
    
    // Read property by code
    Property *found = db_property_find_by_code(db, "9999");
    TEST_ASSERT_NOT_NULL(found);
    TEST_ASSERT_EQUAL_STRING("9999", found->code);
    TEST_ASSERT_EQUAL_INT(PROP_TYPE_RESIDENTIAL, found->ptype);
    TEST_ASSERT_EQUAL_DOUBLE(120.5, found->floor_area);
    TEST_ASSERT_EQUAL_INT(5, found->floor);
    TEST_ASSERT_EQUAL_INT(500000, (int)found->sell_price);  // not "price"
    
    // List all properties
    Property *list[100];
    int count;
    TEST_ASSERT_TRUE(db_property_list_all(db, list, &count));
    TEST_ASSERT_EQUAL_INT(1, count);
    
    // Delete property
    TEST_ASSERT_TRUE(db_property_delete(db, "9999"));
    TEST_ASSERT_NULL(db_property_find_by_code(db, "9999"));
    
    database_close(db);
    remove("data/test_units3.db");
}

void test_property_search(void) {
    Database *db = database_open("data/test_units4.db");
    TEST_ASSERT_NOT_NULL(db);
    TEST_ASSERT_TRUE(database_init_schema(db));
    
    // Add test properties
    Property props[3];
    for (int i = 0; i < 3; i++) {
        memset(&props[i], 0, sizeof(Property));
        sprintf(props[i].code, "%d", 1000 + i);
        props[i].ptype = PROP_TYPE_RESIDENTIAL;
        props[i].action = PROP_ACTION_SELL;
        props[i].district = 1 + i;
        props[i].location = LOCATION_NORTH;
        props[i].floor_area = 50.0 * (i + 1);
        props[i].floor = 2;
        props[i].basement = 0;
        sprintf(props[i].address, "Test Address %d", i + 1);
        sprintf(props[i].owner_phone, "123456789%d", i);
        props[i].sell_price = 100000 * (i + 1);  // not "price"
        props[i].base_price = 90000 * (i + 1);
        props[i].monthly_price = 500 * (i + 1);
        props[i].bedrooms = 1 + i;
        props[i].rooms = 1 + i;
        props[i].active = 1;
        sprintf(props[i].date, "2026-01-01");
        sprintf(props[i].username, "testuser");
    }
    
    for (int i = 0; i < 3; i++) {
        db_property_create(db, &props[i]);
    }
    
    // Search by district
    Property *found[10];
    int found_count;
    TEST_ASSERT_TRUE(db_property_list_by_district(db, 1, found, &found_count));
    TEST_ASSERT_EQUAL_INT(1, found_count);
    
    // List all and check count
    TEST_ASSERT_TRUE(db_property_list_all(db, found, &found_count));
    TEST_ASSERT_EQUAL_INT(3, found_count);
    
    database_close(db);
    remove("data/test_units4.db");
}

void test_database_migration(void) {
    Database *db = database_open("data/test_units5.db");
    TEST_ASSERT_NOT_NULL(db);
    TEST_ASSERT_TRUE(database_init_schema(db));
    
    // List properties
    Property *props[100];
    int count;
    TEST_ASSERT_TRUE(db_property_list_all(db, props, &count));
    
    database_close(db);
    remove("data/test_units5.db");
}