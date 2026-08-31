#include "unity.h"
#include "database.h"
#include "audit.h"
#include "user.h"
#include "common.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void setUp(void) {}
void tearDown(void) {}

void cleanup_db(const char *path) {
    char full_path[300];
    snprintf(full_path, sizeof(full_path), "data/%s", path);
    remove(full_path);
    char buf[300];
    snprintf(buf, sizeof(buf), "%s-shm", full_path); remove(buf);
    snprintf(buf, sizeof(buf), "%s-wal", full_path); remove(buf);
}

Database *open_test_db(const char *path) {
    char full_path[300];
    snprintf(full_path, sizeof(full_path), "data/%s", path);
    cleanup_db(path);
    Database *db = database_open(full_path);
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

void test_audit_log_basic(void) {
    char db_path[100];
    sprintf(db_path, "test_audit_%d.db", rand());
    Database *db = open_test_db(db_path);
    TEST_ASSERT_NOT_NULL(db);
    
    int r = audit_log(db, "testuser", AUDIT_CREATE, AUDIT_ENTITY_PROPERTY, "PROP001", "Created property");
    TEST_ASSERT_EQUAL(1, r);
    
    char **logs = NULL;
    int count = 0;
    r = audit_get_logs(db, "testuser", -1, -1, NULL, 10, 0, &logs, &count);
    TEST_ASSERT_EQUAL(1, r);
    TEST_ASSERT_EQUAL_INT(1, count);
    TEST_ASSERT_TRUE(strstr(logs[0], "CREATE") != NULL);
    TEST_ASSERT_TRUE(strstr(logs[0], "PROPERTY") != NULL);
    
    for (int i = 0; i < count; i++) free(logs[i]);
    free(logs);
    
    database_close(db);
    cleanup_db(db_path);
}

void test_audit_log_multiple_actions(void) {
    char db_path[100];
    sprintf(db_path, "test_audit_multi_%d.db", rand());
    Database *db = open_test_db(db_path);
    TEST_ASSERT_NOT_NULL(db);
    
    audit_log(db, "testuser", AUDIT_CREATE, AUDIT_ENTITY_PROPERTY, "P001", "Created");
    audit_log(db, "testuser", AUDIT_UPDATE, AUDIT_ENTITY_PROPERTY, "P001", "Updated price");
    audit_log(db, "testuser", AUDIT_DELETE, AUDIT_ENTITY_PROPERTY, "P001", "Deleted");
    audit_log(db, "testuser", AUDIT_LOGIN, AUDIT_ENTITY_SYSTEM, NULL, "User logged in");
    audit_log(db, "testuser", AUDIT_EXPORT, AUDIT_ENTITY_SYSTEM, NULL, "Exported to CSV");
    
    char **logs = NULL;
    int count = 0;
    int r = audit_get_logs(db, "testuser", -1, -1, NULL, 10, 0, &logs, &count);
    TEST_ASSERT_EQUAL(1, r);
    TEST_ASSERT_EQUAL_INT(5, count);
    
    for (int i = 0; i < count; i++) free(logs[i]);
    free(logs);
    
    database_close(db);
    cleanup_db(db_path);
}

void test_audit_log_filter_by_user(void) {
    char db_path[100];
    sprintf(db_path, "test_audit_filter_%d.db", rand());
    Database *db = open_test_db(db_path);
    TEST_ASSERT_NOT_NULL(db);
    
    // Create another user
    User u;
    memset(&u, 0, sizeof(User));
    strcpy(u.username, "otheruser");
    strcpy(u.first_name, "Other");
    strcpy(u.last_name, "User");
    strcpy(u.id, "0987654321");
    strcpy(u.phone, "09876543210");
    strcpy(u.email, "other@example.com");
    strcpy(u.password_hash, "hash");
    strcpy(u.salt, "salt");
    db_user_create(db, &u);
    
    audit_log(db, "testuser", AUDIT_CREATE, AUDIT_ENTITY_PROPERTY, "P1", "User 1");
    audit_log(db, "otheruser", AUDIT_CREATE, AUDIT_ENTITY_PROPERTY, "P2", "User 2");
    
    char **logs = NULL;
    int count = 0;
    int r = audit_get_logs(db, "testuser", -1, -1, NULL, 10, 0, &logs, &count);
    TEST_ASSERT_EQUAL(1, r);
    TEST_ASSERT_EQUAL_INT(1, count);
    TEST_ASSERT_TRUE(strstr(logs[0], "testuser") != NULL);
    
    for (int i = 0; i < count; i++) free(logs[i]);
    free(logs);
    
    database_close(db);
    cleanup_db(db_path);
}

void test_audit_log_filter_by_action(void) {
    char db_path[100];
    sprintf(db_path, "test_audit_action_%d.db", rand());
    Database *db = open_test_db(db_path);
    TEST_ASSERT_NOT_NULL(db);
    
    audit_log(db, "testuser", AUDIT_CREATE, AUDIT_ENTITY_PROPERTY, "P1", "Create");
    audit_log(db, "testuser", AUDIT_UPDATE, AUDIT_ENTITY_PROPERTY, "P2", "Update");
    audit_log(db, "testuser", AUDIT_DELETE, AUDIT_ENTITY_PROPERTY, "P3", "Delete");
    
    char **logs = NULL;
    int count = 0;
    int r = audit_get_logs(db, "testuser", AUDIT_CREATE, -1, NULL, 10, 0, &logs, &count);
    TEST_ASSERT_EQUAL(1, r);
    TEST_ASSERT_EQUAL_INT(1, count);
    TEST_ASSERT_TRUE(strstr(logs[0], "CREATE") != NULL);
    
    for (int i = 0; i < count; i++) free(logs[i]);
    free(logs);
    
    database_close(db);
    cleanup_db(db_path);
}

void test_audit_log_pagination(void) {
    char db_path[100];
    sprintf(db_path, "test_audit_page_%d.db", rand());
    Database *db = open_test_db(db_path);
    TEST_ASSERT_NOT_NULL(db);
    
    for (int i = 0; i < 15; i++) {
        char entity_id[20];
        sprintf(entity_id, "P%d", i);
        audit_log(db, "testuser", AUDIT_CREATE, AUDIT_ENTITY_PROPERTY, entity_id, "Created");
    }
    
    char **logs = NULL;
    int count = 0;
    int r = audit_get_logs(db, "testuser", -1, -1, NULL, 10, 0, &logs, &count);
    TEST_ASSERT_EQUAL(1, r);
    TEST_ASSERT_EQUAL_INT(10, count);
    
    for (int i = 0; i < count; i++) free(logs[i]);
    free(logs);
    
    logs = NULL; count = 0;
    r = audit_get_logs(db, "testuser", -1, -1, NULL, 10, 10, &logs, &count);
    TEST_ASSERT_EQUAL(1, r);
    TEST_ASSERT_EQUAL_INT(5, count);
    
    for (int i = 0; i < count; i++) free(logs[i]);
    free(logs);
    
    database_close(db);
    cleanup_db(db_path);
}

void test_audit_log_entity_filter(void) {
    char db_path[100];
    sprintf(db_path, "test_audit_entity_%d.db", rand());
    Database *db = open_test_db(db_path);
    TEST_ASSERT_NOT_NULL(db);
    
    audit_log(db, "testuser", AUDIT_CREATE, AUDIT_ENTITY_PROPERTY, "P1", "Property");
    audit_log(db, "testuser", AUDIT_LOGIN, AUDIT_ENTITY_SYSTEM, NULL, "System login");
    audit_log(db, "testuser", AUDIT_CREATE, AUDIT_ENTITY_USER, "U1", "New user");
    
    char **logs = NULL;
    int count = 0;
    int r = audit_get_logs(db, "testuser", -1, AUDIT_ENTITY_PROPERTY, NULL, 10, 0, &logs, &count);
    TEST_ASSERT_EQUAL(1, r);
    TEST_ASSERT_EQUAL_INT(1, count);
    TEST_ASSERT_TRUE(strstr(logs[0], "PROPERTY") != NULL);
    
    for (int i = 0; i < count; i++) free(logs[i]);
    free(logs);
    
    database_close(db);
    cleanup_db(db_path);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_audit_log_basic);
    RUN_TEST(test_audit_log_multiple_actions);
    RUN_TEST(test_audit_log_filter_by_user);
    RUN_TEST(test_audit_log_filter_by_action);
    RUN_TEST(test_audit_log_pagination);
    RUN_TEST(test_audit_log_entity_filter);
    return UNITY_END();
}