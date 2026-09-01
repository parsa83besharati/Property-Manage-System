#include "unity.h"
#include "database.h"
#include "sha256.h"
#include "common.h"
#include "user.h"
#include <stdio.h>
#include <string.h>

void setUp(void) {}
void tearDown(void) {}

// =============================================================================
// TEST: db_user_create - User creation in database
// =============================================================================
void test_user_create_success(void) {
    Database *db = database_open("data/test_user_create.db");
    TEST_ASSERT_NOT_NULL(db);
    TEST_ASSERT_TRUE(database_init_schema(db));

    User user;
    memset(&user, 0, sizeof(User));
    strcpy(user.username, "testuser");
    strcpy(user.first_name, "Test");
    strcpy(user.last_name, "User");
    strcpy(user.id, "1234567890");
    strcpy(user.phone, "09123456789");
    strcpy(user.email, "test@example.com");
    strcpy(user.password_hash, "abc123def456");
    strcpy(user.salt, "randomsalt");

    int result = db_user_create(db, &user);
    TEST_ASSERT_EQUAL(1, result);

    database_close(db);
    remove("data/test_user_create.db");
}

void test_user_create_duplicate(void) {
    Database *db = database_open("data/test_user_dup.db");
    TEST_ASSERT_NOT_NULL(db);
    TEST_ASSERT_TRUE(database_init_schema(db));

    User user1;
    memset(&user1, 0, sizeof(User));
    strcpy(user1.username, "dupuser");
    strcpy(user1.first_name, "First");
    strcpy(user1.last_name, "One");
    strcpy(user1.id, "1111111111");
    strcpy(user1.phone, "09111111111");
    strcpy(user1.email, "dup1@example.com");
    strcpy(user1.password_hash, "hash1");
    strcpy(user1.salt, "salt1");

    db_user_create(db, &user1);

    User user2;
    memset(&user2, 0, sizeof(User));
    strcpy(user2.username, "dupuser");
    strcpy(user2.first_name, "Second");
    strcpy(user2.last_name, "Two");
    strcpy(user2.id, "2222222222");
    strcpy(user2.phone, "09222222222");
    strcpy(user2.email, "dup2@example.com");
    strcpy(user2.password_hash, "hash2");
    strcpy(user2.salt, "salt2");

    int result = db_user_create(db, &user2);
    TEST_ASSERT_EQUAL(0, result);

    database_close(db);
    remove("data/test_user_dup.db");
}

void test_user_find_by_username(void) {
    Database *db = database_open("data/test_user_find.db");
    TEST_ASSERT_NOT_NULL(db);
    TEST_ASSERT_TRUE(database_init_schema(db));

    User user;
    memset(&user, 0, sizeof(User));
    strcpy(user.username, "findme");
    strcpy(user.first_name, "Find");
    strcpy(user.last_name, "Me");
    strcpy(user.id, "9999999999");
    strcpy(user.phone, "09999999999");
    strcpy(user.email, "find@example.com");
    strcpy(user.password_hash, "findhash");
    strcpy(user.salt, "findsalt");

    db_user_create(db, &user);

    User *found = db_user_find_by_username(db, "findme");
    TEST_ASSERT_NOT_NULL(found);
    TEST_ASSERT_EQUAL_STRING("findme", found->username);
    TEST_ASSERT_EQUAL_STRING("Find", found->first_name);
    TEST_ASSERT_EQUAL_STRING("findhash", found->password_hash);
    TEST_ASSERT_EQUAL_STRING("findsalt", found->salt);

    database_close(db);
    remove("data/test_user_find.db");
}

void test_user_find_nonexistent(void) {
    Database *db = database_open("data/test_user_notfound.db");
    TEST_ASSERT_NOT_NULL(db);
    TEST_ASSERT_TRUE(database_init_schema(db));

    User *found = db_user_find_by_username(db, "ghostuser");
    TEST_ASSERT_NULL(found);

    database_close(db);
    remove("data/test_user_notfound.db");
}

void test_user_update_password(void) {
    Database *db = database_open("data/test_user_upd.db");
    TEST_ASSERT_NOT_NULL(db);
    TEST_ASSERT_TRUE(database_init_schema(db));

    User user;
    memset(&user, 0, sizeof(User));
    strcpy(user.username, "updpass");
    strcpy(user.first_name, "Upd");
    strcpy(user.last_name, "Pass");
    strcpy(user.id, "4444444444");
    strcpy(user.phone, "09444444444");
    strcpy(user.email, "upd@example.com");
    strcpy(user.password_hash, "oldhash");
    strcpy(user.salt, "oldsalt");

    db_user_create(db, &user);

    int result = db_user_update_password(db, "updpass", "newhash", "newsalt");
    TEST_ASSERT_EQUAL(1, result);

    User *updated = db_user_find_by_username(db, "updpass");
    TEST_ASSERT_NOT_NULL(updated);
    TEST_ASSERT_EQUAL_STRING("newhash", updated->password_hash);
    TEST_ASSERT_EQUAL_STRING("newsalt", updated->salt);

    database_close(db);
    remove("data/test_user_upd.db");
}

void test_user_update_field(void) {
    Database *db = database_open("data/test_user_field.db");
    TEST_ASSERT_NOT_NULL(db);
    TEST_ASSERT_TRUE(database_init_schema(db));

    User user;
    memset(&user, 0, sizeof(User));
    strcpy(user.username, "fielduser");
    strcpy(user.first_name, "Original");
    strcpy(user.last_name, "Name");
    strcpy(user.id, "5555555555");
    strcpy(user.phone, "09555555555");
    strcpy(user.email, "old@example.com");
    strcpy(user.password_hash, "fhash");
    strcpy(user.salt, "fsalt");

    db_user_create(db, &user);

    int result = db_user_update_field(db, "fielduser", USER_FIELD_FIRST_NAME, "Changed");
    TEST_ASSERT_EQUAL(1, result);

    User *updated = db_user_find_by_username(db, "fielduser");
    TEST_ASSERT_NOT_NULL(updated);
    TEST_ASSERT_EQUAL_STRING("Changed", updated->first_name);
    TEST_ASSERT_EQUAL_STRING("Name", updated->last_name);

    database_close(db);
    remove("data/test_user_field.db");
}

void test_user_list_all(void) {
    Database *db = database_open("data/test_user_list.db");
    TEST_ASSERT_NOT_NULL(db);
    TEST_ASSERT_TRUE(database_init_schema(db));

    for (int i = 0; i < 5; i++) {
        User user;
        memset(&user, 0, sizeof(User));
        sprintf(user.username, "listuser%d", i);
        strcpy(user.first_name, "List");
        strcpy(user.last_name, "User");
        sprintf(user.id, "600000000%d", i);
        sprintf(user.phone, "0960000000%d", i);
        sprintf(user.email, "list%d@example.com", i);
        strcpy(user.password_hash, "lhash");
        strcpy(user.salt, "lsalt");
        db_user_create(db, &user);
    }

    User *users[10];
    int count;
    int result = db_user_list_all(db, users, &count);
    TEST_ASSERT_EQUAL(1, result);
    TEST_ASSERT_EQUAL_INT(5, count);

    database_close(db);
    remove("data/test_user_list.db");
}

void test_user_count(void) {
    Database *db = database_open("data/test_user_count.db");
    TEST_ASSERT_NOT_NULL(db);
    TEST_ASSERT_TRUE(database_init_schema(db));

    TEST_ASSERT_EQUAL_INT(0, db_user_count(db));

    User user;
    memset(&user, 0, sizeof(User));
    strcpy(user.username, "countuser");
    strcpy(user.first_name, "Count");
    strcpy(user.last_name, "User");
    strcpy(user.id, "7777777777");
    strcpy(user.phone, "09777777777");
    strcpy(user.email, "count@example.com");
    strcpy(user.password_hash, "chash");
    strcpy(user.salt, "csalt");

    db_user_create(db, &user);
    TEST_ASSERT_EQUAL_INT(1, db_user_count(db));

    database_close(db);
    remove("data/test_user_count.db");
}

void test_user_empty_database(void) {
    Database *db = database_open("data/test_user_empty.db");
    TEST_ASSERT_NOT_NULL(db);
    TEST_ASSERT_TRUE(database_init_schema(db));

    User *found = db_user_find_by_username(db, "emptyuser");
    TEST_ASSERT_NULL(found);

    TEST_ASSERT_EQUAL_INT(0, db_user_count(db));

    database_close(db);
    remove("data/test_user_empty.db");
}

void test_user_set_get_role(void) {
    Database *db = database_open("data/test_user_role.db");
    TEST_ASSERT_NOT_NULL(db);
    TEST_ASSERT_TRUE(database_init_schema(db));

    // Test default role is ROLE_USER
    User user;
    memset(&user, 0, sizeof(User));
    strcpy(user.username, "roleuser");
    strcpy(user.first_name, "Role");
    strcpy(user.last_name, "Test");
    strcpy(user.id, "1111111111");
    strcpy(user.phone, "09111111111");
    strcpy(user.email, "role@example.com");
    strcpy(user.password_hash, "hash");
    strcpy(user.salt, "salt");
    db_user_create(db, &user);

    // Default role should be ROLE_USER (0)
    UserRole role = db_user_get_role(db, "roleuser");
    TEST_ASSERT_EQUAL(ROLE_USER, role);

    // Set role to ROLE_ADMIN
    int set_result = db_user_set_role(db, "roleuser", ROLE_ADMIN);
    TEST_ASSERT_EQUAL(1, set_result);

    // Verify role was set
    role = db_user_get_role(db, "roleuser");
    TEST_ASSERT_EQUAL(ROLE_ADMIN, role);

    // Set back to ROLE_USER
    set_result = db_user_set_role(db, "roleuser", ROLE_USER);
    TEST_ASSERT_EQUAL(1, set_result);

    role = db_user_get_role(db, "roleuser");
    TEST_ASSERT_EQUAL(ROLE_USER, role);

    // Test nonexistent user returns ROLE_USER
    role = db_user_get_role(db, "nonexistent");
    TEST_ASSERT_EQUAL(ROLE_USER, role);

    database_close(db);
    remove("data/test_user_role.db");
}

void test_user_create_with_role(void) {
    Database *db = database_open("data/test_user_create_role.db");
    TEST_ASSERT_NOT_NULL(db);
    TEST_ASSERT_TRUE(database_init_schema(db));

    User user;
    memset(&user, 0, sizeof(User));
    strcpy(user.username, "adminuser");
    strcpy(user.first_name, "Admin");
    strcpy(user.last_name, "User");
    strcpy(user.id, "2222222222");
    strcpy(user.phone, "09222222222");
    strcpy(user.email, "admin@example.com");
    strcpy(user.password_hash, "adminhash");
    strcpy(user.salt, "adminsalt");
    user.role = ROLE_ADMIN;  // Set role at creation

    int result = db_user_create(db, &user);
    TEST_ASSERT_EQUAL(1, result);

    // Verify role was stored
    UserRole role = db_user_get_role(db, "adminuser");
    TEST_ASSERT_EQUAL(ROLE_ADMIN, role);

    database_close(db);
    remove("data/test_user_create_role.db");
}