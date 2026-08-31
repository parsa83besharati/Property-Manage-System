#include "unity.h"
#include "common.h"
#include "sha256.h"
#include "database.h"

// Include test functions
#include "test_property_manage.h"

int main(void) {
    UNITY_BEGIN();
    
    // Run all database tests
    test_sha256_hash();
    test_user_register_flow();
    test_password_verification();
    test_property_crud();
    test_property_search();
    test_database_migration();
    
    return UNITY_END();
}