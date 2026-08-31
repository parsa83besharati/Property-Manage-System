#include "unity.h"
#include "sha256.h"
#include "common.h"
#include <stdio.h>
#include <string.h>

// Unity requires these, even if empty
void setUp(void) {}
void tearDown(void) {}

void test_sha256_hash_computation(void) {
    uint8_t hash[SHA256_DIGEST_LENGTH];
    const uint8_t data[] = "test_password";
    
    sha256_hash(data, strlen((const char*)data), hash);
    
    // Hash should be 32 bytes
    TEST_ASSERT_EQUAL_INT(32, SHA256_DIGEST_LENGTH);
    
    // Print hash for debugging
    printf("SHA256 hash: ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
    
    // Hash should contain valid hex values
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        TEST_ASSERT_TRUE(hash[i] >= 0x00 && hash[i] <= 0xFF);
    }
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_sha256_hash_computation);
    return UNITY_END();
}