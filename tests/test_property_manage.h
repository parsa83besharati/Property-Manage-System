#ifndef TEST_PROPERTY_MANAGE_H
#define TEST_PROPERTY_MANAGE_H

#include "unity.h"
#include "common.h"
#include "sha256.h"
#include "database.h"

void test_sha256_hash(void);
void test_user_register_flow(void);
void test_password_verification(void);
void test_property_crud(void);
void test_property_search(void);
void test_database_migration(void);

#endif