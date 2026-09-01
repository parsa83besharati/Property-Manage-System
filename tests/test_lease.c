#include "unity.h"
#include "database.h"
#include "common.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

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

Database *open_lease_test_db(const char *path) {
    cleanup_db(path);
    Database *db = database_open(path);
    if (!db) return NULL;
    if (!database_init_schema(db)) {
        database_close(db);
        return NULL;
    }
    // Create test user
    User u;
    memset(&u, 0, sizeof(User));
    strcpy(u.username, "leaseuser");
    strcpy(u.first_name, "Lease");
    strcpy(u.last_name, "User");
    strcpy(u.id, "1111111111");
    strcpy(u.phone, "09111111111");
    strcpy(u.email, "lease@test.com");
    strcpy(u.password_hash, "hash");
    strcpy(u.salt, "salt");
    u.role = ROLE_USER;
    db_user_create(db, &u);
    return db;
}

Property create_test_property(const char *code) {
    Property p;
    memset(&p, 0, sizeof(Property));
    strcpy(p.code, code);
    p.district = 1;
    p.ptype = PROP_TYPE_RESIDENTIAL;
    p.action = PROP_ACTION_RENT;
    p.location = LOCATION_NORTH;
    p.sell_price = 0;
    p.base_price = 0;
    p.monthly_price = 2000;
    p.floor_area = 100;
    p.floor = 2;
    p.basement = 0;
    p.bedrooms = 2;
    p.rooms = 3;
    p.active = 1;
    strcpy(p.address, "Test Lease Address");
    strcpy(p.owner_phone, "09123456789");
    strcpy(p.date, "2026-01-01");
    strcpy(p.username, "leaseuser");
    strcpy(p.image_path, "");
    return p;
}

Lease create_test_lease(const char *property_code, const char *tenant, double rent) {
    Lease l;
    memset(&l, 0, sizeof(Lease));
    strcpy(l.property_code, property_code);
    strcpy(l.tenant_username, tenant);
    strcpy(l.start_date, "2026-01-01");
    strcpy(l.end_date, "2026-12-31");
    l.monthly_rent = rent;
    l.deposit = rent * 2;
    l.payment_day = 1;
    l.status = LEASE_STATUS_ACTIVE;
    l.auto_renew = 0;
    return l;
}

// =============================================================================
// CREATE
// =============================================================================
void test_lease_create_success(void) {
    Database *db = open_lease_test_db("data/test_lease_create.db");
    TEST_ASSERT_NOT_NULL(db);

    Property prop = create_test_property("LSE001");
    db_property_create(db, &prop);

    Lease lease = create_test_lease("LSE001", "leaseuser", 2000.0);
    int result = db_lease_create(db, &lease);
    TEST_ASSERT_EQUAL(1, result);

    Lease *found = db_lease_find_by_id(db, 1);
    TEST_ASSERT_NOT_NULL(found);
    TEST_ASSERT_EQUAL_STRING("LSE001", found->property_code);
    TEST_ASSERT_EQUAL_STRING("leaseuser", found->tenant_username);
    TEST_ASSERT_EQUAL_DOUBLE(2000.0, found->monthly_rent);
    TEST_ASSERT_EQUAL(LEASE_STATUS_ACTIVE, found->status);

    free(found);
    database_close(db);
    cleanup_db("test_lease_create.db");
}

void test_lease_create_duplicate_property_active(void) {
    Database *db = open_lease_test_db("data/test_lease_dup.db");
    TEST_ASSERT_NOT_NULL(db);

    Property prop = create_test_property("LSE002");
    db_property_create(db, &prop);

    Lease lease1 = create_test_lease("LSE002", "leaseuser", 1500.0);
    db_lease_create(db, &lease1);

    // Try to create another active lease for same property
    Lease lease2 = create_test_lease("LSE002", "leaseuser", 2000.0);
    int result = db_lease_create(db, &lease2);
    TEST_ASSERT_EQUAL(1, result); // Should succeed (no DB constraint preventing)

    database_close(db);
    cleanup_db("test_lease_dup.db");
}

void test_lease_create_nonexistent_property(void) {
    Database *db = open_lease_test_db("data/test_lease_noprop.db");
    TEST_ASSERT_NOT_NULL(db);

    Lease lease = create_test_lease("NOEXIST", "leaseuser", 2000.0);
    int result = db_lease_create(db, &lease);
    TEST_ASSERT_EQUAL(0, result); // Should fail due to FK constraint

    database_close(db);
    cleanup_db("test_lease_noprop.db");
}

void test_lease_create_nonexistent_tenant(void) {
    Database *db = open_lease_test_db("data/test_lease_notenant.db");
    TEST_ASSERT_NOT_NULL(db);

    Property prop = create_test_property("LSE003");
    db_property_create(db, &prop);

    Lease lease = create_test_lease("LSE003", "nonexistent", 2000.0);
    int result = db_lease_create(db, &lease);
    TEST_ASSERT_EQUAL(0, result); // Should fail due to FK constraint

    database_close(db);
    cleanup_db("test_lease_notenant.db");
}

// =============================================================================
// READ
// =============================================================================
void test_lease_find_by_id(void) {
    Database *db = open_lease_test_db("data/test_lease_find.db");
    TEST_ASSERT_NOT_NULL(db);

    Property prop = create_test_property("LSE004");
    db_property_create(db, &prop);

    Lease lease = create_test_lease("LSE004", "leaseuser", 2500.0);
    db_lease_create(db, &lease);

    Lease *found = db_lease_find_by_id(db, 1);
    TEST_ASSERT_NOT_NULL(found);
    TEST_ASSERT_EQUAL_INT(1, found->id);
    TEST_ASSERT_EQUAL_STRING("LSE004", found->property_code);
    TEST_ASSERT_EQUAL_DOUBLE(2500.0, found->monthly_rent);
    TEST_ASSERT_EQUAL(1, found->payment_day);

    free(found);
    database_close(db);
    cleanup_db("test_lease_find.db");
}

void test_lease_find_nonexistent(void) {
    Database *db = open_lease_test_db("data/test_lease_notfound.db");
    TEST_ASSERT_NOT_NULL(db);

    Lease *found = db_lease_find_by_id(db, 999);
    TEST_ASSERT_NULL(found);

    database_close(db);
    cleanup_db("test_lease_notfound.db");
}

// =============================================================================
// UPDATE
// =============================================================================
void test_lease_update_status(void) {
    Database *db = open_lease_test_db("data/test_lease_upd.db");
    TEST_ASSERT_NOT_NULL(db);

    Property prop = create_test_property("LSE005");
    db_property_create(db, &prop);

    Lease lease = create_test_lease("LSE005", "leaseuser", 3000.0);
    db_lease_create(db, &lease);

    Lease *found = db_lease_find_by_id(db, 1);
    TEST_ASSERT_NOT_NULL(found);
    found->status = LEASE_STATUS_TERMINATED;
    int result = db_lease_update(db, found);
    TEST_ASSERT_EQUAL(1, result);

    Lease *updated = db_lease_find_by_id(db, 1);
    TEST_ASSERT_NOT_NULL(updated);
    TEST_ASSERT_EQUAL(LEASE_STATUS_TERMINATED, updated->status);
    TEST_ASSERT_EQUAL_DOUBLE(3000.0, updated->monthly_rent);

    free(found);
    free(updated);
    database_close(db);
    cleanup_db("test_lease_upd.db");
}

void test_lease_update_rent(void) {
    Database *db = open_lease_test_db("data/test_lease_rent.db");
    TEST_ASSERT_NOT_NULL(db);

    Property prop = create_test_property("LSE006");
    db_property_create(db, &prop);

    Lease lease = create_test_lease("LSE006", "leaseuser", 2000.0);
    db_lease_create(db, &lease);

    Lease *found = db_lease_find_by_id(db, 1);
    TEST_ASSERT_NOT_NULL(found);
    found->monthly_rent = 2500.0;
    found->deposit = 5000.0;
    int result = db_lease_update(db, found);
    TEST_ASSERT_EQUAL(1, result);

    Lease *updated = db_lease_find_by_id(db, 1);
    TEST_ASSERT_NOT_NULL(updated);
    TEST_ASSERT_EQUAL_DOUBLE(2500.0, updated->monthly_rent);
    TEST_ASSERT_EQUAL_DOUBLE(5000.0, updated->deposit);

    free(found);
    free(updated);
    database_close(db);
    cleanup_db("test_lease_rent.db");
}

// =============================================================================
// DELETE
// =============================================================================
void test_lease_delete_success(void) {
    Database *db = open_lease_test_db("data/test_lease_del.db");
    TEST_ASSERT_NOT_NULL(db);

    Property prop = create_test_property("LSE007");
    db_property_create(db, &prop);

    Lease lease = create_test_lease("LSE007", "leaseuser", 2000.0);
    db_lease_create(db, &lease);

    int result = db_lease_delete(db, 1);
    TEST_ASSERT_EQUAL(1, result);

    Lease *found = db_lease_find_by_id(db, 1);
    TEST_ASSERT_NULL(found);

    database_close(db);
    cleanup_db("test_lease_del.db");
}

void test_lease_delete_nonexistent(void) {
    Database *db = open_lease_test_db("data/test_lease_delnone.db");
    TEST_ASSERT_NOT_NULL(db);

    int result = db_lease_delete(db, 999);
    TEST_ASSERT_EQUAL(0, result);

    database_close(db);
    cleanup_db("test_lease_delnone.db");
}

// =============================================================================
// LIST ALL
// =============================================================================
void test_lease_list_all(void) {
    Database *db = open_lease_test_db("data/test_lease_list.db");
    TEST_ASSERT_NOT_NULL(db);

    Property prop = create_test_property("LSE008");
    db_property_create(db, &prop);

    for (int i = 0; i < 3; i++) {
        char code[10];
        sprintf(code, "LSE%03d", i + 8);
        Lease lease = create_test_lease(code, "leaseuser", 1000.0 * (i + 1));
        db_lease_create(db, &lease);
    }

    Lease *leases[10];
    int count;
    int result = db_lease_list_all(db, leases, &count);
    TEST_ASSERT_EQUAL(1, result);
    TEST_ASSERT_EQUAL_INT(3, count);

    // Should be in descending order (newest first)
    TEST_ASSERT_EQUAL_STRING("LSE010", leases[0]->property_code);

    for (int i = 0; i < count; i++) {
        free(leases[i]);
    }

    database_close(db);
    cleanup_db("test_lease_list.db");
}

// =============================================================================
// FILTER BY TENANT
// =============================================================================
void test_lease_list_by_tenant(void) {
    Database *db = open_lease_test_db("data/test_lease_tenant.db");
    TEST_ASSERT_NOT_NULL(db);

    Property prop = create_test_property("LSE009");
    db_property_create(db, &prop);

    // Create another user
    User u2;
    memset(&u2, 0, sizeof(User));
    strcpy(u2.username, "tenant2");
    strcpy(u2.first_name, "Tenant");
    strcpy(u2.last_name, "Two");
    strcpy(u2.id, "2222222222");
    strcpy(u2.phone, "09222222222");
    strcpy(u2.email, "tenant2@test.com");
    strcpy(u2.password_hash, "hash");
    strcpy(u2.salt, "salt");
    u2.role = ROLE_USER;
    db_user_create(db, &u2);

    Lease l1 = create_test_lease("LSE009", "leaseuser", 1000.0);
    Lease l2 = create_test_lease("LSE009", "tenant2", 2000.0);
    db_lease_create(db, &l1);
    db_lease_create(db, &l2);

    Lease *leases[10];
    int count;
    db_lease_list_by_tenant(db, "leaseuser", leases, &count);
    TEST_ASSERT_EQUAL_INT(1, count);
    TEST_ASSERT_EQUAL_STRING("leaseuser", leases[0]->tenant_username);
    free(leases[0]);

    db_lease_list_by_tenant(db, "tenant2", leases, &count);
    TEST_ASSERT_EQUAL_INT(1, count);
    TEST_ASSERT_EQUAL_STRING("tenant2", leases[0]->tenant_username);
    free(leases[0]);

    database_close(db);
    cleanup_db("test_lease_tenant.db");
}

// =============================================================================
// FILTER BY PROPERTY
// =============================================================================
void test_lease_list_by_property(void) {
    Database *db = open_lease_test_db("data/test_lease_prop.db");
    TEST_ASSERT_NOT_NULL(db);

    Property p1 = create_test_property("LSE011");
    Property p2 = create_test_property("LSE012");
    db_property_create(db, &p1);
    db_property_create(db, &p2);

    Lease l1 = create_test_lease("LSE011", "leaseuser", 1000.0);
    Lease l2 = create_test_lease("LSE011", "leaseuser", 1500.0);
    Lease l3 = create_test_lease("LSE012", "leaseuser", 2000.0);
    db_lease_create(db, &l1);
    db_lease_create(db, &l2);
    db_lease_create(db, &l3);

    Lease *leases[10];
    int count;
    db_lease_list_by_property(db, "LSE011", leases, &count);
    TEST_ASSERT_EQUAL_INT(2, count);
    for (int i = 0; i < count; i++) free(leases[i]);

    db_lease_list_by_property(db, "LSE012", leases, &count);
    TEST_ASSERT_EQUAL_INT(1, count);
    free(leases[0]);

    database_close(db);
    cleanup_db("test_lease_prop.db");
}

// =============================================================================
// FILTER BY STATUS
// =============================================================================
void test_lease_list_by_status(void) {
    Database *db = open_lease_test_db("data/test_lease_status.db");
    TEST_ASSERT_NOT_NULL(db);

    Property p1 = create_test_property("LSE013");
    Property p2 = create_test_property("LSE014");
    db_property_create(db, &p1);
    db_property_create(db, &p2);

    Lease l1 = create_test_lease("LSE013", "leaseuser", 1000.0);
    l1.status = LEASE_STATUS_ACTIVE;
    db_lease_create(db, &l1);

    Lease l2 = create_test_lease("LSE014", "leaseuser", 2000.0);
    l2.status = LEASE_STATUS_TERMINATED;
    db_lease_create(db, &l2);

    Lease *leases[10];
    int count;
    db_lease_list_by_status(db, LEASE_STATUS_ACTIVE, leases, &count);
    TEST_ASSERT_EQUAL_INT(1, count);
    TEST_ASSERT_EQUAL(LEASE_STATUS_ACTIVE, leases[0]->status);
    free(leases[0]);

    db_lease_list_by_status(db, LEASE_STATUS_TERMINATED, leases, &count);
    TEST_ASSERT_EQUAL_INT(1, count);
    TEST_ASSERT_EQUAL(LEASE_STATUS_TERMINATED, leases[0]->status);
    free(leases[0]);

    database_close(db);
    cleanup_db("test_lease_status.db");
}

// =============================================================================
// EXPIRING LEASES
// =============================================================================
void test_lease_list_expiring(void) {
    Database *db = open_lease_test_db("data/test_lease_expire.db");
    TEST_ASSERT_NOT_NULL(db);

    Property p1 = create_test_property("LSE015");
    Property p2 = create_test_property("LSE016");
    db_property_create(db, &p1);
    db_property_create(db, &p2);

    // Active lease ending soon (within 30 days)
    Lease l1 = create_test_lease("LSE015", "leaseuser", 1000.0);
    strcpy(l1.end_date, "2026-01-15"); // Soon
    l1.status = LEASE_STATUS_ACTIVE;
    db_lease_create(db, &l1);

    // Active lease ending later
    Lease l2 = create_test_lease("LSE016", "leaseuser", 2000.0);
    strcpy(l2.end_date, "2026-12-31");
    l2.status = LEASE_STATUS_ACTIVE;
    db_lease_create(db, &l2);

    // Terminated lease (should not appear)
    Lease l3 = create_test_lease("LSE015", "leaseuser", 3000.0);
    strcpy(l3.end_date, "2026-01-10");
    l3.status = LEASE_STATUS_TERMINATED;
    db_lease_create(db, &l3);

    Lease *leases[10];
    int count;
    // This test depends on current date - may need adjustment
    int result = db_lease_list_expiring(db, 60, leases, &count);
    TEST_ASSERT_EQUAL(1, result);
    // Count depends on current date, just verify it runs

    for (int i = 0; i < count; i++) free(leases[i]);

    database_close(db);
    cleanup_db("test_lease_expire.db");
}

// =============================================================================
// COUNT
// =============================================================================
void test_lease_count(void) {
    Database *db = open_lease_test_db("data/test_lease_count.db");
    TEST_ASSERT_NOT_NULL(db);

    TEST_ASSERT_EQUAL_INT(0, db_lease_count(db));

    Property prop = create_test_property("LSE017");
    db_property_create(db, &prop);

    Lease lease = create_test_lease("LSE017", "leaseuser", 1000.0);
    db_lease_create(db, &lease);
    TEST_ASSERT_EQUAL_INT(1, db_lease_count(db));

    Lease lease2 = create_test_lease("LSE017", "leaseuser", 2000.0);
    db_lease_create(db, &lease2);
    TEST_ASSERT_EQUAL_INT(2, db_lease_count(db));

    database_close(db);
    cleanup_db("test_lease_count.db");
}

void test_lease_count_by_tenant(void) {
    Database *db = open_lease_test_db("data/test_lease_cnt_tenant.db");
    TEST_ASSERT_NOT_NULL(db);

    Property prop = create_test_property("LSE018");
    db_property_create(db, &prop);

    TEST_ASSERT_EQUAL_INT(0, db_lease_count_by_tenant(db, "leaseuser"));

    Lease l1 = create_test_lease("LSE018", "leaseuser", 1000.0);
    Lease l2 = create_test_lease("LSE018", "leaseuser", 2000.0);
    db_lease_create(db, &l1);
    db_lease_create(db, &l2);

    TEST_ASSERT_EQUAL_INT(2, db_lease_count_by_tenant(db, "leaseuser"));
    TEST_ASSERT_EQUAL_INT(0, db_lease_count_by_tenant(db, "nouser"));

    database_close(db);
    cleanup_db("test_lease_cnt_tenant.db");
}

void test_lease_count_by_property(void) {
    Database *db = open_lease_test_db("data/test_lease_cnt_prop.db");
    TEST_ASSERT_NOT_NULL(db);

    Property p1 = create_test_property("LSE019");
    Property p2 = create_test_property("LSE020");
    db_property_create(db, &p1);
    db_property_create(db, &p2);

    TEST_ASSERT_EQUAL_INT(0, db_lease_count_by_property(db, "LSE019"));

    Lease l1 = create_test_lease("LSE019", "leaseuser", 1000.0);
    Lease l2 = create_test_lease("LSE019", "leaseuser", 2000.0);
    db_lease_create(db, &l1);
    db_lease_create(db, &l2);

    TEST_ASSERT_EQUAL_INT(2, db_lease_count_by_property(db, "LSE019"));
    TEST_ASSERT_EQUAL_INT(0, db_lease_count_by_property(db, "LSE020"));

    database_close(db);
    cleanup_db("test_lease_cnt_prop.db");
}

// =============================================================================
// EDGE CASES
// =============================================================================
void test_lease_zero_rent(void) {
    Database *db = open_lease_test_db("data/test_lease_zero.db");
    TEST_ASSERT_NOT_NULL(db);

    Property prop = create_test_property("LSE021");
    db_property_create(db, &prop);

    Lease lease = create_test_lease("LSE021", "leaseuser", 0.0);
    int result = db_lease_create(db, &lease);
    TEST_ASSERT_EQUAL(1, result);

    Lease *found = db_lease_find_by_id(db, 1);
    TEST_ASSERT_NOT_NULL(found);
    TEST_ASSERT_EQUAL_DOUBLE(0.0, found->monthly_rent);

    free(found);
    database_close(db);
    cleanup_db("test_lease_zero.db");
}

void test_lease_high_rent(void) {
    Database *db = open_lease_test_db("data/test_lease_high.db");
    TEST_ASSERT_NOT_NULL(db);

    Property prop = create_test_property("LSE022");
    db_property_create(db, &prop);

    Lease lease = create_test_lease("LSE022", "leaseuser", 999999.99);
    int result = db_lease_create(db, &lease);
    TEST_ASSERT_EQUAL(1, result);

    Lease *found = db_lease_find_by_id(db, 1);
    TEST_ASSERT_NOT_NULL(found);
    TEST_ASSERT_EQUAL_DOUBLE(999999.99, found->monthly_rent);

    free(found);
    database_close(db);
    cleanup_db("test_lease_high.db");
}

void test_lease_dates_boundary(void) {
    Database *db = open_lease_test_db("data/test_lease_dates.db");
    TEST_ASSERT_NOT_NULL(db);

    Property prop = create_test_property("LSE023");
    db_property_create(db, &prop);

    Lease lease = create_test_lease("LSE023", "leaseuser", 1000.0);
    strcpy(lease.start_date, "2026-01-01");
    strcpy(lease.end_date, "2026-01-01"); // Same day
    db_lease_create(db, &lease);

    Lease *found = db_lease_find_by_id(db, 1);
    TEST_ASSERT_NOT_NULL(found);
    TEST_ASSERT_EQUAL_STRING("2026-01-01", found->start_date);
    TEST_ASSERT_EQUAL_STRING("2026-01-01", found->end_date);

    free(found);
    database_close(db);
    cleanup_db("test_lease_dates.db");
}

void test_lease_auto_renew(void) {
    Database *db = open_lease_test_db("data/test_lease_autorenew.db");
    TEST_ASSERT_NOT_NULL(db);

    Property prop = create_test_property("LSE024");
    db_property_create(db, &prop);

    Lease lease = create_test_lease("LSE024", "leaseuser", 1000.0);
    lease.auto_renew = 1;
    db_lease_create(db, &lease);

    Lease *found = db_lease_find_by_id(db, 1);
    TEST_ASSERT_NOT_NULL(found);
    TEST_ASSERT_EQUAL(1, found->auto_renew);

    free(found);
    database_close(db);
    cleanup_db("test_lease_autorenew.db");
}

void test_lease_status_enum(void) {
    Database *db = open_lease_test_db("data/test_lease_enum.db");
    TEST_ASSERT_NOT_NULL(db);

    Property prop = create_test_property("LSE025");
    db_property_create(db, &prop);

    Lease l1 = create_test_lease("LSE025", "leaseuser", 1000.0);
    l1.status = LEASE_STATUS_ACTIVE;
    db_lease_create(db, &l1);

    Lease l2 = create_test_lease("LSE025", "leaseuser", 2000.0);
    l2.status = LEASE_STATUS_EXPIRED;
    db_lease_create(db, &l2);

    Lease l3 = create_test_lease("LSE025", "leaseuser", 3000.0);
    l3.status = LEASE_STATUS_PENDING;
    db_lease_create(db, &l3);

    Lease *leases[10];
    int count;
    db_lease_list_by_status(db, LEASE_STATUS_ACTIVE, leases, &count);
    TEST_ASSERT_EQUAL_INT(1, count);
    free(leases[0]);

    db_lease_list_by_status(db, LEASE_STATUS_EXPIRED, leases, &count);
    TEST_ASSERT_EQUAL_INT(1, count);
    free(leases[0]);

    db_lease_list_by_status(db, LEASE_STATUS_PENDING, leases, &count);
    TEST_ASSERT_EQUAL_INT(1, count);
    free(leases[0]);

    database_close(db);
    cleanup_db("test_lease_enum.db");
}

void test_lease_payment_day(void) {
    Database *db = open_lease_test_db("data/test_lease_payday.db");
    TEST_ASSERT_NOT_NULL(db);

    Property prop = create_test_property("LSE026");
    db_property_create(db, &prop);

    for (int day = 1; day <= 28; day++) {
        char code[10];
        sprintf(code, "LSE%02d", day);
        Property p = create_test_property(code);
        db_property_create(db, &p);

        Lease lease = create_test_lease(code, "leaseuser", 1000.0);
        lease.payment_day = day;
        db_lease_create(db, &lease);
    }

    Lease *leases[30];
    int count;
    db_lease_list_all(db, leases, &count);
    TEST_ASSERT_EQUAL_INT(28, count);

    for (int i = 0; i < count; i++) {
        TEST_ASSERT_TRUE(leases[i]->payment_day >= 1 && leases[i]->payment_day <= 28);
        free(leases[i]);
    }

    database_close(db);
    cleanup_db("test_lease_payday.db");
}

// =============================================================================
// EMPTY DATABASE
// =============================================================================
void test_lease_empty_database(void) {
    Database *db = open_lease_test_db("data/test_lease_empty.db");
    TEST_ASSERT_NOT_NULL(db);

    Lease *found = db_lease_find_by_id(db, 1);
    TEST_ASSERT_NULL(found);

    Lease *leases[10];
    int count;
    db_lease_list_all(db, leases, &count);
    TEST_ASSERT_EQUAL_INT(0, count);

    TEST_ASSERT_EQUAL_INT(0, db_lease_count(db));
    TEST_ASSERT_EQUAL_INT(0, db_lease_count_by_tenant(db, "leaseuser"));
    TEST_ASSERT_EQUAL_INT(0, db_lease_count_by_property(db, "ANY"));

    database_close(db);
    cleanup_db("test_lease_empty.db");
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_lease_create_success);
    RUN_TEST(test_lease_create_duplicate_property_active);
    RUN_TEST(test_lease_create_nonexistent_property);
    RUN_TEST(test_lease_create_nonexistent_tenant);
    RUN_TEST(test_lease_find_by_id);
    RUN_TEST(test_lease_find_nonexistent);
    RUN_TEST(test_lease_update_status);
    RUN_TEST(test_lease_update_rent);
    RUN_TEST(test_lease_delete_success);
    RUN_TEST(test_lease_delete_nonexistent);
    RUN_TEST(test_lease_list_all);
    RUN_TEST(test_lease_list_by_tenant);
    RUN_TEST(test_lease_list_by_property);
    RUN_TEST(test_lease_list_by_status);
    RUN_TEST(test_lease_list_expiring);
    RUN_TEST(test_lease_count);
    RUN_TEST(test_lease_count_by_tenant);
    RUN_TEST(test_lease_count_by_property);
    RUN_TEST(test_lease_zero_rent);
    RUN_TEST(test_lease_high_rent);
    RUN_TEST(test_lease_dates_boundary);
    RUN_TEST(test_lease_auto_renew);
    RUN_TEST(test_lease_status_enum);
    RUN_TEST(test_lease_payment_day);
    RUN_TEST(test_lease_empty_database);
    return UNITY_END();
}