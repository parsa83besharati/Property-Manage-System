#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <stdbool.h>
#include <stdint.h>
#ifdef _WIN32
#include <direct.h>
#define MKDIR(path) _mkdir(path)
#else
#include <sys/stat.h>
#define MKDIR(path) mkdir(path, 0755)
#endif

#define MAX_STRING_LEN 500
#define MAX_FIELD_LEN 50
#define MAX_USERS 1000
#define MAX_PROPERTIES 10000
#define SHA256_DIGEST_LENGTH 32
#define SALT_LENGTH 16

#define DATA_DIR "data/"
#define USERS_FILE "data/users.dat"
#define SALTS_FILE "data/salts.dat"
#define CODES_FILE "data/codes.dat"
#define LOGGED_IN_FILE "data/logged_in.dat"
#define PROPERTIES_FILE "data/properties.dat"

typedef enum {
    PROP_TYPE_RESIDENTIAL,
    PROP_TYPE_COMMERCIAL,
    PROP_TYPE_LAND
} PropertyType;

typedef enum {
    PROP_ACTION_SELL,
    PROP_ACTION_RENT
} PropertyAction;

typedef enum {
    RES_TYPE_APARTMENT,
    RES_TYPE_VILLA
} ResidentialType;

typedef enum {
    COM_TYPE_OFFICIAL,
    COM_TYPE_POSITION
} CommercialType;

typedef enum {
    LAND_TYPE_FARM,
    LAND_TYPE_CITY
} LandType;

typedef enum {
    LOCATION_NORTH,
    LOCATION_SOUTH,
    LOCATION_EAST,
    LOCATION_WEST
} Location;

typedef enum {
    TEMP_COLD,
    TEMP_HOT,
    TEMP_MEDIUM
} Temperature;

typedef enum {
    YES_NO_YES,
    YES_NO_NO
} YesNo;

typedef struct {
    char code[MAX_FIELD_LEN];
    int district;
    char address[MAX_STRING_LEN];
    Location location;
    PropertyType ptype;
    PropertyAction action;
    union {
        ResidentialType res_type;
        CommercialType com_type;
        LandType land_type;
    } subtype;
    int build_age;
    double floor_area;
    int floor;
    double land_area;
    char owner_phone[MAX_FIELD_LEN];
    int bedrooms;
    int rooms;
    double tax_rate;
    YesNo elevator;
    YesNo basement;
    double basement_area;
    YesNo balcony;
    double balcony_area;
    int parkings;
    int phones;
    Temperature temperature;
    double sell_price;
    double base_price;
    double monthly_price;
    char date[MAX_FIELD_LEN];
    char image_path[MAX_STRING_LEN];
    char username[MAX_FIELD_LEN];
    bool active;
} Property;

typedef enum {
    ROLE_USER = 0,
    ROLE_ADMIN = 1
} UserRole;

typedef struct {
    char username[MAX_FIELD_LEN];
    char first_name[MAX_FIELD_LEN];
    char last_name[MAX_FIELD_LEN];
    char id[MAX_FIELD_LEN];
    char phone[MAX_FIELD_LEN];
    char email[MAX_FIELD_LEN];
    char password_hash[SHA256_DIGEST_LENGTH * 2 + 1];
    char salt[SALT_LENGTH + 1];
    UserRole role;
} User;

typedef struct {
    Property *properties;
    int count;
    int capacity;
} PropertyList;

typedef struct {
    User *users;
    int count;
    int capacity;
} UserList;

typedef enum {
    LEASE_STATUS_ACTIVE,
    LEASE_STATUS_EXPIRED,
    LEASE_STATUS_TERMINATED,
    LEASE_STATUS_PENDING
} LeaseStatus;

typedef struct {
    int id;
    char property_code[MAX_FIELD_LEN];
    char tenant_username[MAX_FIELD_LEN];
    char start_date[MAX_FIELD_LEN];
    char end_date[MAX_FIELD_LEN];
    double monthly_rent;
    double deposit;
    int payment_day;
    LeaseStatus status;
    bool auto_renew;
    char created_at[MAX_FIELD_LEN];
} Lease;

typedef struct {
    Lease *leases;
    int count;
    int capacity;
} LeaseList;

typedef struct {
    int id;
    int lease_id;
    double amount;
    char payment_date[MAX_FIELD_LEN];
    char due_date[MAX_FIELD_LEN];
    int is_late;
    double late_fee;
    char notes[MAX_STRING_LEN];
    char recorded_by[MAX_FIELD_LEN];
    char created_at[MAX_FIELD_LEN];
} Payment;

typedef struct {
    Payment *payments;
    int count;
    int capacity;
} PaymentList;

void safe_gets(char *buffer, int size);
void trim_newline(char *str);
void str_to_lower(char *str);
void str_to_upper_first(char *str);
void capitalize_words(char *str);
int validate_int_range(const char *str, int min, int max, int *out);
int validate_double_range(const char *str, double min, double max, double *out);
int validate_phone(const char *phone);
int validate_email(const char *email);
int validate_password(const char *password);
int validate_id(const char *id);
void get_current_date(char *buffer, int size);
void get_current_time(char *buffer, int size);
void clear_screen(void);
void pause_screen(void);
void print_header(const char *title);
void get_password_hidden(char *buffer, int maxlen);

#include "ui.h"

#endif