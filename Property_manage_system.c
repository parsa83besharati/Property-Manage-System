#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <conio.h>
#include <ctype.h>
#include <time.h>
#include <windows.h>

#define SHA256_DIGEST_LENGTH 32

///user structure defining
typedef struct u
{
    char user_name[50];
    char first_name[50];
    char last_name[50];
    char ID[50];
    char phone_number[50];
    char email[50];
    char password[100];
    struct u *next;
} user;
///code structure defining
typedef struct c_d
{
    char code[50];
    struct c_d *next;

} coder;
///sell-residental-property structure defining
typedef struct s_r_p
{
    char code[50];
    char district[50];
    char address[500];
    char location[50]; // N or S or E or W
    char type[50]; //apartment or villa
    char build_age[50];
    char floor_area[50]; //m^2
    char floor[50];
    char land_area[50]; //m^2
    char owner_phone_number[50];
    char bedrooms[50];
    char tax_rate[50]; //percentage
    char elevator[50]; //Y or N
    char basement[50]; //Y or N
    char basement_area[50]; //m^2
    char balcony[50]; //Y or N
    char balcony_area[50];
    char parkings[50];
    char phones[50];
    char temperature[50]; // C or H or M
    char sell_price[50];
    char date[50];
    char userin[50];
    char active[50];
    struct s_r_p *next;
} sell_res;
///sell-land-property
typedef struct s_l_p
{
    char code[50];
    char district[50];
    char address[500];
    char location[50];
    char type[50]; //farm or city
    char land_area[50]; //m^2
    char width[50]; //m
    char owner_phone_number[50];
    char tax_rate[50];
    char well[50]; //Y or N
    char temperature[50]; // C or H or M
    char sell_price[50];
    char date[50];
    char userin[50];
    char active[50];
    struct s_l_p *next;
} sell_lan;
///sell-commercial-property structure defining
typedef struct s_c_p
{
    char code[50];
    char district[50];
    char address[500];
    char location[50]; // N or S or E or W
    char type[50]; // Official or Position
    char build_age[50];
    char floor_area[50]; //m^2
    char floor[50];
    char land_area[50]; //m^2
    char owner_phone_number[50];
    char rooms[50];
    char tax_rate[50]; //percentage
    char elevator[50]; //Y or N
    char basement[50]; //Y or N
    char basement_area[50]; //m^2
    char balcony[50]; //Y or N
    char balcony_area[50];
    char parkings[50];
    char phones[50];
    char temperature[50]; // C or H or M
    char sell_price[50];
    char date[50];
    char userin[50];
    char active[50];
    struct s_c_p *next;
} sell_com;
///rent-residental-property structure defining
typedef struct r_r_p
{
    char code[50];
    char district[50];
    char address[500];
    char location[50]; // N or S or E or W
    char type[50]; //apartment or villa
    char build_age[50];
    char floor_area[50]; //m^2
    char floor[50];
    char land_area[50]; //m^2
    char owner_phone_number[50];
    char bedrooms[50];
    char tax_rate[50]; //percentage
    char elevator[50]; //Y or N
    char basement[50]; //Y or N
    char basement_area[50]; //m^2
    char balcony[50]; //Y or N
    char balcony_area[50];
    char parkings[50];
    char phones[50];
    char temperature[50]; // C or H or M
    char base_price[50];
    char monthly_price[50];
    char date[50];
    char userin[50];
    char active[50];
    struct r_r_p *next;
} rent_res;
///rent-land-property
typedef struct r_l_p
{
    char code[50];
    char district[50];
    char address[500];
    char location[50];
    char type[50]; //farm or city
    char land_area[50]; //m^2
    char width[50]; //m
    char owner_phone_number[50];
    char tax_rate[50];
    char well[50]; //Y or N
    char temperature[50]; // C or H or M
    char base_price[50];
    char monthly_price[50];
    char date[50];
    char userin[50];
    char active[50];
    struct r_l_p *next;
} rent_lan;
///rent-commercial-property structure defining
typedef struct r_c_p
{
    char code[50];
    char district[50];
    char address[500];
    char location[50]; // N or S or E or W
    char type[50]; // Official or Position
    char build_age[50];
    char floor_area[50]; //m^2
    char floor[50];
    char land_area[50]; //m^2
    char owner_phone_number[50];
    char rooms[50];
    char tax_rate[50]; //percentage
    char elevator[50]; //Y or N
    char basement[50]; //Y or N
    char basement_area[50]; //m^2
    char balcony[50]; //Y or N
    char balcony_area[50];
    char parkings[50];
    char phones[50];
    char temperature[50]; // C or H or M
    char base_price[50];
    char monthly_price[50];
    char date[50];
    char userin[50];
    char active[50];
    struct r_c_p *next;
} rent_com;

static const unsigned int SHA256_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

typedef struct {
    unsigned char data[64];
    unsigned int datalen;
    unsigned long long bitlen;
    unsigned int state[8];
} SHA256_CTX;

void sha256_transform(SHA256_CTX *ctx, const unsigned char data[]) {
    unsigned int a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);

    for (; i < 64; ++i)
        m[i] = (m[i - 16] + (m[i - 15] >> 7 | m[i - 15] << 25) + (m[i - 7] >> 18 | m[i - 7] << 14) + m[i - 2]) & 0xffffffff;

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (i = 0; i < 64; ++i) {
        t1 = h + (e >> 6 | e << 26) + ((e & f) ^ (e & g) ^ (f & g)) + SHA256_K[i] + m[i];
        t2 = ((a >> 2 | a << 30) + ((a & b) ^ (a & c) ^ (b & c))) + (a >> 10 | a << 22);

        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void sha256_init(SHA256_CTX *ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

void sha256_update(SHA256_CTX *ctx, const unsigned char data[], size_t len) {
    for (size_t i = 0; i < len; ++i) {
        // Exclude newline character from the data
        if (data[i] != '\n') {
            ctx->data[ctx->datalen] = data[i];
            ctx->datalen++;
            if (ctx->datalen == 64) {
                sha256_transform(ctx, ctx->data);
                ctx->bitlen += 512;
                ctx->datalen = 0;
            }
        }
    }
}

void sha256_final(SHA256_CTX *ctx, unsigned char hash[]) {
    size_t i = ctx->datalen;

    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56)
            ctx->data[i++] = 0x00;
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64)
            ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    ctx->bitlen += ctx->datalen * 8;
    ctx->data[63] = ctx->bitlen;
    ctx->data[62] = ctx->bitlen >> 8;
    ctx->data[61] = ctx->bitlen >> 16;
    ctx->data[60] = ctx->bitlen >> 24;
    ctx->data[59] = ctx->bitlen >> 32;
    ctx->data[58] = ctx->bitlen >> 40;
    ctx->data[57] = ctx->bitlen >> 48;
    ctx->data[56] = ctx->bitlen >> 56;
    sha256_transform(ctx, ctx->data);

    for (i = 0; i < 4; ++i) {
        hash[i] = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 4] = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 8] = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
    }
}

void generateSalt(char *salt) {
    srand(time(NULL));
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const int salt_length = 16;

    for (int i = 0; i < salt_length; ++i) {
        char randomChar;
        do {
            randomChar = charset[rand() % (sizeof(charset) - 1)];
        } while (randomChar == '\n');  // Exclude newline characters

        salt[i] = randomChar;
    }

    salt[salt_length] = '\0';
}

///all functions
void print_art();
void sameall(char *list);
void display_current_date();
void current_date(char *input);
void display_current_time();

void login();
void sign_up();

void entery_menu();

int generateRandomNumber(int min, int max);
char generateRandomOperator();
void generateCaptcha(char* captcha, int* expectedResult);

int username_check(char *input);
int username2_check(char *input);
int name_check(char *input);
int ID_check(char *input);
int phone_check(char *input);
int email_check(char *input);
int password_check(char *input);
void get_password(char *password , int size);
void main_menu();
void adding_information();
void deleting_information();
void reports();
void user_settings();
void sell_property();
void residental_sell();
void commercial_sell();
void land_sell();
void rent_property();
int type1_check(char *input);
int type2_check(char *input);
int code_check(char *input);
int code2_check(char *input);
void edit_first_name();
void edit_last_name();
void edit_ID();
void edit_phone_number();
void edit_email();
void edit_password();

void property_counter();
void all_res_sell();
void all_com_sell();
void all_lan_sell();
void all_res_rent();
void all_com_rent();
void all_lan_rent();

int counter_sell_residental();
int counter_sell_commercial();
int counter_sell_land();
int counter_rent_residental();
int counter_rent_commercial();
int counter_rent_land();

void menu_res_sell();
void menu_com_sell();
void menu_lan_sell();
void menu_res_rent();
void menu_com_sell();
void menu_lan_rent();

void base_res_sell_district();
void base_res_sell_location();
void base_res_sell_type();
void base_res_sell_build_age();
void base_res_sell_floor_area();
void base_res_sell_floor();
void base_res_sell_land_area();
void base_res_sell_bedrooms();
void base_res_sell_tax_rate();
void base_res_sell_elevator();
void base_res_sell_basement();
void base_res_sell_balcony();
void base_res_sell_parkings();
void base_res_sell_phones();
void base_res_sell_temperature();
void base_res_sell_sell_price();

void base_com_sell_district();
void base_com_sell_location();
void base_com_sell_type();
void base_com_sell_build_age();
void base_com_sell_floor_area();
void base_com_sell_floor();
void base_com_sell_land_area();
void base_com_sell_rooms();
void base_com_sell_tax_rate();
void base_com_sell_elevator();
void base_com_sell_basement();
void base_com_sell_balcony();
void base_com_sell_parkings();
void base_com_sell_phones();
void base_com_sell_temperature();
void base_com_sell_sell_price();

void base_lan_sell_district();
void base_lan_sell_land_area();
void base_lan_sell_location();
void base_lan_sell_sell_price();
void base_lan_sell_tax_rate();
void base_lan_sell_temperature();
void base_lan_sell_type();
void base_lan_sell_well();
void base_lan_sell_width();

void base_res_rent_district();
void base_res_rent_location();
void base_res_rent_type();
void base_res_rent_build_age();
void base_res_rent_floor_area();
void base_res_rent_floor();
void base_res_rent_land_area();
void base_res_rent_bedrooms();
void base_res_rent_tax_rate();
void base_res_rent_elevator();
void base_res_rent_basement();
void base_res_rent_balcony();
void base_res_rent_parkings();
void base_res_rent_phones();
void base_res_rent_temperature();
void base_res_rent_price();

void base_com_rent_district();
void base_com_rent_location();
void base_com_rent_type();
void base_com_rent_build_age();
void base_com_rent_floor_area();
void base_com_rent_floor();
void base_com_rent_land_area();
void base_com_rent_rooms();
void base_com_rent_tax_rate();
void base_com_rent_elevator();
void base_com_rent_basement();
void base_com_rent_balcony();
void base_com_rent_parkings();
void base_com_rent_phones();
void base_com_rent_temperature();
void base_com_rent_price();

void base_lan_rent_district();
void base_lan_rent_land_area();
void base_lan_rent_location();
void base_lan_rent_price();
void base_lan_rent_tax_rate();
void base_lan_rent_temperature();
void base_lan_rent_type();
void base_lan_rent_well();
void base_lan_rent_width();

void admin_menu();
///start of the program
void main()
{
    print_art();
    system("cls");
    entery_menu();
}
///date function
void display_current_date()
{
    // Get the current time
    time_t t = time(NULL);
    struct tm *currentTime = localtime(&t);

    // Print the current date
    printf("Current Date: %04d-%02d-%02d\n",
           currentTime->tm_year + 1900, // Years since 1900
           currentTime->tm_mon + 1,     // Month (0-11, so add 1)
           currentTime->tm_mday);       // Day of the month
}
///date save function
void current_date(char *input)
{
    // Get current time
    time_t t;
    struct tm *currentDate;
    time(&t);
    currentDate = localtime(&t);

    // Format current date and store it in the provided char array
    snprintf(input, 16, "%04d-%02d-%02d",
             currentDate->tm_year + 1900,
             currentDate->tm_mon + 1,
             currentDate->tm_mday);
}
///real-time function
void display_current_time()
{
    time_t t;
    struct tm *timeInfo;
    time(&t);
    timeInfo = localtime(&t);
    printf("Current Time: %02d:%02d:%02d\n", timeInfo->tm_hour, timeInfo->tm_min, timeInfo->tm_sec);
}
///first menu after running the application
void entery_menu()
{
    char input[10];
    int number;
    while (1)
    {
        system("cls");
        system("color 07");
        printf("===PROPERTY MANAGE SYSTEM===\n");
        display_current_date();
        display_current_time();
        printf("\n1.Login\n");
        printf("2.Sign-up\n");
        printf("3.Exit\n");
        printf("\nPlease Enter Your Choice : ");
        gets(input);
        system("cls");
        number = atoi(input);
        if (number == 1)
        {
            login();
            continue;
        }
        else if (number == 2)
        {
            sign_up();
            continue;
        }
        else if (number == 3)
        {
            printf("Saving and exiting the program!\n");
            sleep(3);
            exit(0);
        }
        else
        {
            continue;
        }
    }
}
///sign-up menu
void sign_up()
{
    system("cls");
    system("color 02");
    printf("===SIGN UP====\n");
    display_current_date();
    display_current_time();
    char input[50];
    char salt[17];
    char hashed_password[65];
    user *new_user = (user*)malloc(sizeof(user));
    FILE *start;
    start = fopen("Users_data.txt" , "a");
    if (start == NULL)
    {
        printf("Error opening file.\n");
        sleep(3);
        exit(1);
    }

    int size;
    int file_counter = 0;
    if (start != NULL)
    {
        fseek (start, 0, SEEK_END);
        size = ftell(start);

        if (size != 0)
        {
            file_counter++;
        }
    }

    printf("\nEnter The Information Needed Below :\n");

    while (1)
    {
        printf("Username : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the user name is valid
        if (username_check(input) && username2_check(input) && strcasecmp(input, "Admin") != 0)
        {
            // Copy the input to the user structure
            strcpy(new_user->user_name, input);
            break;  // Exit the loop if a valid user name is provided
        }
        else
        {
            printf("Invalid username. Please try again.\n");
        }
    }

    while (1)
    {
        printf("First name : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        if (name_check(input))
        {
            // Copy the input to the user structure
            strcpy(new_user->first_name, input);
            sameall(new_user->first_name);
            break;
        }
        else
        {
            printf("Invalid first name. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Last name : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        if (name_check(input))
        {
            // Copy the input to the user structure
            strcpy(new_user->last_name, input);
            sameall(new_user->last_name);
            break;
        }
        else
        {
            printf("Invalid last name. Please try again.\n");
        }
    }

    while (1)
    {
        printf("ID : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        if (ID_check(input))
        {
            // Copy the input to the user structure
            strcpy(new_user->ID, input);
            break;
        }
        else
        {
            printf("Invalid ID. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Phone number : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        if (phone_check(input))
        {
            // Copy the input to the user structure
            strcpy(new_user->phone_number, input);
            break;
        }
        else
        {
            printf("Invalid phone number. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Email : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        if (email_check(input))
        {
            // Copy the input to the user structure
            strcpy(new_user->email, input);
            break;
        }
        else
        {
            printf("Invalid email. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Password: ");
        get_password(input, 24);

        char passkey[50];

        printf("\nConfirm your password: ");
        get_password(passkey, 24);

        // Remove the trailing newline character from input and passkey
        input[strcspn(input, "\n")] = '\0';
        passkey[strcspn(passkey, "\n")] = '\0';

        if (password_check(input))
        {
            if (strcmp(passkey, input) == 0)
            {
                printf("\nPassword set successfully.\n");
                generateSalt(salt);
                FILE *salter;
                salter = fopen("Salts_data.txt" , "a+");
                fprintf(salter, "%s\n", salt);
                fclose(salter);
                SHA256_CTX sha256_ctx;
                sha256_init(&sha256_ctx);
                char data[256]; // Adjust the size based on your needs
                snprintf(data, sizeof(data), "%s%s", input, salt);
                sha256_update(&sha256_ctx, data, strlen(data));
                sha256_final(&sha256_ctx, hashed_password);
                size_t hexHashSize = sizeof(hashed_password) * 2 + 1;
                char hexhash[hexHashSize];
                for (int z = 0; z < 32; z++) 
                {
                    snprintf(hexhash+z*2, hexHashSize-z*2, "%02x", hashed_password[z]);
                }
                strcpy(new_user->password, hexhash);
                sleep(3);
                break;
            }
            else
            {
                printf("Invalid password confirmation. Please try again.\n");
            }
        }
        else
        {
            printf("Invalid password. Please try again.\n");
        }
    }

    // Save the new user to the file
    if (file_counter == 0)
        {
            fprintf(start,"%s\n",new_user->user_name);
            fprintf(start,"%s\n",new_user->first_name);
            fprintf(start,"%s\n",new_user->last_name);
            fprintf(start,"%s\n",new_user->ID);
            fprintf(start,"%s\n",new_user->phone_number);
            fprintf(start,"%s\n",new_user->email);
            fprintf(start,"%s",new_user->password);
        }
        else
        {
            fprintf(start,"\n%s",new_user->user_name);
            fprintf(start,"\n%s",new_user->first_name);
            fprintf(start,"\n%s",new_user->last_name);
            fprintf(start,"\n%s",new_user->ID);
            fprintf(start,"\n%s",new_user->phone_number);
            fprintf(start,"\n%s",new_user->email);
            fprintf(start,"\n%s",new_user->password);
        }

    // Close the file
    fclose(start);

    // Don't forget to free the allocated memory when you're done
    free(new_user);
}
void print_art()
{
    system("color 04");
    printf("PPPPPPPPPPPP   MMM            MMM   SSSSSSSSSS    \n");
    usleep(500000);
    printf("P          P   MM M          M MM   S           \n");
    usleep(500000);
    printf("P          P   MM  M        M  MM   S           \n");
    usleep(500000);
    printf("P          P   MM   M      M   MM   S           \n");
    usleep(500000);
    printf("PPPPPPPPPPPP   MM    M    M    MM   SSSSSSSSSS    \n");
    usleep(500000);
    printf("P              MM     M  M     MM            S   \n");
    usleep(500000);
    printf("P              MM      M M     MM            S   \n");
    usleep(500000);
    printf("P              MM       M      MM            S   \n");
    usleep(500000);
    printf("P              MM       M      MM   SSSSSSSSSS    \n");
    sleep(3);
    system("color 07");
}
///code-check function
int code_check(char *input)
{
    // Check if the input is not NULL
    if (input == NULL)
    {
        return 0;  // Input is NULL, return false
    }

    // Check if the input is not an empty string
    if (strlen(input) == 0)
    {
        return 0;  // Input is an empty string, return false
    }

    // Convert the input string to an integer
    int number = atoi(input);

    // Check if the conversion was successful
    if (number == 0 && input[0] != '0')
    {
        return 0;  // Conversion failed, input is not a valid integer, return false
    }

    // Check if the number is within the specified range (1-9999)
    if (number >= 1 && number <= 9999 && code2_check(input) == 1)
    {
        return 1;  // Input is a valid integer within the specified range, return true
    }
    else
    {
        return 0;  // Input is not within the specified range, return false
    }
}
///code2-check function
int code2_check(char *input)
{
    coder *start = NULL, *p = NULL;
    FILE *fp;

    fp = fopen("Codes_check.txt", "r");
    if (fp == NULL)
    {
        printf("ERROR!\nFile could not be opened!");
        exit(0);
    }

    int check = 0;

    // Allocate memory for the first coder
    start = malloc(sizeof(coder));
    if (start == NULL)
    {
        printf("Memory allocation failed!\n");
        exit(1);
    }

    p = start;

    while (!feof(fp))
    {
        fgets(p->code, 50, fp);
        // Set null terminator for each string
        p->code[strcspn(p->code, "\n")] = '\0';

        // Allocate memory for the next coder
        p->next = malloc(sizeof(coder));
        if (p->next == NULL)
        {
            printf("Memory allocation failed!\n");
            exit(1);
        }

        p = p->next;

        check++;
    }

    fclose(fp);

    p = start;
    int coding_check = 0;

    for (int i = 0; i < check; i++)
    {
        if (strcmp(p->code, input) == 0)
        {
            coding_check++;
            return 0;
        }
        p = p->next;
    }
    if (coding_check == 0)
    {
        return 1;
    }

    // Free allocated memory for coder nodes
    p = start;
    while (p != NULL)
    {
        coder *temp = p;
        p = p->next;
        free(temp);
    }
}

///username-check function
int username_check(char *input)
{
    // Check if the length is between 8 and 16 characters (inclusive)
    size_t length = strlen(input);
    if (length < 8 || length > 16)
    {
        return 0; // Invalid length
    }

    // Check if the username contains any spaces
    for (size_t i = 0; i < length; i++)
    {
        if (input[i] == ' ')
        {
            return 0; // Invalid, contains space
        }

        // Check if the character is alphanumeric
        if (!isalnum(input[i]))
        {
            return 0; // Invalid, contains non-alphanumeric character
        }
    }
    // If all checks pass, the username is valid
    return 1;
}
///username2_check function
int username2_check(char *input)
{
    user *start = NULL, *p = NULL;
    FILE *fp;
    fp = fopen("Users_data.txt", "r");

    if (fp == NULL)
    {
        printf("ERROR!\nFile could not be opened!");
        exit(0);
    }

    int check = 0;

    // Allocate memory for the first user
    start = malloc(sizeof(user));
    if (start == NULL)
    {
        printf("Memory allocation failed!\n");
        exit(1);
    }

    p = start;

    while (!feof(fp))
    {
        fgets(p->user_name, 49, fp);
        fgets(p->first_name, 49, fp);
        fgets(p->last_name, 49, fp);
        fgets(p->ID, 49, fp);
        fgets(p->phone_number, 49, fp);
        fgets(p->email, 49, fp);
        fgets(p->password, 49, fp);
        // Set null terminator for each string
        p->user_name[strcspn(p->user_name, "\n")] = '\0';
        p->first_name[strcspn(p->first_name, "\n")] = '\0';
        p->last_name[strcspn(p->last_name, "\n")] = '\0';
        p->ID[strcspn(p->ID, "\n")] = '\0';
        p->phone_number[strcspn(p->phone_number, "\n")] = '\0';
        p->email[strcspn(p->email, "\n")] = '\0';
        p->password[strcspn(p->password, "\n")] = '\0';

        // Allocate memory for the next user
        p->next = malloc(sizeof(user));

        p = p->next;

        check++;
    }

    fclose(fp);

    p = start;

    for (int i = 0; i < check; i++)
    {
        if (strcmp(p->user_name, input) == 0)
        {
            return 0;
        }
        p = p->next;
    }

    return 1;
}
///name-check function
int name_check(char *input)
{
    // Check if the length is between 1 and 49 characters (inclusive)
    size_t length = strlen(input);
    if (length < 1 || length > 49)
    {
        return 0; // Invalid length
    }

    // Check if each character is alphabetic or a space
    for (size_t i = 0; i < length; i++)
    {
        if (!isalpha(input[i]) && input[i] != ' ')
        {
            return 0; // Invalid, contains non-alphabetic character (excluding space)
        }
    }

    // If all checks pass, the name is valid
    return 1;
}
///ID-check function
int ID_check(char *input)
{
    int length = strlen(input);
    // Check if the string contains only digits and has a length of 10
    for (int i = 0; i < length; i++)
    {
        if (!isdigit(input[i]) || length != 10)
        {
            return 0; // False
        }
    }
    // If all conditions are met, return 1 (True)
    return 1;
}
///phone-check function
int phone_check(char *input)
{
    // Check if the length is exactly 11 characters
    size_t length = strlen(input);
    if (length != 11)
    {
        return 0; // Invalid length
    }

    // Check if the phone number starts with "09"
    if (strncmp(input, "09", 2) != 0)
    {
        return 0; // Doesn't start with "09"
    }

    // Check if all characters are digits
    for (size_t i = 2; i < length; i++)
    {
        if (!isdigit(input[i]))
        {
            return 0; // Invalid, contains non-digit character
        }
    }

    // If all checks pass, the phone number is valid
    return 1;
}
///email-check function
int email_check(char *input)
{
    int i, dot_count, at_count, total_count;

    if (strlen(input) == 0)
    {
        return 0;
    }

    dot_count = at_count = 0;
    for (i = 0; i < strlen(input); i++)
    {
        if (input[i] == '@')
        {
            at_count++;
        }
        if (input[i] == '.')
        {
            dot_count++;
        }
    }

    if (at_count != 1 || dot_count == 0)
    {
        return 0;
    }

    total_count = 0;
    for (i = 0; i < strlen(input); i++)
    {
        if (input[i] == '.' || input[i] == '@')
        {
            if (total_count == 0)
            {
                return 0;
            }
            total_count = 0;
        }
        else
        {
            total_count++;
        }
    }

    if (total_count == 0)
    {
        return 0;
    }

    return 1;
}
///password_check function
int password_check(char *input)
{
    int length = strlen(input);
    int hasUpperCase = 0;
    int hasLowerCase = 0;
    int hasDigit = 0;

    // Check for minimum length
    if (length < 8)
    {
        return 0;  // False
    }

    // Check each character in the input
    for (int i = 0; i < length; i++)
    {
        char currentChar = input[i];

        // Check for uppercase letters
        if (isupper(currentChar))
        {
            hasUpperCase = 1;
        }

        // Check for lowercase letters
        if (islower(currentChar))
        {
            hasLowerCase = 1;
        }

        // Check for digits
        if (isdigit(currentChar))
        {
            hasDigit = 1;
        }
    }

    // Check if all criteria are met
    if (hasUpperCase && hasLowerCase && hasDigit)
    {
        return 1;  // True
    }
    else
    {
        return 0;  // False
    }
}
///get-password function
void get_password(char *password, int max_length)
{
    int i = 0;
    char ch;

    while (1)
    {
        ch = getch();

        if (ch == 13) // ASCII value of Enter
        {
            break;
        }
        else if (ch == 8) // ASCII value of Backspace
        {
            if (i > 0)
            {
                i--;
                printf("\b \b");  // Move the cursor back, print a space, move the cursor back again
            }
        }
        else if (i < max_length - 1)
        {
            password[i] = ch;
            printf("*");
            i++;
        }
    }
    password[i] = '\0';
}
///sameall as always
void sameall(char *list)
{
    int i;
    strlwr(list);
    list[0] = toupper(list[0]); // upper case first letter
    for (i=0 ; i<=strlen(list)-1 ; i++)
    {
        if (list[i] == 32) // finding spaces
        {
            list[i+1] = toupper(list[i+1]); // upper case after space
            i++;
        }
    }
}
///login menu
void login()
{
    system("cls");
    system("color 02");
    printf("===LOGIN===\n");
    display_current_date();
    display_current_time();

    FILE *start1;
    start1 = fopen("Logined_user.txt" , "w+");

    user *start = NULL, *p = NULL;
    FILE *fp;
    fp = fopen("Users_data.txt", "r");

    if (fp == NULL || start1 == NULL)
    {
        printf("ERROR!\nFile could not be opened!");
        exit(0);
    }

    int check = 0;

    // Allocate memory for the first user
    start = malloc(sizeof(user));
    if (start == NULL)
    {
        printf("Memory allocation failed!\n");
        exit(1);
    }

    p = start;

    while (!feof(fp))
    {
        fgets(p->user_name, 50, fp);
        fgets(p->first_name, 50, fp);
        fgets(p->last_name, 50, fp);
        fgets(p->ID, 50, fp);
        fgets(p->phone_number, 50, fp);
        fgets(p->email, 50, fp);
        fgets(p->password, 100, fp);
        // Set null terminator for each string
        p->user_name[strcspn(p->user_name, "\n")] = '\0';
        p->first_name[strcspn(p->first_name, "\n")] = '\0';
        p->last_name[strcspn(p->last_name, "\n")] = '\0';
        p->ID[strcspn(p->ID, "\n")] = '\0';
        p->phone_number[strcspn(p->phone_number, "\n")] = '\0';
        p->email[strcspn(p->email, "\n")] = '\0';
        p->password[strcspn(p->password, "\n")] = '\0';

        // Allocate memory for the next user
        p->next = malloc(sizeof(user));
        if (p->next == NULL)
        {
            printf("Memory allocation failed!\n");
            exit(1);
        }

        p = p->next;

        check++;
    }

    fclose(fp);

    char username1[50], pass1[100];

    printf("Please enter your username: ");
    fgets(username1, sizeof(username1), stdin);
    username1[strcspn(username1, "\n")] = '\0';

    while (1)
    {
        printf("Password: ");
        get_password(pass1, 24);
        printf("\n");

        // Remove the trailing newline character from input and passkey
        pass1[strcspn(pass1, "\n")] = '\0';

        if (password_check(pass1))
        {
            break;
        }
        else
        {
            printf("Invalid password format. Please try again.\n");
        }
    }

    p = start;
    int placer = 0;
    for (int i = 0; i < check; i++)
    {
        if (strcmp(p->user_name, username1) == 0)
        {
            placer = i;
            break;
        }
        p = p->next;
    }

    char salt[50];
    char hashed_password[65];
    FILE *salter;
    salter = fopen("Salts_data.txt" , "r");
    for(int z = 0 ; z<check ; z++)
    {
        if (z == placer)
        {
            fgets(salt, sizeof(salt), salter);
            salt[strcspn(salt, "\n")] = '\0';
            break;
        }
        fgets(salt, sizeof(salt), salter);
        salt[strcspn(salt, "\n")] = '\0';
    }
    fclose(salter);

    SHA256_CTX sha256_ctx;
    sha256_init(&sha256_ctx);
    char data[256]; // Adjust the size based on your needs
    snprintf(data, sizeof(data), "%s%s", pass1, salt);
    sha256_update(&sha256_ctx, data, strlen(data));
    sha256_final(&sha256_ctx, hashed_password);
    size_t hexHashSize = sizeof(hashed_password) * 2 + 1;
    char hexhash[hexHashSize];
    for (int z = 0; z < 32; z++) 
    {
        snprintf(hexhash+z*2, hexHashSize-z*2, "%02x", hashed_password[z]);
    }

    while (1)
    {
        char captcha[20];
        int expectedResult;

        // Generate the captcha
        generateCaptcha(captcha, &expectedResult);

        // Display the captcha to the user
        printf("Captcha: %s\n", captcha);

        // Get user input
        int userAnswer;
        printf("Enter the result: ");
        scanf("%d", &userAnswer);

        // Check if the user's answer is correct
        if (userAnswer == expectedResult)
        {
            printf("Correct! You are not a robot.\n\n");
            break;
        }
        else
        {
            printf("Incorrect! Please try again.\n\n");
            continue;
        }
    }

    p = start;
    int login_check = 0;

    for (int i = 0; i < check; i++)
    {
        if (strcmp(p->user_name, username1) == 0 && strcmp(p->password, hexhash) == 0)
        {
            printf("Login success!\n");
            login_check++;
            fprintf(start1, "%s\n", p->user_name);
            fclose(start1);
            sleep(3);
            main_menu();
        }
        p = p->next;
    }
    getch();

    if (username1 == "Admin" && pass1 == "Admin1234")
    {
        printf("Login success!\n");
        login_check++;
        fprintf(start1, "%s\n", p->user_name);
        fclose(start1);
        sleep(3);
        admin_menu();
    }
    if (login_check == 0)
    {
        printf("Login failed!\n");
        fclose(start1);
        sleep(3);
    }
}
// Function to generate a random integer between min and max
int generateRandomNumber(int min, int max)
{
    return rand() % (max - min + 1) + min;
}

// Function to generate a random operator (+, -, *)
char generateRandomOperator()
{
    char operators[] = {'+', '-', '*'};
    int randomIndex = generateRandomNumber(0, 2);
    return operators[randomIndex];
}

// Function to generate a random math expression
void generateCaptcha(char* captcha, int* expectedResult)
{
    int num1 = generateRandomNumber(1, 10);
    int num2 = generateRandomNumber(1, 10);
    char operator = generateRandomOperator();

    // Create the math expression and calculate the expected result
    sprintf(captcha, "%d %c %d", num1, operator, num2);
    switch (operator)
    {
        case '+':
            *expectedResult = num1 + num2;
            break;
        case '-':
            *expectedResult = num1 - num2;
            break;
        case '*':
            *expectedResult = num1 * num2;
            break;
    }
}
///main-menu function
void main_menu()
{
    system("color 07");
    char input[10];
    int number;
    while (1)
    {
        system("cls");
        printf("===MAIN MENU===\n");
        display_current_date();
        display_current_time();
        printf("\n1.Adding Information\n");
        printf("2.Deleting Information\n");
        printf("3.Reports\n");
        printf("4.User Settings\n");
        printf("5.Logout\n");
        printf("\nPlease Enter Your Choice : ");
        gets(input);
        system("cls");
        number = atoi(input);
        if (number == 1)
        {
            adding_information();
            continue;
        }
        else if (number == 2)
        {
            deleting_information();
            continue;
        }
        else if (number == 3)
        {
            reports();
            continue;
        }
        else if (number == 4)
        {
            user_settings();
            continue;
        }
        else if (number == 5)
        {
            break;
        }
        else
        {
            continue;
        }
    }
    entery_menu();
}
///adding-information function
void adding_information()
{
    system("color 07");
    char input[10];
    int number;
    while (1)
    {
        system("cls");
        printf("===ADDING INFORMATION===\n");
        display_current_date();
        display_current_time();
        printf("\n1.Sell Property\n");
        printf("2.Rent Property\n");
        printf("0.Back\n");
        printf("\nPlease Enter Your Choice : ");
        gets(input);
        system("cls");
        number = atoi(input);
        if (number == 1)
        {
            sell_property();
            continue;
        }
        else if (number == 2)
        {
            rent_property();
            continue;
        }
        else if (number == 0)
        {
            break;
        }
        else
        {
            continue;
        }
    }
}
///sell-property function
void sell_property()
{
    system("color 07");
    char input[10];
    int number;
    while (1)
    {
        system("cls");
        printf("===SELL PROPERTY===\n");
        display_current_date();
        display_current_time();
        printf("\n1.Residental Property\n");
        printf("2.Commercial Property\n");
        printf("3.Land Property\n");
        printf("0.Back\n");
        printf("\nPlease Enter Your Choice : ");
        gets(input);
        system("cls");
        number = atoi(input);
        if (number == 1)
        {
            residental_sell();
            continue;
        }
        else if (number == 2)
        {
            commercial_sell();
            continue;
        }
        else if (number == 3)
        {
            land_sell();
            continue;
        }
        else if (number == 0)
        {
            break;
        }
        else
        {
            continue;
        }
    }
}
///residental-sell function
void residental_sell()
{
    system("cls");
    system("color 02");
    printf("===RESIDENTAL SELL====\n");
    display_current_date();
    display_current_time();

    char input[500];
    char receiver[50];
    sell_res *new_building = (sell_res*)malloc(sizeof(sell_res));
    FILE *start , *start1 , *start2;
    start = fopen("Sell_res_data.txt" , "a+");
    start1 = fopen("Codes_check.txt" , "a+");
    start2 = fopen("Logined_user.txt" , "r");
    if (start == NULL || start1 == NULL || start2 == NULL)
    {
        printf("Error opening file.\n");
        sleep(3);
        exit(1);
    }

    int size;
    int file_counter = 0;
    if (start != NULL)
    {
        fseek (start, 0, SEEK_END);
        size = ftell(start);

        if (size != 0)
        {
            file_counter++;
        }
    }

    printf("\nEnter The Information Needed Below :\n");

    while (1)
    {
        printf("Code : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the code is valid
        if (code_check(input))
        {
            // Copy the input to the sell_res structure
            strcpy(new_building->code, input);
            break;  // Exit the loop if a valid code is provided
        }
        else
        {
            printf("Invalid code. Please try again.\n");
        }
    }

    while (1)
    {
        printf("District : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the district is valid
        if (district_check(input))
        {
            // Copy the input to the sell_res structure
            strcpy(new_building->district, input);
            break;  // Exit the loop if a valid district is provided
        }
        else
        {
            printf("Invalid district. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Address : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the address is valid
        if (address_check(input))
        {
            // Copy the input to the sell_res structure
            strcpy(new_building->address, input);
            break;  // Exit the loop if a valid address is provided
        }
        else
        {
            printf("Invalid address. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Location (North , South , East , West) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        // Check if the location is valid
        if (location_check(input))
        {
            // Copy the input to the sell_res structure
            strcpy(new_building->location, input);
            break;  // Exit the loop if a valid location is provided
        }
        else
        {
            printf("Invalid location. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Type (Apartment , Villa) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        // Check if the type is valid
        if (type_check(input))
        {
            // Copy the input to the sell_res structure
            strcpy(new_building->type, input);
            break;  // Exit the loop if a valid type is provided
        }
        else
        {
            printf("Invalid type. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Build age : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the build age is valid
        if (build_age_check(input))
        {
            // Copy the input to the sell_res structure
            strcpy(new_building->build_age, input);
            break;  // Exit the loop if a valid build age is provided
        }
        else
        {
            printf("Invalid build age. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Floor area (m^2) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the floor area is valid
        if (floor_area_check(input))
        {
            // Copy the input to the sell_res structure
            strcpy(new_building->floor_area, input);
            break;  // Exit the loop if a valid floor area is provided
        }
        else
        {
            printf("Invalid floor area. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Floor : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the floor is valid
        if (floor_check(input))
        {
            // Copy the input to the sell_res structure
            strcpy(new_building->floor, input);
            break;  // Exit the loop if a valid floor is provided
        }
        else
        {
            printf("Invalid floor. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Land area (m^2) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the land area is valid
        if (floor_area_check(input))
        {
            // Copy the input to the sell_res structure
            strcpy(new_building->land_area, input);
            break;  // Exit the loop if a valid land area is provided
        }
        else
        {
            printf("Invalid land area. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Owner phone number : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the owner phone number is valid
        if (phone_check(input))
        {
            // Copy the input to the sell_res structure
            strcpy(new_building->owner_phone_number, input);
            break;  // Exit the loop if a valid owner phone number is provided
        }
        else
        {
            printf("Invalid owner phone number. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Bedrooms : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the bedrooms is valid
        if (bedrooms_check(input))
        {
            // Copy the input to the sell_res structure
            strcpy(new_building->bedrooms, input);
            break;  // Exit the loop if a valid bedrooms is provided
        }
        else
        {
            printf("Invalid bedrooms. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Tax rate (0%%-100%%) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the tax rate is valid
        if (tax_rate_check(input))
        {
            // Copy the input to the sell_res structure
            strcpy(new_building->tax_rate, input);
            break;  // Exit the loop if a valid tax rate is provided
        }
        else
        {
            printf("Invalid tax rate. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Elevator (Yes , No) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        // Check if the elevator is valid
        if (yes_no_check(input))
        {
            // Copy the input to the sell_res structure
            strcpy(new_building->elevator, input);
            break;  // Exit the loop if a valid elevator is provided
        }
        else
        {
            printf("Invalid elevator. Please try again.\n");
        }
    }

    int basement_counter = 0;
    while (1)
    {
        printf("Basement (Yes , No) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        // Check if the basement is valid
        if (yes_no_check(input))
        {
            if (strcasecmp(input, "No") == 0)
            {
                basement_counter++;
            }
            // Copy the input to the sell_res structure
            strcpy(new_building->basement, input);
            break;  // Exit the loop if a valid basement is provided
        }
        else
        {
            printf("Invalid basement. Please try again.\n");
        }
    }

    while (1)
    {
        if (basement_counter != 0) // If answer is No
        {
            strcpy(new_building->basement_area, "0");
            break;
        }
        printf("Basement area (m^2) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the basement area is valid
        if (basement_area_check(input))
        {
            if (strcasecmp(input, "No") == 0)
            {
                basement_counter++;
            }
            // Copy the input to the sell_res structure
            strcpy(new_building->basement_area, input);
            break;  // Exit the loop if a valid basement area is provided
        }
        else
        {
            printf("Invalid basement area. Please try again.\n");
        }
    }

    int balcony_counter = 0;
    while (1)
    {
        printf("Balcony (Yes , No) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        // Check if the balcony is valid
        if (yes_no_check(input))
        {
            if (strcasecmp(input, "No") == 0)
            {
                balcony_counter++;
            }
            // Copy the input to the sell_res structure
            strcpy(new_building->balcony, input);
            break;  // Exit the loop if a valid balcony is provided
        }
        else
        {
            printf("Invalid balcony. Please try again.\n");
        }
    }

    while (1)
    {
        if (balcony_counter != 0) // If answer is No
        {
            strcpy(new_building->balcony_area, "0");
            break;
        }
        printf("Balcony area (m^2) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the balcony area is valid
        if (balcony_area_check(input))
        {
            // Copy the input to the sell_res structure
            strcpy(new_building->balcony_area, input);
            break;  // Exit the loop if a valid balcony area is provided
        }
        else
        {
            printf("Invalid balcony area. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Parkings : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the parkings is valid
        if (parkings_check(input))
        {
            // Copy the input to the sell_res structure
            strcpy(new_building->parkings, input);
            break;  // Exit the loop if a valid parkings is provided
        }
        else
        {
            printf("Invalid parkings. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Phones : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the phones is valid
        if (phones_check(input))
        {
            // Copy the input to the sell_res structure
            strcpy(new_building->phones, input);
            break;  // Exit the loop if a valid phones is provided
        }
        else
        {
            printf("Invalid phones. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Temperature (Cold , Hot , Medium) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        // Check if the temperature is valid
        if (temperature_check(input))
        {
            // Copy the input to the sell_res structure
            strcpy(new_building->temperature, input);
            break;  // Exit the loop if a valid temperature is provided
        }
        else
        {
            printf("Invalid temperature. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Sell price (Rials) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the sell price is valid
        if (sell_price_check(input))
        {
            // Copy the input to the sell_res structure
            strcpy(new_building->sell_price, input);
            break;  // Exit the loop if a valid sell price is provided
        }
        else
        {
            printf("Invalid sell price. Please try again.\n");
        }
    }

    current_date(input);
    strcpy(new_building->date , input);

    fgets(input, 49, start2);
    input[strcspn(input, "\n")] = '\0';
    strcpy(new_building->userin, input);

    strcpy(new_building->active, "Active");

    fprintf(start1, "%s\n", new_building->code);

    // Save the new user to the file
    if (file_counter == 0)
    {
        fprintf(start, "%s\n", new_building->code);
        fprintf(start, "%s\n", new_building->district);
        fprintf(start, "%s\n", new_building->address);
        fprintf(start, "%s\n", new_building->location);
        fprintf(start, "%s\n", new_building->type);
        fprintf(start, "%s\n", new_building->build_age);
        fprintf(start, "%s\n", new_building->floor_area);
        fprintf(start, "%s\n", new_building->floor);
        fprintf(start, "%s\n", new_building->land_area);
        fprintf(start, "%s\n", new_building->owner_phone_number);
        fprintf(start, "%s\n", new_building->bedrooms);
        fprintf(start, "%s\n", new_building->tax_rate);
        fprintf(start, "%s\n", new_building->elevator);
        fprintf(start, "%s\n", new_building->basement);
        fprintf(start, "%s\n", new_building->basement_area);
        fprintf(start, "%s\n", new_building->balcony);
        fprintf(start, "%s\n", new_building->balcony_area);
        fprintf(start, "%s\n", new_building->parkings);
        fprintf(start, "%s\n", new_building->phones);
        fprintf(start, "%s\n", new_building->temperature);
        fprintf(start, "%s\n", new_building->sell_price);
        fprintf(start, "%s\n", new_building->date);
        fprintf(start, "%s\n", new_building->userin);
        fprintf(start, "%s", new_building->active);
    }
    else
    {
        fprintf(start, "\n%s", new_building->code);
        fprintf(start, "\n%s", new_building->district);
        fprintf(start, "\n%s", new_building->address);
        fprintf(start, "\n%s", new_building->location);
        fprintf(start, "\n%s", new_building->type);
        fprintf(start, "\n%s", new_building->build_age);
        fprintf(start, "\n%s", new_building->floor_area);
        fprintf(start, "\n%s", new_building->floor);
        fprintf(start, "\n%s", new_building->land_area);
        fprintf(start, "\n%s", new_building->owner_phone_number);
        fprintf(start, "\n%s", new_building->bedrooms);
        fprintf(start, "\n%s", new_building->tax_rate);
        fprintf(start, "\n%s", new_building->elevator);
        fprintf(start, "\n%s", new_building->basement);
        fprintf(start, "\n%s", new_building->basement_area);
        fprintf(start, "\n%s", new_building->balcony);
        fprintf(start, "\n%s", new_building->balcony_area);
        fprintf(start, "\n%s", new_building->parkings);
        fprintf(start, "\n%s", new_building->phones);
        fprintf(start, "\n%s", new_building->temperature);
        fprintf(start, "\n%s", new_building->sell_price);
        fprintf(start, "\n%s", new_building->date);
        fprintf(start, "\n%s", new_building->userin);
        fprintf(start, "\n%s", new_building->active);
    }

    // Close the file
    fclose(start);
    fclose(start1);

    // Don't forget to free the allocated memory when you're done
    free(new_building);

}
///district-check function
int district_check(char *input)
{
    // Check if the input is a valid string
    if (input == NULL || strlen(input) == 0)
    {
        return 0; // Invalid input
    }

    // Convert the string to an integer
    int districtNumber = atoi(input);

    // Check if the converted number is within the valid range (1 to 30)
    if (districtNumber >= 1 && districtNumber <= 30)
    {
        return 1; // Valid district number
    }
    else
    {
        return 0; // Invalid district number
    }
}
///address-check function
int address_check(char *input)
{
    // Check if the input is a valid string and not empty
    if (input != NULL && strlen(input) > 0)
    {
        return 1; // Valid address
    }
    else
    {
        return 0; // Invalid address
    }
}
///location-check function
int location_check(char *input)
{
    // Check if the input is a valid cardinal direction
    if (strcasecmp(input, "North") == 0 || strcasecmp(input, "South") == 0 ||
        strcasecmp(input, "East") == 0 || strcasecmp(input, "West") == 0)
    {
        return 1; // Valid cardinal direction
    }
    else
    {
        return 0; // Invalid cardinal direction
    }
}
///type-check function
int type_check(char *input)
{
    // Check if the input is a valid property type
    if (strcasecmp(input, "Apartment") == 0 || strcasecmp(input, "Villa") == 0)
    {
        return 1; // Valid property type
    }
    else
    {
        return 0; // Invalid property type
    }
}
///build-age-check function
int build_age_check(char *input)
{
    // Convert the input to a floating-point number
    float age = atof(input);

    // Check if the input is a valid building age (between 0 and 200)
    if (age > 0 && age <= 200)
    {
        return 1; // Valid building age
    }
    else
    {
        return 0; // Invalid building age
    }
}
///floor-area-check function
int floor_area_check(char *input)
{
    // Convert the input to a floating-point number
    float area = atof(input);

    // Check if the input is a valid floor area (between 0 and 100,000)
    if (area > 0 && area <= 100000)
    {
        return 1; // Valid floor area
    }
    else
    {
        return 0; // Invalid floor area
    }
}
///floor-check function
int floor_check(char *input)
{
    // Convert the input to an integer
    int floorNumber = atoi(input);

    // Check if the input is a valid floor number (between 1 and 50)
    if (floorNumber >= 1 && floorNumber <= 50)
    {
        return 1; // Valid floor number
    }
    else
    {
        return 0; // Invalid floor number
    }
}
///bedrooms-check function
int bedrooms_check(char *input)
{
    // Convert the input to an integer
    int bedroomsNumber = atoi(input);

    // Check if the input is a valid bedrooms number (between 0 and 10)
    if (bedroomsNumber >= 0 && bedroomsNumber <= 10)
    {
        return 1; // Valid bedrooms number
    }
    else
    {
        return 0; // Invalid bedrooms number
    }
}
///tax-rate-check function
int tax_rate_check(char *input)
{
    // Convert the input to a floating-point number
    float taxRate = atof(input);

    // Check if the input is a valid tax rate (between 0 and 100)
    if (taxRate >= 0 && taxRate <= 100)
    {
        return 1; // Valid tax rate
    }
    else
    {
        return 0; // Invalid tax rate
    }
}
///yes-no-check function
int yes_no_check(char *input)
{
    // Check if the input is a valid "Yes" or "No"
    if (strcasecmp(input, "Yes") == 0 || strcasecmp(input, "No") == 0)
    {
        return 1; // Valid input
    }
    else
    {
        return 0; // Invalid input
    }
}
///basement-area-check function
int basement_area_check(char *input)
{
    // Convert the input to a floating-point number
    float area = atof(input);

    // Check if the input is a valid basement area (between 0 and 10,000)
    if (area > 0 && area <= 10000)
    {
        return 1; // Valid basement area
    }
    else
    {
        return 0; // Invalid basement area
    }
}
///balcony-area-check function
int balcony_area_check(char *input)
{
    // Convert the input to a floating-point number
    float area = atof(input);

    // Check if the input is a valid balcony area (between 0 and 1,000)
    if (area > 0 && area <= 1000)
    {
        return 1; // Valid balcony area
    }
    else
    {
        return 0; // Invalid balcony area
    }
}
///parkings-check function
int parkings_check(char *input)
{
    // Convert the input to an integer
    int parkingsNumber = atoi(input);

    // Check if the input is a valid parkings number (between 0 and 10)
    if (parkingsNumber >= 0 && parkingsNumber <= 10)
    {
        return 1; // Valid parkings number
    }
    else
    {
        return 0; // Invalid parkings number
    }
}
///phones-check function
int phones_check(char *input)
{
    // Convert the input to an integer
    int phonesNumber = atoi(input);

    // Check if the input is a valid phones number (between 0 and 10)
    if (phonesNumber >= 0 && phonesNumber <= 10)
    {
        return 1; // Valid phones number
    }
    else
    {
        return 0; // Invalid phones number
    }
}
///temperature-check function
int temperature_check(char *input)
{
    // Check if the input is a valid temperature ("Hot," "Cold," or "Medium")
    if (strcasecmp(input, "Hot") == 0 || strcasecmp(input, "Cold") == 0 || strcasecmp(input, "Medium") == 0)
    {
        return 1; // Valid input
    }
    else
    {
        return 0; // Invalid input
    }
}
///sell-price function
int sell_price_check(char *input)
{
    // Convert the input to a floating-point number
    float price = atof(input);

    // Check if the input is a valid positive number
    if (price > 0)
    {
        return 1; // Valid input
    }
    else
    {
        return 0; // Invalid input
    }
}
///commercial-sell function
void commercial_sell()
{
    system("cls");
    system("color 02");
    printf("===COMMERCIAL SELL===\n");
    display_current_date();
    display_current_time();
    char input[500];
    sell_com *new_building = (sell_com*)malloc(sizeof(sell_com));
    FILE *start , *start1 , *start2;
    start = fopen("Sell_com_data.txt" , "a+");
    start1 = fopen("Codes_check.txt" , "a+");
    start2 = fopen("Logined_user.txt" , "r");
    if (start == NULL || start1 == NULL || start2 == NULL)
    {
        printf("Error opening file.\n");
        sleep(3);
        exit(1);
    }

    int size;
    int file_counter = 0;
    if (start != NULL)
    {
        fseek (start, 0, SEEK_END);
        size = ftell(start);

        if (size != 0)
        {
            file_counter++;
        }
    }

    printf("\nEnter The Information Needed Below :\n");

    while (1)
    {
        printf("Code : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the code is valid
        if (code_check(input))
        {
            // Copy the input to the sell_com structure
            strcpy(new_building->code, input);
            break;  // Exit the loop if a valid code is provided
        }
        else
        {
            printf("Invalid code. Please try again.\n");
        }
    }

    while (1)
    {
        printf("District : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the district is valid
        if (district_check(input))
        {
            // Copy the input to the sell_com structure
            strcpy(new_building->district, input);
            break;  // Exit the loop if a valid district is provided
        }
        else
        {
            printf("Invalid district. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Address : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the address is valid
        if (address_check(input))
        {
            // Copy the input to the sell_com structure
            strcpy(new_building->address, input);
            break;  // Exit the loop if a valid address is provided
        }
        else
        {
            printf("Invalid address. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Location (North , South , East , West) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        // Check if the location is valid
        if (location_check(input))
        {
            // Copy the input to the sell_com structure
            strcpy(new_building->location, input);
            break;  // Exit the loop if a valid location is provided
        }
        else
        {
            printf("Invalid location. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Type (Official , Position) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        // Check if the type is valid
        if (type1_check(input))
        {
            // Copy the input to the sell_com structure
            strcpy(new_building->type, input);
            break;  // Exit the loop if a valid type is provided
        }
        else
        {
            printf("Invalid type. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Build age : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the build age is valid
        if (build_age_check(input))
        {
            // Copy the input to the sell_com structure
            strcpy(new_building->build_age, input);
            break;  // Exit the loop if a valid build age is provided
        }
        else
        {
            printf("Invalid build age. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Floor area (m^2) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the floor area is valid
        if (floor_area_check(input))
        {
            // Copy the input to the sell_com structure
            strcpy(new_building->floor_area, input);
            break;  // Exit the loop if a valid floor area is provided
        }
        else
        {
            printf("Invalid floor area. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Floor : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the floor is valid
        if (floor_check(input))
        {
            // Copy the input to the sell_com structure
            strcpy(new_building->floor, input);
            break;  // Exit the loop if a valid floor is provided
        }
        else
        {
            printf("Invalid floor. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Land area (m^2) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the land area is valid
        if (floor_area_check(input))
        {
            // Copy the input to the sell_com structure
            strcpy(new_building->land_area, input);
            break;  // Exit the loop if a valid land area is provided
        }
        else
        {
            printf("Invalid land area. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Owner phone number : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the owner phone number is valid
        if (phone_check(input))
        {
            // Copy the input to the sell_com structure
            strcpy(new_building->owner_phone_number, input);
            break;  // Exit the loop if a valid owner phone number is provided
        }
        else
        {
            printf("Invalid owner phone number. Please try again.\n");
        }
    }

    while (1)
    {
        printf("rooms : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the rooms is valid
        if (bedrooms_check(input))
        {
            // Copy the input to the sell_com structure
            strcpy(new_building->rooms, input);
            break;  // Exit the loop if a valid rooms is provided
        }
        else
        {
            printf("Invalid bedrooms. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Tax rate (0%%-100%%) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the tax rate is valid
        if (tax_rate_check(input))
        {
            // Copy the input to the sell_com structure
            strcpy(new_building->tax_rate, input);
            break;  // Exit the loop if a valid tax rate is provided
        }
        else
        {
            printf("Invalid tax rate. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Elevator (Yes , No) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        // Check if the elevator is valid
        if (yes_no_check(input))
        {
            // Copy the input to the sell_com structure
            strcpy(new_building->elevator, input);
            break;  // Exit the loop if a valid elevator is provided
        }
        else
        {
            printf("Invalid elevator. Please try again.\n");
        }
    }

    int basement_counter = 0;
    while (1)
    {
        printf("Basement (Yes , No) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        // Check if the basement is valid
        if (yes_no_check(input))
        {
            if (strcasecmp(input, "No") == 0)
            {
                basement_counter++;
            }
            // Copy the input to the sell_com structure
            strcpy(new_building->basement, input);
            break;  // Exit the loop if a valid basement is provided
        }
        else
        {
            printf("Invalid basement. Please try again.\n");
        }
    }

    while (1)
    {
        if (basement_counter != 0) // If answer is No
        {
            strcpy(new_building->basement_area, "0");
            break;
        }
        printf("Basement area (m^2) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the basement area is valid
        if (basement_area_check(input))
        {
            if (strcasecmp(input, "No") == 0)
            {
                basement_counter++;
            }
            // Copy the input to the sell_com structure
            strcpy(new_building->basement_area, input);
            break;  // Exit the loop if a valid basement area is provided
        }
        else
        {
            printf("Invalid basement area. Please try again.\n");
        }
    }

    int balcony_counter = 0;
    while (1)
    {
        printf("Balcony (Yes , No) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        // Check if the balcony is valid
        if (yes_no_check(input))
        {
            if (strcasecmp(input, "No") == 0)
            {
                balcony_counter++;
            }
            // Copy the input to the sell_com structure
            strcpy(new_building->balcony, input);
            break;  // Exit the loop if a valid balcony is provided
        }
        else
        {
            printf("Invalid balcony. Please try again.\n");
        }
    }

    while (1)
    {
        if (balcony_counter != 0) // If answer is No
        {
            strcpy(new_building->balcony_area, "0");
            break;
        }
        printf("Balcony area (m^2) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the balcony area is valid
        if (balcony_area_check(input))
        {
            // Copy the input to the sell_com structure
            strcpy(new_building->balcony_area, input);
            break;  // Exit the loop if a valid balcony area is provided
        }
        else
        {
            printf("Invalid balcony area. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Parkings : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the parkings is valid
        if (parkings_check(input))
        {
            // Copy the input to the sell_com structure
            strcpy(new_building->parkings, input);
            break;  // Exit the loop if a valid parkings is provided
        }
        else
        {
            printf("Invalid parkings. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Phones : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the phones is valid
        if (phones_check(input))
        {
            // Copy the input to the sell_com structure
            strcpy(new_building->phones, input);
            break;  // Exit the loop if a valid phones is provided
        }
        else
        {
            printf("Invalid phones. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Temperature (Cold , Hot , Medium) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        // Check if the temperature is valid
        if (temperature_check(input))
        {
            // Copy the input to the sell_com structure
            strcpy(new_building->temperature, input);
            break;  // Exit the loop if a valid temperature is provided
        }
        else
        {
            printf("Invalid temperature. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Sell price (Rials) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the sell price is valid
        if (sell_price_check(input))
        {
            // Copy the input to the sell_com structure
            strcpy(new_building->sell_price, input);
            break;  // Exit the loop if a valid sell price is provided
        }
        else
        {
            printf("Invalid sell price. Please try again.\n");
        }
    }

    current_date(input);
    strcpy(new_building->date , input);

    fgets(input, 49, start2);
    input[strcspn(input, "\n")] = '\0';
    strcpy(new_building->userin, input);

    strcpy(new_building->active, "Active");

    fprintf(start1, "%s\n", new_building->code);

    // Save the new user to the file
    if (file_counter == 0)
    {
        fprintf(start, "%s\n", new_building->code);
        fprintf(start, "%s\n", new_building->district);
        fprintf(start, "%s\n", new_building->address);
        fprintf(start, "%s\n", new_building->location);
        fprintf(start, "%s\n", new_building->type);
        fprintf(start, "%s\n", new_building->build_age);
        fprintf(start, "%s\n", new_building->floor_area);
        fprintf(start, "%s\n", new_building->floor);
        fprintf(start, "%s\n", new_building->land_area);
        fprintf(start, "%s\n", new_building->owner_phone_number);
        fprintf(start, "%s\n", new_building->rooms);
        fprintf(start, "%s\n", new_building->tax_rate);
        fprintf(start, "%s\n", new_building->elevator);
        fprintf(start, "%s\n", new_building->basement);
        fprintf(start, "%s\n", new_building->basement_area);
        fprintf(start, "%s\n", new_building->balcony);
        fprintf(start, "%s\n", new_building->balcony_area);
        fprintf(start, "%s\n", new_building->parkings);
        fprintf(start, "%s\n", new_building->phones);
        fprintf(start, "%s\n", new_building->temperature);
        fprintf(start, "%s\n", new_building->sell_price);
        fprintf(start, "%s\n", new_building->date);
        fprintf(start, "%s\n", new_building->userin);
        fprintf(start, "%s", new_building->active);
    }
    else
    {
        fprintf(start, "\n%s", new_building->code);
        fprintf(start, "\n%s", new_building->district);
        fprintf(start, "\n%s", new_building->address);
        fprintf(start, "\n%s", new_building->location);
        fprintf(start, "\n%s", new_building->type);
        fprintf(start, "\n%s", new_building->build_age);
        fprintf(start, "\n%s", new_building->floor_area);
        fprintf(start, "\n%s", new_building->floor);
        fprintf(start, "\n%s", new_building->land_area);
        fprintf(start, "\n%s", new_building->owner_phone_number);
        fprintf(start, "\n%s", new_building->rooms);
        fprintf(start, "\n%s", new_building->tax_rate);
        fprintf(start, "\n%s", new_building->elevator);
        fprintf(start, "\n%s", new_building->basement);
        fprintf(start, "\n%s", new_building->basement_area);
        fprintf(start, "\n%s", new_building->balcony);
        fprintf(start, "\n%s", new_building->balcony_area);
        fprintf(start, "\n%s", new_building->parkings);
        fprintf(start, "\n%s", new_building->phones);
        fprintf(start, "\n%s", new_building->temperature);
        fprintf(start, "\n%s", new_building->sell_price);
        fprintf(start, "\n%s", new_building->date);
        fprintf(start, "\n%s", new_building->userin);
        fprintf(start, "\n%s", new_building->active);
    }

    // Close the file
    fclose(start);
    fclose(start1);

    // Don't forget to free the allocated memory when you're done
    free(new_building);
}
///type2-check function
int type1_check(char *input)
{
    // Check if the input is a valid property type
    if (strcasecmp(input, "Official") == 0 || strcasecmp(input, "Position") == 0)
    {
        return 1; // Valid property type
    }
    else
    {
        return 0; // Invalid property type
    }
}
///land-sell function
void land_sell()
{
    system("cls");
    system("color 02");
    printf("===LAND SELL===\n");
    display_current_date();
    display_current_time();
    char input[500];
    sell_lan *new_building = (sell_lan*)malloc(sizeof(sell_lan));
    FILE *start , *start1 , *start2;
    start = fopen("Sell_lan_data.txt" , "a+");
    start1 = fopen("Codes_check.txt" , "a+");
    start2 = fopen("Logined_user.txt" , "r");
    if (start == NULL || start1 == NULL || start2 == NULL)
    {
        printf("Error opening file.\n");
        sleep(3);
        exit(1);
    }

    int size;
    int file_counter = 0;
    if (start != NULL)
    {
        fseek (start, 0, SEEK_END);
        size = ftell(start);

        if (size != 0)
        {
            file_counter++;
        }
    }

    printf("\nEnter The Information Needed Below :\n");

    while (1)
    {
        printf("Code : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the code is valid
        if (code_check(input))
        {
            // Copy the input to the sell_lan structure
            strcpy(new_building->code, input);
            break;  // Exit the loop if a valid code is provided
        }
        else
        {
            printf("Invalid code. Please try again.\n");
        }
    }

    while (1)
    {
        printf("District : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the district is valid
        if (district_check(input))
        {
            // Copy the input to the sell_lan structure
            strcpy(new_building->district, input);
            break;  // Exit the loop if a valid district is provided
        }
        else
        {
            printf("Invalid district. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Address : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the address is valid
        if (address_check(input))
        {
            // Copy the input to the sell_lan structure
            strcpy(new_building->address, input);
            break;  // Exit the loop if a valid address is provided
        }
        else
        {
            printf("Invalid address. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Location (North , South , East , West) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        // Check if the location is valid
        if (location_check(input))
        {
            // Copy the input to the sell_lan structure
            strcpy(new_building->location, input);
            break;  // Exit the loop if a valid location is provided
        }
        else
        {
            printf("Invalid location. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Type (Farm , City) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        // Check if the type is valid
        if (type2_check(input))
        {
            // Copy the input to the sell_lan structure
            strcpy(new_building->type, input);
            break;  // Exit the loop if a valid type is provided
        }
        else
        {
            printf("Invalid type. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Land area (m^2) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the land area is valid
        if (floor_area_check(input))
        {
            // Copy the input to the sell_com structure
            strcpy(new_building->land_area, input);
            break;  // Exit the loop if a valid land area is provided
        }
        else
        {
            printf("Invalid land area. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Width (m) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the width is valid
        if (floor_area_check(input))
        {
            // Copy the input to the sell_com structure
            strcpy(new_building->width, input);
            break;  // Exit the loop if a valid width is provided
        }
        else
        {
            printf("Invalid width. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Owner phone number : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the owner phone number is valid
        if (phone_check(input))
        {
            // Copy the input to the sell_com structure
            strcpy(new_building->owner_phone_number, input);
            break;  // Exit the loop if a valid owner phone number is provided
        }
        else
        {
            printf("Invalid owner phone number. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Tax rate (0%%-100%%) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the tax rate is valid
        if (tax_rate_check(input))
        {
            // Copy the input to the sell_lan structure
            strcpy(new_building->tax_rate, input);
            break;  // Exit the loop if a valid tax rate is provided
        }
        else
        {
            printf("Invalid tax rate. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Well (Yes , No) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        // Check if the well is valid
        if (yes_no_check(input))
        {
            // Copy the input to the sell_lan structure
            strcpy(new_building->well, input);
            break;  // Exit the loop if a valid well is provided
        }
        else
        {
            printf("Invalid well. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Temperature (Cold , Hot , Medium) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        // Check if the temperature is valid
        if (temperature_check(input))
        {
            // Copy the input to the sell_lan structure
            strcpy(new_building->temperature, input);
            break;  // Exit the loop if a valid temperature is provided
        }
        else
        {
            printf("Invalid temperature. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Sell price (Rials) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the sell price is valid
        if (sell_price_check(input))
        {
            // Copy the input to the sell_lan structure
            strcpy(new_building->sell_price, input);
            break;  // Exit the loop if a valid sell price is provided
        }
        else
        {
            printf("Invalid sell price. Please try again.\n");
        }
    }

    current_date(input);
    strcpy(new_building->date , input);

    fgets(input, 49, start2);
    input[strcspn(input, "\n")] = '\0';
    strcpy(new_building->userin, input);

    strcpy(new_building->active, "Active");

    fprintf(start1, "%s\n", new_building->code);

    // Save the new user to the file
    if (file_counter == 0)
    {
        fprintf(start, "%s\n", new_building->code);
        fprintf(start, "%s\n", new_building->district);
        fprintf(start, "%s\n", new_building->address);
        fprintf(start, "%s\n", new_building->location);
        fprintf(start, "%s\n", new_building->type);
        fprintf(start, "%s\n", new_building->land_area);
        fprintf(start, "%s\n", new_building->width);
        fprintf(start, "%s\n", new_building->owner_phone_number);
        fprintf(start, "%s\n", new_building->tax_rate);
        fprintf(start, "%s\n", new_building->well);
        fprintf(start, "%s\n", new_building->temperature);
        fprintf(start, "%s\n", new_building->sell_price);
        fprintf(start, "%s\n", new_building->date);
        fprintf(start, "%s\n", new_building->userin);
        fprintf(start, "%s", new_building->active);
    }
    else
    {
        fprintf(start, "\n%s", new_building->code);
        fprintf(start, "\n%s", new_building->district);
        fprintf(start, "\n%s", new_building->address);
        fprintf(start, "\n%s", new_building->location);
        fprintf(start, "\n%s", new_building->type);
        fprintf(start, "\n%s", new_building->land_area);
        fprintf(start, "\n%s", new_building->width);
        fprintf(start, "\n%s", new_building->owner_phone_number);
        fprintf(start, "\n%s", new_building->tax_rate);
        fprintf(start, "\n%s", new_building->well);
        fprintf(start, "\n%s", new_building->temperature);
        fprintf(start, "\n%s", new_building->sell_price);
        fprintf(start, "\n%s", new_building->date);
        fprintf(start, "\n%s", new_building->userin);
        fprintf(start, "\n%s", new_building->active);
    }

    // Close the file
    fclose(start);
    fclose(start1);

    // Don't forget to free the allocated memory when you're done
    free(new_building);
}
///type2-check function
int type2_check(char *input)
{
    // Check if the input is a valid property type
    if (strcasecmp(input, "Farm") == 0 || strcasecmp(input, "City") == 0)
    {
        return 1; // Valid property type
    }
    else
    {
        return 0; // Invalid property type
    }
}
///rent-property function
void rent_property()
{
    char input[10];
    int number;
    while (1)
    {
        system("cls");
        system("color 07");
        printf("===SELL PROPERTY===");
        display_current_date();
        display_current_time();
        printf("\n1.Residental Property\n");
        printf("2.Commercial Property\n");
        printf("3.Land Property\n");
        printf("0.Back\n");
        printf("\nPlease Enter Your Choice : ");
        gets(input);
        system("cls");
        number = atoi(input);
        if (number == 1)
        {
            residental_rent();
            continue;
        }
        else if (number == 2)
        {
            commercial_rent();
            continue;
        }
        else if (number == 3)
        {
            land_rent();
            continue;
        }
        else if (number == 0)
        {
            break;
        }
        else
        {
            continue;
        }
    }
}
///residental-rent function
void residental_rent()
{
    system("cls");
    system("color 02");
    printf("===RESIDENTAL RENT====\n");
    display_current_date();
    display_current_time();
    char input[500];
    rent_res *new_building = (rent_res*)malloc(sizeof(rent_res));
    FILE *start , *start1 , *start2;
    start = fopen("Rent_res_data.txt" , "a+");
    start1 = fopen("Codes_check.txt" , "a+");
    start2 = fopen("Logined_user.txt" , "r");
    if (start == NULL || start1 == NULL || start2 == NULL)
    {

        printf("Error opening file.\n");
        sleep(3);
        exit(1);
    }

    int size;
    int file_counter = 0;
    if (start != NULL)
    {
        fseek (start, 0, SEEK_END);
        size = ftell(start);

        if (size != 0)
        {
            file_counter++;
        }
    }

    printf("\nEnter The Information Needed Below :\n");

    while (1)
    {
        printf("Code : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the code is valid
        if (code_check(input))
        {
            // Copy the input to the rent_res structure
            strcpy(new_building->code, input);
            break;  // Exit the loop if a valid code is provided
        }
        else
        {
            printf("Invalid code. Please try again.\n");
        }
    }

    while (1)
    {
        printf("District : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the district is valid
        if (district_check(input))
        {
            // Copy the input to the rent_res structure
            strcpy(new_building->district, input);
            break;  // Exit the loop if a valid district is provided
        }
        else
        {
            printf("Invalid district. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Address : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the address is valid
        if (address_check(input))
        {
            // Copy the input to the rent_res structure
            strcpy(new_building->address, input);
            break;  // Exit the loop if a valid address is provided
        }
        else
        {
            printf("Invalid address. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Location (North , South , East , West) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        // Check if the location is valid
        if (location_check(input))
        {
            // Copy the input to the rent_res structure
            strcpy(new_building->location, input);
            break;  // Exit the loop if a valid location is provided
        }
        else
        {
            printf("Invalid location. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Type (Apartment , Villa) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        // Check if the type is valid
        if (type_check(input))
        {
            // Copy the input to the rent_res structure
            strcpy(new_building->type, input);
            break;  // Exit the loop if a valid type is provided
        }
        else
        {
            printf("Invalid type. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Build age : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the build age is valid
        if (build_age_check(input))
        {
            // Copy the input to the rent_res structure
            strcpy(new_building->build_age, input);
            break;  // Exit the loop if a valid build age is provided
        }
        else
        {
            printf("Invalid build age. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Floor area (m^2) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the floor area is valid
        if (floor_area_check(input))
        {
            // Copy the input to the rent_res structure
            strcpy(new_building->floor_area, input);
            break;  // Exit the loop if a valid floor area is provided
        }
        else
        {
            printf("Invalid floor area. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Floor : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the floor is valid
        if (floor_check(input))
        {
            // Copy the input to the rent_res structure
            strcpy(new_building->floor, input);
            break;  // Exit the loop if a valid floor is provided
        }
        else
        {
            printf("Invalid floor. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Land area (m^2) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the land area is valid
        if (floor_area_check(input))
        {
            // Copy the input to the rent_res structure
            strcpy(new_building->land_area, input);
            break;  // Exit the loop if a valid land area is provided
        }
        else
        {
            printf("Invalid land area. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Owner phone number : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the owner phone number is valid
        if (phone_check(input))
        {
            // Copy the input to the rent_res structure
            strcpy(new_building->owner_phone_number, input);
            break;  // Exit the loop if a valid owner phone number is provided
        }
        else
        {
            printf("Invalid owner phone number. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Bedrooms : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the bedrooms is valid
        if (bedrooms_check(input))
        {
            // Copy the input to the rent_res structure
            strcpy(new_building->bedrooms, input);
            break;  // Exit the loop if a valid bedrooms is provided
        }
        else
        {
            printf("Invalid bedrooms. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Tax rate (0%%-100%%) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the tax rate is valid
        if (tax_rate_check(input))
        {
            // Copy the input to the rent_res structure
            strcpy(new_building->tax_rate, input);
            break;  // Exit the loop if a valid tax rate is provided
        }
        else
        {
            printf("Invalid tax rate. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Elevator (Yes , No) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        // Check if the elevator is valid
        if (yes_no_check(input))
        {
            // Copy the input to the rent_res structure
            strcpy(new_building->elevator, input);
            break;  // Exit the loop if a valid elevator is provided
        }
        else
        {
            printf("Invalid elevator. Please try again.\n");
        }
    }

    int basement_counter = 0;
    while (1)
    {
        printf("Basement (Yes , No) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        // Check if the basement is valid
        if (yes_no_check(input))
        {
            if (strcasecmp(input, "No") == 0)
            {
                basement_counter++;
            }
            // Copy the input to the rent_res structure
            strcpy(new_building->basement, input);
            break;  // Exit the loop if a valid basement is provided
        }
        else
        {
            printf("Invalid basement. Please try again.\n");
        }
    }

    while (1)
    {
        if (basement_counter != 0) // If answer is No
        {
            strcpy(new_building->basement_area, "0");
            break;
        }
        printf("Basement area (m^2) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the basement area is valid
        if (basement_area_check(input))
        {
            if (strcasecmp(input, "No") == 0)
            {
                basement_counter++;
            }
            // Copy the input to the rent_res structure
            strcpy(new_building->basement_area, input);
            break;  // Exit the loop if a valid basement area is provided
        }
        else
        {
            printf("Invalid basement area. Please try again.\n");
        }
    }

    int balcony_counter = 0;
    while (1)
    {
        printf("Balcony (Yes , No) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        // Check if the balcony is valid
        if (yes_no_check(input))
        {
            if (strcasecmp(input, "No") == 0)
            {
                balcony_counter++;
            }
            // Copy the input to the rent_res structure
            strcpy(new_building->balcony, input);
            break;  // Exit the loop if a valid balcony is provided
        }
        else
        {
            printf("Invalid balcony. Please try again.\n");
        }
    }

    while (1)
    {
        if (balcony_counter != 0) // If answer is No
        {
            strcpy(new_building->balcony_area, "0");
            break;
        }
        printf("Balcony area (m^2) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the balcony area is valid
        if (balcony_area_check(input))
        {
            // Copy the input to the rent_res structure
            strcpy(new_building->balcony_area, input);
            break;  // Exit the loop if a valid balcony area is provided
        }
        else
        {
            printf("Invalid balcony area. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Parkings : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the parkings is valid
        if (parkings_check(input))
        {
            // Copy the input to the rent_res structure
            strcpy(new_building->parkings, input);
            break;  // Exit the loop if a valid parkings is provided
        }
        else
        {
            printf("Invalid parkings. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Phones : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the phones is valid
        if (phones_check(input))
        {
            // Copy the input to the rent_res structure
            strcpy(new_building->phones, input);
            break;  // Exit the loop if a valid phones is provided
        }
        else
        {
            printf("Invalid phones. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Temperature (Cold , Hot , Medium) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        // Check if the temperature is valid
        if (temperature_check(input))
        {
            // Copy the input to the rent_res structure
            strcpy(new_building->temperature, input);
            break;  // Exit the loop if a valid temperature is provided
        }
        else
        {
            printf("Invalid temperature. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Base price (Rials) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the base price is valid
        if (sell_price_check(input))
        {
            // Copy the input to the rent_res structure
            strcpy(new_building->base_price, input);
            break;  // Exit the loop if a valid base price is provided
        }
        else
        {
            printf("Invalid base price. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Monthly price (Rials) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the monthly price is valid
        if (sell_price_check(input))
        {
            // Copy the input to the rent_res structure
            strcpy(new_building->monthly_price, input);
            break;  // Exit the loop if a valid monthly price is provided
        }
        else
        {
            printf("Invalid monthly price. Please try again.\n");
        }
    }

    current_date(input);
    strcpy(new_building->date , input);

    fgets(input, 49, start2);
    input[strcspn(input, "\n")] = '\0';
    strcpy(new_building->userin, input);

    strcpy(new_building->active, "Active");

    fprintf(start1, "%s\n", new_building->code);

    // Save the new user to the file
    if (file_counter == 0)
    {
        fprintf(start, "%s\n", new_building->code);
        fprintf(start, "%s\n", new_building->district);
        fprintf(start, "%s\n", new_building->address);
        fprintf(start, "%s\n", new_building->location);
        fprintf(start, "%s\n", new_building->type);
        fprintf(start, "%s\n", new_building->build_age);
        fprintf(start, "%s\n", new_building->floor_area);
        fprintf(start, "%s\n", new_building->floor);
        fprintf(start, "%s\n", new_building->land_area);
        fprintf(start, "%s\n", new_building->owner_phone_number);
        fprintf(start, "%s\n", new_building->bedrooms);
        fprintf(start, "%s\n", new_building->tax_rate);
        fprintf(start, "%s\n", new_building->elevator);
        fprintf(start, "%s\n", new_building->basement);
        fprintf(start, "%s\n", new_building->basement_area);
        fprintf(start, "%s\n", new_building->balcony);
        fprintf(start, "%s\n", new_building->balcony_area);
        fprintf(start, "%s\n", new_building->parkings);
        fprintf(start, "%s\n", new_building->phones);
        fprintf(start, "%s\n", new_building->temperature);
        fprintf(start, "%s\n", new_building->base_price);
        fprintf(start, "%s\n", new_building->monthly_price);
        fprintf(start, "%s\n", new_building->date);
        fprintf(start, "%s\n", new_building->userin);
        fprintf(start, "%s", new_building->active);
    }
    else
    {
        fprintf(start, "\n%s", new_building->code);
        fprintf(start, "\n%s", new_building->district);
        fprintf(start, "\n%s", new_building->address);
        fprintf(start, "\n%s", new_building->location);
        fprintf(start, "\n%s", new_building->type);
        fprintf(start, "\n%s", new_building->build_age);
        fprintf(start, "\n%s", new_building->floor_area);
        fprintf(start, "\n%s", new_building->floor);
        fprintf(start, "\n%s", new_building->land_area);
        fprintf(start, "\n%s", new_building->owner_phone_number);
        fprintf(start, "\n%s", new_building->bedrooms);
        fprintf(start, "\n%s", new_building->tax_rate);
        fprintf(start, "\n%s", new_building->elevator);
        fprintf(start, "\n%s", new_building->basement);
        fprintf(start, "\n%s", new_building->basement_area);
        fprintf(start, "\n%s", new_building->balcony);
        fprintf(start, "\n%s", new_building->balcony_area);
        fprintf(start, "\n%s", new_building->parkings);
        fprintf(start, "\n%s", new_building->phones);
        fprintf(start, "\n%s", new_building->temperature);
        fprintf(start, "\n%s", new_building->base_price);
        fprintf(start, "\n%s", new_building->monthly_price);
        fprintf(start, "\n%s", new_building->date);
        fprintf(start, "\n%s", new_building->userin);
        fprintf(start, "\n%s", new_building->active);
    }

    // Close the file
    fclose(start);
    fclose(start1);

    // Don't forget to free the allocated memory when you're done
    free(new_building);

}
///commercial-rent function
void commercial_rent()
{
    system("cls");
    system("color 02");
    printf("===COMMERCIAL RENT===\n");
    display_current_date();
    display_current_time();
    char input[500];
    rent_com *new_building = (rent_com*)malloc(sizeof(rent_com));
    FILE *start , *start1 , *start2;
    start = fopen("Rent_com_data.txt" , "a+");
    start1 = fopen("Codes_check.txt" , "a+");
    start2 = fopen("Logined_user.txt" , "r");
    if (start == NULL || start1 == NULL || start2 == NULL)
    {
        printf("Error opening file.\n");
        sleep(3);
        exit(1);
    }

    int size;
    int file_counter = 0;
    if (start != NULL)
    {
        fseek (start, 0, SEEK_END);
        size = ftell(start);

        if (size != 0)
        {
            file_counter++;
        }
    }

    printf("\nEnter The Information Needed Below :\n");

    while (1)
    {
        printf("Code : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the code is valid
        if (code_check(input))
        {
            // Copy the input to the rent_com structure
            strcpy(new_building->code, input);
            break;  // Exit the loop if a valid code is provided
        }
        else
        {
            printf("Invalid code. Please try again.\n");
        }
    }

    while (1)
    {
        printf("District : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the district is valid
        if (district_check(input))
        {
            // Copy the input to the rent_com structure
            strcpy(new_building->district, input);
            break;  // Exit the loop if a valid district is provided
        }
        else
        {
            printf("Invalid district. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Address : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the address is valid
        if (address_check(input))
        {
            // Copy the input to the rent_com structure
            strcpy(new_building->address, input);
            break;  // Exit the loop if a valid address is provided
        }
        else
        {
            printf("Invalid address. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Location (North , South , East , West) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        // Check if the location is valid
        if (location_check(input))
        {
            // Copy the input to the rent_com structure
            strcpy(new_building->location, input);
            break;  // Exit the loop if a valid location is provided
        }
        else
        {
            printf("Invalid location. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Type (Official , Position) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        // Check if the type is valid
        if (type1_check(input))
        {
            // Copy the input to the rent_com structure
            strcpy(new_building->type, input);
            break;  // Exit the loop if a valid type is provided
        }
        else
        {
            printf("Invalid type. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Build age : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the build age is valid
        if (build_age_check(input))
        {
            // Copy the input to the rent_com structure
            strcpy(new_building->build_age, input);
            break;  // Exit the loop if a valid build age is provided
        }
        else
        {
            printf("Invalid build age. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Floor area (m^2) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the floor area is valid
        if (floor_area_check(input))
        {
            // Copy the input to the rent_com structure
            strcpy(new_building->floor_area, input);
            break;  // Exit the loop if a valid floor area is provided
        }
        else
        {
            printf("Invalid floor area. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Floor : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the floor is valid
        if (floor_check(input))
        {
            // Copy the input to the rent_com structure
            strcpy(new_building->floor, input);
            break;  // Exit the loop if a valid floor is provided
        }
        else
        {
            printf("Invalid floor. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Land area (m^2) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the land area is valid
        if (floor_area_check(input))
        {
            // Copy the input to the rent_com structure
            strcpy(new_building->land_area, input);
            break;  // Exit the loop if a valid land area is provided
        }
        else
        {
            printf("Invalid land area. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Owner phone number : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the owner phone number is valid
        if (phone_check(input))
        {
            // Copy the input to the rent_com structure
            strcpy(new_building->owner_phone_number, input);
            break;  // Exit the loop if a valid owner phone number is provided
        }
        else
        {
            printf("Invalid owner phone number. Please try again.\n");
        }
    }

    while (1)
    {
        printf("rooms : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the rooms is valid
        if (bedrooms_check(input))
        {
            // Copy the input to the rent_com structure
            strcpy(new_building->rooms, input);
            break;  // Exit the loop if a valid rooms is provided
        }
        else
        {
            printf("Invalid bedrooms. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Tax rate (0%%-100%%) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the tax rate is valid
        if (tax_rate_check(input))
        {
            // Copy the input to the rent_com structure
            strcpy(new_building->tax_rate, input);
            break;  // Exit the loop if a valid tax rate is provided
        }
        else
        {
            printf("Invalid tax rate. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Elevator (Yes , No) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        // Check if the elevator is valid
        if (yes_no_check(input))
        {
            // Copy the input to the rent_com structure
            strcpy(new_building->elevator, input);
            break;  // Exit the loop if a valid elevator is provided
        }
        else
        {
            printf("Invalid elevator. Please try again.\n");
        }
    }

    int basement_counter = 0;
    while (1)
    {
        printf("Basement (Yes , No) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        // Check if the basement is valid
        if (yes_no_check(input))
        {
            if (strcasecmp(input, "No") == 0)
            {
                basement_counter++;
            }
            // Copy the input to the rent_com structure
            strcpy(new_building->basement, input);
            break;  // Exit the loop if a valid basement is provided
        }
        else
        {
            printf("Invalid basement. Please try again.\n");
        }
    }

    while (1)
    {
        if (basement_counter != 0) // If answer is No
        {
            strcpy(new_building->basement_area, "0");
            break;
        }
        printf("Basement area (m^2) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the basement area is valid
        if (basement_area_check(input))
        {
            if (strcasecmp(input, "No") == 0)
            {
                basement_counter++;
            }
            // Copy the input to the rent_com structure
            strcpy(new_building->basement_area, input);
            break;  // Exit the loop if a valid basement area is provided
        }
        else
        {
            printf("Invalid basement area. Please try again.\n");
        }
    }

    int balcony_counter = 0;
    while (1)
    {
        printf("Balcony (Yes , No) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        // Check if the balcony is valid
        if (yes_no_check(input))
        {
            if (strcasecmp(input, "No") == 0)
            {
                balcony_counter++;
            }
            // Copy the input to the rent_com structure
            strcpy(new_building->balcony, input);
            break;  // Exit the loop if a valid balcony is provided
        }
        else
        {
            printf("Invalid balcony. Please try again.\n");
        }
    }

    while (1)
    {
        if (balcony_counter != 0) // If answer is No
        {
            strcpy(new_building->balcony_area, "0");
            break;
        }
        printf("Balcony area (m^2) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the balcony area is valid
        if (balcony_area_check(input))
        {
            // Copy the input to the rent_com structure
            strcpy(new_building->balcony_area, input);
            break;  // Exit the loop if a valid balcony area is provided
        }
        else
        {
            printf("Invalid balcony area. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Parkings : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the parkings is valid
        if (parkings_check(input))
        {
            // Copy the input to the rent_com structure
            strcpy(new_building->parkings, input);
            break;  // Exit the loop if a valid parkings is provided
        }
        else
        {
            printf("Invalid parkings. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Phones : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the phones is valid
        if (phones_check(input))
        {
            // Copy the input to the rent_com structure
            strcpy(new_building->phones, input);
            break;  // Exit the loop if a valid phones is provided
        }
        else
        {
            printf("Invalid phones. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Temperature (Cold , Hot , Medium) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        // Check if the temperature is valid
        if (temperature_check(input))
        {
            // Copy the input to the rent_com structure
            strcpy(new_building->temperature, input);
            break;  // Exit the loop if a valid temperature is provided
        }
        else
        {
            printf("Invalid temperature. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Base price (Rials) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the base price is valid
        if (sell_price_check(input))
        {
            // Copy the input to the rent_com structure
            strcpy(new_building->base_price, input);
            break;  // Exit the loop if a valid base price is provided
        }
        else
        {
            printf("Invalid base price. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Monthly price (Rials) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the monthly price is valid
        if (sell_price_check(input))
        {
            // Copy the input to the rent_com structure
            strcpy(new_building->monthly_price, input);
            break;  // Exit the loop if a valid monthly price is provided
        }
        else
        {
            printf("Invalid monthly price. Please try again.\n");
        }
    }

    current_date(input);
    strcpy(new_building->date , input);

    fgets(input, 49, start2);
    input[strcspn(input, "\n")] = '\0';
    strcpy(new_building->userin, input);

    strcpy(new_building->active, "Active");

    fprintf(start1, "%s\n", new_building->code);

    // Save the new user to the file
    if (file_counter == 0)
    {
        fprintf(start, "%s\n", new_building->code);
        fprintf(start, "%s\n", new_building->district);
        fprintf(start, "%s\n", new_building->address);
        fprintf(start, "%s\n", new_building->location);
        fprintf(start, "%s\n", new_building->type);
        fprintf(start, "%s\n", new_building->build_age);
        fprintf(start, "%s\n", new_building->floor_area);
        fprintf(start, "%s\n", new_building->floor);
        fprintf(start, "%s\n", new_building->land_area);
        fprintf(start, "%s\n", new_building->owner_phone_number);
        fprintf(start, "%s\n", new_building->rooms);
        fprintf(start, "%s\n", new_building->tax_rate);
        fprintf(start, "%s\n", new_building->elevator);
        fprintf(start, "%s\n", new_building->basement);
        fprintf(start, "%s\n", new_building->basement_area);
        fprintf(start, "%s\n", new_building->balcony);
        fprintf(start, "%s\n", new_building->balcony_area);
        fprintf(start, "%s\n", new_building->parkings);
        fprintf(start, "%s\n", new_building->phones);
        fprintf(start, "%s\n", new_building->temperature);
        fprintf(start, "%s\n", new_building->base_price);
        fprintf(start, "%s\n", new_building->monthly_price);
        fprintf(start, "%s\n", new_building->date);
        fprintf(start, "%s\n", new_building->userin);
        fprintf(start, "%s", new_building->active);
    }
    else
    {
        fprintf(start, "\n%s", new_building->code);
        fprintf(start, "\n%s", new_building->district);
        fprintf(start, "\n%s", new_building->address);
        fprintf(start, "\n%s", new_building->location);
        fprintf(start, "\n%s", new_building->type);
        fprintf(start, "\n%s", new_building->build_age);
        fprintf(start, "\n%s", new_building->floor_area);
        fprintf(start, "\n%s", new_building->floor);
        fprintf(start, "\n%s", new_building->land_area);
        fprintf(start, "\n%s", new_building->owner_phone_number);
        fprintf(start, "\n%s", new_building->rooms);
        fprintf(start, "\n%s", new_building->tax_rate);
        fprintf(start, "\n%s", new_building->elevator);
        fprintf(start, "\n%s", new_building->basement);
        fprintf(start, "\n%s", new_building->basement_area);
        fprintf(start, "\n%s", new_building->balcony);
        fprintf(start, "\n%s", new_building->balcony_area);
        fprintf(start, "\n%s", new_building->parkings);
        fprintf(start, "\n%s", new_building->phones);
        fprintf(start, "\n%s", new_building->temperature);
        fprintf(start, "\n%s", new_building->base_price);
        fprintf(start, "\n%s", new_building->monthly_price);
        fprintf(start, "\n%s", new_building->date);
        fprintf(start, "\n%s", new_building->userin);
        fprintf(start, "\n%s", new_building->active);
    }

    // Close the file
    fclose(start);
    fclose(start1);

    // Don't forget to free the allocated memory when you're done
    free(new_building);
}
///land-rent function
void land_rent()
{
    system("cls");
    system("color 02");
    printf("===LAND SELL===\n");
    display_current_date();
    display_current_time();
    char input[500];
    rent_lan *new_building = (rent_lan*)malloc(sizeof(rent_lan));
    FILE *start , *start1 , *start2;
    start = fopen("Rent_lan_data.txt" , "a+");
    start1 = fopen("Codes_check.txt" , "a+");
    start2 = fopen("Logined_user.txt" , "r");
    if (start == NULL || start1 == NULL || start2 == NULL)
    {
        printf("Error opening file.\n");
        sleep(3);
        exit(1);
    }

    int size;
    int file_counter = 0;
    if (start != NULL)
    {
        fseek (start, 0, SEEK_END);
        size = ftell(start);

        if (size != 0)
        {
            file_counter++;
        }
    }

    printf("\nEnter The Information Needed Below :\n");

    while (1)
    {
        printf("Code : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the code is valid
        if (code_check(input))
        {
            // Copy the input to the rent_lan structure
            strcpy(new_building->code, input);
            break;  // Exit the loop if a valid code is provided
        }
        else
        {
            printf("Invalid code. Please try again.\n");
        }
    }

    while (1)
    {
        printf("District : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the district is valid
        if (district_check(input))
        {
            // Copy the input to the rent_lan structure
            strcpy(new_building->district, input);
            break;  // Exit the loop if a valid district is provided
        }
        else
        {
            printf("Invalid district. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Address : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the address is valid
        if (address_check(input))
        {
            // Copy the input to the rent_lan structure
            strcpy(new_building->address, input);
            break;  // Exit the loop if a valid address is provided
        }
        else
        {
            printf("Invalid address. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Location (North , South , East , West) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        // Check if the location is valid
        if (location_check(input))
        {
            // Copy the input to the rent_lan structure
            strcpy(new_building->location, input);
            break;  // Exit the loop if a valid location is provided
        }
        else
        {
            printf("Invalid location. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Type (Farm , City) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        // Check if the type is valid
        if (type2_check(input))
        {
            // Copy the input to the rent_lan structure
            strcpy(new_building->type, input);
            break;  // Exit the loop if a valid type is provided
        }
        else
        {
            printf("Invalid type. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Land area (m^2) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the land area is valid
        if (floor_area_check(input))
        {
            // Copy the input to the rent_com structure
            strcpy(new_building->land_area, input);
            break;  // Exit the loop if a valid land area is provided
        }
        else
        {
            printf("Invalid land area. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Width (m) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the width is valid
        if (floor_area_check(input))
        {
            // Copy the input to the rent_com structure
            strcpy(new_building->width, input);
            break;  // Exit the loop if a valid width is provided
        }
        else
        {
            printf("Invalid width. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Owner phone number : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the owner phone number is valid
        if (phone_check(input))
        {
            // Copy the input to the rent_com structure
            strcpy(new_building->owner_phone_number, input);
            break;  // Exit the loop if a valid owner phone number is provided
        }
        else
        {
            printf("Invalid owner phone number. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Tax rate (0%%-100%%) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the tax rate is valid
        if (tax_rate_check(input))
        {
            // Copy the input to the rent_lan structure
            strcpy(new_building->tax_rate, input);
            break;  // Exit the loop if a valid tax rate is provided
        }
        else
        {
            printf("Invalid tax rate. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Well (Yes , No) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        // Check if the well is valid
        if (yes_no_check(input))
        {
            // Copy the input to the rent_lan structure
            strcpy(new_building->well, input);
            break;  // Exit the loop if a valid well is provided
        }
        else
        {
            printf("Invalid well. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Temperature (Cold , Hot , Medium) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        // Check if the temperature is valid
        if (temperature_check(input))
        {
            // Copy the input to the rent_lan structure
            strcpy(new_building->temperature, input);
            break;  // Exit the loop if a valid temperature is provided
        }
        else
        {
            printf("Invalid temperature. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Base price (Rials) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the sell price is valid
        if (sell_price_check(input))
        {
            // Copy the input to the rent_lan structure
            strcpy(new_building->base_price, input);
            break;  // Exit the loop if a valid sell price is provided
        }
        else
        {
            printf("Invalid base price. Please try again.\n");
        }
    }

    while (1)
    {
        printf("Monthly price (Rials) : ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';

        // Check if the monthly price is valid
        if (sell_price_check(input))
        {
            // Copy the input to the rent_lan structure
            strcpy(new_building->monthly_price, input);
            break;  // Exit the loop if a valid sell price is provided
        }
        else
        {
            printf("Invalid monthly price. Please try again.\n");
        }
    }

    current_date(input);
    strcpy(new_building->date , input);

    fgets(input, 49, start2);
    input[strcspn(input, "\n")] = '\0';
    strcpy(new_building->userin, input);

    strcpy(new_building->active, "Active");

    fprintf(start1, "%s\n", new_building->code);

    // Save the new user to the file
    if (file_counter == 0)
    {
        fprintf(start, "%s\n", new_building->code);
        fprintf(start, "%s\n", new_building->district);
        fprintf(start, "%s\n", new_building->address);
        fprintf(start, "%s\n", new_building->location);
        fprintf(start, "%s\n", new_building->type);
        fprintf(start, "%s\n", new_building->land_area);
        fprintf(start, "%s\n", new_building->width);
        fprintf(start, "%s\n", new_building->owner_phone_number);
        fprintf(start, "%s\n", new_building->tax_rate);
        fprintf(start, "%s\n", new_building->well);
        fprintf(start, "%s\n", new_building->temperature);
        fprintf(start, "%s\n", new_building->base_price);
        fprintf(start, "%s\n", new_building->monthly_price);
        fprintf(start, "%s\n", new_building->date);
        fprintf(start, "%s\n", new_building->userin);
        fprintf(start, "%s", new_building->active);
    }
    else
    {
        fprintf(start, "\n%s", new_building->code);
        fprintf(start, "\n%s", new_building->district);
        fprintf(start, "\n%s", new_building->address);
        fprintf(start, "\n%s", new_building->location);
        fprintf(start, "\n%s", new_building->type);
        fprintf(start, "\n%s", new_building->land_area);
        fprintf(start, "\n%s", new_building->width);
        fprintf(start, "\n%s", new_building->owner_phone_number);
        fprintf(start, "\n%s", new_building->tax_rate);
        fprintf(start, "\n%s", new_building->well);
        fprintf(start, "\n%s", new_building->temperature);
        fprintf(start, "\n%s", new_building->base_price);
        fprintf(start, "\n%s", new_building->monthly_price);
        fprintf(start, "\n%s", new_building->date);
        fprintf(start, "\n%s", new_building->userin);
        fprintf(start, "\n%s", new_building->active);

    }

    // Close the file
    fclose(start);
    fclose(start1);

    // Don't forget to free the allocated memory when you're done
    free(new_building);
}
///user-settings function
void user_settings()
{
    char input[10];
    int number;
    while (1)
    {
        system("cls");
        system("color 07");
        printf("===USER SETTINGS===\n");
        display_current_date();
        display_current_time();
        printf("\n1.Edit first name\n");
        printf("2.Edit last name\n");
        printf("3.Edit ID\n");
        printf("4.Edit phone number\n");
        printf("5.Edit email\n");
        printf("6.Edit password\n");
        printf("0.Back");
        printf("\nPlease Enter Your Choice : ");
        gets(input);
        system("cls");
        number = atoi(input);
        if (number == 1)
        {
            edit_first_name();
            continue;
        }
        else if (number == 2)
        {
            edit_last_name();
            continue;
        }
        else if (number == 3)
        {
            edit_ID();
            continue;
        }
        else if (number == 4)
        {
            edit_phone_number();
            continue;
        }
        else if (number == 5)
        {
            edit_email();
            continue;
        }
        else if (number == 6)
        {
            edit_password();
            continue;
        }
        else if (number == 0)
        {
            main_menu();
            continue;
        }
        else
        {
            continue;
        }
    }
}
///edit-first-name function
void edit_first_name()
{
    system("cls");
    system("color 02");
    printf("===EDIT FIRST NAME===\n");
    display_current_date();
    display_current_time();

    char input[50];
    FILE *fp;
    user *start=NULL , *end=NULL , *temp ;
    char username1[50];

    fp = fopen("Logined_user.txt" , "r");
    fgets(username1, 50, fp);
    username1[strcspn(username1, "\n")] = '\0';
    fclose(fp);

    fp = fopen("Users_data.txt","r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(user));
        fgets(temp->user_name, 50, fp);
        fgets(temp->first_name, 50, fp);
        fgets(temp->last_name, 50, fp);
        fgets(temp->ID, 50, fp);
        fgets(temp->phone_number, 50, fp);
        fgets(temp->email, 50, fp);
        fgets(temp->password, 50, fp);


        temp->user_name[strcspn(temp->user_name, "\n")] = '\0';
        temp->first_name[strcspn(temp->first_name, "\n")] = '\0';
        temp->last_name[strcspn(temp->last_name, "\n")] = '\0';
        temp->ID[strcspn(temp->ID, "\n")] = '\0';
        temp->phone_number[strcspn(temp->phone_number, "\n")] = '\0';
        temp->email[strcspn(temp->email, "\n")] = '\0';
        temp->password[strcspn(temp->password, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    fp = fopen("Users_data.txt" , "w");
    temp = start;
    int counter = 0;
    for(int i=0 ; i<check ; i++)
    {
        if (strcmp(temp->user_name , username1) == 0)
        {
            counter++;
            while (1)
            {
                printf("First name : ");
                fgets(input, sizeof(input), stdin);
                input[strcspn(input, "\n")] = '\0';

                if (name_check(input))
                {
                    // Copy the input to the user structure
                    strcpy(temp->first_name, input);
                    sameall(temp->first_name);
                    break;
                }
                else
                {
                    printf("Invalid first name. Please try again.\n");
                }
            }
        }
        if (i == 0)
        {
            fprintf(fp,"%s\n",temp->user_name);
            fprintf(fp,"%s\n",temp->first_name);
            fprintf(fp,"%s\n",temp->last_name);
            fprintf(fp,"%s\n",temp->ID);
            fprintf(fp,"%s\n",temp->phone_number);
            fprintf(fp,"%s\n",temp->email);
            fprintf(fp,"%s",temp->password);
        }
        else
        {
            fprintf(fp,"\n%s",temp->user_name);
            fprintf(fp,"\n%s",temp->first_name);
            fprintf(fp,"\n%s",temp->last_name);
            fprintf(fp,"\n%s",temp->ID);
            fprintf(fp,"\n%s",temp->phone_number);
            fprintf(fp,"\n%s",temp->email);
            fprintf(fp,"\n%s",temp->password);
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("Invalid Request!\n");
        sleep(3);
    }
    else if (counter == 1)
    {
        printf("Edit completed!\n");
        sleep(3);
    }
}
///edit-last-name function
void edit_last_name()
{
    system("cls");
    system("color 02");
    printf("===EDIT LAST NAME===\n");
    display_current_date();
    display_current_time();

    char input[50];
    FILE *fp;
    user *start=NULL , *end=NULL , *temp ;
    char username1[50];

    fp = fopen("Logined_user.txt" , "r");
    fgets(username1, 50, fp);
    username1[strcspn(username1, "\n")] = '\0';
    fclose(fp);

    fp = fopen("Users_data.txt","r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(user));
        fgets(temp->user_name, 50, fp);
        fgets(temp->first_name, 50, fp);
        fgets(temp->last_name, 50, fp);
        fgets(temp->ID, 50, fp);
        fgets(temp->phone_number, 50, fp);
        fgets(temp->email, 50, fp);
        fgets(temp->password, 50, fp);

        temp->user_name[strcspn(temp->user_name, "\n")] = '\0';
        temp->first_name[strcspn(temp->first_name, "\n")] = '\0';
        temp->last_name[strcspn(temp->last_name, "\n")] = '\0';
        temp->ID[strcspn(temp->ID, "\n")] = '\0';
        temp->phone_number[strcspn(temp->phone_number, "\n")] = '\0';
        temp->email[strcspn(temp->email, "\n")] = '\0';
        temp->password[strcspn(temp->password, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    fp = fopen("Users_data.txt" , "w");
    temp = start;
    int counter = 0;
    for (int i=0 ; i<check ; i++)
    {
        if (strcmp(temp->user_name , username1) == 0)
        {
            counter++;
            while (1)
            {
                printf("Last name : ");
                fgets(input, sizeof(input), stdin);
                input[strcspn(input, "\n")] = '\0';

                if (name_check(input))
                {
                    // Copy the input to the user structure
                    strcpy(temp->last_name, input);
                    sameall(temp->last_name);
                    break;
                }
                else
                {
                    printf("Invalid last name. Please try again.\n");
                }
            }
        }
        if (i == 0)
        {
            fprintf(fp,"%s\n",temp->user_name);
            fprintf(fp,"%s\n",temp->first_name);
            fprintf(fp,"%s\n",temp->last_name);
            fprintf(fp,"%s\n",temp->ID);
            fprintf(fp,"%s\n",temp->phone_number);
            fprintf(fp,"%s\n",temp->email);
            fprintf(fp,"%s",temp->password);
        }
        else
        {
            fprintf(fp,"\n%s",temp->user_name);
            fprintf(fp,"\n%s",temp->first_name);
            fprintf(fp,"\n%s",temp->last_name);
            fprintf(fp,"\n%s",temp->ID);
            fprintf(fp,"\n%s",temp->phone_number);
            fprintf(fp,"\n%s",temp->email);
            fprintf(fp,"\n%s",temp->password);
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("Invalid Request!\n");
        sleep(3);
    }
    else if (counter == 1)
    {
        printf("Edit completed!\n");
        sleep(3);
    }
}
///edit-ID function
void edit_ID()
{
    system("cls");
    system("color 02");
    printf("===EDIT ID===\n");
    display_current_date();
    display_current_time();

    char input[50];
    FILE *fp;
    user *start=NULL , *end=NULL , *temp ;
    char username1[50];

    fp = fopen("Logined_user.txt" , "r");
    fgets(username1, 50, fp);
    username1[strcspn(username1, "\n")] = '\0';
    fclose(fp);

    fp = fopen("Users_data.txt","r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(user));
        fgets(temp->user_name, 50, fp);
        fgets(temp->first_name, 50, fp);
        fgets(temp->last_name, 50, fp);
        fgets(temp->ID, 50, fp);
        fgets(temp->phone_number, 50, fp);
        fgets(temp->email, 50, fp);
        fgets(temp->password, 50, fp);

        temp->user_name[strcspn(temp->user_name, "\n")] = '\0';
        temp->first_name[strcspn(temp->first_name, "\n")] = '\0';
        temp->last_name[strcspn(temp->last_name, "\n")] = '\0';
        temp->ID[strcspn(temp->ID, "\n")] = '\0';
        temp->phone_number[strcspn(temp->phone_number, "\n")] = '\0';
        temp->email[strcspn(temp->email, "\n")] = '\0';
        temp->password[strcspn(temp->password, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    fp = fopen("Users_data.txt" , "w");
    temp = start;
    int counter = 0;
    for(int i=0 ; i<check ; i++)
    {
        if (strcmp(temp->user_name , username1) == 0)
        {
            counter++;
            while (1)
            {
                printf("ID : ");
                fgets(input, sizeof(input), stdin);
                input[strcspn(input, "\n")] = '\0';

                if (ID_check(input))
                {
                    // Copy the input to the user structure
                    strcpy(temp->ID, input);
                    break;
                }
                else
                {
                    printf("Invalid ID. Please try again.\n");
                }
            }
        }
        if (i == 0)
        {
            fprintf(fp,"%s\n",temp->user_name);
            fprintf(fp,"%s\n",temp->first_name);
            fprintf(fp,"%s\n",temp->last_name);
            fprintf(fp,"%s\n",temp->ID);
            fprintf(fp,"%s\n",temp->phone_number);
            fprintf(fp,"%s\n",temp->email);
            fprintf(fp,"%s",temp->password);
        }
        else
        {
            fprintf(fp,"\n%s",temp->user_name);
            fprintf(fp,"\n%s",temp->first_name);
            fprintf(fp,"\n%s",temp->last_name);
            fprintf(fp,"\n%s",temp->ID);
            fprintf(fp,"\n%s",temp->phone_number);
            fprintf(fp,"\n%s",temp->email);
            fprintf(fp,"\n%s",temp->password);
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("Invalid Request!\n");
    }
    else if (counter == 1)
    {
        sleep(3);
        printf("Edit completed!\n");
    }
}
///edit-phone-number function
void edit_phone_number()
{
    system("cls");
    system("color 02");
    printf("===EDIT PHONE NUMBER===\n");
    display_current_date();
    display_current_time();

    char input[50];
    FILE *fp;
    user *start=NULL , *end=NULL , *temp ;
    char username1[50];

    fp = fopen("Logined_user.txt" , "r");
    fgets(username1, 50, fp);
    username1[strcspn(username1, "\n")] = '\0';
    fclose(fp);

    fp = fopen("Users_data.txt","r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(user));
        fgets(temp->user_name, 50, fp);
        fgets(temp->first_name, 50, fp);
        fgets(temp->last_name, 50, fp);
        fgets(temp->ID, 50, fp);
        fgets(temp->phone_number, 50, fp);
        fgets(temp->email, 50, fp);
        fgets(temp->password, 50, fp);

        temp->user_name[strcspn(temp->user_name, "\n")] = '\0';
        temp->first_name[strcspn(temp->first_name, "\n")] = '\0';
        temp->last_name[strcspn(temp->last_name, "\n")] = '\0';
        temp->ID[strcspn(temp->ID, "\n")] = '\0';
        temp->phone_number[strcspn(temp->phone_number, "\n")] = '\0';
        temp->email[strcspn(temp->email, "\n")] = '\0';
        temp->password[strcspn(temp->password, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    fp = fopen("Users_data.txt" , "w");
    temp = start;
    int counter = 0;
    for(int i=0 ; i<check ; i++)
    {
        if (strcmp(temp->user_name , username1) == 0)
        {
            counter++;
            while (1)
            {
                printf("Phone number : ");
                fgets(input, sizeof(input), stdin);
                input[strcspn(input, "\n")] = '\0';

                if (phone_check(input))
                {
                    // Copy the input to the user structure
                    strcpy(temp->phone_number, input);
                    break;
                }
                else
                {
                    printf("Invalid phone number. Please try again.\n");
                }
            }
        }
        if (i == 0)
        {
            fprintf(fp,"%s\n",temp->user_name);
            fprintf(fp,"%s\n",temp->first_name);
            fprintf(fp,"%s\n",temp->last_name);
            fprintf(fp,"%s\n",temp->ID);
            fprintf(fp,"%s\n",temp->phone_number);
            fprintf(fp,"%s\n",temp->email);
            fprintf(fp,"%s",temp->password);
        }
        else
        {
            fprintf(fp,"\n%s",temp->user_name);
            fprintf(fp,"\n%s",temp->first_name);
            fprintf(fp,"\n%s",temp->last_name);
            fprintf(fp,"\n%s",temp->ID);
            fprintf(fp,"\n%s",temp->phone_number);
            fprintf(fp,"\n%s",temp->email);
            fprintf(fp,"\n%s",temp->password);
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("Invalid Request!\n");
        sleep(3);
    }
    else if (counter == 1)
    {
        printf("Edit completed!\n");
        sleep(3);
    }
}
///edit-email function
void edit_email()
{
    system("cls");
    system("color 02");
    printf("===EDIT EMAIL===\n");
    display_current_date();
    display_current_time();

    char input[50];
    FILE *fp;
    user *start=NULL , *end=NULL , *temp ;
    char username1[50];

    fp = fopen("Logined_user.txt" , "r");
    fgets(username1, 50, fp);
    username1[strcspn(username1, "\n")] = '\0';
    fclose(fp);

    fp = fopen("Users_data.txt","r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(user));
        fgets(temp->user_name, 50, fp);
        fgets(temp->first_name, 50, fp);
        fgets(temp->last_name, 50, fp);
        fgets(temp->ID, 50, fp);
        fgets(temp->phone_number, 50, fp);
        fgets(temp->email, 50, fp);
        fgets(temp->password, 50, fp);

        temp->user_name[strcspn(temp->user_name, "\n")] = '\0';
        temp->first_name[strcspn(temp->first_name, "\n")] = '\0';
        temp->last_name[strcspn(temp->last_name, "\n")] = '\0';
        temp->ID[strcspn(temp->ID, "\n")] = '\0';
        temp->phone_number[strcspn(temp->phone_number, "\n")] = '\0';
        temp->email[strcspn(temp->email, "\n")] = '\0';
        temp->password[strcspn(temp->password, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    fp = fopen("Users_data.txt" , "w");
    temp = start;
    int counter = 0;
    for(int i=0 ; i<check ; i++)
    {
        if (strcmp(temp->user_name , username1) == 0)
        {
            counter++;
            while (1)
            {
                printf("Email : ");
                fgets(input, sizeof(input), stdin);
                input[strcspn(input, "\n")] = '\0';

                if (email_check(input))
                {
                    // Copy the input to the user structure
                    strcpy(temp->email, input);
                    break;
                }
                else
                {
                    printf("Invalid email. Please try again.\n");
                }
            }
        }
        if (i == 0)
        {
            fprintf(fp,"%s\n",temp->user_name);
            fprintf(fp,"%s\n",temp->first_name);
            fprintf(fp,"%s\n",temp->last_name);
            fprintf(fp,"%s\n",temp->ID);
            fprintf(fp,"%s\n",temp->phone_number);
            fprintf(fp,"%s\n",temp->email);
            fprintf(fp,"%s",temp->password);
        }
        else
        {
            fprintf(fp,"\n%s",temp->user_name);
            fprintf(fp,"\n%s",temp->first_name);
            fprintf(fp,"\n%s",temp->last_name);
            fprintf(fp,"\n%s",temp->ID);
            fprintf(fp,"\n%s",temp->phone_number);
            fprintf(fp,"\n%s",temp->email);
            fprintf(fp,"\n%s",temp->password);
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("Invalid Request!\n");
        sleep(3);
    }
    else if (counter == 1)
    {
        printf("Edit completed!\n");
        sleep(3);
    }
}
///edit-password function
void edit_password()
{
    system("cls");
    system("color 02");
    printf("===EDIT PASSWORD===\n");
    display_current_date();
    display_current_time();

    char input[50];
    FILE *fp;
    user *start=NULL , *end=NULL , *temp ;
    char username1[50];

    fp = fopen("Logined_user.txt" , "r");
    fgets(username1, 50, fp);
    username1[strcspn(username1, "\n")] = '\0';
    fclose(fp);

    fp = fopen("Users_data.txt","r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(user));
        fgets(temp->user_name, 50, fp);
        fgets(temp->first_name, 50, fp);
        fgets(temp->last_name, 50, fp);
        fgets(temp->ID, 50, fp);
        fgets(temp->phone_number, 50, fp);
        fgets(temp->email, 50, fp);
        fgets(temp->password, 50, fp);

        temp->user_name[strcspn(temp->user_name, "\n")] = '\0';
        temp->first_name[strcspn(temp->first_name, "\n")] = '\0';
        temp->last_name[strcspn(temp->last_name, "\n")] = '\0';
        temp->ID[strcspn(temp->ID, "\n")] = '\0';
        temp->phone_number[strcspn(temp->phone_number, "\n")] = '\0';
        temp->email[strcspn(temp->email, "\n")] = '\0';
        temp->password[strcspn(temp->password, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    fp = fopen("Users_data.txt" , "w");
    temp = start;
    int counter = 0;
    for(int i=0 ; i<check ; i++)
    {
        if (strcmp(temp->user_name , username1) == 0)
        {
            counter++;
            while (1)
            {
                printf("Password: ");
                get_password(input, 24);

                char passkey[50];

                printf("\nConfirm your password: ");
                get_password(passkey, 24);

                // Remove the trailing newline character from input and passkey
                input[strcspn(input, "\n")] = '\0';
                passkey[strcspn(passkey, "\n")] = '\0';

                if (password_check(input))
                {
                    if (strcmp(passkey, input) == 0)
                    {
                        printf("\nPassword set successfully.\n");
                        strcpy(temp->password, input);
                        break;
                        sleep(3);
                    }
                    else
                    {
                        printf("\nInvalid password confirmation. Please try again.\n");
                    }
                }
                else
                {
                    printf("Invalid password. Please try again.\n");
                }
            }
        }
        if (i == 0)
        {
            fprintf(fp,"%s\n",temp->user_name);
            fprintf(fp,"%s\n",temp->first_name);
            fprintf(fp,"%s\n",temp->last_name);
            fprintf(fp,"%s\n",temp->ID);
            fprintf(fp,"%s\n",temp->phone_number);
            fprintf(fp,"%s\n",temp->email);
            fprintf(fp,"%s",temp->password);
        }
        else
        {
            fprintf(fp,"\n%s",temp->user_name);
            fprintf(fp,"\n%s",temp->first_name);
            fprintf(fp,"\n%s",temp->last_name);
            fprintf(fp,"\n%s",temp->ID);
            fprintf(fp,"\n%s",temp->phone_number);
            fprintf(fp,"\n%s",temp->email);
            fprintf(fp,"\n%s",temp->password);
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("Invalid Request!\n");
        sleep(3);
    }
    else if (counter == 1)
    {
        printf("Edit completed!\n");
        sleep(3);
    }
}
///reports function
void reports()
{
    char input[10];
    int number;
    while (1)
    {
        system("cls");
        system("color 07");
        printf("===REPORTS===\n");
        display_current_date();
        display_current_time();
        printf("\n1.Property Counter\n");
        printf("2.All Residentals For Sell\n");
        printf("3.All Commercials For Sell\n");
        printf("4.All Lands For Sell\n");
        printf("5.All Residentals For Rent\n");
        printf("6.All Commercial For Rent\n");
        printf("7.All Lands For Rent\n");
        printf("8.Based On Residental For Sell\n");
        printf("9.Based On Commercial For Sell\n");
        printf("10.Based On Land For Sell\n");
        printf("11.Based On Resiental For Rent\n");
        printf("12.Based On Commercial For Rent\n");
        printf("13.Based On Land For Rent\n");
        printf("0.Back\n");
        printf("\nPlease Enter Your Choice : ");
        gets(input);
        system("cls");
        number = atoi(input);
        if (number == 1)
        {
            property_counter();
            continue;
        }
        else if (number == 2)
        {
            all_res_sell();
            continue;
        }
        else if (number == 3)
        {
            all_com_sell();
            continue;
        }
        else if (number == 4)
        {
            all_lan_sell();
            continue;
        }
        else if (number == 5)
        {
            all_res_rent();
            continue;
        }
        else if (number == 6)
        {
            all_com_rent();
            continue;
        }
        else if (number == 7)
        {
            all_lan_rent();
            continue;
        }
        else if (number == 8)
        {
            menu_res_sell();
            continue;
        }
        else if (number == 9)
        {
            menu_com_sell();
            continue;
        }
        else if (number == 10)
        {
            menu_lan_sell();
            continue;
        }
        else if (number == 11)
        {
            menu_res_rent();
            continue;
        }
        else if (number == 12)
        {
            menu_com_rent();
            continue;
        }
        else if (number == 13)
        {
            menu_lan_rent();
            continue;
        }
        else if (number == 0)
        {
            break;
        }
        else
        {
            continue;
        }
    }
}
///menu-res-sell function
void menu_res_sell()
{
    char input[10];
    int number;
    while (1)
    {
        system("cls");
        system("color 07");
        printf("===MENU RESIDENTAL SELL===\n");
        display_current_date();
        display_current_time();
        printf("\n1.Base On District\n");
        printf("2.Base On Location\n");
        printf("3.Base On Type\n");
        printf("4.Base On Build Age\n");
        printf("5.Base On Floor Area\n");
        printf("6.Base On Floor\n");
        printf("7.Base On Land Area\n");
        printf("8.Base On Bedrooms\n");
        printf("9.Base On Tax-rate\n");
        printf("10.Base On Elevator\n");
        printf("11.Base On Basement\n");
        printf("12.Base On Balcony\n");
        printf("13.Base On Parkings\n");
        printf("14.Base On Phones\n");
        printf("15.Base On Temperature\n");
        printf("16.Base On Sell-price\n");
        printf("0.Back\n");
        printf("\nPlease Enter Your Choice : ");
        gets(input);
        system("cls");
        number = atoi(input);
        if (number == 0)
        {
            break;
        }
        else if (number == 1)
        {
            base_res_sell_district();
            continue;
        }
        else if (number == 2)
        {
            base_res_sell_location();
            continue;
        }
        else if (number == 3)
        {
            base_res_sell_type();
            continue;
        }
        else if (number == 4)
        {
            base_res_sell_build_age();
            continue;
        }
        else if (number == 5)
        {
            base_res_sell_floor_area();
            continue;
        }
        else if (number == 6)
        {
            base_res_sell_floor();
            continue;
        }
        else if (number == 7)
        {
            base_res_sell_land_area();
            continue;
        }
        else if (number == 8)
        {
            base_res_sell_bedrooms();
            continue;
        }
        else if (number == 9)
        {
            base_res_sell_tax_rate();
            continue;
        }
        else if (number == 10)
        {
            base_res_sell_elevator();
            continue;
        }
        else if (number == 11)
        {
            base_res_sell_basement();
            continue;
        }
        else if (number == 12)
        {
            base_res_sell_balcony();
            continue;
        }
        else if (number == 13)
        {
            base_res_sell_parkings();
            continue;
        }
        else if (number == 14)
        {
            base_res_sell_phones();
            continue;
        }
        else if (number == 15)
        {
            base_res_sell_temperature();
            continue;
        }
        else if (number == 16)
        {
            base_res_sell_sell_price();
            continue;
        }
        else
        {
            continue;
        }
    }
}
///base-res-sell-district function
void base_res_sell_district()
{
    system("cls");
    system("color 02");
    printf("===RESIDENTAL SELL BASE ON DISTRICT===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    sell_res *start=NULL , *end=NULL , *temp ;

    char input[50];

    while (1)
    {
        printf("District : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';

        if (district_check(input))
        {
            break;
        }
        else
        {
            printf("Invalid district. Please try again.");
            continue;
        }
    }

    fp = fopen("Sell_res_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_res));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->bedrooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->sell_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->bedrooms[strcspn(temp->bedrooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->sell_price[strcspn(temp->sell_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->district , input) == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->bedrooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Sell Price: %s\n", temp->sell_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-res-sell-location function
void base_res_sell_location()
{
    system("cls");
    system("color 02");
    printf("===RESIDENTAL SELL BASE ON LOCATION===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    sell_res *start=NULL , *end=NULL , *temp ;

    char input[50];

    while (1)
    {
        printf("Location (North , South , East , West) : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        if (location_check(input))
        {
            break;
        }
        else
        {
            printf("Invalid location. Please try again.");
            continue;
        }
    }

    fp = fopen("Sell_res_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_res));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->bedrooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->sell_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->bedrooms[strcspn(temp->bedrooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->sell_price[strcspn(temp->sell_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->location , input) == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->bedrooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Sell Price: %s\n", temp->sell_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();

}
///base-res-sell-type function
void base_res_sell_type()
{
    system("cls");
    system("color 02");
    printf("===RESIDENTAL SELL BASE ON TYPE===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    sell_res *start=NULL , *end=NULL , *temp ;

    char input[50];

    while (1)
    {
        printf("Type (Apartment , Villa) : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        if (type_check(input))
        {
            break;
        }
        else
        {
            printf("Invalid type. Please try again.");
            continue;
        }
    }

    fp = fopen("Sell_res_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_res));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->bedrooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->sell_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->bedrooms[strcspn(temp->bedrooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->sell_price[strcspn(temp->sell_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->type , input) == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->bedrooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Sell Price: %s\n", temp->sell_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-res-sell-build-age function
void base_res_sell_build_age()
{
    system("cls");
    system("color 02");
    printf("===RESIDENTAL SELL BASE ON BUILD AGE===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    sell_res *start=NULL , *end=NULL , *temp ;

    char input[50];
    char input1[50];

    while (1)
    {
        printf("Build age start : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';

        printf("Build age end : ");
        fgets(input1, 50, stdin);
        input1[strcspn(input1, "\n")] = '\0';

        if (build_age_check(input) && build_age_check(input1))
        {
            break;
        }
        else
        {
            printf("Invalid build age. Please try again.");
            continue;
        }
    }

    fp = fopen("Sell_res_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_res));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->bedrooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->sell_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->bedrooms[strcspn(temp->bedrooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->sell_price[strcspn(temp->sell_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (atof(temp->build_age) >= atof(input) && atof(temp->build_age) <= atof(input1))
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->bedrooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Sell Price: %s\n", temp->sell_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-res-sell function
void base_res_sell_floor_area()
{
    system("cls");
    system("color 02");
    printf("===RESIDENTAL SELL BASE ON FLOOR AREA===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    sell_res *start=NULL , *end=NULL , *temp ;

    char input[50];
    char input1[50];

    while (1)
    {
        printf("Floor area start : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';

        printf("Floor area end : ");
        fgets(input1, 50, stdin);
        input1[strcspn(input1, "\n")] = '\0';

        if (floor_area_check(input) && floor_area_check(input1))
        {
            break;
        }
        else
        {
            printf("Invalid floor area. Please try again.");
            continue;
        }
    }

    fp = fopen("Sell_res_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_res));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->bedrooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->sell_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->bedrooms[strcspn(temp->bedrooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->sell_price[strcspn(temp->sell_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (atof(temp->floor_area) >= atof(input) && atof(temp->floor_area) <= atof(input1))
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->bedrooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Sell Price: %s\n", temp->sell_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-res-sell-floor function
void base_res_sell_floor()
{
    system("cls");
    system("color 02");
    printf("===RESIDENTAL SELL BASE ON FLOOR===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    sell_res *start=NULL , *end=NULL , *temp ;

    char input[50];

    while (1)
    {
        printf("Floor : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';

        if (floor_check(input))
        {
            break;
        }
        else
        {
            printf("Invalid floor. Please try again.");
            continue;
        }
    }

    fp = fopen("Sell_res_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_res));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->bedrooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->sell_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->bedrooms[strcspn(temp->bedrooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->sell_price[strcspn(temp->sell_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->floor , input) == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->bedrooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Sell Price: %s\n", temp->sell_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-res-sell-land-area function
void base_res_sell_land_area()
{
    system("cls");
    system("color 02");
    printf("===RESIDENTAL SELL BASE ON LAND AREA===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    sell_res *start=NULL , *end=NULL , *temp ;

    char input[50];
    char input1[50];

    while (1)
    {
        printf("Land area start : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';

        printf("Land area end : ");
        fgets(input1, 50, stdin);
        input1[strcspn(input1, "\n")] = '\0';

        if (floor_area_check(input) && floor_area_check(input1))
        {
            break;
        }
        else
        {
            printf("Invalid land area. Please try again.");
            continue;
        }
    }

    fp = fopen("Sell_res_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_res));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->bedrooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->sell_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->bedrooms[strcspn(temp->bedrooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->sell_price[strcspn(temp->sell_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (atof(temp->land_area) >= atof(input) && atof(temp->land_area) <= atof(input1))
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->bedrooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Sell Price: %s\n", temp->sell_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-res-sell-bedrooms function
void base_res_sell_bedrooms()
{
    system("cls");
    system("color 02");
    printf("===RESIDENTAL SELL BASE ON BEDROOMS===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    sell_res *start=NULL , *end=NULL , *temp ;

    char input[50];

    while (1)
    {
        printf("Bedrooms : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';

        if (bedrooms_check(input))
        {
            break;
        }
        else
        {
            printf("Invalid bedrooms. Please try again.");
            continue;
        }
    }

    fp = fopen("Sell_res_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_res));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->bedrooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->sell_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->bedrooms[strcspn(temp->bedrooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->sell_price[strcspn(temp->sell_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->bedrooms , input) == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->bedrooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Sell Price: %s\n", temp->sell_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-res-sell-tax-rate function
void base_res_sell_tax_rate()
{
    system("cls");
    system("color 02");
    printf("===RESIDENTAL SELL BASE ON TAX RATE===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    sell_res *start=NULL , *end=NULL , *temp ;

    char input[50];
    char input1[50];

    while (1)
    {
        printf("Tax-rate start : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';

        printf("Tax-rate end : ");
        fgets(input1, 50, stdin);
        input1[strcspn(input1, "\n")] = '\0';

        if (tax_rate_check(input) && tax_rate_check(input1))
        {
            break;
        }
        else
        {
            printf("Invalid tax rate. Please try again.");
            continue;
        }
    }

    fp = fopen("Sell_res_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_res));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->bedrooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->sell_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->bedrooms[strcspn(temp->bedrooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->sell_price[strcspn(temp->sell_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (atof(temp->tax_rate) >= atof(input) && atof(temp->tax_rate) <= atof(input1))
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->bedrooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Sell Price: %s\n", temp->sell_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-res-sell-elevator function
void base_res_sell_elevator()
{
    system("cls");
    system("color 02");
    printf("===RESIDENTAL SELL BASE ON ELEVATOR===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    sell_res *start=NULL , *end=NULL , *temp ;

    char input[50];

    while (1)
    {
        printf("Elevator (Yes , NO) : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        if (yes_no_check(input))
        {
            break;
        }
        else
        {
            printf("Invalid elevator. Please try again.");
        }
    }

    fp = fopen("Sell_res_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_res));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->bedrooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->sell_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->bedrooms[strcspn(temp->bedrooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->sell_price[strcspn(temp->sell_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->elevator , input) == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->bedrooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Sell Price: %s\n", temp->sell_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-res-sell-basement function
void base_res_sell_basement()
{
    system("cls");
    system("color 02");
    printf("===RESIDENTAL SELL BASE ON BASEMENT===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    sell_res *start=NULL , *end=NULL , *temp ;

    char input[50];

    while (1)
    {
        printf("Basement (Yes , NO) : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        if (yes_no_check(input))
        {
            break;
        }
        else
        {
            printf("Invalid basement. Please try again.");
            continue;
        }
    }

    fp = fopen("Sell_res_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_res));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->bedrooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->sell_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->bedrooms[strcspn(temp->bedrooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->sell_price[strcspn(temp->sell_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->basement , input) == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->bedrooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Sell Price: %s\n", temp->sell_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-res-sell-balcony function
void base_res_sell_balcony()
{
    system("cls");
    system("color 02");
    printf("===RESIDENTAL SELL BASE ON BALCONY===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    sell_res *start=NULL , *end=NULL , *temp ;

    char input[50];

    while (1)
    {
        printf("Balcony (Yes , NO) : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        if (yes_no_check(input))
        {
            break;
        }
        else
        {
            printf("Invalid balcony. Please try again.");
            continue;
        }
    }

    fp = fopen("Sell_res_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_res));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->bedrooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->sell_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->bedrooms[strcspn(temp->bedrooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->sell_price[strcspn(temp->sell_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->balcony , input) == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->bedrooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Sell Price: %s\n", temp->sell_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-res-sell-parkings
void base_res_sell_parkings()
{
    system("cls");
    system("color 02");
    printf("===RESIDENTAL SELL BASE ON PARKINGS===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    sell_res *start=NULL , *end=NULL , *temp ;

    char input[50];

    while (1)
    {
        printf("Parkings : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';

        if (parkings_check(input))
        {
            break;
        }
        else
        {
            printf("Invalid parkings. Please try again.");
            continue;
        }
    }

    fp = fopen("Sell_res_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_res));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->bedrooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->sell_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->bedrooms[strcspn(temp->bedrooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->sell_price[strcspn(temp->sell_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->parkings , input) == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->bedrooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Sell Price: %s\n", temp->sell_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-res-sell-phones
void base_res_sell_phones()
{
    system("cls");
    system("color 02");
    printf("===RESIDENTAL SELL BASE ON PHONES===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    sell_res *start=NULL , *end=NULL , *temp ;

    char input[50];

    while (1)
    {
        printf("Phones : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';

        if (phones_check(input))
        {
            break;
        }
        else
        {
            printf("Invalid phones. Please try again.");
            continue;
        }
    }

    fp = fopen("Sell_res_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_res));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->bedrooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->sell_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->bedrooms[strcspn(temp->bedrooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->sell_price[strcspn(temp->sell_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->phones , input) == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->bedrooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Sell Price: %s\n", temp->sell_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-res-sell-temperature function
void base_res_sell_temperature()
{
    system("cls");
    system("color 02");
    printf("===RESIDENTAL SELL BASE ON TEMPERATURE===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    sell_res *start=NULL , *end=NULL , *temp ;

    char input[50];

    while (1)
    {
        printf("Temperature (Cold , Hot , Medium) : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        if (temperature_check(input))
        {
            break;
        }
        else
        {
            printf("Invalid temperature. Please try again.");
            continue;
        }
    }

    fp = fopen("Sell_res_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_res));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->bedrooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->sell_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->bedrooms[strcspn(temp->bedrooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->sell_price[strcspn(temp->sell_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->temperature , input) == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->bedrooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Sell Price: %s\n", temp->sell_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-res-sell-sell-price function
void base_res_sell_sell_price()
{
    system("cls");
    system("color 02");
    printf("===RESIDENTAL SELL BASE ON SELL PRICE===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    sell_res *start=NULL , *end=NULL , *temp ;

    char input[50];
    char input1[50];

    while (1)
    {
        printf("Sell-price start : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';

        printf("Sell-price end : ");
        fgets(input1, 50, stdin);
        input1[strcspn(input1, "\n")] = '\0';

        if (sell_price_check(input) && sell_price_check(input1))
        {
            break;
        }
        else
        {
            printf("Invalid sell price. Please try again.");
            continue;
        }
    }

    fp = fopen("Sell_res_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_res));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->bedrooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->sell_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->bedrooms[strcspn(temp->bedrooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->sell_price[strcspn(temp->sell_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (atof(temp->sell_price) >= atof(input) && atof(temp->sell_price) <= atof(input1))
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->bedrooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Sell Price: %s\n", temp->sell_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///menu-com-sell function
void menu_com_sell()
{
    char input[10];
    int number;
    while (1)
    {
        system("cls");
        system("color 07");
        printf("===MENU COMMERCIAL SELL===\n");
        display_current_date();
        display_current_time();
        printf("\n1.Base On District\n");
        printf("2.Base On Location\n");
        printf("3.Base On Type\n");
        printf("4.Base On Build Age\n");
        printf("5.Base On Floor Area\n");
        printf("6.Base On Floor\n");
        printf("7.Base On Land Area\n");
        printf("8.Base On Rooms\n");
        printf("9.Base On Tax-rate\n");
        printf("10.Base On Elevator\n");
        printf("11.Base On Basement\n");
        printf("12.Base On Balcony\n");
        printf("13.Base On Parkings\n");
        printf("14.Base On Phones\n");
        printf("15.Base On Temperature\n");
        printf("16.Base On Sell-price\n");
        printf("0.Exit\n");
        printf("\nPlease Enter Your Choice : ");
        gets(input);
        system("cls");
        number = atoi(input);
        if (number == 0)
        {
            break;
        }
        else if (number == 1)
        {
            base_com_sell_district();
            continue;
        }
        else if (number == 2)
        {
            base_com_sell_location();
            continue;
        }
        else if (number == 3)
        {
            base_com_sell_type();
            continue;
        }
        else if (number == 4)
        {
            base_com_sell_build_age();
            continue;
        }
        else if (number == 5)
        {
            base_com_sell_floor_area();
            continue;
        }
        else if (number == 6)
        {
            base_com_sell_floor();
            continue;
        }
        else if (number == 7)
        {
            base_com_sell_land_area();
            continue;
        }
        else if (number == 8)
        {
            base_com_sell_rooms();
            continue;
        }
        else if (number == 9)
        {
            base_com_sell_tax_rate();
            continue;
        }
        else if (number == 10)
        {
            base_com_sell_elevator();
            continue;
        }
        else if (number == 11)
        {
            base_com_sell_basement();
            continue;
        }
        else if (number == 12)
        {
            base_com_sell_balcony();
            continue;
        }
        else if (number == 13)
        {
            base_com_sell_parkings();
            continue;
        }
        else if (number == 14)
        {
            base_com_sell_phones();
            continue;
        }
        else if (number == 15)
        {
            base_com_sell_temperature();
            continue;
        }
        else if (number == 16)
        {
            base_com_sell_sell_price();
            continue;
        }
        else
        {
            continue;
        }
    }
}
///base-com-sell-district function
void base_com_sell_district()
{
    system("cls");
    system("color 02");
    printf("===COMMERCIAL SELL BASE ON DISTRICT===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    sell_com *start=NULL , *end=NULL , *temp ;

    char input[50];

    while (1)
    {
        printf("District : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        if (district_check(input))
        {
            break;
        }
        else
        {
            printf("Invalid district. Please try again.");
            continue;
        }
    }

    fp = fopen("Sell_com_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_com));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->rooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->sell_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->rooms[strcspn(temp->rooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->sell_price[strcspn(temp->sell_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->district , input) == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->rooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Sell Price: %s\n", temp->sell_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-com-sell-location function
void base_com_sell_location()
{
    system("cls");
    system("color 02");
    printf("===COMMERCIAL SELL BASE ON LOCATION===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    sell_com *start=NULL , *end=NULL , *temp ;

    char input[50];

    while (1)
    {
        printf("Location (North , South , East , West) : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        if (location_check(input))
        {
            break;
        }
        else
        {
            printf("Invalid location. Please try again.");
            continue;
        }
    }

    fp = fopen("Sell_com_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_com));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->rooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->sell_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->rooms[strcspn(temp->rooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->sell_price[strcspn(temp->sell_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->location , input) == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->rooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Sell Price: %s\n", temp->sell_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-com-sell-type function
void base_com_sell_type()
{
    system("cls");
    system("color 02");
    printf("===COMMERCIAL SELL BASE ON TYPE===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    sell_com *start=NULL , *end=NULL , *temp ;

    char input[50];

    while (1)
    {
        printf("Type (Official , Position) : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        if (type1_check(input))
        {
            break;
        }
        else
        {
            printf("Invalid type. Please try again.");
            continue;
        }
    }

    fp = fopen("Sell_com_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_com));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->rooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->sell_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->rooms[strcspn(temp->rooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->sell_price[strcspn(temp->sell_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->type , input) == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->rooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Sell Price: %s\n", temp->sell_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-com-sell-build-age function
void base_com_sell_build_age()
{
    system("cls");
    system("color 02");
    printf("===COMMERCIAL SELL BASE ON BUILD AGE===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    sell_com *start=NULL , *end=NULL , *temp ;

    char input[50];
    char input1[50];

    while (1)
    {
        printf("Build age start : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';

        printf("Build age end : ");
        fgets(input1, 50, stdin);
        input1[strcspn(input1, "\n")] = '\0';

        if (build_age_check(input) && build_age_check(input1))
        {
            break;
        }
        else
        {
            printf("Invalid build age. Please try again.");
            continue;
        }
    }

    fp = fopen("Sell_com_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_com));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->rooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->sell_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->rooms[strcspn(temp->rooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->sell_price[strcspn(temp->sell_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (atof(temp->build_age) >= atof(input) && atof(temp->build_age) <= atof(input1))
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->rooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Sell Price: %s\n", temp->sell_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-com-sell-floor-area function
void base_com_sell_floor_area()
{
    system("cls");
    system("color 02");
    printf("===COMMERCIAL SELL BASE ON FLOOR AREA===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    sell_com *start=NULL , *end=NULL , *temp ;

    char input[50];
    char input1[50];

    while (1)
    {
        printf("Floor area start : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';

        printf("Floor area end : ");
        fgets(input1, 50, stdin);
        input1[strcspn(input1, "\n")] = '\0';

        if (floor_area_check(input) && floor_area_check(input1))
        {
            break;
        }
        else
        {
            printf("Invalid floor area. Please try again.");
            continue;
        }
    }

    fp = fopen("Sell_com_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_com));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->rooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->sell_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->rooms[strcspn(temp->rooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->sell_price[strcspn(temp->sell_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (atof(temp->floor_area) >= atof(input) && atof(temp->floor_area) <= atof(input1))
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->rooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Sell Price: %s\n", temp->sell_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-com-sell-floor function
void base_com_sell_floor()
{
    system("cls");
    system("color 02");
    printf("===COMMERCIAL SELL BASE ON FLOOR===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    sell_com *start=NULL , *end=NULL , *temp ;

    char input[50];

    while (1)
    {
        printf("Floor : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';

        if (floor_check(input))
        {
            break;
        }
        else
        {
            printf("Invalid floor. Please try again.");
            continue;
        }
    }

    fp = fopen("Sell_com_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_com));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->rooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->sell_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->rooms[strcspn(temp->rooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->sell_price[strcspn(temp->sell_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->floor , input) == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->rooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Sell Price: %s\n", temp->sell_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-com-sell-land-area function
void base_com_sell_land_area()
{
    system("cls");
    system("color 02");
    printf("===COMMERCIAL SELL BASE ON LAND AREA===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    sell_com *start=NULL , *end=NULL , *temp ;

    char input[50];
    char input1[50];

    while (1)
    {
        printf("Land area start : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';

        printf("Land area end : ");
        fgets(input1, 50, stdin);
        input1[strcspn(input1, "\n")] = '\0';

        if (floor_area_check(input) && floor_area_check(input1))
        {
            break;
        }
        else
        {
            printf("Invalid land area. Please try again.");
            continue;
        }
    }

    fp = fopen("Sell_com_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_com));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->rooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->sell_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->rooms[strcspn(temp->rooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->sell_price[strcspn(temp->sell_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (atof(temp->land_area) >= atof(input) && atof(temp->land_area) <= atof(input1))
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->rooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Sell Price: %s\n", temp->sell_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-com-sell-rooms function
void base_com_sell_rooms()
{
    system("cls");
    system("color 02");
    printf("===COMMERCIAL SELL BASE ON ROOMS===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    sell_com *start=NULL , *end=NULL , *temp ;

    char input[50];

    while (1)
    {
        printf("Rooms : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';

        if (bedrooms_check(input))
        {
            break;
        }
        else
        {
            printf("Invalid rooms. Please try again.");
            continue;
        }
    }

    fp = fopen("Sell_com_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_com));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->rooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->sell_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->rooms[strcspn(temp->rooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->sell_price[strcspn(temp->sell_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->rooms , input) == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->rooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Sell Price: %s\n", temp->sell_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-com-sell-tax-rate function
void base_com_sell_tax_rate()
{
    system("cls");
    system("color 02");
    printf("===COMMERCIAL SELL BASE ON TAX RATE===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    sell_com *start=NULL , *end=NULL , *temp ;

    char input[50];
    char input1[50];

    while (1)
    {
        printf("Tax rate start : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';

        printf("Tax rate end : ");
        fgets(input1, 50, stdin);
        input1[strcspn(input1, "\n")] = '\0';

        if (tax_rate_check(input) && tax_rate_check(input1))
        {
            break;
        }
        else
        {
            printf("Invalid tax rate. Please try again.");
            continue;
        }
    }

    fp = fopen("Sell_com_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_com));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->rooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->sell_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->rooms[strcspn(temp->rooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->sell_price[strcspn(temp->sell_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (atof(temp->tax_rate) >= atof(input) && atof(temp->tax_rate) <= atof(input1))
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->rooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Sell Price: %s\n", temp->sell_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-com-sell-elevator function
void base_com_sell_elevator()
{
    system("cls");
    system("color 02");
    printf("===COMMERCIAL SELL BASE ON ELEVATOR===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    sell_com *start=NULL , *end=NULL , *temp ;

    char input[50];

    while (1)
    {
        printf("Elevator (Yes , No) : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        if (yes_no_check(input))
        {
            break;
        }
        else
        {
            printf("Invalid elevator. Please try again.");
            continue;
        }
    }

    fp = fopen("Sell_com_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_com));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->rooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->sell_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->rooms[strcspn(temp->rooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->sell_price[strcspn(temp->sell_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->elevator , input) == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->rooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Sell Price: %s\n", temp->sell_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-com-sell-basement function
void base_com_sell_basement()
{
    system("cls");
    system("color 02");
    printf("===COMMERCIAL SELL BASE ON BASEMENT===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    sell_com *start=NULL , *end=NULL , *temp ;

    char input[50];

    while (1)
    {
        printf("Basement (Yes , No) : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        if (yes_no_check(input))
        {
            break;
        }
        else
        {
            printf("Invalid basement. Please try again.");
            continue;
        }
    }

    fp = fopen("Sell_com_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_com));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->rooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->sell_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->rooms[strcspn(temp->rooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->sell_price[strcspn(temp->sell_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->basement , input) == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->rooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Sell Price: %s\n", temp->sell_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-com-sell-balcony function
void base_com_sell_balcony()
{
    system("cls");
    system("color 02");
    printf("===COMMERCIAL SELL BASE ON BALCONY===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    sell_com *start=NULL , *end=NULL , *temp ;

    char input[50];

    while (1)
    {
        printf("Balcony (Yes , No) : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        if (yes_no_check(input))
        {
            break;
        }
        else
        {
            printf("Invalid balcony. Please try again.");
            continue;
        }
    }

    fp = fopen("Sell_com_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_com));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->rooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->sell_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->rooms[strcspn(temp->rooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->sell_price[strcspn(temp->sell_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->balcony , input) == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->rooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Sell Price: %s\n", temp->sell_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-com-sell-parkings function
void base_com_sell_parkings()
{
    system("cls");
    system("color 02");
    printf("===COMMERCIAL SELL BASE ON PARKINGS===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    sell_com *start=NULL , *end=NULL , *temp ;

    char input[50];

    while (1)
    {
        printf("Parkings : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';

        if (parkings_check(input))
        {
            break;
        }
        else
        {
            printf("Invalid parkings. Please try again.");
            continue;
        }
    }

    fp = fopen("Sell_com_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_com));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->rooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->sell_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->rooms[strcspn(temp->rooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->sell_price[strcspn(temp->sell_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->parkings , input) == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->rooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Sell Price: %s\n", temp->sell_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-com-sell-phones function
void base_com_sell_phones()
{
    system("cls");
    system("color 02");
    printf("===COMMERCIAL SELL BASE ON PHONES===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    sell_com *start=NULL , *end=NULL , *temp ;

    char input[50];

    while (1)
    {
        printf("Phones : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';

        if (floor_check(input))
        {
            break;
        }
        else
        {
            printf("Invalid phones. Please try again.");
            continue;
        }
    }

    fp = fopen("Sell_com_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_com));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->rooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->sell_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->rooms[strcspn(temp->rooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->sell_price[strcspn(temp->sell_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->phones , input) == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->rooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Sell Price: %s\n", temp->sell_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-com-sell-temperature function
void base_com_sell_temperature()
{
    system("cls");
    system("color 02");
    printf("===COMMERCIAL SELL BASE ON TEMPERATURE===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    sell_com *start=NULL , *end=NULL , *temp ;

    char input[50];

    while (1)
    {
        printf("Temperature (Cold , Hot , Medium) : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';

        if (temperature_check(input))
        {
            break;
        }
        else
        {
            printf("Invalid temperature. Please try again.");
            continue;
        }
    }

    fp = fopen("Sell_com_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_com));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->rooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->sell_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->rooms[strcspn(temp->rooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->sell_price[strcspn(temp->sell_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->temperature , input) == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->rooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Sell Price: %s\n", temp->sell_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-com-sell-sell-price function
void base_com_sell_sell_price()
{
    system("cls");
    system("color 02");
    printf("===COMMERCIAL SELL BASE ON SELL PRICE===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    sell_com *start=NULL , *end=NULL , *temp ;

    char input[50];
    char input1[50];

    while (1)
    {
        printf("Sell price start : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';

        printf("Sell price end : ");
        fgets(input1, 50, stdin);
        input1[strcspn(input1, "\n")] = '\0';

        if (sell_price_check(input) && sell_price_check(input1))
        {
            break;
        }
        else
        {
            printf("Invalid sell price. Please try again.");
            continue;
        }
    }

    fp = fopen("Sell_com_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_com));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->rooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->sell_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->rooms[strcspn(temp->rooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->sell_price[strcspn(temp->sell_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (atof(temp->sell_price) >= atof(input) && atof(temp->sell_price) <= atof(input1))
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->rooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Sell Price: %s\n", temp->sell_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///menu-lan-sell function
void menu_lan_sell()
{
    char input[10];
    int number;
    while (1)
    {
        system("cls");
        system("color 07");
        printf("===MENU LAND SELL===\n");
        display_current_date();
        display_current_time();
        printf("\n1.Base On District\n");
        printf("2.Base On Location\n");
        printf("3.Base On Type\n");
        printf("4.Base On Land Area\n");
        printf("5.Base On Width\n");
        printf("6.Base On Tax-rate\n");
        printf("7.Base On Well\n");
        printf("8.Base On Temperature\n");
        printf("9.Base On Sell-price\n");
        printf("0.Back\n");
        printf("\nPlease Enter Your Choice : ");
        gets(input);
        system("cls");
        number = atoi(input);
        if (number == 0)
        {
            break;
        }
        else if (number == 1)
        {
            base_lan_sell_district();
            continue;
        }
        else if (number == 2)
        {
            base_lan_sell_location();
            continue;
        }
        else if (number == 3)
        {
            base_lan_sell_type();
            continue;
        }
        else if (number == 4)
        {
            base_lan_sell_land_area();
            continue;
        }
        else if (number == 5)
        {
            base_lan_sell_width();
            continue;
        }
        else if (number == 6)
        {
            base_lan_sell_tax_rate();
            continue;
        }
        else if (number == 7)
        {
            base_lan_sell_well();
            continue;
        }
        else if (number == 8)
        {
            base_lan_sell_temperature();
            continue;
        }
        else if (number == 9)
        {
            base_lan_sell_sell_price();
            continue;
        }
        else
        {
            continue;
        }
    }
}
///base-lan-sell-district function
void base_lan_sell_district()
{
    system("cls");
    system("color 02");
    printf("===LAND SELL BASE ON DISTRICT===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    sell_lan *start=NULL , *end=NULL , *temp ;

    char input[50];

    while (1)
    {
        printf("District : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';

        if (district_check(input))
        {
            break;
        }
        else
        {
            printf("Invalid district. Please try again.");
            continue;
        }
    }

    fp = fopen("Sell_lan_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_lan));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->width, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->well, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->sell_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->width[strcspn(temp->width, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->well[strcspn(temp->well, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->sell_price[strcspn(temp->sell_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->district , input) == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Land Area: %s\n", temp->land_area);
            printf("Width: %s\n", temp->width);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Well: %s\n", temp->well);
            printf("Temperature: %s\n", temp->temperature);
            printf("Sell Price: %s\n", temp->sell_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
void base_lan_sell_location()
{
    system("cls");
    system("color 02");
    printf("===LAND SELL BASE ON LOCATION===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    sell_lan *start=NULL , *end=NULL , *temp ;

    char input[50];

    while (1)
    {
        printf("Location (North , South , East , West) : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        if (location_check(input))
        {
            break;
        }
        else
        {
            printf("Invalid location. Please try again.");
            continue;
        }
    }

    fp = fopen("Sell_lan_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_lan));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->width, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->well, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->sell_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->width[strcspn(temp->width, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->well[strcspn(temp->well, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->sell_price[strcspn(temp->sell_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->location , input) == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Land Area: %s\n", temp->land_area);
            printf("Width: %s\n", temp->width);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Well: %s\n", temp->well);
            printf("Temperature: %s\n", temp->temperature);
            printf("Sell Price: %s\n", temp->sell_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-lan-sell-type function
void base_lan_sell_type()
{
    system("cls");
    system("color 02");
    printf("===LAND SELL BASE ON TYPE===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    sell_lan *start=NULL , *end=NULL , *temp ;

    char input[50];

    while (1)
    {
        printf("Type (Farm , City) : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        if (type2_check(input))
        {
            break;
        }
        else
        {
            printf("Invalid type. Please try again.");
            continue;
        }
    }

    fp = fopen("Sell_lan_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_lan));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->width, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->well, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->sell_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->width[strcspn(temp->width, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->well[strcspn(temp->well, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->sell_price[strcspn(temp->sell_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->type , input) == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Land Area: %s\n", temp->land_area);
            printf("Width: %s\n", temp->width);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Well: %s\n", temp->well);
            printf("Temperature: %s\n", temp->temperature);
            printf("Sell Price: %s\n", temp->sell_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-lan-sell-land-area function
void base_lan_sell_land_area()
{
    system("cls");
    system("color 02");
    printf("===LAND SELL BASE ON LAND AREA===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    sell_lan *start=NULL , *end=NULL , *temp ;

    char input[50];
    char input1[50];

    while (1)
    {
        printf("Land area start : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';

        printf("Land area end : ");
        fgets(input1, 50, stdin);
        input1[strcspn(input1, "\n")] = '\0';

        if (floor_area_check(input) && floor_area_check(input1))
        {
            break;
        }
        else
        {
            printf("Invalid land area. Please try again.");
            continue;
        }
    }

    fp = fopen("Sell_lan_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_lan));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->width, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->well, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->sell_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->width[strcspn(temp->width, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->well[strcspn(temp->well, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->sell_price[strcspn(temp->sell_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (atof(temp->land_area) >= atof(input) && atof(temp->land_area) <= atof(input1))
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Land Area: %s\n", temp->land_area);
            printf("Width: %s\n", temp->width);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Well: %s\n", temp->well);
            printf("Temperature: %s\n", temp->temperature);
            printf("Sell Price: %s\n", temp->sell_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-lan-sell-width function
void base_lan_sell_width()
{
    system("cls");
    system("color 02");
    printf("===LAND SELL BASE ON WIDTH===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    sell_lan *start=NULL , *end=NULL , *temp ;

    char input[50];
    char input1[50];

    while (1)
    {
        printf("Width start : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';

        printf("Width end : ");
        fgets(input1, 50, stdin);
        input1[strcspn(input1, "\n")] = '\0';

        if (floor_area_check(input) && floor_area_check(input1))
        {
            break;
        }
        else
        {
            printf("Invalid width. Please try again.");
            continue;
        }
    }

    fp = fopen("Sell_lan_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_lan));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->width, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->well, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->sell_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->width[strcspn(temp->width, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->well[strcspn(temp->well, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->sell_price[strcspn(temp->sell_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (atof(temp->width) >= atof(input) && atof(temp->width) <= atof(input1))
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Land Area: %s\n", temp->land_area);
            printf("Width: %s\n", temp->width);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Well: %s\n", temp->well);
            printf("Temperature: %s\n", temp->temperature);
            printf("Sell Price: %s\n", temp->sell_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-lan-sell-tax-rate function
void base_lan_sell_tax_rate()
{
    system("cls");
    system("color 02");
    printf("===LAND SELL BASE On Tax Rate===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    sell_lan *start=NULL , *end=NULL , *temp ;

    char input[50];
    char input1[50];

    while (1)
    {
        printf("Tax rate start : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';

        printf("Tax rate end : ");
        fgets(input1, 50, stdin);
        input1[strcspn(input1, "\n")] = '\0';

        if (tax_rate_check(input) && tax_rate_check(input1))
        {
            break;
        }
        else
        {
            printf("Invalid tax rate. Please try again.");
            continue;
        }
    }

    fp = fopen("Sell_lan_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_lan));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->width, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->well, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->sell_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->width[strcspn(temp->width, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->well[strcspn(temp->well, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->sell_price[strcspn(temp->sell_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (atof(temp->tax_rate) >= atof(input) && atof(temp->tax_rate) <= atof(input1))
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Land Area: %s\n", temp->land_area);
            printf("Width: %s\n", temp->width);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Well: %s\n", temp->well);
            printf("Temperature: %s\n", temp->temperature);
            printf("Sell Price: %s\n", temp->sell_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-lan-sell-well function
void base_lan_sell_well()
{
    system("cls");
    system("color 02");
    printf("===LAND SELL BASE ON WELL===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    sell_lan *start=NULL , *end=NULL , *temp ;

    char input[50];

    while (1)
    {
        printf("Well (Yes , No) : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        if (yes_no_check(input))
        {
            break;
        }
        else
        {
            printf("Invalid well. Please try again.");
            continue;
        }
    }

    fp = fopen("Sell_lan_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_lan));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->width, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->well, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->sell_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->width[strcspn(temp->width, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->well[strcspn(temp->well, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->sell_price[strcspn(temp->sell_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->well , input) == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Land Area: %s\n", temp->land_area);
            printf("Width: %s\n", temp->width);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Well: %s\n", temp->well);
            printf("Temperature: %s\n", temp->temperature);
            printf("Sell Price: %s\n", temp->sell_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-lan-sell-temperature function
void base_lan_sell_temperature()
{
    system("cls");
    system("color 02");
    printf("===LAND SELL BASE ON TEMPERATURE===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    sell_lan *start=NULL , *end=NULL , *temp ;

    char input[50];

    while (1)
    {
        printf("Temperature (Cold , Hot , Medium) : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        if (temperature_check(input))
        {
            break;
        }
        else
        {
            printf("Invalid temperature. Please try again.");
            continue;
        }
    }

    fp = fopen("Sell_lan_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_lan));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->width, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->well, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->sell_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->width[strcspn(temp->width, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->well[strcspn(temp->well, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->sell_price[strcspn(temp->sell_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->temperature , input) == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Land Area: %s\n", temp->land_area);
            printf("Width: %s\n", temp->width);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Well: %s\n", temp->well);
            printf("Temperature: %s\n", temp->temperature);
            printf("Sell Price: %s\n", temp->sell_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-lan-sell-sell-price function
void base_lan_sell_sell_price()
{
    system("cls");
    system("color 02");
    printf("===LAND SELL BASE ON SELL PRICE===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    sell_lan *start=NULL , *end=NULL , *temp ;

    char input[50];
    char input1[50];

    while (1)
    {
        printf("Sell price start : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';

        printf("Sell price end : ");
        fgets(input1, 50, stdin);
        input1[strcspn(input1, "\n")] = '\0';

        if (sell_price_check(input) && sell_price_check(input1))
        {
            break;
        }
        else
        {
            printf("Invalid sell price. Please try again.");
            continue;
        }
    }

    fp = fopen("Sell_lan_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_lan));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->width, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->well, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->sell_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->width[strcspn(temp->width, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->well[strcspn(temp->well, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->sell_price[strcspn(temp->sell_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (atof(temp->sell_price) >= atof(input) && atof(temp->sell_price) <= atof(input1))
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Land Area: %s\n", temp->land_area);
            printf("Width: %s\n", temp->width);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Well: %s\n", temp->well);
            printf("Temperature: %s\n", temp->temperature);
            printf("Sell Price: %s\n", temp->sell_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///menu-res-rent function
void menu_res_rent()
{
    char input[10];
    int number;
    while (1)
    {
        system("cls");
        system("color 07");
        printf("===MENU RESIDENTAL RENT===\n");
        display_current_date();
        display_current_time();
        printf("\n1.Base On District\n");
        printf("2.Base On Location\n");
        printf("3.Base On Type\n");
        printf("4.Base On Build Age\n");
        printf("5.Base On Floor Area\n");
        printf("6.Base On Floor\n");
        printf("7.Base On Land Area\n");
        printf("8.Base On Bedrooms\n");
        printf("9.Base On Tax-rate\n");
        printf("10.Base On Elevator\n");
        printf("11.Base On Basement\n");
        printf("12.Base On Balcony\n");
        printf("13.Base On Parkings\n");
        printf("14.Base On Phones\n");
        printf("15.Base On Temperature\n");
        printf("16.Base On Price\n");
        printf("0.Exit\n");
        printf("\nPlease Enter Your Choice : ");
        gets(input);
        system("cls");
        number = atoi(input);
        if (number == 0)
        {
            break;
        }
        else if (number == 1)
        {
            base_res_rent_district();
            continue;
        }
        else if (number == 2)
        {
            base_res_rent_location();
            continue;
        }
        else if (number == 3)
        {
            base_res_rent_type();
            continue;
        }
        else if (number == 4)
        {
            base_res_rent_build_age();
            continue;
        }
        else if (number == 5)
        {
            base_res_rent_floor_area();
            continue;
        }
        else if (number == 6)
        {
            base_res_rent_floor();
            continue;
        }
        else if (number == 7)
        {
            base_res_rent_land_area();
            continue;
        }
        else if (number == 8)
        {
            base_res_rent_bedrooms();
            continue;
        }
        else if (number == 9)
        {
            base_res_rent_tax_rate();
            continue;
        }
        else if (number == 10)
        {
            base_res_rent_elevator();
            continue;
        }
        else if (number == 11)
        {
            base_res_rent_basement();
            continue;
        }
        else if (number == 12)
        {
            base_res_rent_balcony();
            continue;
        }
        else if (number == 13)
        {
            base_res_rent_parkings();
            continue;
        }
        else if (number == 14)
        {
            base_res_rent_phones();
            continue;
        }
        else if (number == 15)
        {
            base_res_rent_temperature();
            continue;
        }
        else if (number == 16)
        {
            base_res_rent_price();
            continue;
        }
        else
        {
            continue;
        }
    }
}
///base-res-rent-district function
void base_res_rent_district()
{
    system("cls");
    system("color 02");
    printf("===RESIDENTAL RENT BASE ON DISTRICT===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    rent_res *start=NULL , *end=NULL , *temp ;

    char input[50];

    while (1)
    {
        printf("District : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';

        if (district_check(input))
        {
            break;
        }
        else
        {
            printf("Invalid district. Please try again.");
            continue;
        }
    }

    fp = fopen("Rent_res_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(rent_res));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->bedrooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->base_price, 50, fp);
        fgets(temp->monthly_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->bedrooms[strcspn(temp->bedrooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->base_price[strcspn(temp->base_price, "\n")] = '\0';
        temp->monthly_price[strcspn(temp->monthly_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->district , input) == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->bedrooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Base Price: %s\n", temp->base_price);
            printf("Monthly Price: %s\n", temp->monthly_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-res-rent-location function
void base_res_rent_location()
{
    system("cls");
    system("color 02");
    printf("===RESIDENTAL RENT BASE ON LOCATION===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    rent_res *start=NULL , *end=NULL , *temp ;

    char input[50];

    while (1)
    {
        printf("Location (North , South , East , West) : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        if (location_check(input))
        {
            break;
        }
        else
        {
            printf("Invalid location. Please try again.");
            continue;
        }
    }

    fp = fopen("Rent_res_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(rent_res));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->bedrooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->base_price, 50, fp);
        fgets(temp->monthly_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->bedrooms[strcspn(temp->bedrooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->base_price[strcspn(temp->base_price, "\n")] = '\0';
        temp->monthly_price[strcspn(temp->monthly_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->location , input) == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->bedrooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Base Price: %s\n", temp->base_price);
            printf("Monthly Price: %s\n", temp->monthly_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-res-rent-type function
void base_res_rent_type()
{
    system("cls");
    system("color 02");
    printf("===RESIDENTAL RENT BASE ON TYPE===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    rent_res *start=NULL , *end=NULL , *temp ;

    char input[50];

    while (1)
    {
        printf("Type (Apartment , Villa) : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        if (type_check(input))
        {
            break;
        }
        else
        {
            printf("Invalid type. Please try again.");
            continue;
        }
    }

    fp = fopen("Rent_res_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(rent_res));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->bedrooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->base_price, 50, fp);
        fgets(temp->monthly_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->bedrooms[strcspn(temp->bedrooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->base_price[strcspn(temp->base_price, "\n")] = '\0';
        temp->monthly_price[strcspn(temp->monthly_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->type , input) == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->bedrooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Base Price: %s\n", temp->base_price);
            printf("Monthly Price: %s\n", temp->monthly_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-res-rent-build-age function
void base_res_rent_build_age()
{
    system("cls");
    system("color 02");
    printf("===RESIDENTAL RENT BASE ON BUILD AGE===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    rent_res *start=NULL , *end=NULL , *temp ;

    char input[50];
    char input1[50];

    while (1)
    {
        printf("Build age start : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';

        printf("Build age end : ");
        fgets(input1, 50, stdin);
        input1[strcspn(input1, "\n")] = '\0';

        if (build_age_check(input) && build_age_check(input1))
        {
            break;
        }
        else
        {
            printf("Invalid build age. Please try again.");
            continue;
        }
    }

    fp = fopen("Rent_res_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(rent_res));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->bedrooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->base_price, 50, fp);
        fgets(temp->monthly_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->bedrooms[strcspn(temp->bedrooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->base_price[strcspn(temp->base_price, "\n")] = '\0';
        temp->monthly_price[strcspn(temp->monthly_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if(atof(temp->build_age) >= atof(input) && atof(temp->build_age) <= atof(input1))
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->bedrooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Base Price: %s\n", temp->base_price);
            printf("Monthly Price: %s\n", temp->monthly_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-res-rent-floor-area function
void base_res_rent_floor_area()
{
    system("cls");
    system("color 02");
    printf("===RESIDENTAL RENT BASE ON FLOOR AREA===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    rent_res *start=NULL , *end=NULL , *temp ;

    char input[50];
    char input1[50];

    while (1)
    {
        printf("Floor area start : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';

        printf("Floor area end : ");
        fgets(input1, 50, stdin);
        input1[strcspn(input1, "\n")] = '\0';

        if (floor_area_check(input) && floor_area_check(input1))
        {
            break;
        }
        else
        {
            printf("Invalid floor area. Please try again.");
            continue;
        }
    }

    fp = fopen("Rent_res_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(rent_res));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->bedrooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->base_price, 50, fp);
        fgets(temp->monthly_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->bedrooms[strcspn(temp->bedrooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->base_price[strcspn(temp->base_price, "\n")] = '\0';
        temp->monthly_price[strcspn(temp->monthly_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if(atof(temp->floor_area) >= atof(input) && atof(temp->floor_area) <= atof(input1))
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->bedrooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Base Price: %s\n", temp->base_price);
            printf("Monthly Price: %s\n", temp->monthly_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-res-rent-floor function
void base_res_rent_floor()
{
    system("cls");
    system("color 02");
    printf("===RESIDENTAL RENT BASE ON FLOOR===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    rent_res *start=NULL , *end=NULL , *temp ;

    char input[50];

    while (1)
    {
        printf("Floor : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';

        if (floor_check(input))
        {
            break;
        }
        else
        {
            printf("Invalid floor. Please try again.");
            continue;
        }
    }

    fp = fopen("Rent_res_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(rent_res));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->bedrooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->base_price, 50, fp);
        fgets(temp->monthly_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->bedrooms[strcspn(temp->bedrooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->base_price[strcspn(temp->base_price, "\n")] = '\0';
        temp->monthly_price[strcspn(temp->monthly_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->floor , input) == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->bedrooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Base Price: %s\n", temp->base_price);
            printf("Monthly Price: %s\n", temp->monthly_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-res-rent-land-area function
void base_res_rent_land_area()
{
    system("cls");
    system("color 02");
    printf("===RESIDENTAL RENT BASE ON LAND AREA===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    rent_res *start=NULL , *end=NULL , *temp ;

    char input[50];
    char input1[50];

    while (1)
    {
        printf("Land area start : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';

        printf("Land area end : ");
        fgets(input1, 50, stdin);
        input1[strcspn(input1, "\n")] = '\0';

        if (floor_area_check(input) && floor_area_check(input1))
        {
            break;
        }
        else
        {
            printf("Invalid land area. Please try again.");
            continue;
        }
    }

    fp = fopen("Rent_res_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(rent_res));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->bedrooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->base_price, 50, fp);
        fgets(temp->monthly_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->bedrooms[strcspn(temp->bedrooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->base_price[strcspn(temp->base_price, "\n")] = '\0';
        temp->monthly_price[strcspn(temp->monthly_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if(atof(temp->land_area) >= atof(input) && atof(temp->land_area) <= atof(input1))
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->bedrooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Base Price: %s\n", temp->base_price);
            printf("Monthly Price: %s\n", temp->monthly_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-res-rent-bedrooms function
void base_res_rent_bedrooms()
{
    system("cls");
    system("color 02");
    printf("===RESIDENTAL RENT BASE ON BEDROOMS===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    rent_res *start=NULL , *end=NULL , *temp ;

    char input[50];

    while (1)
    {
        printf("Bedrooms : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';

        if (bedrooms_check(input))
        {
            break;
        }
        else
        {
            printf("Invalid bedrooms. Please try again.");
            continue;
        }
    }

    fp = fopen("Rent_res_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(rent_res));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->bedrooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->base_price, 50, fp);
        fgets(temp->monthly_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->bedrooms[strcspn(temp->bedrooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->base_price[strcspn(temp->base_price, "\n")] = '\0';
        temp->monthly_price[strcspn(temp->monthly_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->bedrooms , input) == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->bedrooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Base Price: %s\n", temp->base_price);
            printf("Monthly Price: %s\n", temp->monthly_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-res-rent-tax-rate function
void base_res_rent_tax_rate()
{
    system("cls");
    system("color 02");
    printf("===RESIDENTAL RENT BASE ON TAX RATE===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    rent_res *start=NULL , *end=NULL , *temp ;

    char input[50];
    char input1[50];

    while (1)
    {
        printf("Tax rate start : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';

        printf("Tax rate end : ");
        fgets(input1, 50, stdin);
        input1[strcspn(input1, "\n")] = '\0';

        if (tax_rate_check(input) && tax_rate_check(input1))
        {
            break;
        }
        else
        {
            printf("Invalid tax rate. Please try again.");
            continue;
        }
    }

    fp = fopen("Rent_res_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(rent_res));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->bedrooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->base_price, 50, fp);
        fgets(temp->monthly_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->bedrooms[strcspn(temp->bedrooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->base_price[strcspn(temp->base_price, "\n")] = '\0';
        temp->monthly_price[strcspn(temp->monthly_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if(atof(temp->tax_rate) >= atof(input) && atof(temp->tax_rate) <= atof(input1))
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->bedrooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Base Price: %s\n", temp->base_price);
            printf("Monthly Price: %s\n", temp->monthly_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-res-rent-elevator function
void base_res_rent_elevator()
{
    system("cls");
    system("color 02");
    printf("===RESIDENTAL RENT BASE ON ELEVATOR===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    rent_res *start=NULL , *end=NULL , *temp ;

    char input[50];

    while (1)
    {
        printf("Elevator (Yes , No) : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        if (yes_no_check(input))
        {
            break;
        }
        else
        {
            printf("Invalid elevator. Please try again.");
            continue;
        }
    }

    fp = fopen("Rent_res_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(rent_res));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->bedrooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->base_price, 50, fp);
        fgets(temp->monthly_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->bedrooms[strcspn(temp->bedrooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->base_price[strcspn(temp->base_price, "\n")] = '\0';
        temp->monthly_price[strcspn(temp->monthly_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->elevator , input) == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->bedrooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Base Price: %s\n", temp->base_price);
            printf("Monthly Price: %s\n", temp->monthly_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-res-rent-basement function
void base_res_rent_basement()
{
    system("cls");
    system("color 02");
    printf("===RESIDENTAL RENT BASE ON BASEMENT===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    rent_res *start=NULL , *end=NULL , *temp ;

    char input[50];

    while (1)
    {
        printf("Basement (Yes , No) : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        if (yes_no_check(input))
        {
            break;
        }
        else
        {
            printf("Invalid basement. Please try again.");
            continue;
        }
    }

    fp = fopen("Rent_res_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(rent_res));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->bedrooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->base_price, 50, fp);
        fgets(temp->monthly_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->bedrooms[strcspn(temp->bedrooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->base_price[strcspn(temp->base_price, "\n")] = '\0';
        temp->monthly_price[strcspn(temp->monthly_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->basement , input) == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->bedrooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Base Price: %s\n", temp->base_price);
            printf("Monthly Price: %s\n", temp->monthly_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-res-rent-balcony function
void base_res_rent_balcony()
{
    system("cls");
    system("color 02");
    printf("===RESIDENTAL RENT BASE ON BALCONY===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    rent_res *start=NULL , *end=NULL , *temp ;

    char input[50];

    while (1)
    {
        printf("Balcony (Yes , No) : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        if (yes_no_check(input))
        {
            break;
        }
        else
        {
            printf("Invalid balcony. Please try again.");
            continue;
        }
    }

    fp = fopen("Rent_res_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(rent_res));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->bedrooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->base_price, 50, fp);
        fgets(temp->monthly_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->bedrooms[strcspn(temp->bedrooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->base_price[strcspn(temp->base_price, "\n")] = '\0';
        temp->monthly_price[strcspn(temp->monthly_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->balcony , input) == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->bedrooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Base Price: %s\n", temp->base_price);
            printf("Monthly Price: %s\n", temp->monthly_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-res-rent-parkings function
void base_res_rent_parkings()
{
    system("cls");
    system("color 02");
    printf("===RESIDENTAL RENT BASE ON PARKINGS===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    rent_res *start=NULL , *end=NULL , *temp ;

    char input[50];

    while (1)
    {
        printf("Parkings : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';

        if (parkings_check(input))
        {
            break;
        }
        else
        {
            printf("Invalid parkings. Please try again.");
            continue;
        }
    }

    fp = fopen("Rent_res_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(rent_res));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->bedrooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->base_price, 50, fp);
        fgets(temp->monthly_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->bedrooms[strcspn(temp->bedrooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->base_price[strcspn(temp->base_price, "\n")] = '\0';
        temp->monthly_price[strcspn(temp->monthly_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->parkings , input) == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->bedrooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Base Price: %s\n", temp->base_price);
            printf("Monthly Price: %s\n", temp->monthly_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-res-rent-phones function
void base_res_rent_phones()
{
    system("cls");
    system("color 02");
    printf("===RESIDENTAL RENT BASE ON PHONES===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    rent_res *start=NULL , *end=NULL , *temp ;

    char input[50];

    while (1)
    {
        printf("Phones : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';

        if (phones_check(input))
        {
            break;
        }
        else
        {
            printf("Invalid phones. Please try again.");
            continue;
        }
    }

    fp = fopen("Rent_res_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(rent_res));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->bedrooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->base_price, 50, fp);
        fgets(temp->monthly_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->bedrooms[strcspn(temp->bedrooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->base_price[strcspn(temp->base_price, "\n")] = '\0';
        temp->monthly_price[strcspn(temp->monthly_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->phones , input) == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->bedrooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Base Price: %s\n", temp->base_price);
            printf("Monthly Price: %s\n", temp->monthly_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-res-rent-temperature function
void base_res_rent_temperature()
{
    system("cls");
    system("color 02");
    printf("===RESIDENTAL RENT BASE ON TEMPERATURE===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    rent_res *start=NULL , *end=NULL , *temp ;

    char input[50];

    while (1)
    {
        printf("Temperature (Cold , Hot , Medium) : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        if (temperature_check(input))
        {
            break;
        }
        else
        {
            printf("Invalid temperature. Please try again.");
            continue;
        }
    }

    fp = fopen("Rent_res_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(rent_res));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->bedrooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->base_price, 50, fp);
        fgets(temp->monthly_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->bedrooms[strcspn(temp->bedrooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->base_price[strcspn(temp->base_price, "\n")] = '\0';
        temp->monthly_price[strcspn(temp->monthly_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->temperature , input) == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->bedrooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Base Price: %s\n", temp->base_price);
            printf("Monthly Price: %s\n", temp->monthly_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-res-rent-price function
void base_res_rent_price()
{
    system("cls");
    system("color 02");
    printf("===RESIDENTAL RENT BASE ON PRICE===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    rent_res *start=NULL , *end=NULL , *temp ;

    char input[50];
    char input1[50];
    char input2[50];
    char input3[50];

    while (1)
    {
        printf("Base price start : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';

        printf("Base price end : ");
        fgets(input1, 50, stdin);
        input1[strcspn(input1, "\n")] = '\0';

        printf("Monthly price start : ");
        fgets(input2, 50, stdin);
        input2[strcspn(input2, "\n")] = '\0';

        printf("Monthly price end : ");
        fgets(input3, 50, stdin);
        input3[strcspn(input3, "\n")] = '\0';

        if (sell_price_check(input) && sell_price_check(input1) && sell_price_check(input2) && sell_price_check(input3))
        {
            break;
        }
        else
        {
            printf("Invalid price. Please try again.");
            continue;
        }
    }

    fp = fopen("Rent_res_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(rent_res));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->bedrooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->base_price, 50, fp);
        fgets(temp->monthly_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->bedrooms[strcspn(temp->bedrooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->base_price[strcspn(temp->base_price, "\n")] = '\0';
        temp->monthly_price[strcspn(temp->monthly_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if(atof(temp->base_price) >= atof(input) && atof(temp->base_price) <= atof(input1) &&
            atof(temp->monthly_price) >= atof(input2) && atof(temp->monthly_price) <= atof(input3))
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->bedrooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Base Price: %s\n", temp->base_price);
            printf("Monthly Price: %s\n", temp->monthly_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///menu-com-rent function
void menu_com_rent()
{
    char input[10];
    int number;
    while (1)
    {
        system("cls");
        system("color 07");
        printf("===MENU COMMERCIAL RENT===\n");
        display_current_date();
        display_current_time();
        printf("\n1.Base On District\n");
        printf("2.Base On Location\n");
        printf("3.Base On Type\n");
        printf("4.Base On Build Age\n");
        printf("5.Base On Floor Area\n");
        printf("6.Base On Floor\n");
        printf("7.Base On Land Area\n");
        printf("8.Base On Rooms\n");
        printf("9.Base On Tax-rate\n");
        printf("10.Base On Elevator\n");
        printf("11.Base On Basement\n");
        printf("12.Base On Balcony\n");
        printf("13.Base On Parkings\n");
        printf("14.Base On Phones\n");
        printf("15.Base On Temperature\n");
        printf("16.Base On Price\n");
        printf("0.Exit\n");
        printf("\nPlease Enter Your Choice : ");
        gets(input);
        system("cls");
        number = atoi(input);
        if (number == 0)
        {
            break;
        }
        else if (number == 1)
        {
            base_com_rent_district();
            continue;
        }
        else if (number == 2)
        {
            base_com_rent_location();
            continue;
        }
        else if (number == 3)
        {
            base_com_rent_type();
            continue;
        }
        else if (number == 4)
        {
            base_com_rent_build_age();
            continue;
        }
        else if (number == 5)
        {
            base_com_rent_floor_area();
            continue;
        }
        else if (number == 6)
        {
            base_com_rent_floor();
            continue;
        }
        else if (number == 7)
        {
            base_com_rent_land_area();
            continue;
        }
        else if (number == 8)
        {
            base_com_rent_rooms();
            continue;
        }
        else if (number == 9)
        {
            base_com_rent_tax_rate();
            continue;
        }
        else if (number == 10)
        {
            base_com_rent_elevator();
            continue;
        }
        else if (number == 11)
        {
            base_com_rent_basement();
            continue;
        }
        else if (number == 12)
        {
            base_com_rent_balcony();
            continue;
        }
        else if (number == 13)
        {
            base_com_rent_parkings();
            continue;
        }
        else if (number == 14)
        {
            base_com_rent_phones();
            continue;
        }
        else if (number == 15)
        {
            base_com_rent_temperature();
            continue;
        }
        else if (number == 16)
        {
            base_com_rent_price();
            continue;
        }
        else
        {
            continue;
        }
    }
}
///base-com-rent-distrcit function
void base_com_rent_district()
{
    system("cls");
    system("color 02");
    printf("===COMMERCIAL RENT BASE ON DISTRICT===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    rent_com *start=NULL , *end=NULL , *temp ;

    char input[50];

    while (1)
    {
        printf("District : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';

        if (district_check(input))
        {
            break;
        }
        else
        {
            printf("Invalid district. Please try again.");
            continue;
        }
    }

    fp = fopen("Rent_com_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_com));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->rooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->base_price, 50, fp);
        fgets(temp->monthly_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->rooms[strcspn(temp->rooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->base_price[strcspn(temp->base_price, "\n")] = '\0';
        temp->monthly_price[strcspn(temp->monthly_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->district , input) == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->rooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Base Price: %s\n", temp->base_price);
            printf("Monthly Price: %s\n", temp->monthly_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-com-rent-location function
void base_com_rent_location()
{
    system("cls");
    system("color 02");
    printf("===COMMERCIAL RENT BASE ON LOCATION===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    rent_com *start=NULL , *end=NULL , *temp ;

    char input[50];

    while (1)
    {
        printf("Location (North , South , East , West) : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        if (location_check(input))
        {
            break;
        }
        else
        {
            printf("Invalid location. Please try again.");
            continue;
        }
    }

    fp = fopen("Rent_com_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_com));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->rooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->base_price, 50, fp);
        fgets(temp->monthly_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->rooms[strcspn(temp->rooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->base_price[strcspn(temp->base_price, "\n")] = '\0';
        temp->monthly_price[strcspn(temp->monthly_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->location , input) == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->rooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Base Price: %s\n", temp->base_price);
            printf("Monthly Price: %s\n", temp->monthly_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-com-rent-type function
void base_com_rent_type()
{
    system("cls");
    system("color 02");
    printf("===COMMERCIAL RENT BASE ON TYPE===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    rent_com *start=NULL , *end=NULL , *temp ;

    char input[50];

    while (1)
    {
        printf("Type (Official , Position) : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        if (type1_check(input))
        {
            break;
        }
        else
        {
            printf("Invalid type. Please try again.");
            continue;
        }
    }

    fp = fopen("Rent_com_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_com));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->rooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->base_price, 50, fp);
        fgets(temp->monthly_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->rooms[strcspn(temp->rooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->base_price[strcspn(temp->base_price, "\n")] = '\0';
        temp->monthly_price[strcspn(temp->monthly_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->type , input) == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->rooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Base Price: %s\n", temp->base_price);
            printf("Monthly Price: %s\n", temp->monthly_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-com-rent-build-age function
void base_com_rent_build_age()
{
    system("cls");
    system("color 02");
    printf("===COMMERCIAL RENT BASE ON BUILD AGE===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    rent_com *start=NULL , *end=NULL , *temp ;

    char input[50];
    char input1[50];

    while (1)
    {
        printf("Build age start : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';

        printf("Build age end : ");
        fgets(input1, 50, stdin);
        input1[strcspn(input1, "\n")] = '\0';

        if (build_age_check(input) && build_age_check(input1))
        {
            break;
        }
        else
        {
            printf("Invalid build age. Please try again.");
            continue;
        }
    }

    fp = fopen("Rent_com_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_com));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->rooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->base_price, 50, fp);
        fgets(temp->monthly_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->rooms[strcspn(temp->rooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->base_price[strcspn(temp->base_price, "\n")] = '\0';
        temp->monthly_price[strcspn(temp->monthly_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (atof(temp->build_age) >= atof(input) && atof(temp->build_age) <= atof(input1))
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->rooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Base Price: %s\n", temp->base_price);
            printf("Monthly Price: %s\n", temp->monthly_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-com-rent-floor-area function
void base_com_rent_floor_area()
{
    system("cls");
    system("color 02");
    printf("===COMMERCIAL RENT BASE ON FLOOR AREA===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    rent_com *start=NULL , *end=NULL , *temp ;

    char input[50];
    char input1[50];

    while (1)
    {
        printf("Floor area start : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';

        printf("Floor area end : ");
        fgets(input1, 50, stdin);
        input1[strcspn(input1, "\n")] = '\0';

        if (floor_area_check(input) && floor_area_check(input1))
        {
            break;
        }
        else
        {
            printf("Invalid floor area. Please try again.");
            continue;
        }
    }

    fp = fopen("Rent_com_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_com));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->rooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->base_price, 50, fp);
        fgets(temp->monthly_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->rooms[strcspn(temp->rooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->base_price[strcspn(temp->base_price, "\n")] = '\0';
        temp->monthly_price[strcspn(temp->monthly_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (atof(temp->floor_area) >= atof(input) && atof(temp->floor_area) <= atof(input1))
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->rooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Base Price: %s\n", temp->base_price);
            printf("Monthly Price: %s\n", temp->monthly_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-com-rent-floor function
void base_com_rent_floor()
{
    system("cls");
    system("color 02");
    printf("===COMMERCIAL RENT BASE ON FLOOR===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    rent_com *start=NULL , *end=NULL , *temp ;

    char input[50];

    while (1)
    {
        printf("Floor : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';

        if (floor_check(input))
        {
            break;
        }
        else
        {
            printf("Invalid floor. Please try again.");
            continue;
        }
    }

    fp = fopen("Rent_com_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_com));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->rooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->base_price, 50, fp);
        fgets(temp->monthly_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->rooms[strcspn(temp->rooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->base_price[strcspn(temp->base_price, "\n")] = '\0';
        temp->monthly_price[strcspn(temp->monthly_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->floor , input) == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->rooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Base Price: %s\n", temp->base_price);
            printf("Monthly Price: %s\n", temp->monthly_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-com-rent-land-area function
void base_com_rent_land_area()
{
    system("cls");
    system("color 02");
    printf("===COMMERCIAL RENT BASE ON LAND AREA===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    rent_com *start=NULL , *end=NULL , *temp ;

    char input[50];
    char input1[50];

    while (1)
    {
        printf("Land area start : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';

        printf("Land area end : ");
        fgets(input1, 50, stdin);
        input1[strcspn(input1, "\n")] = '\0';

        if (floor_area_check(input) && floor_area_check(input1))
        {
            break;
        }
        else
        {
            printf("Invalid land area. Please try again.");
            continue;
        }
    }

    fp = fopen("Rent_com_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_com));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->rooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->base_price, 50, fp);
        fgets(temp->monthly_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->rooms[strcspn(temp->rooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->base_price[strcspn(temp->base_price, "\n")] = '\0';
        temp->monthly_price[strcspn(temp->monthly_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (atof(temp->land_area) >= atof(input) && atof(temp->land_area) <= atof(input1))
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->rooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Base Price: %s\n", temp->base_price);
            printf("Monthly Price: %s\n", temp->monthly_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-com-rent-rooms function
void base_com_rent_rooms()
{
    system("cls");
    system("color 02");
    printf("===COMMERCIAL RENT BASE ON ROOMS===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    rent_com *start=NULL , *end=NULL , *temp ;

    char input[50];

    while (1)
    {
        printf("Rooms : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';

        if (bedrooms_check(input))
        {
            break;
        }
        else
        {
            printf("Invalid rooms. Please try again.");
            continue;
        }
    }

    fp = fopen("Rent_com_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_com));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->rooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->base_price, 50, fp);
        fgets(temp->monthly_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->rooms[strcspn(temp->rooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->base_price[strcspn(temp->base_price, "\n")] = '\0';
        temp->monthly_price[strcspn(temp->monthly_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->rooms , input) == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->rooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Base Price: %s\n", temp->base_price);
            printf("Monthly Price: %s\n", temp->monthly_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-com-rent-tax-rate function
void base_com_rent_tax_rate()
{
    system("cls");
    system("color 02");
    printf("===COMMERCIAL RENT BASE ON TAX RATE===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    rent_com *start=NULL , *end=NULL , *temp ;

    char input[50];
    char input1[50];

    while (1)
    {
        printf("Tax rate start : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';

        printf("Tax rate end : ");
        fgets(input1, 50, stdin);
        input1[strcspn(input1, "\n")] = '\0';

        if (tax_rate_check(input) && tax_rate_check(input1))
        {
            break;
        }
        else
        {
            printf("Invalid tax rate. Please try again.");
            continue;
        }
    }

    fp = fopen("Rent_com_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_com));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->rooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->base_price, 50, fp);
        fgets(temp->monthly_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->rooms[strcspn(temp->rooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->base_price[strcspn(temp->base_price, "\n")] = '\0';
        temp->monthly_price[strcspn(temp->monthly_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (atof(temp->tax_rate) >= atof(input) && atof(temp->tax_rate) <= atof(input1))
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->rooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Base Price: %s\n", temp->base_price);
            printf("Monthly Price: %s\n", temp->monthly_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-com-rent-elevator function
void base_com_rent_elevator()
{
    system("cls");
    system("color 02");
    printf("===COMMERCIAL RENT BASE ON ELEVATOR===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    rent_com *start=NULL , *end=NULL , *temp ;

    char input[50];

    while (1)
    {
        printf("Elevator (Yes , No) : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        if (yes_no_check(input))
        {
            break;
        }
        else
        {
            printf("Invalid elevator. Please try again.");
            continue;
        }
    }

    fp = fopen("Rent_com_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_com));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->rooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->base_price, 50, fp);
        fgets(temp->monthly_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->rooms[strcspn(temp->rooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->base_price[strcspn(temp->base_price, "\n")] = '\0';
        temp->monthly_price[strcspn(temp->monthly_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->elevator , input) == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->rooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Base Price: %s\n", temp->base_price);
            printf("Monthly Price: %s\n", temp->monthly_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-com-rent-basement function
void base_com_rent_basement()
{
    system("cls");
    system("color 02");
    printf("===COMMERCIAL RENT BASE ON BASEMENT===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    rent_com *start=NULL , *end=NULL , *temp ;

    char input[50];

    while (1)
    {
        printf("Basement (Yes , No) : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        if (yes_no_check(input))
        {
            break;
        }
        else
        {
            printf("Invalid basement. Please try again.");
            continue;
        }
    }

    fp = fopen("Rent_com_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_com));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->rooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->base_price, 50, fp);
        fgets(temp->monthly_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->rooms[strcspn(temp->rooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->base_price[strcspn(temp->base_price, "\n")] = '\0';
        temp->monthly_price[strcspn(temp->monthly_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->basement , input) == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->rooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Base Price: %s\n", temp->base_price);
            printf("Monthly Price: %s\n", temp->monthly_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-com-rent-balcony function
void base_com_rent_balcony()
{
    system("cls");
    system("color 02");
    printf("===COMMERCIAL RENT BASE ON BALCONY===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    rent_com *start=NULL , *end=NULL , *temp ;

    char input[50];

    while (1)
    {
        printf("Balcony (Yes , No) : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        if (yes_no_check(input))
        {
            break;
        }
        else
        {
            printf("Invalid balcony. Please try again.");
            continue;
        }
    }

    fp = fopen("Rent_com_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_com));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->rooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->base_price, 50, fp);
        fgets(temp->monthly_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->rooms[strcspn(temp->rooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->base_price[strcspn(temp->base_price, "\n")] = '\0';
        temp->monthly_price[strcspn(temp->monthly_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->balcony , input) == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->rooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Base Price: %s\n", temp->base_price);
            printf("Monthly Price: %s\n", temp->monthly_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-com-rent-parkings function
void base_com_rent_parkings()
{
    system("cls");
    system("color 02");
    printf("===COMMERCIAL RENT BASE ON PARKINGS===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    rent_com *start=NULL , *end=NULL , *temp ;

    char input[50];

    while (1)
    {
        printf("Parkings : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';

        if (parkings_check(input))
        {
            break;
        }
        else
        {
            printf("Invalid parkings. Please try again.");
            continue;
        }
    }

    fp = fopen("Rent_com_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_com));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->rooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->base_price, 50, fp);
        fgets(temp->monthly_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->rooms[strcspn(temp->rooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->base_price[strcspn(temp->base_price, "\n")] = '\0';
        temp->monthly_price[strcspn(temp->monthly_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->parkings , input) == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->rooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Base Price: %s\n", temp->base_price);
            printf("Monthly Price: %s\n", temp->monthly_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-com-rent-phones function
void base_com_rent_phones()
{
    system("cls");
    system("color 02");
    printf("===COMMERCIAL RENT BASE ON PHONES===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    rent_com *start=NULL , *end=NULL , *temp ;

    char input[50];

    while (1)
    {
        printf("Phones : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';

        if (phones_check(input))
        {
            break;
        }
        else
        {
            printf("Invalid phones. Please try again.");
            continue;
        }
    }

    fp = fopen("Rent_com_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_com));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->rooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->base_price, 50, fp);
        fgets(temp->monthly_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->rooms[strcspn(temp->rooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->base_price[strcspn(temp->base_price, "\n")] = '\0';
        temp->monthly_price[strcspn(temp->monthly_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->phones , input) == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->rooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Base Price: %s\n", temp->base_price);
            printf("Monthly Price: %s\n", temp->monthly_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-com-rent-temperature function
void base_com_rent_temperature()
{
    system("cls");
    system("color 02");
    printf("===COMMERCIAL RENT BASE ON TEMPERATURE===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    rent_com *start=NULL , *end=NULL , *temp ;

    char input[50];

    while (1)
    {
        printf("Temperature (Cold , Hot , Medium) : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        if (temperature_check(input))
        {
            break;
        }
        else
        {
            printf("Invalid temperature. Please try again.");
            continue;
        }
    }

    fp = fopen("Rent_com_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_com));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->rooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->base_price, 50, fp);
        fgets(temp->monthly_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->rooms[strcspn(temp->rooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->base_price[strcspn(temp->base_price, "\n")] = '\0';
        temp->monthly_price[strcspn(temp->monthly_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->temperature , input) == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->rooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Base Price: %s\n", temp->base_price);
            printf("Monthly Price: %s\n", temp->monthly_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-com-rent-price function
void base_com_rent_price()
{
    system("cls");
    system("color 02");
    printf("===COMMERCIAL RENT BASE ON PRICE===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    rent_com *start=NULL , *end=NULL , *temp ;

     char input[50];
    char input1[50];
    char input2[50];
    char input3[50];

    while (1)
    {
        printf("Base price start : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';

        printf("Base price end : ");
        fgets(input1, 50, stdin);
        input1[strcspn(input1, "\n")] = '\0';

        printf("Monthly price start : ");
        fgets(input2, 50, stdin);
        input2[strcspn(input2, "\n")] = '\0';

        printf("Monthly price end : ");
        fgets(input3, 50, stdin);
        input3[strcspn(input3, "\n")] = '\0';

        if (sell_price_check(input) && sell_price_check(input1) && sell_price_check(input2) && sell_price_check(input3))
        {
            break;
        }
        else
        {
            printf("Invalid price. Please try again.");
            continue;
        }
    }

    fp = fopen("Rent_com_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_com));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->rooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->base_price, 50, fp);
        fgets(temp->monthly_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->rooms[strcspn(temp->rooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->base_price[strcspn(temp->base_price, "\n")] = '\0';
        temp->monthly_price[strcspn(temp->monthly_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (atof(temp->base_price) >= atof(input) && atof(temp->base_price) <= atof(input1) &&
            atof(temp->monthly_price) >= atof(input2) && atof(temp->monthly_price) <= atof(input3))
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->rooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Base Price: %s\n", temp->base_price);
            printf("Monthly Price: %s\n", temp->monthly_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///menu-lan-rent function
void menu_lan_rent()
{
    char input[10];
    int number;
    while (1)
    {
        system("cls");
        system("color 07");
        printf("===MENU LAND RENT===\n");
        display_current_date();
        display_current_time();
        printf("\n1.Base On District\n");
        printf("2.Base On Location\n");
        printf("3.Base On Type\n");
        printf("4.Base On Land Area\n");
        printf("5.Base On Width\n");
        printf("6.Base On Tax-rate\n");
        printf("7.Base On Well\n");
        printf("8.Base On Temperature\n");
        printf("9.Base On Price\n");
        printf("0.Back\n");
        printf("\nPlease Enter Your Choice : ");
        gets(input);
        system("cls");
        number = atoi(input);
        if (number == 0)
        {
            break;
        }
        else if (number == 1)
        {
            base_lan_rent_district();
            continue;
        }
        else if (number == 2)
        {
            base_lan_rent_location();
            continue;
        }
        else if (number == 3)
        {
            base_lan_rent_type();
            continue;
        }
        else if (number == 4)
        {
            base_lan_rent_land_area();
            continue;
        }
        else if (number == 5)
        {
            base_lan_rent_width();
            continue;
        }
        else if (number == 6)
        {
            base_lan_rent_tax_rate();
            continue;
        }
        else if (number == 7)
        {
            base_lan_rent_well();
            continue;
        }
        else if (number == 8)
        {
            base_lan_rent_temperature();
            continue;
        }
        else if (number == 9)
        {
            base_lan_rent_price();
            continue;
        }
        else
        {
            continue;
        }
    }
}
///base-lan-rent-district function
void base_lan_rent_district()
{
    system("cls");
    system("color 02");
    printf("===LAND RENT BASE ON DISTRICT===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    rent_lan *start=NULL , *end=NULL , *temp ;

    char input[50];

    while (1)
    {
        printf("District : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';

        if (district_check(input))
        {
            break;
        }
        else
        {
            printf("Invalid district. Please try again.");
            continue;
        }
    }

    fp = fopen("Rent_lan_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(rent_lan));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->width, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->well, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->base_price, 50, fp);
        fgets(temp->monthly_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->width[strcspn(temp->width, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->well[strcspn(temp->well, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->base_price[strcspn(temp->base_price, "\n")] = '\0';
        temp->monthly_price[strcspn(temp->monthly_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->district , input) == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Land Area: %s\n", temp->land_area);
            printf("Width: %s\n", temp->width);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Well: %s\n", temp->well);
            printf("Temperature: %s\n", temp->temperature);
            printf("Base Price: %s\n", temp->base_price);
            printf("Monthly Price: %s\n", temp->monthly_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-lan-rent-location function
void base_lan_rent_location()
{
    system("cls");
    system("color 02");
    printf("===LAND RENT BASE ON LOCATION===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    rent_lan *start=NULL , *end=NULL , *temp ;

    char input[50];

    while (1)
    {
        printf("Location (North , South , East , West) : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        if (location_check(input))
        {
            break;
        }
        else
        {
            printf("Invalid location. Please try again.");
            continue;
        }
    }

    fp = fopen("Rent_lan_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(rent_lan));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->width, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->well, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->base_price, 50, fp);
        fgets(temp->monthly_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->width[strcspn(temp->width, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->well[strcspn(temp->well, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->base_price[strcspn(temp->base_price, "\n")] = '\0';
        temp->monthly_price[strcspn(temp->monthly_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->location , input) == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Land Area: %s\n", temp->land_area);
            printf("Width: %s\n", temp->width);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Well: %s\n", temp->well);
            printf("Temperature: %s\n", temp->temperature);
            printf("Base Price: %s\n", temp->base_price);
            printf("Monthly Price: %s\n", temp->monthly_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-lan-rent-type function
void base_lan_rent_type()
{
    system("cls");
    system("color 02");
    printf("===LAND RENT BASE ON TYPE===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    rent_lan *start=NULL , *end=NULL , *temp ;

    char input[50];

    while (1)
    {
        printf("Type (Farm , City) : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        if (type2_check(input))
        {
            break;
        }
        else
        {
            printf("Invalid type. Please try again.");
            continue;
        }
    }

    fp = fopen("Rent_lan_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(rent_lan));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->width, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->well, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->base_price, 50, fp);
        fgets(temp->monthly_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->width[strcspn(temp->width, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->well[strcspn(temp->well, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->base_price[strcspn(temp->base_price, "\n")] = '\0';
        temp->monthly_price[strcspn(temp->monthly_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->type , input) == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Land Area: %s\n", temp->land_area);
            printf("Width: %s\n", temp->width);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Well: %s\n", temp->well);
            printf("Temperature: %s\n", temp->temperature);
            printf("Base Price: %s\n", temp->base_price);
            printf("Monthly Price: %s\n", temp->monthly_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-lan-rent-land-area function
void base_lan_rent_land_area()
{
    system("cls");
    system("color 02");
    printf("===LAND RENT BASE ON LAND AREA===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    rent_lan *start=NULL , *end=NULL , *temp ;

    char input[50];
    char input1[50];

    while (1)
    {
        printf("Land area start : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';

        printf("Land area end : ");
        fgets(input1, 50, stdin);
        input1[strcspn(input1, "\n")] = '\0';

        if (floor_area_check(input) && floor_area_check(input1))
        {
            break;
        }
        else
        {
            printf("Invalid land area. Please try again.");
            continue;
        }
    }

    fp = fopen("Rent_lan_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(rent_lan));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->width, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->well, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->base_price, 50, fp);
        fgets(temp->monthly_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->width[strcspn(temp->width, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->well[strcspn(temp->well, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->base_price[strcspn(temp->base_price, "\n")] = '\0';
        temp->monthly_price[strcspn(temp->monthly_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (atof(temp->land_area) >= atof(input) && atof(temp->land_area) <= atof(input1))
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Land Area: %s\n", temp->land_area);
            printf("Width: %s\n", temp->width);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Well: %s\n", temp->well);
            printf("Temperature: %s\n", temp->temperature);
            printf("Base Price: %s\n", temp->base_price);
            printf("Monthly Price: %s\n", temp->monthly_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-lan-rent-width function
void base_lan_rent_width()
{
    system("cls");
    system("color 02");
    printf("===LAND RENT BASE ON WIDTH===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    rent_lan *start=NULL , *end=NULL , *temp ;

    char input[50];
    char input1[50];

    while (1)
    {
        printf("Width start : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';

        printf("Width end : ");
        fgets(input1, 50, stdin);
        input1[strcspn(input1, "\n")] = '\0';

        if (floor_area_check(input) && floor_area_check(input1))
        {
            break;
        }
        else
        {
            printf("Invalid width. Please try again.");
            continue;
        }
    }

    fp = fopen("Rent_lan_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(rent_lan));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->width, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->well, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->base_price, 50, fp);
        fgets(temp->monthly_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->width[strcspn(temp->width, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->well[strcspn(temp->well, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->base_price[strcspn(temp->base_price, "\n")] = '\0';
        temp->monthly_price[strcspn(temp->monthly_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (atof(temp->width) >= atof(input) && atof(temp->width) <= atof(input1))
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Land Area: %s\n", temp->land_area);
            printf("Width: %s\n", temp->width);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Well: %s\n", temp->well);
            printf("Temperature: %s\n", temp->temperature);
            printf("Base Price: %s\n", temp->base_price);
            printf("Monthly Price: %s\n", temp->monthly_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-lan-rent-tax-rate function
void base_lan_rent_tax_rate()
{
    system("cls");
    system("color 02");
    printf("===LAND RENT BASE ON TAX RATE===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    rent_lan *start=NULL , *end=NULL , *temp ;

    char input[50];
    char input1[50];

    while (1)
    {
        printf("Tax rate start : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';

        printf("Tax rate end : ");
        fgets(input1, 50, stdin);
        input1[strcspn(input1, "\n")] = '\0';

        if (tax_rate_check(input) && tax_rate_check(input1))
        {
            break;
        }
        else
        {
            printf("Invalid tax rate. Please try again.");
            continue;
        }
    }

    fp = fopen("Rent_lan_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(rent_lan));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->width, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->well, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->base_price, 50, fp);
        fgets(temp->monthly_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->width[strcspn(temp->width, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->well[strcspn(temp->well, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->base_price[strcspn(temp->base_price, "\n")] = '\0';
        temp->monthly_price[strcspn(temp->monthly_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (atof(temp->tax_rate) >= atof(input) && atof(temp->tax_rate) <= atof(input1))
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Land Area: %s\n", temp->land_area);
            printf("Width: %s\n", temp->width);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Well: %s\n", temp->well);
            printf("Temperature: %s\n", temp->temperature);
            printf("Base Price: %s\n", temp->base_price);
            printf("Monthly Price: %s\n", temp->monthly_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-lan-rent-well function
void base_lan_rent_well()
{
    system("cls");
    system("color 02");
    printf("===LAND RENT BASE ON WELL===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    rent_lan *start=NULL , *end=NULL , *temp ;

    char input[50];

    while (1)
    {
        printf("Well (Yes , No) : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        if (yes_no_check(input))
        {
            break;
        }
        else
        {
            printf("Invalid well. Please try again.");
            continue;
        }
    }

    fp = fopen("Rent_lan_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(rent_lan));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->width, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->well, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->base_price, 50, fp);
        fgets(temp->monthly_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->width[strcspn(temp->width, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->well[strcspn(temp->well, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->base_price[strcspn(temp->base_price, "\n")] = '\0';
        temp->monthly_price[strcspn(temp->monthly_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->well , input) == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Land Area: %s\n", temp->land_area);
            printf("Width: %s\n", temp->width);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Well: %s\n", temp->well);
            printf("Temperature: %s\n", temp->temperature);
            printf("Base Price: %s\n", temp->base_price);
            printf("Monthly Price: %s\n", temp->monthly_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-lan-rent-temperature funtion
void base_lan_rent_temperature()
{
    system("cls");
    system("color 02");
    printf("===LAND RENT BASE ON TEMPERATURE===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    rent_lan *start=NULL , *end=NULL , *temp ;

    char input[50];

    while (1)
    {
        printf("Temperature (Cold , Hot , Medium) : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';
        sameall(input);

        if (temperature_check(input))
        {
            break;
        }
        else
        {
            printf("Invalid temperature. Please try again.");
            continue;
        }
    }

    fp = fopen("Rent_lan_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(rent_lan));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->width, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->well, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->base_price, 50, fp);
        fgets(temp->monthly_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->width[strcspn(temp->width, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->well[strcspn(temp->well, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->base_price[strcspn(temp->base_price, "\n")] = '\0';
        temp->monthly_price[strcspn(temp->monthly_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->temperature , input) == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Land Area: %s\n", temp->land_area);
            printf("Width: %s\n", temp->width);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Well: %s\n", temp->well);
            printf("Temperature: %s\n", temp->temperature);
            printf("Base Price: %s\n", temp->base_price);
            printf("Monthly Price: %s\n", temp->monthly_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///base-lan-rent-price function
void base_lan_rent_price()
{
    system("cls");
    system("color 02");
    printf("===LAND RENT BASE ON PRICE===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    rent_lan *start=NULL , *end=NULL , *temp ;

    char input[50];
    char input1[50];
    char input2[50];
    char input3[50];

    while (1)
    {
        printf("Base price start : ");
        fgets(input, 50, stdin);
        input[strcspn(input, "\n")] = '\0';

        printf("Base price end : ");
        fgets(input1, 50, stdin);
        input1[strcspn(input1, "\n")] = '\0';

        printf("Monthly price start : ");
        fgets(input2, 50, stdin);
        input2[strcspn(input2, "\n")] = '\0';

        printf("Monthly price end : ");
        fgets(input3, 50, stdin);
        input3[strcspn(input3, "\n")] = '\0';

        if (sell_price_check(input) && sell_price_check(input1) && sell_price_check(input2) && sell_price_check(input3))
        {
            break;
        }
        else
        {
            printf("Invalid price. Please try again.");
            continue;
        }
    }

    fp = fopen("Rent_lan_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(rent_lan));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->width, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->well, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->base_price, 50, fp);
        fgets(temp->monthly_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->width[strcspn(temp->width, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->well[strcspn(temp->well, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->base_price[strcspn(temp->base_price, "\n")] = '\0';
        temp->monthly_price[strcspn(temp->monthly_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (atof(temp->base_price) >= atof(input) && atof(temp->base_price) <= atof(input1) &&
            atof(temp->monthly_price) >= atof(input2) && atof(temp->monthly_price) <= atof(input3))
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Land Area: %s\n", temp->land_area);
            printf("Width: %s\n", temp->width);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Well: %s\n", temp->well);
            printf("Temperature: %s\n", temp->temperature);
            printf("Base Price: %s\n", temp->base_price);
            printf("Monthly Price: %s\n", temp->monthly_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///all-res-sell function
void all_res_sell()
{
    system("cls");
    system("color 02");
    printf("===ALL RESIDENTAL SELL===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    sell_res *start=NULL , *end=NULL , *temp ;

    fp = fopen("Sell_res_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_res));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->bedrooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->sell_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->bedrooms[strcspn(temp->bedrooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->sell_price[strcspn(temp->sell_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcasecmp(temp->active , "Active") == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->bedrooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Sell Price: %s\n", temp->sell_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///all-com-sell function
void all_com_sell()
{
    system("cls");
    system("color 02");
    printf("===ALL COMMERCIAL SELL===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    sell_com *start=NULL , *end=NULL , *temp ;

    fp = fopen("Sell_com_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_com));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->rooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->sell_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->rooms[strcspn(temp->rooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->sell_price[strcspn(temp->sell_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcasecmp(temp->active , "Active") == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->rooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Sell Price: %s\n", temp->sell_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///all-lan-sell function
void all_lan_sell()
{
    system("cls");
    system("color 02");
    printf("===ALL LAND SELL===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    sell_lan *start=NULL , *end=NULL , *temp ;

    fp = fopen("Sell_lan_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_lan));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->width, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->well, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->sell_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->width[strcspn(temp->width, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->well[strcspn(temp->well, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->sell_price[strcspn(temp->sell_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcasecmp(temp->active , "Active") == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Land Area: %s\n", temp->land_area);
            printf("Width: %s\n", temp->width);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Well: %s\n", temp->well);
            printf("Temperature: %s\n", temp->temperature);
            printf("Sell Price: %s\n", temp->sell_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///all-res-rent function
void all_res_rent()
{
    system("cls");
    system("color 02");
    printf("===ALL RESIDENTAL RENT===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    rent_res *start=NULL , *end=NULL , *temp ;

    fp = fopen("Rent_res_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(rent_res));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->bedrooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->base_price, 50, fp);
        fgets(temp->monthly_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->bedrooms[strcspn(temp->bedrooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->base_price[strcspn(temp->base_price, "\n")] = '\0';
        temp->monthly_price[strcspn(temp->monthly_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcasecmp(temp->active , "Active") == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->bedrooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Base Price: %s\n", temp->base_price);
            printf("Monthly Price: %s\n", temp->monthly_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///all_com_rent function
void all_com_rent()
{
    system("cls");
    system("color 02");
    printf("===ALL COMMERCIAL RENT===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    rent_com *start=NULL , *end=NULL , *temp ;

    fp = fopen("Rent_com_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_com));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->rooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->base_price, 50, fp);
        fgets(temp->monthly_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->rooms[strcspn(temp->rooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->base_price[strcspn(temp->base_price, "\n")] = '\0';
        temp->monthly_price[strcspn(temp->monthly_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcasecmp(temp->active , "Active") == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Build Age: %s\n", temp->build_age);
            printf("Floor Area: %s\n", temp->floor_area);
            printf("Floor: %s\n", temp->floor);
            printf("Land Area: %s\n", temp->land_area);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Bedrooms: %s\n", temp->rooms);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Elevator: %s\n", temp->elevator);
            printf("Basement: %s\n", temp->basement);
            printf("Basement Area: %s\n", temp->basement_area);
            printf("Balcony: %s\n", temp->balcony);
            printf("Balcony Area: %s\n", temp->balcony_area);
            printf("Parkings: %s\n", temp->parkings);
            printf("Phones: %s\n", temp->phones);
            printf("Temperature: %s\n", temp->temperature);
            printf("Base Price: %s\n", temp->base_price);
            printf("Monthly Price: %s\n", temp->monthly_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///all-lan-rent function
void all_lan_rent()
{
    system("cls");
    system("color 02");
    printf("===ALL LAND RENT===\n");
    display_current_date();
    display_current_time();

    FILE *fp;
    rent_lan *start=NULL , *end=NULL , *temp ;

    fp = fopen("Rent_lan_data.txt" , "r");
    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(rent_lan));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->width, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->well, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->base_price, 50, fp);
        fgets(temp->monthly_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->width[strcspn(temp->width, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->well[strcspn(temp->well, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->base_price[strcspn(temp->base_price, "\n")] = '\0';
        temp->monthly_price[strcspn(temp->monthly_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    temp = start;
    int counter = 0 , i = 0;

    for(int j=0 ; j<check ; j++)
    {
        if (strcasecmp(temp->active , "Active") == 0)
        {
            i++;
            counter++;
            printf("Property Number : %d\n" , i);
            printf("Code: %s\n", temp->code);
            printf("District: %s\n", temp->district);
            printf("Address: %s\n", temp->address);
            printf("Location: %s\n", temp->location);
            printf("Type: %s\n", temp->type);
            printf("Land Area: %s\n", temp->land_area);
            printf("Width: %s\n", temp->width);
            printf("Owner Phone Number: %s\n", temp->owner_phone_number);
            printf("Tax Rate: %s\n", temp->tax_rate);
            printf("Well: %s\n", temp->well);
            printf("Temperature: %s\n", temp->temperature);
            printf("Base Price: %s\n", temp->base_price);
            printf("Monthly Price: %s\n", temp->monthly_price);
            printf("Date: %s\n", temp->date);
            printf("Userin: %s\n", temp->userin);
            printf("\n");
        }

        temp = temp->next;
    }
    fclose(fp);
    if (counter == 0)
    {
        printf("No match found!\n");
    }
    printf("Press any key to continue!");
    getch();
}
///property-counter function
void property_counter()
{
    system("cls");
    system("color 02");
    printf("===PROPERTY COUNTER===\n");
    display_current_date();
    display_current_time();

    printf("Residental Properties For Sell : %d\n" , counter_sell_residental()-1);
    printf("Commercial Properties For Sell : %d\n" , counter_sell_commercial()-1);
    printf("Land Properties For Sell : %d\n" , counter_sell_land()-1);
    printf("Residental Properties For Rent : %d\n" , counter_rent_residental()-1);
    printf("Commercial Properties For Rent : %d\n" , counter_rent_commercial()-1);
    printf("Land Properties For Rent : %d\n" , counter_rent_land()-1);

    printf("\nPress anykey to continue : ");
    getch();
}
///counter-sell-res function
int counter_sell_residental()
{
    FILE *fp;
    int counter_sell_res = 0;

    sell_res *start=NULL , *end=NULL , *temp ;

    fp = fopen("Sell_res_data.txt" , "r");

    while(!feof(fp))
    {
        counter_sell_res++;
        temp = malloc(sizeof(sell_res));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->bedrooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->sell_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->bedrooms[strcspn(temp->bedrooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->sell_price[strcspn(temp->sell_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }
    }
    fclose(fp);
    temp = start;
    while (temp != NULL)
    {
        sell_res *temper = temp;
        temp = temp->next;
        free(temper);
    }
    return counter_sell_res;
}
///counter-sell-commercial function
int counter_sell_commercial()
{
    FILE *fp;
    int counter_sell_com = 0;

    sell_com *start2=NULL , *end2=NULL , *temp2 ;

    fp = fopen("Sell_com_data.txt" , "r");

    while(!feof(fp))
    {
        counter_sell_com++;
        temp2 = malloc(sizeof(sell_com));
        fgets(temp2->code, 50, fp);
        fgets(temp2->district, 50, fp);
        fgets(temp2->address, 500, fp);
        fgets(temp2->location, 50, fp);
        fgets(temp2->type, 50, fp);
        fgets(temp2->build_age, 50, fp);
        fgets(temp2->floor_area, 50, fp);
        fgets(temp2->floor, 50, fp);
        fgets(temp2->land_area, 50, fp);
        fgets(temp2->owner_phone_number, 50, fp);
        fgets(temp2->rooms, 50, fp);
        fgets(temp2->tax_rate, 50, fp);
        fgets(temp2->elevator, 50, fp);
        fgets(temp2->basement, 50, fp);
        fgets(temp2->basement_area, 50, fp);
        fgets(temp2->balcony, 50, fp);
        fgets(temp2->balcony_area, 50, fp);
        fgets(temp2->parkings, 50, fp);
        fgets(temp2->phones, 50, fp);
        fgets(temp2->temperature, 50, fp);
        fgets(temp2->sell_price, 50, fp);
        fgets(temp2->date, 50, fp);
        fgets(temp2->userin, 50, fp);
        fgets(temp2->active, 50, fp);


        temp2->code[strcspn(temp2->code, "\n")] = '\0';
        temp2->district[strcspn(temp2->district, "\n")] = '\0';
        temp2->address[strcspn(temp2->address, "\n")] = '\0';
        temp2->location[strcspn(temp2->location, "\n")] = '\0';
        temp2->type[strcspn(temp2->type, "\n")] = '\0';
        temp2->build_age[strcspn(temp2->build_age, "\n")] = '\0';
        temp2->floor_area[strcspn(temp2->floor_area, "\n")] = '\0';
        temp2->floor[strcspn(temp2->floor, "\n")] = '\0';
        temp2->land_area[strcspn(temp2->land_area, "\n")] = '\0';
        temp2->owner_phone_number[strcspn(temp2->owner_phone_number, "\n")] = '\0';
        temp2->rooms[strcspn(temp2->rooms, "\n")] = '\0';
        temp2->tax_rate[strcspn(temp2->tax_rate, "\n")] = '\0';
        temp2->elevator[strcspn(temp2->elevator, "\n")] = '\0';
        temp2->basement[strcspn(temp2->basement, "\n")] = '\0';
        temp2->basement_area[strcspn(temp2->basement_area, "\n")] = '\0';
        temp2->balcony[strcspn(temp2->balcony, "\n")] = '\0';
        temp2->balcony_area[strcspn(temp2->balcony_area, "\n")] = '\0';
        temp2->parkings[strcspn(temp2->parkings, "\n")] = '\0';
        temp2->phones[strcspn(temp2->phones, "\n")] = '\0';
        temp2->temperature[strcspn(temp2->temperature, "\n")] = '\0';
        temp2->sell_price[strcspn(temp2->sell_price, "\n")] = '\0';
        temp2->date[strcspn(temp2->date, "\n")] = '\0';
        temp2->userin[strcspn(temp2->userin, "\n")] = '\0';
        temp2->active[strcspn(temp2->active, "\n")] = '\0';

        temp2->next = NULL;

        if(start2 == NULL)
        {
            start2 = temp2 ;
            end2 = start2 ;
        }
        else
        {
            end2->next = temp2 ;
            end2 = temp2 ;
        }
    }
    fclose(fp);
    temp2 = start2;
    while (temp2 != NULL)
    {
        sell_com *temper2 = temp2;
        temp2 = temp2->next;
        free(temper2);
    }
    return counter_sell_com;
}
///counter-sell-land function
int counter_sell_land()
{
    FILE *fp;
    int counter_sell_lan = 0;

    sell_lan *start3=NULL , *end3=NULL , *temp3 ;

    fp = fopen("Sell_lan_data.txt" , "r");

    while(!feof(fp))
    {
        counter_sell_lan++;
        temp3 = malloc(sizeof(sell_lan));
        fgets(temp3->code, 50, fp);
        fgets(temp3->district, 50, fp);
        fgets(temp3->address, 500, fp);
        fgets(temp3->location, 50, fp);
        fgets(temp3->type, 50, fp);
        fgets(temp3->land_area, 50, fp);
        fgets(temp3->width, 50, fp);
        fgets(temp3->owner_phone_number, 50, fp);
        fgets(temp3->tax_rate, 50, fp);
        fgets(temp3->well, 50, fp);
        fgets(temp3->temperature, 50, fp);
        fgets(temp3->sell_price, 50, fp);
        fgets(temp3->date, 50, fp);
        fgets(temp3->userin, 50, fp);
        fgets(temp3->active, 50, fp);


        temp3->code[strcspn(temp3->code, "\n")] = '\0';
        temp3->district[strcspn(temp3->district, "\n")] = '\0';
        temp3->address[strcspn(temp3->address, "\n")] = '\0';
        temp3->location[strcspn(temp3->location, "\n")] = '\0';
        temp3->type[strcspn(temp3->type, "\n")] = '\0';
        temp3->land_area[strcspn(temp3->land_area, "\n")] = '\0';
        temp3->width[strcspn(temp3->width, "\n")] = '\0';
        temp3->owner_phone_number[strcspn(temp3->owner_phone_number, "\n")] = '\0';
        temp3->tax_rate[strcspn(temp3->tax_rate, "\n")] = '\0';
        temp3->well[strcspn(temp3->well, "\n")] = '\0';
        temp3->temperature[strcspn(temp3->temperature, "\n")] = '\0';
        temp3->sell_price[strcspn(temp3->sell_price, "\n")] = '\0';
        temp3->date[strcspn(temp3->date, "\n")] = '\0';
        temp3->userin[strcspn(temp3->userin, "\n")] = '\0';
        temp3->active[strcspn(temp3->active, "\n")] = '\0';

        temp3->next = NULL;

        if(start3 == NULL)
        {
            start3 = temp3 ;
            end3 = start3 ;
        }
        else
        {
            end3->next = temp3 ;
            end3 = temp3 ;
        }
    }
    fclose(fp);
    temp3 = start3;
    while (temp3 != NULL)
    {
        sell_lan *temper3 = temp3;
        temp3 = temp3->next;
        free(temper3);
    }
    return counter_sell_lan;
}
///counter-rent-residental function
int counter_rent_residental()
{
    FILE *fp;
    int counter_rent_res = 0;

    rent_res *start4=NULL , *end4=NULL , *temp4 ;

    fp = fopen("Rent_res_data.txt" , "r");

    while(!feof(fp))
    {
        counter_rent_res++;
        temp4 = malloc(sizeof(rent_res));
        fgets(temp4->code, 50, fp);
        fgets(temp4->district, 50, fp);
        fgets(temp4->address, 500, fp);
        fgets(temp4->location, 50, fp);
        fgets(temp4->type, 50, fp);
        fgets(temp4->build_age, 50, fp);
        fgets(temp4->floor_area, 50, fp);
        fgets(temp4->floor, 50, fp);
        fgets(temp4->land_area, 50, fp);
        fgets(temp4->owner_phone_number, 50, fp);
        fgets(temp4->bedrooms, 50, fp);
        fgets(temp4->tax_rate, 50, fp);
        fgets(temp4->elevator, 50, fp);
        fgets(temp4->basement, 50, fp);
        fgets(temp4->basement_area, 50, fp);
        fgets(temp4->balcony, 50, fp);
        fgets(temp4->balcony_area, 50, fp);
        fgets(temp4->parkings, 50, fp);
        fgets(temp4->phones, 50, fp);
        fgets(temp4->temperature, 50, fp);
        fgets(temp4->base_price, 50, fp);
        fgets(temp4->monthly_price, 50, fp);
        fgets(temp4->date, 50, fp);
        fgets(temp4->userin, 50, fp);
        fgets(temp4->active, 50, fp);


        temp4->code[strcspn(temp4->code, "\n")] = '\0';
        temp4->district[strcspn(temp4->district, "\n")] = '\0';
        temp4->address[strcspn(temp4->address, "\n")] = '\0';
        temp4->location[strcspn(temp4->location, "\n")] = '\0';
        temp4->type[strcspn(temp4->type, "\n")] = '\0';
        temp4->build_age[strcspn(temp4->build_age, "\n")] = '\0';
        temp4->floor_area[strcspn(temp4->floor_area, "\n")] = '\0';
        temp4->floor[strcspn(temp4->floor, "\n")] = '\0';
        temp4->land_area[strcspn(temp4->land_area, "\n")] = '\0';
        temp4->owner_phone_number[strcspn(temp4->owner_phone_number, "\n")] = '\0';
        temp4->bedrooms[strcspn(temp4->bedrooms, "\n")] = '\0';
        temp4->tax_rate[strcspn(temp4->tax_rate, "\n")] = '\0';
        temp4->elevator[strcspn(temp4->elevator, "\n")] = '\0';
        temp4->basement[strcspn(temp4->basement, "\n")] = '\0';
        temp4->basement_area[strcspn(temp4->basement_area, "\n")] = '\0';
        temp4->balcony[strcspn(temp4->balcony, "\n")] = '\0';
        temp4->balcony_area[strcspn(temp4->balcony_area, "\n")] = '\0';
        temp4->parkings[strcspn(temp4->parkings, "\n")] = '\0';
        temp4->phones[strcspn(temp4->phones, "\n")] = '\0';
        temp4->temperature[strcspn(temp4->temperature, "\n")] = '\0';
        temp4->base_price[strcspn(temp4->base_price, "\n")] = '\0';
        temp4->monthly_price[strcspn(temp4->monthly_price, "\n")] = '\0';
        temp4->date[strcspn(temp4->date, "\n")] = '\0';
        temp4->userin[strcspn(temp4->userin, "\n")] = '\0';
        temp4->active[strcspn(temp4->active, "\n")] = '\0';

        temp4->next = NULL;

        if(start4 == NULL)
        {
            start4 = temp4 ;
            end4 = start4 ;
        }
        else
        {
            end4->next = temp4 ;
            end4 = temp4 ;
        }
    }
    fclose(fp);
    temp4 = start4;
    while (temp4 != NULL)
    {
        rent_res *temper4 = temp4;
        temp4 = temp4->next;
        free(temper4);
    }
    return counter_rent_res;
}
///counter-rent-commercial function
int counter_rent_commercial()
{
    FILE *fp;
    int counter_rent_com = 0;

    rent_com *start5=NULL , *end5=NULL , *temp5 ;

    fp = fopen("Rent_com_data.txt" , "r");

    while(!feof(fp))
    {
        counter_rent_com++;
        temp5 = malloc(sizeof(sell_com));
        fgets(temp5->code, 50, fp);
        fgets(temp5->district, 50, fp);
        fgets(temp5->address, 500, fp);
        fgets(temp5->location, 50, fp);
        fgets(temp5->type, 50, fp);
        fgets(temp5->build_age, 50, fp);
        fgets(temp5->floor_area, 50, fp);
        fgets(temp5->floor, 50, fp);
        fgets(temp5->land_area, 50, fp);
        fgets(temp5->owner_phone_number, 50, fp);
        fgets(temp5->rooms, 50, fp);
        fgets(temp5->tax_rate, 50, fp);
        fgets(temp5->elevator, 50, fp);
        fgets(temp5->basement, 50, fp);
        fgets(temp5->basement_area, 50, fp);
        fgets(temp5->balcony, 50, fp);
        fgets(temp5->balcony_area, 50, fp);
        fgets(temp5->parkings, 50, fp);
        fgets(temp5->phones, 50, fp);
        fgets(temp5->temperature, 50, fp);
        fgets(temp5->base_price, 50, fp);
        fgets(temp5->monthly_price, 50, fp);
        fgets(temp5->date, 50, fp);
        fgets(temp5->userin, 50, fp);
        fgets(temp5->active, 50, fp);


        temp5->code[strcspn(temp5->code, "\n")] = '\0';
        temp5->district[strcspn(temp5->district, "\n")] = '\0';
        temp5->address[strcspn(temp5->address, "\n")] = '\0';
        temp5->location[strcspn(temp5->location, "\n")] = '\0';
        temp5->type[strcspn(temp5->type, "\n")] = '\0';
        temp5->build_age[strcspn(temp5->build_age, "\n")] = '\0';
        temp5->floor_area[strcspn(temp5->floor_area, "\n")] = '\0';
        temp5->floor[strcspn(temp5->floor, "\n")] = '\0';
        temp5->land_area[strcspn(temp5->land_area, "\n")] = '\0';
        temp5->owner_phone_number[strcspn(temp5->owner_phone_number, "\n")] = '\0';
        temp5->rooms[strcspn(temp5->rooms, "\n")] = '\0';
        temp5->tax_rate[strcspn(temp5->tax_rate, "\n")] = '\0';
        temp5->elevator[strcspn(temp5->elevator, "\n")] = '\0';
        temp5->basement[strcspn(temp5->basement, "\n")] = '\0';
        temp5->basement_area[strcspn(temp5->basement_area, "\n")] = '\0';
        temp5->balcony[strcspn(temp5->balcony, "\n")] = '\0';
        temp5->balcony_area[strcspn(temp5->balcony_area, "\n")] = '\0';
        temp5->parkings[strcspn(temp5->parkings, "\n")] = '\0';
        temp5->phones[strcspn(temp5->phones, "\n")] = '\0';
        temp5->temperature[strcspn(temp5->temperature, "\n")] = '\0';
        temp5->base_price[strcspn(temp5->base_price, "\n")] = '\0';
        temp5->monthly_price[strcspn(temp5->monthly_price, "\n")] = '\0';
        temp5->date[strcspn(temp5->date, "\n")] = '\0';
        temp5->userin[strcspn(temp5->userin, "\n")] = '\0';
        temp5->active[strcspn(temp5->active, "\n")] = '\0';

        temp5->next = NULL;

        if(start5 == NULL)
        {
            start5 = temp5 ;
            end5 = start5 ;
        }
        else
        {
            end5->next = temp5 ;
            end5 = temp5 ;
        }
    }
    fclose(fp);
    temp5 = start5;
    while (temp5 != NULL)
    {
        rent_res *temper5 = temp5;
        temp5 = temp5->next;
        free(temper5);
    }
    return counter_rent_com;
}
///counter-rent-land function
int counter_rent_land()
{
    FILE *fp;
    int counter_rent_lan = 0;

    rent_lan *start6=NULL , *end6=NULL , *temp6 ;

    fp = fopen("Rent_lan_data.txt" , "r");

    while(!feof(fp))
    {
        counter_rent_lan++;
        temp6 = malloc(sizeof(rent_lan));
        fgets(temp6->code, 50, fp);
        fgets(temp6->district, 50, fp);
        fgets(temp6->address, 500, fp);
        fgets(temp6->location, 50, fp);
        fgets(temp6->type, 50, fp);
        fgets(temp6->land_area, 50, fp);
        fgets(temp6->width, 50, fp);
        fgets(temp6->owner_phone_number, 50, fp);
        fgets(temp6->tax_rate, 50, fp);
        fgets(temp6->well, 50, fp);
        fgets(temp6->temperature, 50, fp);
        fgets(temp6->base_price, 50, fp);
        fgets(temp6->monthly_price, 50, fp);
        fgets(temp6->date, 50, fp);
        fgets(temp6->userin, 50, fp);
        fgets(temp6->active, 50, fp);


        temp6->code[strcspn(temp6->code, "\n")] = '\0';
        temp6->district[strcspn(temp6->district, "\n")] = '\0';
        temp6->address[strcspn(temp6->address, "\n")] = '\0';
        temp6->location[strcspn(temp6->location, "\n")] = '\0';
        temp6->type[strcspn(temp6->type, "\n")] = '\0';
        temp6->land_area[strcspn(temp6->land_area, "\n")] = '\0';
        temp6->width[strcspn(temp6->width, "\n")] = '\0';
        temp6->owner_phone_number[strcspn(temp6->owner_phone_number, "\n")] = '\0';
        temp6->tax_rate[strcspn(temp6->tax_rate, "\n")] = '\0';
        temp6->well[strcspn(temp6->well, "\n")] = '\0';
        temp6->temperature[strcspn(temp6->temperature, "\n")] = '\0';
        temp6->base_price[strcspn(temp6->base_price, "\n")] = '\0';
        temp6->monthly_price[strcspn(temp6->monthly_price, "\n")] = '\0';
        temp6->date[strcspn(temp6->date, "\n")] = '\0';
        temp6->userin[strcspn(temp6->userin, "\n")] = '\0';
        temp6->active[strcspn(temp6->active, "\n")] = '\0';

        temp6->next = NULL;

        if(start6 == NULL)
        {
            start6 = temp6 ;
            end6 = start6 ;
        }
        else
        {
            end6->next = temp6 ;
            end6 = temp6 ;
        }
    }
    fclose(fp);
    temp6 = start6;
    while (temp6 != NULL)
    {
        rent_res *temper6 = temp6;
        temp6 = temp6->next;
        free(temper6);
    }
    return counter_rent_lan;
}
///deleting-information function
void deleting_information()
{
    system("cls");
    system("color 02");
    printf("===DELETING INFORMATION===\n");
    display_current_date();
    display_current_time();

    char coder1[50];
    printf("Please choose the code you want to delete from the data : ");
    fgets(coder1, 49, stdin);
    coder1[strcspn(coder1, "\n")] = '\0';

    delete_sell_residental(coder1);
    delete_sell_commercial(coder1);
    delete_sell_land(coder1);
    delete_rent_residental(coder1);
    delete_rent_commercial(coder1);
    delete_rent_land(coder1);

    printf("Delete completed!\n");
    sleep(3);
}
///delete-sell-residental function
void delete_sell_residental(char *input_coder1)
{
    FILE *fp;
    sell_res *start=NULL , *end=NULL , *temp;
    fp = fopen("Sell_res_data.txt" , "r");

    int size;
    if (fp != NULL)
    {
        fseek (fp, 0, SEEK_END);
        size = ftell(fp);
        rewind(fp);

        if (size == 0)
        {
            return 0;
        }
    }

    int check = 0;
    while(!feof(fp))
    {
        temp = malloc(sizeof(sell_res));
        fgets(temp->code, 50, fp);
        fgets(temp->district, 50, fp);
        fgets(temp->address, 500, fp);
        fgets(temp->location, 50, fp);
        fgets(temp->type, 50, fp);
        fgets(temp->build_age, 50, fp);
        fgets(temp->floor_area, 50, fp);
        fgets(temp->floor, 50, fp);
        fgets(temp->land_area, 50, fp);
        fgets(temp->owner_phone_number, 50, fp);
        fgets(temp->bedrooms, 50, fp);
        fgets(temp->tax_rate, 50, fp);
        fgets(temp->elevator, 50, fp);
        fgets(temp->basement, 50, fp);
        fgets(temp->basement_area, 50, fp);
        fgets(temp->balcony, 50, fp);
        fgets(temp->balcony_area, 50, fp);
        fgets(temp->parkings, 50, fp);
        fgets(temp->phones, 50, fp);
        fgets(temp->temperature, 50, fp);
        fgets(temp->sell_price, 50, fp);
        fgets(temp->date, 50, fp);
        fgets(temp->userin, 50, fp);
        fgets(temp->active, 50, fp);


        temp->code[strcspn(temp->code, "\n")] = '\0';
        temp->district[strcspn(temp->district, "\n")] = '\0';
        temp->address[strcspn(temp->address, "\n")] = '\0';
        temp->location[strcspn(temp->location, "\n")] = '\0';
        temp->type[strcspn(temp->type, "\n")] = '\0';
        temp->build_age[strcspn(temp->build_age, "\n")] = '\0';
        temp->floor_area[strcspn(temp->floor_area, "\n")] = '\0';
        temp->floor[strcspn(temp->floor, "\n")] = '\0';
        temp->land_area[strcspn(temp->land_area, "\n")] = '\0';
        temp->owner_phone_number[strcspn(temp->owner_phone_number, "\n")] = '\0';
        temp->bedrooms[strcspn(temp->bedrooms, "\n")] = '\0';
        temp->tax_rate[strcspn(temp->tax_rate, "\n")] = '\0';
        temp->elevator[strcspn(temp->elevator, "\n")] = '\0';
        temp->basement[strcspn(temp->basement, "\n")] = '\0';
        temp->basement_area[strcspn(temp->basement_area, "\n")] = '\0';
        temp->balcony[strcspn(temp->balcony, "\n")] = '\0';
        temp->balcony_area[strcspn(temp->balcony_area, "\n")] = '\0';
        temp->parkings[strcspn(temp->parkings, "\n")] = '\0';
        temp->phones[strcspn(temp->phones, "\n")] = '\0';
        temp->temperature[strcspn(temp->temperature, "\n")] = '\0';
        temp->sell_price[strcspn(temp->sell_price, "\n")] = '\0';
        temp->date[strcspn(temp->date, "\n")] = '\0';
        temp->userin[strcspn(temp->userin, "\n")] = '\0';
        temp->active[strcspn(temp->active, "\n")] = '\0';

        temp->next = NULL;

        if(start == NULL)
        {
            start = temp ;
            end = start ;
        }
        else
        {
            end->next = temp ;
            end = temp ;
        }

        check++;
    }
    fclose(fp);

    fp = fopen("Sell_res_data.txt" , "w+");
    temp = start;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp->code , input_coder1) == 0)
        {
            strcpy(temp->active , "Inactive");
        }
        if ( j == 0)
        {
            fprintf(fp, "%s\n", temp->code);
            fprintf(fp, "%s\n", temp->district);
            fprintf(fp, "%s\n", temp->address);
            fprintf(fp, "%s\n", temp->location);
            fprintf(fp, "%s\n", temp->type);
            fprintf(fp, "%s\n", temp->build_age);
            fprintf(fp, "%s\n", temp->floor_area);
            fprintf(fp, "%s\n", temp->floor);
            fprintf(fp, "%s\n", temp->land_area);
            fprintf(fp, "%s\n", temp->owner_phone_number);
            fprintf(fp, "%s\n", temp->bedrooms);
            fprintf(fp, "%s\n", temp->tax_rate);
            fprintf(fp, "%s\n", temp->elevator);
            fprintf(fp, "%s\n", temp->basement);
            fprintf(fp, "%s\n", temp->basement_area);
            fprintf(fp, "%s\n", temp->balcony);
            fprintf(fp, "%s\n", temp->balcony_area);
            fprintf(fp, "%s\n", temp->parkings);
            fprintf(fp, "%s\n", temp->phones);
            fprintf(fp, "%s\n", temp->temperature);
            fprintf(fp, "%s\n", temp->sell_price);
            fprintf(fp, "%s\n", temp->date);
            fprintf(fp, "%s\n", temp->userin);
            fprintf(fp, "%s", temp->active);
        }
        else
        {
            fprintf(fp, "\n%s", temp->code);
            fprintf(fp, "\n%s", temp->district);
            fprintf(fp, "\n%s", temp->address);
            fprintf(fp, "\n%s", temp->location);
            fprintf(fp, "\n%s", temp->type);
            fprintf(fp, "\n%s", temp->build_age);
            fprintf(fp, "\n%s", temp->floor_area);
            fprintf(fp, "\n%s", temp->floor);
            fprintf(fp, "\n%s", temp->land_area);
            fprintf(fp, "\n%s", temp->owner_phone_number);
            fprintf(fp, "\n%s", temp->bedrooms);
            fprintf(fp, "\n%s", temp->tax_rate);
            fprintf(fp, "\n%s", temp->elevator);
            fprintf(fp, "\n%s", temp->basement);
            fprintf(fp, "\n%s", temp->basement_area);
            fprintf(fp, "\n%s", temp->balcony);
            fprintf(fp, "\n%s", temp->balcony_area);
            fprintf(fp, "\n%s", temp->parkings);
            fprintf(fp, "\n%s", temp->phones);
            fprintf(fp, "\n%s", temp->temperature);
            fprintf(fp, "\n%s", temp->sell_price);
            fprintf(fp, "\n%s", temp->date);
            fprintf(fp, "\n%s", temp->userin);
            fprintf(fp, "\n%s", temp->active);
        }

        temp = temp->next;
    }
    fclose(fp);
    temp = start;
    while (temp != NULL)
    {
        rent_res *temper = temp;
        temp = temp->next;
        free(temper);
    }
}
///delete-sell-commercial function
void delete_sell_commercial(char *input_coder1)
{
    FILE *fp;
    sell_com *start2=NULL , *end2=NULL , *temp2;

    fp = fopen("Sell_com_data.txt" , "r");
    int check = 0;

    int size;
    if (fp != NULL)
    {
        fseek (fp, 0, SEEK_END);
        size = ftell(fp);
        rewind(fp);

        if (size == 0)
        {
            return 0;
        }
    }

    while(!feof(fp))
    {
        temp2 = malloc(sizeof(sell_com));
        fgets(temp2->code, 50, fp);
        fgets(temp2->district, 50, fp);
        fgets(temp2->address, 500, fp);
        fgets(temp2->location, 50, fp);
        fgets(temp2->type, 50, fp);
        fgets(temp2->build_age, 50, fp);
        fgets(temp2->floor_area, 50, fp);
        fgets(temp2->floor, 50, fp);
        fgets(temp2->land_area, 50, fp);
        fgets(temp2->owner_phone_number, 50, fp);
        fgets(temp2->rooms, 50, fp);
        fgets(temp2->tax_rate, 50, fp);
        fgets(temp2->elevator, 50, fp);
        fgets(temp2->basement, 50, fp);
        fgets(temp2->basement_area, 50, fp);
        fgets(temp2->balcony, 50, fp);
        fgets(temp2->balcony_area, 50, fp);
        fgets(temp2->parkings, 50, fp);
        fgets(temp2->phones, 50, fp);
        fgets(temp2->temperature, 50, fp);
        fgets(temp2->sell_price, 50, fp);
        fgets(temp2->date, 50, fp);
        fgets(temp2->userin, 50, fp);
        fgets(temp2->active, 50, fp);


        temp2->code[strcspn(temp2->code, "\n")] = '\0';
        temp2->district[strcspn(temp2->district, "\n")] = '\0';
        temp2->address[strcspn(temp2->address, "\n")] = '\0';
        temp2->location[strcspn(temp2->location, "\n")] = '\0';
        temp2->type[strcspn(temp2->type, "\n")] = '\0';
        temp2->build_age[strcspn(temp2->build_age, "\n")] = '\0';
        temp2->floor_area[strcspn(temp2->floor_area, "\n")] = '\0';
        temp2->floor[strcspn(temp2->floor, "\n")] = '\0';
        temp2->land_area[strcspn(temp2->land_area, "\n")] = '\0';
        temp2->owner_phone_number[strcspn(temp2->owner_phone_number, "\n")] = '\0';
        temp2->rooms[strcspn(temp2->rooms, "\n")] = '\0';
        temp2->tax_rate[strcspn(temp2->tax_rate, "\n")] = '\0';
        temp2->elevator[strcspn(temp2->elevator, "\n")] = '\0';
        temp2->basement[strcspn(temp2->basement, "\n")] = '\0';
        temp2->basement_area[strcspn(temp2->basement_area, "\n")] = '\0';
        temp2->balcony[strcspn(temp2->balcony, "\n")] = '\0';
        temp2->balcony_area[strcspn(temp2->balcony_area, "\n")] = '\0';
        temp2->parkings[strcspn(temp2->parkings, "\n")] = '\0';
        temp2->phones[strcspn(temp2->phones, "\n")] = '\0';
        temp2->temperature[strcspn(temp2->temperature, "\n")] = '\0';
        temp2->sell_price[strcspn(temp2->sell_price, "\n")] = '\0';
        temp2->date[strcspn(temp2->date, "\n")] = '\0';
        temp2->userin[strcspn(temp2->userin, "\n")] = '\0';
        temp2->active[strcspn(temp2->active, "\n")] = '\0';

        temp2->next = NULL;

        if(start2 == NULL)
        {
            start2 = temp2 ;
            end2 = start2 ;
        }
        else
        {
            end2->next = temp2 ;
            end2 = temp2 ;
        }

        check++;
    }
    fclose(fp);

    fp = fopen("Sell_com_data.txt" , "w+");
    temp2 = start2;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp2->code , input_coder1) == 0)
        {
            strcpy(temp2->active , "Inactive");
        }
        if (j == 0)
        {
            fprintf(fp, "%s\n", temp2->code);
            fprintf(fp, "%s\n", temp2->district);
            fprintf(fp, "%s\n", temp2->address);
            fprintf(fp, "%s\n", temp2->location);
            fprintf(fp, "%s\n", temp2->type);
            fprintf(fp, "%s\n", temp2->build_age);
            fprintf(fp, "%s\n", temp2->floor_area);
            fprintf(fp, "%s\n", temp2->floor);
            fprintf(fp, "%s\n", temp2->land_area);
            fprintf(fp, "%s\n", temp2->owner_phone_number);
            fprintf(fp, "%s\n", temp2->rooms);
            fprintf(fp, "%s\n", temp2->tax_rate);
            fprintf(fp, "%s\n", temp2->elevator);
            fprintf(fp, "%s\n", temp2->basement);
            fprintf(fp, "%s\n", temp2->basement_area);
            fprintf(fp, "%s\n", temp2->balcony);
            fprintf(fp, "%s\n", temp2->balcony_area);
            fprintf(fp, "%s\n", temp2->parkings);
            fprintf(fp, "%s\n", temp2->phones);
            fprintf(fp, "%s\n", temp2->temperature);
            fprintf(fp, "%s\n", temp2->sell_price);
            fprintf(fp, "%s\n", temp2->date);
            fprintf(fp, "%s\n", temp2->userin);
            fprintf(fp, "%s", temp2->active);
        }
        else
        {
            fprintf(fp, "\n%s", temp2->code);
            fprintf(fp, "\n%s", temp2->district);
            fprintf(fp, "\n%s", temp2->address);
            fprintf(fp, "\n%s", temp2->location);
            fprintf(fp, "\n%s", temp2->type);
            fprintf(fp, "\n%s", temp2->build_age);
            fprintf(fp, "\n%s", temp2->floor_area);
            fprintf(fp, "\n%s", temp2->floor);
            fprintf(fp, "\n%s", temp2->land_area);
            fprintf(fp, "\n%s", temp2->owner_phone_number);
            fprintf(fp, "\n%s", temp2->rooms);
            fprintf(fp, "\n%s", temp2->tax_rate);
            fprintf(fp, "\n%s", temp2->elevator);
            fprintf(fp, "\n%s", temp2->basement);
            fprintf(fp, "\n%s", temp2->basement_area);
            fprintf(fp, "\n%s", temp2->balcony);
            fprintf(fp, "\n%s", temp2->balcony_area);
            fprintf(fp, "\n%s", temp2->parkings);
            fprintf(fp, "\n%s", temp2->phones);
            fprintf(fp, "\n%s", temp2->temperature);
            fprintf(fp, "\n%s", temp2->sell_price);
            fprintf(fp, "\n%s", temp2->date);
            fprintf(fp, "\n%s", temp2->userin);
            fprintf(fp, "\n%s", temp2->active);
        }

        temp2 = temp2->next;
    }
    fclose(fp);
    temp2 = start2;
    while (temp2 != NULL)
    {
        rent_res *temper2 = temp2;
        temp2 = temp2->next;
        free(temper2);
    }
}
///delete-sell-land function
void delete_sell_land(char *input_coder1)
{
    FILE *fp;
    sell_lan *start3=NULL , *end3=NULL , *temp3;

    fp = fopen("Sell_lan_data.txt" , "r");
    int check = 0;

    int size;
    if (fp != NULL)
    {
        fseek (fp, 0, SEEK_END);
        size = ftell(fp);
        rewind(fp);

        if (size == 0)
        {
            return 0;
        }
    }

    while(!feof(fp))
    {
        temp3 = malloc(sizeof(sell_lan));
        fgets(temp3->code, 50, fp);
        fgets(temp3->district, 50, fp);
        fgets(temp3->address, 500, fp);
        fgets(temp3->location, 50, fp);
        fgets(temp3->type, 50, fp);
        fgets(temp3->land_area, 50, fp);
        fgets(temp3->width, 50, fp);
        fgets(temp3->owner_phone_number, 50, fp);
        fgets(temp3->tax_rate, 50, fp);
        fgets(temp3->well, 50, fp);
        fgets(temp3->temperature, 50, fp);
        fgets(temp3->sell_price, 50, fp);
        fgets(temp3->date, 50, fp);
        fgets(temp3->userin, 50, fp);
        fgets(temp3->active, 50, fp);


        temp3->code[strcspn(temp3->code, "\n")] = '\0';
        temp3->district[strcspn(temp3->district, "\n")] = '\0';
        temp3->address[strcspn(temp3->address, "\n")] = '\0';
        temp3->location[strcspn(temp3->location, "\n")] = '\0';
        temp3->type[strcspn(temp3->type, "\n")] = '\0';
        temp3->land_area[strcspn(temp3->land_area, "\n")] = '\0';
        temp3->width[strcspn(temp3->width, "\n")] = '\0';
        temp3->owner_phone_number[strcspn(temp3->owner_phone_number, "\n")] = '\0';
        temp3->tax_rate[strcspn(temp3->tax_rate, "\n")] = '\0';
        temp3->well[strcspn(temp3->well, "\n")] = '\0';
        temp3->temperature[strcspn(temp3->temperature, "\n")] = '\0';
        temp3->sell_price[strcspn(temp3->sell_price, "\n")] = '\0';
        temp3->date[strcspn(temp3->date, "\n")] = '\0';
        temp3->userin[strcspn(temp3->userin, "\n")] = '\0';
        temp3->active[strcspn(temp3->active, "\n")] = '\0';

        temp3->next = NULL;

        if(start3 == NULL)
        {
            start3 = temp3 ;
            end3 = start3 ;
        }
        else
        {
            end3->next = temp3 ;
            end3 = temp3 ;
        }

        check++;
    }
    fclose(fp);
    fp = fopen("Sell_lan_data.txt" , "w+");
    temp3 = start3;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp3->code , input_coder1) == 0)
        {
            strcpy(temp3->active , "Inactive");
        }
        if (j == 0)
        {
            fprintf(fp, "%s\n", temp3->code);
            fprintf(fp, "%s\n", temp3->district);
            fprintf(fp, "%s\n", temp3->address);
            fprintf(fp, "%s\n", temp3->location);
            fprintf(fp, "%s\n", temp3->type);
            fprintf(fp, "%s\n", temp3->land_area);
            fprintf(fp, "%s\n", temp3->width);
            fprintf(fp, "%s\n", temp3->owner_phone_number);
            fprintf(fp, "%s\n", temp3->tax_rate);
            fprintf(fp, "%s\n", temp3->well);
            fprintf(fp, "%s\n", temp3->temperature);
            fprintf(fp, "%s\n", temp3->sell_price);
            fprintf(fp, "%s\n", temp3->date);
            fprintf(fp, "%s\n", temp3->userin);
            fprintf(fp, "%s", temp3->active);
        }
        else
        {
            fprintf(fp, "\n%s", temp3->code);
            fprintf(fp, "\n%s", temp3->district);
            fprintf(fp, "\n%s", temp3->address);
            fprintf(fp, "\n%s", temp3->location);
            fprintf(fp, "\n%s", temp3->type);
            fprintf(fp, "\n%s", temp3->land_area);
            fprintf(fp, "\n%s", temp3->width);
            fprintf(fp, "\n%s", temp3->owner_phone_number);
            fprintf(fp, "\n%s", temp3->tax_rate);
            fprintf(fp, "\n%s", temp3->well);
            fprintf(fp, "\n%s", temp3->temperature);
            fprintf(fp, "\n%s", temp3->sell_price);
            fprintf(fp, "\n%s", temp3->date);
            fprintf(fp, "\n%s", temp3->userin);
            fprintf(fp, "\n%s", temp3->active);
        }

        temp3 = temp3->next;
    }
    fclose(fp);
    temp3 = start3;
    while (temp3 != NULL)
    {
        rent_res *temper3 = temp3;
        temp3 = temp3->next;
        free(temper3);
    }

}
///delete-rent-residental
void delete_rent_residental(char *input_coder1)
{
    FILE *fp;
    rent_res *start4=NULL , *end4=NULL , *temp4;

    fp = fopen("Rent_res_data.txt" , "r");
    int check = 0;

    int size;
    if (fp != NULL)
    {
        fseek (fp, 0, SEEK_END);
        size = ftell(fp);
        rewind(fp);

        if (size == 0)
        {
            return 0;
        }
    }

    while(!feof(fp))
    {
        temp4 = malloc(sizeof(rent_res));
        fgets(temp4->code, 50, fp);
        fgets(temp4->district, 50, fp);
        fgets(temp4->address, 500, fp);
        fgets(temp4->location, 50, fp);
        fgets(temp4->type, 50, fp);
        fgets(temp4->build_age, 50, fp);
        fgets(temp4->floor_area, 50, fp);
        fgets(temp4->floor, 50, fp);
        fgets(temp4->land_area, 50, fp);
        fgets(temp4->owner_phone_number, 50, fp);
        fgets(temp4->bedrooms, 50, fp);
        fgets(temp4->tax_rate, 50, fp);
        fgets(temp4->elevator, 50, fp);
        fgets(temp4->basement, 50, fp);
        fgets(temp4->basement_area, 50, fp);
        fgets(temp4->balcony, 50, fp);
        fgets(temp4->balcony_area, 50, fp);
        fgets(temp4->parkings, 50, fp);
        fgets(temp4->phones, 50, fp);
        fgets(temp4->temperature, 50, fp);
        fgets(temp4->base_price, 50, fp);
        fgets(temp4->monthly_price, 50, fp);
        fgets(temp4->date, 50, fp);
        fgets(temp4->userin, 50, fp);
        fgets(temp4->active, 50, fp);


        temp4->code[strcspn(temp4->code, "\n")] = '\0';
        temp4->district[strcspn(temp4->district, "\n")] = '\0';
        temp4->address[strcspn(temp4->address, "\n")] = '\0';
        temp4->location[strcspn(temp4->location, "\n")] = '\0';
        temp4->type[strcspn(temp4->type, "\n")] = '\0';
        temp4->build_age[strcspn(temp4->build_age, "\n")] = '\0';
        temp4->floor_area[strcspn(temp4->floor_area, "\n")] = '\0';
        temp4->floor[strcspn(temp4->floor, "\n")] = '\0';
        temp4->land_area[strcspn(temp4->land_area, "\n")] = '\0';
        temp4->owner_phone_number[strcspn(temp4->owner_phone_number, "\n")] = '\0';
        temp4->bedrooms[strcspn(temp4->bedrooms, "\n")] = '\0';
        temp4->tax_rate[strcspn(temp4->tax_rate, "\n")] = '\0';
        temp4->elevator[strcspn(temp4->elevator, "\n")] = '\0';
        temp4->basement[strcspn(temp4->basement, "\n")] = '\0';
        temp4->basement_area[strcspn(temp4->basement_area, "\n")] = '\0';
        temp4->balcony[strcspn(temp4->balcony, "\n")] = '\0';
        temp4->balcony_area[strcspn(temp4->balcony_area, "\n")] = '\0';
        temp4->parkings[strcspn(temp4->parkings, "\n")] = '\0';
        temp4->phones[strcspn(temp4->phones, "\n")] = '\0';
        temp4->temperature[strcspn(temp4->temperature, "\n")] = '\0';
        temp4->base_price[strcspn(temp4->base_price, "\n")] = '\0';
        temp4->monthly_price[strcspn(temp4->monthly_price, "\n")] = '\0';
        temp4->date[strcspn(temp4->date, "\n")] = '\0';
        temp4->userin[strcspn(temp4->userin, "\n")] = '\0';
        temp4->active[strcspn(temp4->active, "\n")] = '\0';

        temp4->next = NULL;

        if(start4 == NULL)
        {
            start4 = temp4 ;
            end4 = start4 ;
        }
        else
        {
            end4->next = temp4 ;
            end4 = temp4 ;
        }

        check++;
    }
    fclose(fp);
    fp = fopen("Rent_res_data.txt" , "w+");
    temp4 = start4;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp4->code , input_coder1) == 0)
        {
            strcpy(temp4->active , "Inactive");
        }
        if (j == 0)
        {
            fprintf(fp, "%s\n", temp4->code);
            fprintf(fp, "%s\n", temp4->district);
            fprintf(fp, "%s\n", temp4->address);
            fprintf(fp, "%s\n", temp4->location);
            fprintf(fp, "%s\n", temp4->type);
            fprintf(fp, "%s\n", temp4->build_age);
            fprintf(fp, "%s\n", temp4->floor_area);
            fprintf(fp, "%s\n", temp4->floor);
            fprintf(fp, "%s\n", temp4->land_area);
            fprintf(fp, "%s\n", temp4->owner_phone_number);
            fprintf(fp, "%s\n", temp4->bedrooms);
            fprintf(fp, "%s\n", temp4->tax_rate);
            fprintf(fp, "%s\n", temp4->elevator);
            fprintf(fp, "%s\n", temp4->basement);
            fprintf(fp, "%s\n", temp4->basement_area);
            fprintf(fp, "%s\n", temp4->balcony);
            fprintf(fp, "%s\n", temp4->balcony_area);
            fprintf(fp, "%s\n", temp4->parkings);
            fprintf(fp, "%s\n", temp4->phones);
            fprintf(fp, "%s\n", temp4->temperature);
            fprintf(fp, "%s\n", temp4->base_price);
            fprintf(fp, "%s\n", temp4->monthly_price);
            fprintf(fp, "%s\n", temp4->date);
            fprintf(fp, "%s\n", temp4->userin);
            fprintf(fp, "%s", temp4->active);
        }
        else
        {
            fprintf(fp, "\n%s", temp4->code);
            fprintf(fp, "\n%s", temp4->district);
            fprintf(fp, "\n%s", temp4->address);
            fprintf(fp, "\n%s", temp4->location);
            fprintf(fp, "\n%s", temp4->type);
            fprintf(fp, "\n%s", temp4->build_age);
            fprintf(fp, "\n%s", temp4->floor_area);
            fprintf(fp, "\n%s", temp4->floor);
            fprintf(fp, "\n%s", temp4->land_area);
            fprintf(fp, "\n%s", temp4->owner_phone_number);
            fprintf(fp, "\n%s", temp4->bedrooms);
            fprintf(fp, "\n%s", temp4->tax_rate);
            fprintf(fp, "\n%s", temp4->elevator);
            fprintf(fp, "\n%s", temp4->basement);
            fprintf(fp, "\n%s", temp4->basement_area);
            fprintf(fp, "\n%s", temp4->balcony);
            fprintf(fp, "\n%s", temp4->balcony_area);
            fprintf(fp, "\n%s", temp4->parkings);
            fprintf(fp, "\n%s", temp4->phones);
            fprintf(fp, "\n%s", temp4->temperature);
            fprintf(fp, "\n%s", temp4->base_price);
            fprintf(fp, "\n%s", temp4->monthly_price);
            fprintf(fp, "\n%s", temp4->date);
            fprintf(fp, "\n%s", temp4->userin);
            fprintf(fp, "\n%s", temp4->active);
        }

        temp4 = temp4->next;
    }
    fclose(fp);
    temp4 = start4;
    while (temp4 != NULL)
    {
        rent_res *temper4 = temp4;
        temp4 = temp4->next;
        free(temper4);
    }
}
///delete-rent-commercial function
void delete_rent_commercial(char *input_coder1)
{
    FILE *fp;
    rent_com *start5=NULL , *end5=NULL , *temp5;

    fp = fopen("Rent_com_data.txt" , "r");
    int check = 0;

    int size;
    if (fp != NULL)
    {
        fseek (fp, 0, SEEK_END);
        size = ftell(fp);
        rewind(fp);

        if (size == 0)
        {
            return 0;
        }
    }

    while(!feof(fp))
    {
        temp5 = malloc(sizeof(rent_com));
        fgets(temp5->code, 50, fp);
        fgets(temp5->district, 50, fp);
        fgets(temp5->address, 500, fp);
        fgets(temp5->location, 50, fp);
        fgets(temp5->type, 50, fp);
        fgets(temp5->build_age, 50, fp);
        fgets(temp5->floor_area, 50, fp);
        fgets(temp5->floor, 50, fp);
        fgets(temp5->land_area, 50, fp);
        fgets(temp5->owner_phone_number, 50, fp);
        fgets(temp5->rooms, 50, fp);
        fgets(temp5->tax_rate, 50, fp);
        fgets(temp5->elevator, 50, fp);
        fgets(temp5->basement, 50, fp);
        fgets(temp5->basement_area, 50, fp);
        fgets(temp5->balcony, 50, fp);
        fgets(temp5->balcony_area, 50, fp);
        fgets(temp5->parkings, 50, fp);
        fgets(temp5->phones, 50, fp);
        fgets(temp5->temperature, 50, fp);
        fgets(temp5->base_price, 50, fp);
        fgets(temp5->monthly_price, 50, fp);
        fgets(temp5->date, 50, fp);
        fgets(temp5->userin, 50, fp);
        fgets(temp5->active, 50, fp);


        temp5->code[strcspn(temp5->code, "\n")] = '\0';
        temp5->district[strcspn(temp5->district, "\n")] = '\0';
        temp5->address[strcspn(temp5->address, "\n")] = '\0';
        temp5->location[strcspn(temp5->location, "\n")] = '\0';
        temp5->type[strcspn(temp5->type, "\n")] = '\0';
        temp5->build_age[strcspn(temp5->build_age, "\n")] = '\0';
        temp5->floor_area[strcspn(temp5->floor_area, "\n")] = '\0';
        temp5->floor[strcspn(temp5->floor, "\n")] = '\0';
        temp5->land_area[strcspn(temp5->land_area, "\n")] = '\0';
        temp5->owner_phone_number[strcspn(temp5->owner_phone_number, "\n")] = '\0';
        temp5->rooms[strcspn(temp5->rooms, "\n")] = '\0';
        temp5->tax_rate[strcspn(temp5->tax_rate, "\n")] = '\0';
        temp5->elevator[strcspn(temp5->elevator, "\n")] = '\0';
        temp5->basement[strcspn(temp5->basement, "\n")] = '\0';
        temp5->basement_area[strcspn(temp5->basement_area, "\n")] = '\0';
        temp5->balcony[strcspn(temp5->balcony, "\n")] = '\0';
        temp5->balcony_area[strcspn(temp5->balcony_area, "\n")] = '\0';
        temp5->parkings[strcspn(temp5->parkings, "\n")] = '\0';
        temp5->phones[strcspn(temp5->phones, "\n")] = '\0';
        temp5->temperature[strcspn(temp5->temperature, "\n")] = '\0';
        temp5->base_price[strcspn(temp5->base_price, "\n")] = '\0';
        temp5->monthly_price[strcspn(temp5->monthly_price, "\n")] = '\0';
        temp5->date[strcspn(temp5->date, "\n")] = '\0';
        temp5->userin[strcspn(temp5->userin, "\n")] = '\0';
        temp5->active[strcspn(temp5->active, "\n")] = '\0';

        temp5->next = NULL;

        if(start5 == NULL)
        {
            start5 = temp5 ;
            end5 = start5 ;
        }
        else
        {
            end5->next = temp5 ;
            end5 = temp5 ;
        }

        check++;
    }
    fclose(fp);
    fp = fopen("Rent_com_data.txt" , "w+");
    temp5 = start5;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp5->code , input_coder1) == 0)
        {
            strcpy(temp5->active , "Inactive");
        }
        if ( j == 0)
        {
            fprintf(fp, "%s\n", temp5->code);
            fprintf(fp, "%s\n", temp5->district);
            fprintf(fp, "%s\n", temp5->address);
            fprintf(fp, "%s\n", temp5->location);
            fprintf(fp, "%s\n", temp5->type);
            fprintf(fp, "%s\n", temp5->build_age);
            fprintf(fp, "%s\n", temp5->floor_area);
            fprintf(fp, "%s\n", temp5->floor);
            fprintf(fp, "%s\n", temp5->land_area);
            fprintf(fp, "%s\n", temp5->owner_phone_number);
            fprintf(fp, "%s\n", temp5->rooms);
            fprintf(fp, "%s\n", temp5->tax_rate);
            fprintf(fp, "%s\n", temp5->elevator);
            fprintf(fp, "%s\n", temp5->basement);
            fprintf(fp, "%s\n", temp5->basement_area);
            fprintf(fp, "%s\n", temp5->balcony);
            fprintf(fp, "%s\n", temp5->balcony_area);
            fprintf(fp, "%s\n", temp5->parkings);
            fprintf(fp, "%s\n", temp5->phones);
            fprintf(fp, "%s\n", temp5->temperature);
            fprintf(fp, "%s\n", temp5->base_price);
            fprintf(fp, "%s\n", temp5->monthly_price);
            fprintf(fp, "%s\n", temp5->date);
            fprintf(fp, "%s\n", temp5->userin);
            fprintf(fp, "%s", temp5->active);
        }
        else
        {
            fprintf(fp, "\n%s", temp5->code);
            fprintf(fp, "\n%s", temp5->district);
            fprintf(fp, "\n%s", temp5->address);
            fprintf(fp, "\n%s", temp5->location);
            fprintf(fp, "\n%s", temp5->type);
            fprintf(fp, "\n%s", temp5->build_age);
            fprintf(fp, "\n%s", temp5->floor_area);
            fprintf(fp, "\n%s", temp5->floor);
            fprintf(fp, "\n%s", temp5->land_area);
            fprintf(fp, "\n%s", temp5->owner_phone_number);
            fprintf(fp, "\n%s", temp5->rooms);
            fprintf(fp, "\n%s", temp5->tax_rate);
            fprintf(fp, "\n%s", temp5->elevator);
            fprintf(fp, "\n%s", temp5->basement);
            fprintf(fp, "\n%s", temp5->basement_area);
            fprintf(fp, "\n%s", temp5->balcony);
            fprintf(fp, "\n%s", temp5->balcony_area);
            fprintf(fp, "\n%s", temp5->parkings);
            fprintf(fp, "\n%s", temp5->phones);
            fprintf(fp, "\n%s", temp5->temperature);
            fprintf(fp, "\n%s", temp5->base_price);
            fprintf(fp, "\n%s", temp5->monthly_price);
            fprintf(fp, "\n%s", temp5->date);
            fprintf(fp, "\n%s", temp5->userin);
            fprintf(fp, "\n%s", temp5->active);
        }

        temp5 = temp5->next;
    }
    fclose(fp);
    temp5 = start5;
    while (temp5 != NULL)
    {
        rent_res *temper5 = temp5;
        temp5 = temp5->next;
        free(temper5);
    }
}
///delete-rent-land function
void delete_rent_land(char *input_coder1)
{
    FILE *fp;
    rent_lan *start6=NULL , *end6=NULL , *temp6;

    fp = fopen("Rent_lan_data.txt" , "r");
    int check = 0;

    int size;
    if (fp != NULL)
    {
        fseek (fp, 0, SEEK_END);
        size = ftell(fp);
        rewind(fp);

        if (size == 0)
        {
            return 0;
        }
    }

    while(!feof(fp))
    {
        temp6 = malloc(sizeof(rent_lan));
        fgets(temp6->code, 50, fp);
        fgets(temp6->district, 50, fp);
        fgets(temp6->address, 500, fp);
        fgets(temp6->location, 50, fp);
        fgets(temp6->type, 50, fp);
        fgets(temp6->land_area, 50, fp);
        fgets(temp6->width, 50, fp);
        fgets(temp6->owner_phone_number, 50, fp);
        fgets(temp6->tax_rate, 50, fp);
        fgets(temp6->well, 50, fp);
        fgets(temp6->temperature, 50, fp);
        fgets(temp6->base_price, 50, fp);
        fgets(temp6->monthly_price, 50, fp);
        fgets(temp6->date, 50, fp);
        fgets(temp6->userin, 50, fp);
        fgets(temp6->active, 50, fp);


        temp6->code[strcspn(temp6->code, "\n")] = '\0';
        temp6->district[strcspn(temp6->district, "\n")] = '\0';
        temp6->address[strcspn(temp6->address, "\n")] = '\0';
        temp6->location[strcspn(temp6->location, "\n")] = '\0';
        temp6->type[strcspn(temp6->type, "\n")] = '\0';
        temp6->land_area[strcspn(temp6->land_area, "\n")] = '\0';
        temp6->width[strcspn(temp6->width, "\n")] = '\0';
        temp6->owner_phone_number[strcspn(temp6->owner_phone_number, "\n")] = '\0';
        temp6->tax_rate[strcspn(temp6->tax_rate, "\n")] = '\0';
        temp6->well[strcspn(temp6->well, "\n")] = '\0';
        temp6->temperature[strcspn(temp6->temperature, "\n")] = '\0';
        temp6->base_price[strcspn(temp6->base_price, "\n")] = '\0';
        temp6->monthly_price[strcspn(temp6->base_price, "\n")] = '\0';
        temp6->date[strcspn(temp6->date, "\n")] = '\0';
        temp6->userin[strcspn(temp6->userin, "\n")] = '\0';
        temp6->active[strcspn(temp6->active, "\n")] = '\0';

        temp6->next = NULL;

        if(start6 == NULL)
        {
            start6 = temp6 ;
            end6 = start6 ;
        }
        else
        {
            end6->next = temp6 ;
            end6 = temp6 ;
        }

        check++;
    }
    fclose(fp);
    fp = fopen("Rent_lan_data.txt" , "w+");
    temp6 = start6;

    for(int j=0 ; j<check ; j++)
    {
        if (strcmp(temp6->code , input_coder1) == 0)
        {
            strcpy(temp6->active , "Inactive");
        }
        if (j == 0)
        {
            fprintf(fp, "%s\n", temp6->code);
            fprintf(fp, "%s\n", temp6->district);
            fprintf(fp, "%s\n", temp6->address);
            fprintf(fp, "%s\n", temp6->location);
            fprintf(fp, "%s\n", temp6->type);
            fprintf(fp, "%s\n", temp6->land_area);
            fprintf(fp, "%s\n", temp6->width);
            fprintf(fp, "%s\n", temp6->owner_phone_number);
            fprintf(fp, "%s\n", temp6->tax_rate);
            fprintf(fp, "%s\n", temp6->well);
            fprintf(fp, "%s\n", temp6->temperature);
            fprintf(fp, "%s\n", temp6->base_price);
            fprintf(fp, "%s\n", temp6->monthly_price);
            fprintf(fp, "%s\n", temp6->date);
            fprintf(fp, "%s\n", temp6->userin);
            fprintf(fp, "%s", temp6->active);
        }
        else
        {
            fprintf(fp, "\n%s", temp6->code);
            fprintf(fp, "\n%s", temp6->district);
            fprintf(fp, "\n%s", temp6->address);
            fprintf(fp, "\n%s", temp6->location);
            fprintf(fp, "\n%s", temp6->type);
            fprintf(fp, "\n%s", temp6->land_area);
            fprintf(fp, "\n%s", temp6->width);
            fprintf(fp, "\n%s", temp6->owner_phone_number);
            fprintf(fp, "\n%s", temp6->tax_rate);
            fprintf(fp, "\n%s", temp6->well);
            fprintf(fp, "\n%s", temp6->temperature);
            fprintf(fp, "\n%s", temp6->base_price);
            fprintf(fp, "\n%s", temp6->monthly_price);
            fprintf(fp, "\n%s", temp6->date);
            fprintf(fp, "\n%s", temp6->userin);
            fprintf(fp, "\n%s", temp6->active);
        }

        temp6 = temp6->next;
    }
    fclose(fp);
    temp6 = start6;
    while (temp6 != NULL)
    {
        rent_res *temper6 = temp6;
        temp6 = temp6->next;
        free(temper6);
    }
}
///admin-menu function
void admin_menu()
{

}
