#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/md5.h>

#define HASH_BITS 5 // Number of hex characters to match
#define MAX_STRING_LENGTH 26 // Max random string length

typedef char string15[16]; // Defines a fixed-size string type

// Function to compute MD5 hash and return the first `HASH_BITS` hex chars
void md5_hash(const char *input, string15 output) {
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5((unsigned char*)input, strlen(input), digest);

    for (int i = 0; i < HASH_BITS; i++) {
        sprintf(output + (i * 2), "%02x", digest[i]);
    }
    output[HASH_BITS * 2] = '\0';
}

// Function to generate a random string of given length
void generate_random_string(char *str, int length) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()";
    for (int i = 0; i < length; i++) {
        str[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    str[length] = '\0';
}

// Brute-force preimage attack (One-way property)
void one_way_property(const char *original_msg) {
    string15 original_hash, candidate_hash;
    char random_string[MAX_STRING_LENGTH + 1];
    int attempts = 0;

    md5_hash(original_msg, original_hash);
    
    do {
        attempts++;
        int length = (rand() % MAX_STRING_LENGTH) + 1;
        generate_random_string(random_string, length);
        md5_hash(random_string, candidate_hash);
    } while (strncmp(original_hash, candidate_hash, HASH_BITS * 2) != 0);

    printf("\nONE-WAY PROPERTY:\n");
    printf("Original Message: %s\nHash: %s\n", original_msg, original_hash);
    printf("Matching Random String: %s\nHash: %s\n", random_string, candidate_hash);
    printf("Attempts: %d\n", attempts);
}

// Brute-force collision attack (Collision-free property)
void collision_free_property() {
    char random_string[MAX_STRING_LENGTH + 1];
    string15 hash;
    char *hash_table[1 << 16] = {0}; // Simple hash table to store hashes
    int attempts = 0;

    srand(time(NULL));

    while (1) {
        attempts++;
        int length = (rand() % MAX_STRING_LENGTH) + 1;
        generate_random_string(random_string, length);
        md5_hash(random_string, hash);

        unsigned int index = strtol(hash, NULL, 16) % (1 << 16); // Reduce collisions

        if (hash_table[index] != NULL) {
            printf("\nCOLLISION FOUND:\n");
            printf("Message 1: %s\nHash: %s\n", hash_table[index], hash);
            printf("Message 2: %s\nHash: %s\n", random_string, hash);
            printf("Attempts: %d\n", attempts);
            free(hash_table[index]);
            break;
        }

        hash_table[index] = strdup(random_string);
    }
}

int main() {
    srand(time(NULL));
    clock_t start = clock();

    one_way_property("Breaking one-way property");
    printf("\n------------------------------------------------------\n");
    collision_free_property();

    printf("\nExecution Time: %.2f seconds\n", (double)(clock() - start) / CLOCKS_PER_SEC);
    return 0;
}
