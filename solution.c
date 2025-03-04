#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>  

#define HASH_SIZE 3  

void hash_message(const char *message, unsigned char *hash_output) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    const EVP_MD *md = EVP_sha256();
    unsigned char full_hash[EVP_MAX_MD_SIZE];
    unsigned int md_len;

    if (!mdctx) {
        fprintf(stderr, "Error creating EVP_MD_CTX\n");
        exit(1);
    }

    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, message, strlen(message));
    EVP_DigestFinal_ex(mdctx, full_hash, &md_len);
    EVP_MD_CTX_destroy(mdctx);

    memcpy(hash_output, full_hash, HASH_SIZE);  
}


uint32_t hash_to_int(const unsigned char *hash) {
    return (hash[0] << 16) | (hash[1] << 8) | hash[2];
}


void one_way_attack(const unsigned char *target_hash) {
    char test_message[32];
    unsigned char test_hash[HASH_SIZE];
    uint32_t trials = 0;

    while (1) {
        snprintf(test_message, sizeof(test_message), "msg-%u-%d", trials, rand());  
        hash_message(test_message, test_hash);
        uint32_t hash_value = hash_to_int(test_hash);

        // For debugging
        if (trials < 5) {
            printf("Trial %u: %s -> Hash: %02x%02x%02x (%u)\n",
                   trials, test_message, test_hash[0], test_hash[1], test_hash[2], hash_value);
        }

        if (hash_value == hash_to_int(target_hash)) {
            printf("\nPreimage found after %u trials!\n", trials);
            printf("Original Message: %s\n", test_message);
            break;
        }

        trials++;
    }
}

int main() {
    srand(time(NULL) ^ getpid());  

    const char *target_message = "secret";
    unsigned char target_hash[HASH_SIZE];
    hash_message(target_message, target_hash);

    printf("Target Message: %s\n", target_message);
    printf("Target Hash: %02x%02x%02x\n", target_hash[0], target_hash[1], target_hash[2]);

    printf("Starting brute-force attack on one-way property...\n");
    one_way_attack(target_hash);
   
    return 0;
}
