/*
 * Advanced Encryption Atandard (AES) primitive algorithm.
 * - Security for IoT / IMT Atlantique
 */

#include "aes.h"
#include <stdio.h>

#include <assert.h>

// print a state
void printOut(uint8_t state[STATE_ROW_SIZE][STATE_COL_SIZE]) {
    for (int i=0; i < STATE_ROW_SIZE; i++) {
        for (int j=0; j < STATE_COL_SIZE; j++) {
            printf("%x\t", state[i][j]);
        }
        printf("\n");
    }
}

// print roundkeys keychain
void printOut3(uint8_t roundkeys[ROUND_COUNT+1][STATE_ROW_SIZE][STATE_COL_SIZE]) {
    uint8_t sp;
    for (int i=0; i < STATE_ROW_SIZE; i++) {
        for (int j=0; j < ROUND_COUNT+1; j++) {
            for (int k=0; k < STATE_COL_SIZE; k++) {
                sp = (roundkeys[j][i][k] <= 0xF) ? 3 : 2; 
                printf("%x", roundkeys[j][i][k]);
                for (int s=0; s < sp; s++) printf(" ");
            }
            printf("|");
        }
        printf("\n");
    }
}


int main() {
    uint8_t  input[DATA_SIZE] = {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
    };
    uint8_t cipherkey[DATA_SIZE] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    uint8_t expected_output[DATA_SIZE] = {
        0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32 
    };

    uint8_t ciphertext[DATA_SIZE];


    AESEncrypt(ciphertext, input, cipherkey);
    printf("--output: ");
    for (int i = 0; i < DATA_SIZE; i++) {
        printf(" %x ", ciphertext[i]);
        assert(ciphertext[i] == expected_output[i]);
    }
    printf("\nOK.\n");

    return 0;
}
