/*
 * Advanced Encryption Standard (AES) primitive algorithm library definition.
 * - Security for IoT / IMT Atlantique
 */

#include "aes.h"
#include <stdio.h>

const uint8_t rcon[10] = {
    0x01,
    0x02,
    0x04,
    0x08,
    0x10,
    0x20,
    0x40,
    0x80,
    0x1b,
    0x36
};

const uint8_t sboxtab[256] = {
    //0    1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// extern const uint8_t invsbox[256];

// the round that will trigger
// extern uint8_t targeted_round;

void AESEncrypt(uint8_t ciphertext[DATA_SIZE], uint8_t plaintext[DATA_SIZE], uint8_t key[DATA_SIZE]) {
    uint8_t state[STATE_ROW_SIZE][STATE_COL_SIZE];
    uint8_t master_key[STATE_ROW_SIZE][STATE_COL_SIZE];
    uint8_t round_key[STATE_ROW_SIZE][STATE_COL_SIZE];
    uint8_t roundkeys[ROUND_COUNT+1][STATE_ROW_SIZE][STATE_COL_SIZE]; 
    uint8_t round = 0;
    
    MessageToState(state, plaintext);   // Input
    MessageToState(master_key, key);    // Cipherkey
    KeyGen(roundkeys, master_key);      // KeyChain

    // Round 0
    GetRoundKey(round_key, roundkeys, round);
    AddRoundKey(state, round_key); 
    // Round 1-10
    for (round = 1; round < ROUND_COUNT; round++) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        GetRoundKey(round_key, roundkeys, round);
        AddRoundKey(state, round_key); 
    }
    // Final round
    SubBytes(state);
    ShiftRows(state);
    GetRoundKey(round_key, roundkeys, round);
    AddRoundKey(state, round_key); 

    // Ciphertext
    StateToMessage(ciphertext, state);
}

void AddRoundKey(uint8_t state[STATE_ROW_SIZE][STATE_COL_SIZE], uint8_t roundkey[STATE_ROW_SIZE][STATE_COL_SIZE]) {
    // each column of the state, gets an xor with each column of the roundkey
    uint8_t r, c;
    for (c = 0; c < STATE_COL_SIZE; c++) {
        for (r = 0; r < STATE_ROW_SIZE; r++) {
            state[r][c] ^= roundkey[r][c];
        }
    }
}

void SubBytes(uint8_t state[STATE_ROW_SIZE][STATE_COL_SIZE]) {
    uint8_t c, r;
    for (c = 0; c < STATE_COL_SIZE; c++) {
        for (r = 0; r < STATE_ROW_SIZE; r++) {
            // Substitute each value for the corresponding one in S-box
            state[r][c] = sboxtab[state[r][c]];
        }
    }
}

void ShiftRows(uint8_t state[STATE_ROW_SIZE][STATE_COL_SIZE]) {
    uint8_t r, c, tmp;
    for(r = 1; r < STATE_ROW_SIZE; r++) {
        for (uint8_t i = 0; i < r; i++) {
            tmp = state[r][0]; // save 1st element
            // shift all to the left
            for (c = 0; c < STATE_COL_SIZE-1; c++) {
                state[r][c] = state[r][c+1];
            }
            state[r][c] = tmp; // set last element
        }
    }
}

void MixColumns(uint8_t state[STATE_ROW_SIZE][STATE_COL_SIZE]) {
    uint8_t r, c;
    uint8_t mcol[4];
    for (c = 0; c < STATE_COL_SIZE; c++) {
        mcol[0] = gmul(0x02, state[0][c]) ^ (gmul(0x02, state[1][c]) ^ state[1][c]) ^ state[2][c] ^ state[3][c]; 
        mcol[1] = state[0][c] ^ gmul(0x02, state[1][c]) ^ (gmul(0x02, state[2][c]) ^ state[2][c]) ^ state[3][c]; 
        mcol[2] = state[0][c] ^ state[1][c] ^ gmul(0x02, state[2][c]) ^ (gmul(0x02, state[3][c]) ^ state[3][c]);
        mcol[3] = (gmul(0x02, state[0][c]) ^ state[0][c]) ^ state[1][c] ^ state[2][c] ^ gmul(0x02, state[3][c]);
        // Set mixed column values
        for (r = 0; r < STATE_ROW_SIZE; r++) state[r][c] = mcol[r];
    }
}

void KeyGen(uint8_t roundkeys[][STATE_ROW_SIZE][STATE_COL_SIZE], uint8_t master_key[STATE_ROW_SIZE][STATE_COL_SIZE]) {
    // Copy master key into roundkeys[0]
    uint8_t r, c, round;
    for (r = 0; r < STATE_ROW_SIZE; r++) {
        for (c = 0; c < STATE_COL_SIZE; c++) {
            roundkeys[0][r][c] = master_key[r][c];
        }
    }
    // Gen roundkeys[1-10]
    for (round = 1; round < ROUND_COUNT+1; round++) {
        ColumnFill(roundkeys, round);
        OtherColumnsFill(roundkeys, round);
    }
}

// fill the first column of a given round key
void ColumnFill(uint8_t roundkeys[][STATE_ROW_SIZE][STATE_COL_SIZE], int round) {
    if (round <= 0) return; // round cannot be 0?
    uint8_t r, tmp, rcon_value;
    // Rotate last col of prev key, applying subbytes, then XOR w first column & rcon[round]
    tmp = roundkeys[round-1][0][STATE_COL_SIZE-1];
    for (r = 0; r < STATE_ROW_SIZE-1; r++) {
        // first_col = roundkeys[round-1][r][0];
        rcon_value = (r == 0) ? rcon[round-1] : 0x00;

        roundkeys[round][r][0] = 
            roundkeys[round-1][r][0] 
            ^ sboxtab[roundkeys[round-1][r+1][STATE_COL_SIZE-1]]
            ^ rcon_value;
            // ^ rcon[round-1]; // ???
    }
    roundkeys[round][r][0] = 
        roundkeys[round-1][r][0] 
        ^ sboxtab[tmp]
        ^ rcon_value;
        // ^ rcon[round-1]; // ???
}

// fill the other 3 columns of a given round key
void OtherColumnsFill(uint8_t roundkeys[][STATE_ROW_SIZE][STATE_COL_SIZE], int round) {
    if (round <= 0) return; // round cannot be 0?
    // Take first col of roundkeys[round] & xor with last 3 cols from roundkeys[round-1]
    uint8_t r, c;
    for (c = 1; c < STATE_COL_SIZE; c++) {
        // take prev col from current round key & xor with curr_col from prev round.
        for (r = 0; r < STATE_ROW_SIZE; r++) {
            roundkeys[round][r][c] = roundkeys[round][r][c-1] ^ roundkeys[round-1][r][c];
        }
    }
}

void GetRoundKey(uint8_t roundkey[STATE_ROW_SIZE][STATE_COL_SIZE], uint8_t roundkeys[][STATE_ROW_SIZE][STATE_COL_SIZE], int round) {
    // Set roundkey to roundkeys[round] (round=[0,10])
    uint8_t r, c;
    for (c = 0; c < STATE_COL_SIZE; c++) {
        for (r = 0; r < STATE_ROW_SIZE; r++) {
            roundkey[r][c] = roundkeys[round][r][c];
        }
    }
}

void MessageToState(uint8_t state[STATE_ROW_SIZE][STATE_COL_SIZE], uint8_t message[DATA_SIZE]) {
    uint8_t nb, c, r;
    for (nb = 0; nb < DATA_SIZE; nb++) {
        c = nb / STATE_COL_SIZE; 
        r = nb % STATE_ROW_SIZE;
        state[r][c] = message[nb];
    }
}

void StateToMessage(uint8_t message[DATA_SIZE], uint8_t state[STATE_ROW_SIZE][STATE_COL_SIZE]) {
    uint8_t nb, c, r;
    for (nb = 0; nb < DATA_SIZE; nb++) {
        c = nb / STATE_COL_SIZE; 
        r = nb % STATE_ROW_SIZE;
        message[nb] = state[r][c];
    }
}

void MCMatrixColumnProduct(uint8_t colonne[STATE_COL_SIZE]);

// Mult for MixColumns: a = 0x02; b = col[r]
uint8_t gmul(uint8_t a, uint8_t b) {
    if (a == 0x02) {
        return (b < 0x80) ? a*b : 0xff&((a*b)^0x1b); // macro?
    }
    return 0; // what.
}
