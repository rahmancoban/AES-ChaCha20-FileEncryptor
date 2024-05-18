#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define AES_BLOCK_SIZE 16
#define Nb 4  // Number of columns comprising the state
#define Nk 4  // Number of 32-bit words comprising the key
#define Nr 10 // Number of rounds

// S-box used in the SubBytes step
static const uint8_t sbox[256] = {
    // This is a part of the actual S-box used in AES
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    // The rest of the S-box should be filled in similarly
    // ...
};

// Inverse S-box used in the InvSubBytes step
static const uint8_t rsbox[256] = {
    // This is a part of the actual inverse S-box used in AES
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    // The rest of the inverse S-box should be filled in similarly
    // ...
};

// Round constant word array
static const uint8_t rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};

// State array type definition
typedef uint8_t state_t[4][4];

// Function to perform key expansion
void KeyExpansion(uint8_t *RoundKey, const uint8_t *Key)
{
    int i, j;
    uint8_t temp[4], k;

    // Copy the initial key into the first part of the expanded key
    for (i = 0; i < Nk; i++)
    {
        RoundKey[i * 4] = Key[i * 4];
        RoundKey[i * 4 + 1] = Key[i * 4 + 1];
        RoundKey[i * 4 + 2] = Key[i * 4 + 2];
        RoundKey[i * 4 + 3] = Key[i * 4 + 3];
    }

    // Generate the remaining round keys
    for (; i < Nb * (Nr + 1); i++)
    {
        for (j = 0; j < 4; j++)
        {
            temp[j] = RoundKey[(i - 1) * 4 + j];
        }

        if (i % Nk == 0)
        {
            // Rotate the word and apply S-box and round constant
            k = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = k;
            temp[0] = sbox[temp[0]];
            temp[1] = sbox[temp[1]];
            temp[2] = sbox[temp[2]];
            temp[3] = sbox[temp[3]];
            temp[0] ^= rcon[i / Nk];
        }

        // XOR with the previous round key
        for (j = 0; j < 4; j++)
        {
            RoundKey[i * 4 + j] = RoundKey[(i - Nk) * 4 + j] ^ temp[j];
        }
    }
}

// Function to add the round key to the state
void AddRoundKey(uint8_t round, state_t *state, const uint8_t *RoundKey)
{
    uint8_t i, j;
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
        {
            (*state)[j][i] ^= RoundKey[round * Nb * 4 + i * Nb + j];
        }
    }
}

// Function to perform the SubBytes step
void SubBytes(state_t *state)
{
    uint8_t i, j;
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
        {
            (*state)[j][i] = sbox[(*state)[j][i]];
        }
    }
}

// Function to perform the InvSubBytes step
void InvSubBytes(state_t *state)
{
    uint8_t i, j;
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
        {
            (*state)[j][i] = rsbox[(*state)[j][i]];
        }
    }
}

// Function to perform the ShiftRows step
void ShiftRows(state_t *state)
{
    uint8_t temp;

    // Rotate first row 1 column to the left
    temp = (*state)[1][0];
    (*state)[1][0] = (*state)[1][1];
    (*state)[1][1] = (*state)[1][2];
    (*state)[1][2] = (*state)[1][3];
    (*state)[1][3] = temp;

    // Rotate second row 2 columns to the left
    temp = (*state)[2][0];
    (*state)[2][0] = (*state)[2][2];
    (*state)[2][2] = temp;
    temp = (*state)[2][1];
    (*state)[2][1] = (*state)[2][3];
    (*state)[2][3] = temp;

    // Rotate third row 3 columns to the left
    temp = (*state)[3][0];
    (*state)[3][0] = (*state)[3][3];
    (*state)[3][3] = (*state)[3][2];
    (*state)[3][2] = (*state)[3][1];
    (*state)[3][1] = temp;
}

// Function to perform the InvShiftRows step
void InvShiftRows(state_t *state)
{
    uint8_t temp;

    // Rotate first row 1 column to the right
    temp = (*state)[1][3];
    (*state)[1][3] = (*state)[1][2];
    (*state)[1][2] = (*state)[1][1];
    (*state)[1][1] = (*state)[1][0];
    (*state)[1][0] = temp;

    // Rotate second row 2 columns to the right
    temp = (*state)[2][0];
    (*state)[2][0] = (*state)[2][2];
    (*state)[2][2] = temp;
    temp = (*state)[2][1];
    (*state)[2][1] = (*state)[2][3];
    (*state)[2][3] = temp;

    // Rotate third row 3 columns to the right
    temp = (*state)[3][0];
    (*state)[3][0] = (*state)[3][1];
    (*state)[3][1] = (*state)[3][2];
    (*state)[3][2] = (*state)[3][3];
    (*state)[3][3] = temp;
}

// Function to multiply by 2 in GF(2^8)
uint8_t xtime(uint8_t x)
{
    return (x << 1) ^ (((x >> 7) & 1) * 0x1b);
}

// Function to perform the MixColumns step
void MixColumns(state_t *state)
{
    uint8_t i;
    uint8_t Tmp, Tm, t;
    for (i = 0; i < 4; i++)
    {
        t = (*state)[i][0];
        Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3];
        Tm = (*state)[i][0] ^ (*state)[i][1];
        Tm = xtime(Tm);
        (*state)[i][0] ^= Tm ^ Tmp;
        Tm = (*state)[i][1] ^ (*state)[i][2];
        Tm = xtime(Tm);
        (*state)[i][1] ^= Tm ^ Tmp;
        Tm = (*state)[i][2] ^ (*state)[i][3];
        Tm = xtime(Tm);
        (*state)[i][2] ^= Tm ^ Tmp;
        Tm = (*state)[i][3] ^ t;
        Tm = xtime(Tm);
        (*state)[i][3] ^= Tm ^ Tmp;
    }
}

// Function to perform the InvMixColumns step
void InvMixColumns(state_t *state)
{
    int i;
    uint8_t a, b, c, d;
    for (i = 0; i < 4; i++)
    {
        a = (*state)[i][0];
        b = (*state)[i][1];
        c = (*state)[i][2];
        d = (*state)[i][3];
        (*state)[i][0] = xtime(0x0e ^ a) ^ xtime(0x0b ^ b) ^ xtime(0x0d ^ c) ^ xtime(0x09 ^ d);
        (*state)[i][1] = xtime(0x09 ^ a) ^ xtime(0x0e ^ b) ^ xtime(0x0b ^ c) ^ xtime(0x0d ^ d);
        (*state)[i][2] = xtime(0x0d ^ a) ^ xtime(0x09 ^ b) ^ xtime(0x0e ^ c) ^ xtime(0x0b ^ d);
        (*state)[i][3] = xtime(0x0b ^ a) ^ xtime(0x0d ^ b) ^ xtime(0x09 ^ c) ^ xtime(0x0e ^ d);
    }
}

// Function to perform the AES encryption
void Cipher(state_t *state, const uint8_t *RoundKey)
{
    uint8_t round = 0;

    // Initial AddRoundKey step
    AddRoundKey(0, state, RoundKey);

    // Main rounds
    for (round = 1; round < Nr; round++)
    {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(round, state, RoundKey);
    }

    // Final round (without MixColumns)
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(Nr, state, RoundKey);
}

// Function to perform the AES decryption
void InvCipher(state_t *state, const uint8_t *RoundKey)
{
    uint8_t round = 0;

    // Initial AddRoundKey step
    AddRoundKey(Nr, state, RoundKey);

    // Main rounds
    for (round = Nr - 1; round > 0; round--)
    {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(round, state, RoundKey);
        InvMixColumns(state);
    }

    // Final round (without InvMixColumns)
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(0, state, RoundKey);
}

// Function to encrypt a 16-byte block using AES
void AES_Encrypt(const uint8_t *input, const uint8_t *key, uint8_t *output)
{
    state_t state;
    uint8_t RoundKey[176]; // 11 * 16 bytes for AES-128

    // Copy input to state
    for (int i = 0; i < 16; i++)
    {
        state[i % 4][i / 4] = input[i];
    }

    // Expand the key
    KeyExpansion(RoundKey, key);

    // Perform the encryption
    Cipher(&state, RoundKey);

    // Copy state to output
    for (int i = 0; i < 16; i++)
    {
        output[i] = state[i % 4][i / 4];
    }
}

// Function to decrypt a 16-byte block using AES
void AES_Decrypt(const uint8_t *input, const uint8_t *key, uint8_t *output)
{
    state_t state;
    uint8_t RoundKey[176]; // 11 * 16 bytes for AES-128

    // Copy input to state
    for (int i = 0; i < 16; i++)
    {
        state[i % 4][i / 4] = input[i];
    }

    // Expand the key
    KeyExpansion(RoundKey, key);

    // Perform the decryption
    InvCipher(&state, RoundKey);

    // Copy state to output
    for (int i = 0; i < 16; i++)
    {
        output[i] = state[i % 4][i / 4];
    }
}

// Function to pad the input data to a multiple of the block size
void pad(uint8_t *input, size_t length, uint8_t *padded_input)
{
    size_t padding = AES_BLOCK_SIZE - (length % AES_BLOCK_SIZE);
    memcpy(padded_input, input, length);
    memset(padded_input + length, padding, padding);
}

// Function to remove padding from the decrypted data
void unpad(uint8_t *input, size_t length, uint8_t *unpadded_input, size_t *unpadded_length)
{
    size_t padding = input[length - 1];
    *unpadded_length = length - padding;
    memcpy(unpadded_input, input, *unpadded_length);
}

// Function to encrypt or decrypt a file using AES
void process_file(const char *filename, const char *key, const char *mode)
{
    FILE *file = fopen(filename, "rb");
    if (!file)
    {
        perror("Failed to open file");
        exit(1);
    }

    // Get the file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Allocate memory for the input and output data
    size_t padded_size = ((file_size / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
    uint8_t *input = malloc(padded_size);
    uint8_t *output = malloc(padded_size);
    uint8_t *padded_input = malloc(padded_size);

    // Read the input file
    fread(input, 1, file_size, file);
    fclose(file);

    if (strcmp(mode, "encrypt") == 0)
    {
        // Pad the input and encrypt each block
        pad(input, file_size, padded_input);
        for (long i = 0; i < padded_size; i += AES_BLOCK_SIZE)
        {
            AES_Encrypt(padded_input + i, (uint8_t *)key, output + i);
        }
    }
    else if (strcmp(mode, "decrypt") == 0)
    {
        // Decrypt each block and remove padding
        for (long i = 0; i < padded_size; i += AES_BLOCK_SIZE)
        {
            AES_Decrypt(input + i, (uint8_t *)key, output + i);
        }
        uint8_t *unpadded_output = malloc(padded_size);
        size_t unpadded_length;
        unpad(output, padded_size, unpadded_output, &unpadded_length);
        memcpy(output, unpadded_output, unpadded_length);
        padded_size = unpadded_length;
        free(unpadded_output);
    }

    // Write the output file
    file = fopen(filename, "wb");
    fwrite(output, 1, padded_size, file);
    fclose(file);

    // Free the allocated memory
    free(input);
    free(output);
    free(padded_input);
}

// Main function to handle command-line arguments and call the process_file function
int main(int argc, char *argv[])
{
    if (argc != 4)
    {
        fprintf(stderr, "Usage: %s <file> <key> <encrypt|decrypt>\n", argv[0]);
        return 1;
    }

    const char *filename = argv[1];
    const char *key = argv[2];
    const char *mode = argv[3];

    // Ensure the key length is correct
    if (strlen(key) != 16)
    {
        fprintf(stderr, "Key must be exactly 16 characters long\n");
        return 1;
    }

    // Process the file
    process_file(filename, key, mode);

    return 0;
}
