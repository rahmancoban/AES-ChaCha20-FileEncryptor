#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ROUNDS 20 // Number of rounds in ChaCha20

// ChaCha20 constants
static const char *constants = "expand 32-byte k";

// Structure to hold the ChaCha20 state
typedef struct
{
    uint32_t state[16];
} chacha20_ctx;

// Function to perform a left rotation on a 32-bit integer
static uint32_t rotate(uint32_t v, int c)
{
    return (v << c) | (v >> (32 - c));
}

// Function to load 4 bytes from the input array into a 32-bit integer
static uint32_t load32(const uint8_t *x)
{
    return ((uint32_t)(x[0]) << 0) |
           ((uint32_t)(x[1]) << 8) |
           ((uint32_t)(x[2]) << 16) |
           ((uint32_t)(x[3]) << 24);
}

// Function to store a 32-bit integer into 4 bytes of the output array
static void store32(uint8_t *x, uint32_t u)
{
    x[0] = u >> 0;
    x[1] = u >> 8;
    x[2] = u >> 16;
    x[3] = u >> 24;
}

// Function to initialize the ChaCha20 state with the key and nonce
static void chacha20_keysetup(chacha20_ctx *ctx, const uint8_t *key, const uint8_t *nonce)
{
    int i;
    // Load the constants into the state
    ctx->state[0] = load32((const uint8_t *)(constants + 0));
    ctx->state[1] = load32((const uint8_t *)(constants + 4));
    ctx->state[2] = load32((const uint8_t *)(constants + 8));
    ctx->state[3] = load32((const uint8_t *)(constants + 12));

    // Load the key into the state
    for (i = 0; i < 8; ++i)
    {
        ctx->state[4 + i] = load32(key + i * 4);
    }

    // Initialize the counter and nonce
    ctx->state[12] = 0; // Counter
    ctx->state[13] = 0; // Counter
    ctx->state[14] = load32(nonce + 0);
    ctx->state[15] = load32(nonce + 4);
}

// Function to generate a 64-byte keystream block
static void chacha20_block(chacha20_ctx *ctx, uint32_t *out)
{
    int i;
    uint32_t x[16];
    // Copy the state to a working array
    memcpy(x, ctx->state, sizeof(uint32_t) * 16);

    // Perform the ChaCha20 quarter round operations
    for (i = 0; i < ROUNDS; i += 2)
    {
        x[0] += x[4];
        x[12] = rotate(x[12] ^ x[0], 16);
        x[8] += x[12];
        x[4] = rotate(x[4] ^ x[8], 12);
        x[0] += x[4];
        x[12] = rotate(x[12] ^ x[0], 8);
        x[8] += x[12];
        x[4] = rotate(x[4] ^ x[8], 7);

        x[1] += x[5];
        x[13] = rotate(x[13] ^ x[1], 16);
        x[9] += x[13];
        x[5] = rotate(x[5] ^ x[9], 12);
        x[1] += x[5];
        x[13] = rotate(x[13] ^ x[1], 8);
        x[9] += x[13];
        x[5] = rotate(x[5] ^ x[9], 7);

        x[2] += x[6];
        x[14] = rotate(x[14] ^ x[2], 16);
        x[10] += x[14];
        x[6] = rotate(x[6] ^ x[10], 12);
        x[2] += x[6];
        x[14] = rotate(x[14] ^ x[2], 8);
        x[10] += x[14];
        x[6] = rotate(x[6] ^ x[10], 7);

        x[3] += x[7];
        x[15] = rotate(x[15] ^ x[3], 16);
        x[11] += x[15];
        x[7] = rotate(x[7] ^ x[11], 12);
        x[3] += x[7];
        x[15] = rotate(x[15] ^ x[3], 8);
        x[11] += x[15];
        x[7] = rotate(x[7] ^ x[11], 7);

        x[0] += x[5];
        x[15] = rotate(x[15] ^ x[0], 16);
        x[10] += x[15];
        x[5] = rotate(x[5] ^ x[10], 12);
        x[0] += x[5];
        x[15] = rotate(x[15] ^ x[0], 8);
        x[10] += x[15];
        x[5] = rotate(x[5] ^ x[10], 7);

        x[1] += x[6];
        x[12] = rotate(x[12] ^ x[1], 16);
        x[11] += x[12];
        x[6] = rotate(x[6] ^ x[11], 12);
        x[1] += x[6];
        x[12] = rotate(x[12] ^ x[1], 8);
        x[11] += x[12];
        x[6] = rotate(x[6] ^ x[11], 7);

        x[2] += x[7];
        x[13] = rotate(x[13] ^ x[2], 16);
        x[8] += x[13];
        x[7] = rotate(x[7] ^ x[8], 12);
        x[2] += x[7];
        x[13] = rotate(x[13] ^ x[2], 8);
        x[8] += x[13];
        x[7] = rotate(x[7] ^ x[8], 7);

        x[3] += x[4];
        x[14] = rotate(x[14] ^ x[3], 16);
        x[9] += x[14];
        x[4] = rotate(x[4] ^ x[9], 12);
        x[3] += x[4];
        x[14] = rotate(x[14] ^ x[3], 8);
        x[9] += x[14];
        x[4] = rotate(x[4] ^ x[9], 7);
    }

    // Add the original state to the final state to produce the keystream
    for (i = 0; i < 16; ++i)
    {
        out[i] = x[i] + ctx->state[i];
    }
}

// Function to encrypt or decrypt data using ChaCha20
void chacha20_encrypt(chacha20_ctx *ctx, const uint8_t *input, uint8_t *output, uint32_t length)
{
    uint8_t block[64];
    uint32_t i, j;

    // Process each 64-byte block
    for (i = 0; i < length; i += 64)
    {
        // Generate the keystream block
        chacha20_block(ctx, (uint32_t *)block);

        // Increment the counter
        ctx->state[12]++;
        if (ctx->state[12] == 0)
        {
            ctx->state[13]++;
        }

        // XOR the input with the keystream to produce the output
        for (j = 0; j < 64 && i + j < length; ++j)
        {
            output[i + j] = input[i + j] ^ block[j];
        }
    }
}

// Function to process a file using ChaCha20 encryption or decryption
void process_file(const char *filename, const char *key, const char *nonce, const char *mode)
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
    uint8_t *input = malloc(file_size);
    uint8_t *output = malloc(file_size);

    // Read the input file
    fread(input, 1, file_size, file);
    fclose(file);

    // Initialize the ChaCha20 context with the key and nonce
    chacha20_ctx ctx;
    chacha20_keysetup(&ctx, (const uint8_t *)key, (const uint8_t *)nonce);

    // Encrypt or decrypt the data
    if (strcmp(mode, "encrypt") == 0)
    {
        chacha20_encrypt(&ctx, input, output, file_size);
    }
    else if (strcmp(mode, "decrypt") == 0)
    {
        chacha20_encrypt(&ctx, input, output, file_size); // Same function for both
    }

    // Write the output file
    file = fopen(filename, "wb");
    fwrite(output, 1, file_size, file);
    fclose(file);

    // Free the allocated memory
    free(input);
    free(output);
}

// Main function to handle command-line arguments and call the process_file function
int main(int argc, char *argv[])
{
    if (argc != 5)
    {
        fprintf(stderr, "Usage: %s <file> <key> <nonce> <encrypt|decrypt>\n", argv[0]);
        return 1;
    }

    const char *filename = argv[1];
    const char *key = argv[2];
    const char *nonce = argv[3];
    const char *mode = argv[4];

    // Ensure the key and nonce lengths are correct
    if (strlen(key) != 32)
    {
        fprintf(stderr, "Key must be exactly 32 characters long\n");
        return 1;
    }

    if (strlen(nonce) != 8)
    {
        fprintf(stderr, "Nonce must be exactly 8 characters long\n");
        return 1;
    }

    // Process the file
    process_file(filename, key, nonce, mode);

    return 0;
}
