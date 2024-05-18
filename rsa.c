#include <stdio.h>  // Include standard input/output library for handling input and output.
#include <stdlib.h> // Include standard library for memory allocation, process control, and conversions.

// Function to perform modular exponentiation. It returns (base^exp) % mod.
// This function is crucial for RSA as it handles the power and mod operations efficiently.
long long mod_pow(long long base, long long exp, long long mod)
{
    long long result = 1; // Start with a result of 1.
    while (exp > 0)
    {                     // Continue looping until exp is 0.
        if (exp % 2 == 1) // If exp is odd, multiply the current result by the base modulo mod.
            result = (result * base) % mod;
        base = (base * base) % mod; // Square the base and take mod.
        exp /= 2;                   // Divide exp by 2.
    }
    return result; // Return the final result of the modular exponentiation.
}

// Main function: controls program execution.
int main(int argc, char *argv[])
{
    // Check for the correct number of command-line arguments.
    if (argc != 5)
    {
        fprintf(stderr, "Usage: %s <file> <n> <exp> <mode>\n", argv[0]); // Provide the correct usage if not met.
        return 1;                                                        // Return an error status.
    }

    // Store command line arguments for easy access.
    const char *filepath = argv[1]; // File path for input/output.
    int n = atoi(argv[2]);          // Convert string to integer for modulus n.
    int exp = atoi(argv[3]);        // Convert string to integer for exponent (e or d).
    const char *mode = argv[4];     // Operation mode ("encrypt" or "decrypt").

    // Open the file in read/write mode ("r+").
    FILE *fp = fopen(filepath, "r+");
    if (!fp)
    {
        perror("Failed to open file"); // If the file fails to open, print an error.
        return 1;                      // Return an error status.
    }

    int num;
    // Attempt to read an integer from the file.
    if (fscanf(fp, "%d", &num) != 1)
    {
        perror("Failed to read the number from the file"); // Error if read fails.
        fclose(fp);                                        // Ensure the file is closed properly.
        return 1;                                          // Return an error status.
    }

    // Perform the RSA encryption or decryption using the mod_pow function.
    long long result = mod_pow(num, exp, n);

    // Rewind the file to the beginning to overwrite it with the result.
    rewind(fp);
    fprintf(fp, "%lld", result); // Write the result as a long long integer.
    fclose(fp);                  // Close the file.

    // Print a completion message indicating mode and the result.
    printf("%s operation complete. Result: %lld\n", mode, result);
    return 0; // Return a success status.
}
