#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <zlib.h>

#define SALT_SIZE 16 // Salt size for the encryption
#define BUFFER_SIZE 1024

int contains_malicious_pattern(const char *line);
void encryptFile(const char *inputFile, const char *outputFile);
void decryptFile(const char *inputFile, const char *outputFile);
void compressFile(const char *source, const char *destination);
void decompressFile(const char *source, const char *destination);
void generateSalt(char *salt, int length);
int m_ip();
char *hiddenData;

// Functions for malcious text file detction
// List of suspicious patterns to check
const char *malicious_patterns[] = {
    "<script>",
    "eval(",
    "base64_decode(",
    "system(",
    "exec(",
    "<?php",
    "?>",
    "union select",
    "drop table",
    "or 1=1",
    "<iframe",
    "<object",
    "<embed",
    "onload=",
    "onerror=",
    "alert(",
    "document.cookie",
    "window.location",
    "innerHTML",
    "javascript:",
    "vbscript:"};

#define NUM_PATTERNS (sizeof(malicious_patterns) / sizeof(malicious_patterns[0]))

// Function to convert a string to lowercase
void to_lowercase(char *str)
{
    for (; *str; ++str)
    {
        *str = tolower(*str);
    }
}

// Function to check if a line contains any of the malicious patterns
int contains_malicious_pattern(const char *line)
{
    char *lower_line = strdup(line); // Create a copy of the line
    to_lowercase(lower_line);        // Convert it to lowercase

    int found = 0;
    for (size_t i = 0; i < NUM_PATTERNS; i++)
    {
        if (strstr(lower_line, malicious_patterns[i]) != NULL)
        {
            found = 1; // Pattern found
            break;
        }
    }

    free(lower_line); // Free the allocated memory
    return found;
}

int malt()
{
    const char *filename = "message.txt";
    FILE *file = fopen(filename, "r");
    if (file == NULL)
    {
        perror("Error opening message file");
        return EXIT_FAILURE;
    }

    char *buffer = NULL;
    size_t buffer_size = 0;
    int line_number = 0;
    int found_malicious = 0;

    while (getline(&buffer, &buffer_size, file) != -1)
    {
        line_number++;
        if (contains_malicious_pattern(buffer))
        {
            printf("Malicious pattern found on line %d: %s", line_number, buffer);
            found_malicious = 1;
            exit(0);
        }
    }

    if (!found_malicious)
    {
        printf("No malicious patterns found in the file.\nThe input message is: ");
    }
    // Display contents of file
    // char ch;
    // fseek(file, 0, SEEK_SET);
    // while ((ch = fgetc(file)) != EOF)
    // {
    //     putchar(ch);
    // }
    // printf("\n");
    free(buffer); // Free the allocated memory
    fclose(file);
    return EXIT_SUCCESS;
}

/// Functions for encryption and decryption
int encrypt(int choice)
{
    switch (choice)
    {
    case 1:
        encryptFile("message.txt", "encrypted.txt");
        m_ip();
        break;
    case 2:
        decryptFile("extracted.txt", "output.txt");
        break;
    }
    return 0;
}

void generateSalt(char *salt, int length)
{
    srand(time(NULL)); // Initialize random seed
    for (int i = 0; i < length; i++)
    {
        salt[i] = rand() % 256; // Generate random byte
    }
}

void encryptFile(const char *inputFile, const char *outputFile)
{
    FILE *fp = fopen(inputFile, "rb");
    FILE *fpOut = fopen(outputFile, "wb");
    char salt[SALT_SIZE];
    if (!fp || !fpOut)
    {
        perror("File opening failed");
        return;
    }

    generateSalt(salt, SALT_SIZE);
    fwrite(salt, 1, SALT_SIZE, fpOut); // Write the salt to the output file

    int c, i = 0;
    while ((c = fgetc(fp)) != EOF)
    {
        unsigned char encryptedChar = c ^ salt[i % SALT_SIZE];
        fputc(encryptedChar, fpOut);
        i++;
    }

    fclose(fp);
    fclose(fpOut);
    printf("File encrypted successfully!\n");
}

void decryptFile(const char *inputFile, const char *outputFile)
{
    FILE *fp = fopen(inputFile, "rb");
    FILE *fpOut = fopen(outputFile, "wb");
    char salt[SALT_SIZE];
    if (!fp || !fpOut)
    {
        perror("File opening failed");
        return;
    }

    fread(salt, 1, SALT_SIZE, fp); // Read the salt from the input file

    int c, i = 0;
    while ((c = fgetc(fp)) != EOF)
    {
        unsigned char decryptedChar = c ^ salt[i % SALT_SIZE];
        fputc(decryptedChar, fpOut);
        i++;
    }

    fclose(fp);
    fclose(fpOut);
    printf("File decrypted successfully!\n");
}

// Function to Compress and Decompress ecnrypted file
#define CHUNK 16384

void compressFile(const char *source, const char *destination)
{
    FILE *sourceFile = fopen(source, "rb");
    if (!sourceFile)
    {
        perror("Failed to ope2n source file");
        exit(EXIT_FAILURE);
    }

    FILE *destFile = fopen(destination, "wb");
    if (!destFile)
    {
        perror("Failed to open destination file");
        fclose(sourceFile);
        exit(EXIT_FAILURE);
    }

    z_stream strm;
    unsigned char in[CHUNK];
    unsigned char out[CHUNK];

    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    if (deflateInit(&strm, Z_DEFAULT_COMPRESSION) != Z_OK)
    {
        fprintf(stderr, "deflateInit failed\n");
        fclose(sourceFile);
        fclose(destFile);
        exit(EXIT_FAILURE);
    }

    int flush;
    do
    {
        strm.avail_in = fread(in, 1, CHUNK, sourceFile);
        if (ferror(sourceFile))
        {
            deflateEnd(&strm);
            fprintf(stderr, "Error reading source file\n");
            fclose(sourceFile);
            fclose(destFile);
            exit(EXIT_FAILURE);
        }
        flush = feof(sourceFile) ? Z_FINISH : Z_NO_FLUSH;
        strm.next_in = in;

        do
        {
            strm.avail_out = CHUNK;
            strm.next_out = out;
            deflate(&strm, flush);
            size_t have = CHUNK - strm.avail_out;
            if (fwrite(out, 1, have, destFile) != have || ferror(destFile))
            {
                deflateEnd(&strm);
                fprintf(stderr, "Error writing to destination file\n");
                fclose(sourceFile);
                fclose(destFile);
                exit(EXIT_FAILURE);
            }
        } while (strm.avail_out == 0);

    } while (flush != Z_FINISH);

    deflateEnd(&strm);
    fclose(sourceFile);
    fclose(destFile);
    printf("File compressed successfully!\n");
}

void decompressFile(const char *source, const char *destination)
{
    FILE *sourceFile = fopen(source, "rb");
    if (!sourceFile)
    {
        perror("Failed to open source file");
        exit(EXIT_FAILURE);
    }

    FILE *destFile = fopen(destination, "wb");
    if (!destFile)
    {
        perror("Failed to open destination file");
        fclose(sourceFile);
        exit(EXIT_FAILURE);
    }

    z_stream strm;
    unsigned char in[CHUNK];
    unsigned char out[CHUNK];

    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;
    if (inflateInit(&strm) != Z_OK)
    {
        fprintf(stderr, "inflateInit failed\n");
        fclose(sourceFile);
        fclose(destFile);
        exit(EXIT_FAILURE);
    }

    int ret;
    do
    {
        strm.avail_in = fread(in, 1, CHUNK, sourceFile);
        if (ferror(sourceFile))
        {
            inflateEnd(&strm);
            fprintf(stderr, "Error reading source file\n");
            fclose(sourceFile);
            fclose(destFile);
            exit(EXIT_FAILURE);
        }
        if (strm.avail_in == 0)
            break;
        strm.next_in = in;

        do
        {
            strm.avail_out = CHUNK;
            strm.next_out = out;
            ret = inflate(&strm, Z_NO_FLUSH);
            switch (ret)
            {
            case Z_NEED_DICT:
            case Z_DATA_ERROR:
            case Z_MEM_ERROR:
                inflateEnd(&strm);
                fprintf(stderr, "Error during decompression\n");
                fclose(sourceFile);
                fclose(destFile);
                exit(EXIT_FAILURE);
            }
            size_t have = CHUNK - strm.avail_out;
            if (fwrite(out, 1, have, destFile) != have || ferror(destFile))
            {
                inflateEnd(&strm);
                fprintf(stderr, "Error writing to destination file\n");
                fclose(sourceFile);
                fclose(destFile);
                exit(EXIT_FAILURE);
            }
        } while (strm.avail_out == 0);

    } while (ret != Z_STREAM_END);

    inflateEnd(&strm);
    fclose(sourceFile);
    fclose(destFile);
    printf("File decompressed successfully!\n");
}

int compression(int ch)
{
    const char *inputFile = "encrypted.txt";
    const char *compressedFile = "compressed.txt";
    const char *decompressedFile = "decompressed.txt";

    switch (ch)
    {
    case 1:
        compressFile(inputFile, compressedFile);
        break;
    case 2:
        decompressFile(compressedFile, decompressedFile);
        break;
    default:
        printf("Invalid choice. Please try again.\n");
    }
}

void hideDataInImage(char *imagePath, char *dataToHide)
{
    FILE *imageFile = fopen(imagePath, "rb+");
    if (imageFile == NULL)
    {
        printf("Error: Unable to open the image file for hiding.\n");
        return;
    }

    // Read the image file into memory
    fseek(imageFile, 0, SEEK_END);
    long imageSize = ftell(imageFile);
    rewind(imageFile);
    unsigned char *imageData = (unsigned char *)malloc(imageSize);
    if (imageData == NULL)
    {
        printf("Error: Unable to allocate memory for the image data.\n");
        fclose(imageFile);
        return;
    }
    fread(imageData, sizeof(unsigned char), imageSize, imageFile);

    // Hide the data in the image
    size_t dataLength = strlen(dataToHide);
    size_t totalBits = (dataLength + sizeof(size_t)) * 8;
    if (totalBits > (imageSize - 54) * 8)
    {
        printf("Error: Not enough space to hide the data.\n");
        free(imageData);
        fclose(imageFile);
        return;
    }

    // Write the length of the data
    for (size_t i = 0; i < sizeof(size_t) * 8; i++)
    {
        imageData[54 + i / 8] &= ~(1 << (i % 8));                    // Clear the bit
        imageData[54 + i / 8] |= ((dataLength >> i) & 1) << (i % 8); // Set the bit
    }

    // Write the data
    for (size_t i = 0; i < dataLength * 8; i++)
    {
        imageData[54 + sizeof(size_t) * 8 / 8 + i / 8] &= ~(1 << (i % 8));                                 // Clear the bit
        imageData[54 + sizeof(size_t) * 8 / 8 + i / 8] |= ((dataToHide[i / 8] >> (i % 8)) & 1) << (i % 8); // Set the bit
    }

    // Write the modified image data back to the file
    rewind(imageFile);
    fwrite(imageData, sizeof(unsigned char), imageSize, imageFile);

    free(imageData);
    fclose(imageFile);

    printf("Data hidden in the image successfully!\n");
}

// Function to extract hidden data from an image using LSB steganography
void extractDataFromImage(char *imagePath)
{
    FILE *imageFile = fopen(imagePath, "rb");
    if (imageFile == NULL)
    {
        printf("Error: Unable to open the image file for extraction.\n");
        return;
    }

    // Read the image file into memory
    fseek(imageFile, 0, SEEK_END);
    long imageSize = ftell(imageFile);
    rewind(imageFile);
    unsigned char *imageData = (unsigned char *)malloc(imageSize);
    if (imageData == NULL)
    {
        printf("Error: Unable to allocate memory for the image data.\n");
        fclose(imageFile);
        return;
    }
    fread(imageData, sizeof(unsigned char), imageSize, imageFile);

    // Extract the length of the data
    size_t dataLength = 0;
    for (size_t i = 0; i < sizeof(size_t) * 8; i++)
    {
        dataLength |= ((imageData[54 + i / 8] & (1 << (i % 8))) >> (i % 8)) << i;
    }

    // Extract the data
    char *hiddenData = (char *)malloc(dataLength + 1);
    if (hiddenData == NULL)
    {
        printf("Error: Unable to allocate memory for the hidden data.\n");
        free(imageData);
        fclose(imageFile);
        return;
    }

    for (size_t i = 0; i < dataLength * 8; i++)
    {
        hiddenData[i / 8] &= ~(1 << (i % 8));                                                                           // Clear the bit
        hiddenData[i / 8] |= ((imageData[54 + sizeof(size_t) * 8 / 8 + i / 8] & (1 << (i % 8))) >> (i % 8)) << (i % 8); // Set the bit
    }

    hiddenData[dataLength] = '\0'; // Null-terminate the extracted string

    FILE *fpOut = fopen("extracted.txt", "w");
    if (fpOut == NULL)
    {
        printf("Error: Unable to open the output file for writing.\n");
        free(hiddenData);
        free(imageData);
        fclose(imageFile);
        return;
    }

    fprintf(fpOut, "%s", hiddenData);

    fclose(fpOut); // Close the output file
    printf("Extracted hidden data: %s\n", hiddenData);

    free(hiddenData);
    free(imageData);
    fclose(imageFile);

    printf("Data extracted from the image successfully!\n");
}

char *message;
int m_ip()
{
    FILE *file;

    long file_size;

    // Open the file in read mode
    file = fopen("encrypted.txt", "r");
    if (file == NULL)
    {
        printf("Could not open file message.txt\n");
        return 1;
    }

    // Get the file size
    fseek(file, 0, SEEK_END);
    file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Allocate memory for the message
    message = (char *)malloc((file_size + 1) * sizeof(char));
    if (message == NULL)
    {
        printf("Memory allocation failed\n");
        fclose(file);
        return 1;
    }

    // Read the file into the message variable
    fread(message, sizeof(char), file_size, file);
    message[file_size] = '\0'; // Null-terminate the string

    // Clean up
    fclose(file);
    return 0;
}

int main()
{
    char imagePath[] = "stego.jpg";
    int choice;
    // char dataToHide[20];

    do
    {
        printf("Menu:\n");
        printf("1. Encode Image\n");
        printf("2. Decode Image\n");
        printf("3. Exit\n");
        printf("Enter your choice: ");
        scanf("%d", &choice);

        switch (choice)
        {
        case 1:
            malt();
            printf("Checked malicious text");
            encrypt(1);
            compression(1);
            printf("Encrypted Message: %s\n", message);
            hideDataInImage(imagePath, message);
            break;
        case 2:
            extractDataFromImage(imagePath);
            compression(2);
            encrypt(2);
            break;
        case 3:
            printf("Exiting...\n");
            break;
        default:
            printf("Invalid choice. Please try again.\n");
        }
    } while (choice != 3);

    return 0;
}