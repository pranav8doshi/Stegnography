# Introduction to Steganography
Steganography is the practice of hiding a secret message within a non-suspicious file, like an image or a video. Unlike cryptography, which obscures the content of a message, steganography conceals the very existence of the message. The term originates from Greek, meaning "hidden writing." This method can be used for securely transmitting information without drawing attention to the fact that a message is being sent.

Practical Implementation of Image-Based Steganography
In this guide, we will demonstrate how to hide a text message inside an image using a C program. The text to be hidden is stored in message.txt, and the image in which it will be concealed is named stego.jpg. After processing, the hidden message can be extracted and viewed in the output.txt file.

How it Works
The program takes the text from message.txt and embeds it into the image stego.jpg. After processing, the hidden message can be retrieved and viewed in output.txt.

Here’s a quick summary of its key functions:

Malicious Pattern Detection: The function malt() scans a text file for known malicious patterns like <script> or eval() to detect potential harmful code.
Encryption and Decryption: The program uses XOR-based encryption, with a randomly generated salt, to encrypt and decrypt files. The salt is written to the encrypted file, which is required for decryption.
Compression and Decompression: The program uses the zlib library to compress and decompress files. This is applied to the encrypted files before hiding them in an image.
Steganography: The program can hide encrypted data within an image using Least Significant Bit (LSB) steganography. The hidden data can later be extracted.
Main Menu: The user is presented with a menu to either encode or decode an image, applying the above functions step by step.

Steps to Run the Code:

Source Code Compilation
First, you need to compile the C program named Steganography.c. 
To do this, use the GCC compiler with the following command: gcc -o Steganography Steganography.c -lz
This will compile the source code and create an executable file named Steganography.

Executing the Program
Once the program is compiled, you can run it using the command: ./Steganography

Input Files
message.txt: This file should contain the text you wish to hide within the image.
stego.jpg: This is the image file in which you can hide te data.

Output Files
stego.jpg: The original file will be modifies to  add the data to be hidden.
output.txt: After hiding the text, the program will generate this file to display the hidden message extracted from the image.

By following these steps, you will be able to hide and later retrieve secret text messages inside images using steganography.