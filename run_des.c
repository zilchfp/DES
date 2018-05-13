#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "des.h"

static FILE *key_file, *input_file, *output_file;
#define ACTION_GENERATE_KEY "-g"
#define ACTION_ENCRYPT "-e"
#define ACTION_DECRYPT "-d"
#define DES_KEY_SIZE 8


int mymain(int argc, char* argv[]) {
	unsigned long file_size;
	unsigned short int padding;

	if (strcmp(argv[1], ACTION_GENERATE_KEY) == 0) { // Generate key file
		if (argc != 3) {
			printf("Invalid # of parameter specified. Usage: run_des -g keyfile.key");
			return 1;
		}

		key_file = fopen(argv[2], "wb");
		if (!key_file) {
			printf("Could not open file to write key.");
			return 1;
		}

		short int bytes_written;
		unsigned char* des_key = (unsigned char*) malloc(8*sizeof(char));
		generate_key(des_key);
		bytes_written = fwrite(des_key, 1, DES_KEY_SIZE, key_file);
		if (bytes_written != DES_KEY_SIZE) {
			printf("Error writing key to output file.");
			fclose(key_file);
			free(des_key);
			return 1;
		}

		free(des_key);
		fclose(key_file);
	} else if ((strcmp(argv[1], ACTION_ENCRYPT) == 0) || (strcmp(argv[1], ACTION_DECRYPT) == 0)) { // Encrypt or decrypt
		// Read key file
		key_file = fopen(argv[2], "rb");
		if (!key_file) {
			printf("Could not open key file to read key.");
			return 1;
		}

		short int bytes_read;
		unsigned char* des_key = (unsigned char*) malloc(8*sizeof(char));
		bytes_read = fread(des_key, sizeof(unsigned char), DES_KEY_SIZE, key_file);
		if (bytes_read != DES_KEY_SIZE) {
			printf("Key read from key file does nto have valid key size.");
			fclose(key_file);
			return 1;
		}
		fclose(key_file);

		// Open input file
		input_file = fopen(argv[3], "rb");
		if (!input_file) {
			printf("Could not open input file to read data.");
			return 1;
		}

		// Open output file
		output_file = fopen(argv[4], "wb");
		if (!output_file) {
			printf("Could not open output file to write data.");
			return 1;
		}

		// Generate DES key set
		short int bytes_written, process_mode;
		unsigned long block_count = 0, number_of_blocks;
		unsigned char* data_block = (unsigned char*) malloc(8*sizeof(char));
		unsigned char* processed_block = (unsigned char*) malloc(8*sizeof(char));
		key_set* key_sets = (key_set*)malloc(17*sizeof(key_set));

		generate_sub_keys(des_key, key_sets);

		// Determine process mode
		if (strcmp(argv[1], ACTION_ENCRYPT) == 0) {
			process_mode = ENCRYPTION_MODE;
			printf("Encrypting..\n");
		} else {
			process_mode = DECRYPTION_MODE;
			printf("Decrypting..\n");
		}

		// Get number of blocks in the file
		fseek(input_file, 0L, SEEK_END);
		file_size = ftell(input_file);

		fseek(input_file, 0L, SEEK_SET);
		number_of_blocks = file_size/8 + ((file_size%8)?1:0);

		// Start reading input file, process and write to output file
		while(fread(data_block, 1, 8, input_file)) {
			block_count++;
			if (block_count == number_of_blocks) {
				if (process_mode == ENCRYPTION_MODE) {
					padding = 8 - file_size%8;
					if (padding < 8) { // Fill empty data block bytes with padding
						memset((data_block + 8 - padding), (unsigned char)padding, padding);
					}

					process_message(data_block, processed_block, key_sets, process_mode);
					bytes_written = fwrite(processed_block, 1, 8, output_file);

					if (padding == 8) { // Write an extra block for padding
						memset(data_block, (unsigned char)padding, 8);
						process_message(data_block, processed_block, key_sets, process_mode);
						bytes_written = fwrite(processed_block, 1, 8, output_file);
					}
				} else {
					process_message(data_block, processed_block, key_sets, process_mode);
					padding = processed_block[7];

					if (padding < 8) {
						bytes_written = fwrite(processed_block, 1, 8 - padding, output_file);
					}
				}
			} else {
				process_message(data_block, processed_block, key_sets, process_mode);
				bytes_written = fwrite(processed_block, 1, 8, output_file);
			}
			memset(data_block, 0, 8);
		}

		// Free up memory
		free(des_key);
		free(data_block);
		free(processed_block);
		fclose(input_file);
		fclose(output_file);

		return 0;
	} else {
		printf("Invalid action: %s. First parameter must be [ -g | -e | -d ].", argv[1]);
		return 1;
	}

	return 0;
}

int main() {
	char* argv1[] = {"test", "-g", "keyfile.txt"};	int argc1 = 3;
	char* argv2[] = {"test", "-e", "keyfile.txt", "sample.txt", "sample.enc"}; int argc2 = 5;
	char* argv3[] = {"test", "-d", "keyfile.txt", "sample.enc", "sample_decrypted.txt"}; int argc3 = 5;

    mymain(argc1, argv1);
    mymain(argc2, argv2);
    mymain(argc3, argv3);
    return 0;
}

