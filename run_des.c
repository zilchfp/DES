#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "des.h"

static FILE *key_file, *input_file, *output_file;
#define DES_KEY_SIZE 8

char input_file_name[] = {"sample.txt"};
char output_file_name[] = {"sample_decrypted.txt"};
char encrptred_file_name[] = {"sample.enc"};
char key_file_name[] = {"keyfile.txt"};

int generateKey() {
	unsigned long file_size;
	unsigned short int padding;
	printf("正在生成密钥...\n");

	key_file = fopen(key_file_name, "wb");
	if (!key_file) {
		printf("无法打开密钥文件！\n");
		return 1;
	}

	short int bytes_written;
	unsigned char* des_key = (unsigned char*) malloc(8*sizeof(char));

	generate_key(des_key);

	bytes_written = fwrite(des_key, 1, DES_KEY_SIZE, key_file);

	if (bytes_written != DES_KEY_SIZE) {
		printf("输出密钥时发生错误！\n");
		fclose(key_file);
		free(des_key);
		return 1;
	}

	free(des_key);
	fclose(key_file);
	printf("新密钥已生成！\n");
	return 0;
}

int encryption() {
	unsigned long file_size;
	unsigned short int padding;

	//读取相关文件
	key_file = fopen(key_file_name, "rb");
	if (!key_file) {
		printf("打开key文件失败\n");
		return 1;
	}
	short int bytes_read;
	unsigned char* des_key = (unsigned char*) malloc(8*sizeof(char));
	bytes_read = fread(des_key, sizeof(unsigned char), DES_KEY_SIZE, key_file);
	if (bytes_read != DES_KEY_SIZE) {
		printf("密钥长度不对！\n");
		fclose(key_file);
		return 1;
	}
	fclose(key_file);
	input_file = fopen(input_file_name, "rb");
	if (!input_file) {
		printf("打开明文文件失败");
		return 1;
	}
	output_file = fopen(encrptred_file_name, "wb");
	if (!output_file) {
		printf("打开输出解密结果文件失败");
		return 1;
	}

	// Generate DES key set
	short int bytes_written, process_mode;
	unsigned long block_count = 0, number_of_blocks;
	unsigned char* data_block = (unsigned char*) malloc(8*sizeof(char));
	unsigned char* processed_block = (unsigned char*) malloc(8*sizeof(char));
	key_set* key_sets = (key_set*)malloc(17*sizeof(key_set));

	generate_sub_keys(des_key, key_sets);

	process_mode = ENCRYPTION_MODE;
	printf("加密中\n");

	// Get number of blocks in the file
	fseek(input_file, 0L, SEEK_END);
	file_size = ftell(input_file);
	fseek(input_file, 0L, SEEK_SET);
	number_of_blocks = file_size/8 + ((file_size%8)?1:0);

	while(fread(data_block, 1, 8, input_file)) {
		block_count++;
		if (block_count == number_of_blocks) {
			padding = 8 - file_size%8;
			if (padding < 8) { //长度不够时，填满 
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
			bytes_written = fwrite(processed_block, 1, 8, output_file);
		}
		memset(data_block, 0, 8);
	}

	free(des_key);
	free(data_block);
	free(processed_block);
	fclose(input_file);
	fclose(output_file);
	printf("加密结束！\n");
	return 0;
}

int decryption() {
	unsigned long file_size;
	unsigned short int padding;

	key_file = fopen(key_file_name, "rb");
	if (!key_file) {
		printf("无法打开密钥文件\n");
		return 1;
	}
	short int bytes_read;
	unsigned char* des_key = (unsigned char*) malloc(8*sizeof(char));
	bytes_read = fread(des_key, sizeof(unsigned char), DES_KEY_SIZE, key_file);
	if (bytes_read != DES_KEY_SIZE) {
		printf("读入的密文文件大小不对！\n");
		fclose(key_file);
		return 1;
	}
	fclose(key_file);
	input_file = fopen(encrptred_file_name, "rb");
	if (!input_file) {
		printf("无法打开密文文件");
		return 1;
	}
	output_file = fopen(output_file_name, "wb");
	if (!output_file) {
		printf("无法打开明文文件！\n");
		return 1;
	}

	// Generate DES key set
	short int bytes_written, process_mode;
	unsigned long block_count = 0, number_of_blocks;
	unsigned char* data_block = (unsigned char*) malloc(8*sizeof(char));
	unsigned char* processed_block = (unsigned char*) malloc(8*sizeof(char));
	key_set* key_sets = (key_set*)malloc(17*sizeof(key_set));

	generate_sub_keys(des_key, key_sets);
	
	process_mode = DECRYPTION_MODE;
	printf("解密中...\n");

	// Get number of blocks in the file
	fseek(input_file, 0L, SEEK_END);
	file_size = ftell(input_file);
	fseek(input_file, 0L, SEEK_SET);
	number_of_blocks = file_size/8 + ((file_size%8)?1:0);

	while(fread(data_block, 1, 8, input_file)) {
		block_count++;
		if (block_count == number_of_blocks) {
			process_message(data_block, processed_block, key_sets, process_mode);
			padding = processed_block[7];

			if (padding < 8) {
				bytes_written = fwrite(processed_block, 1, 8 - padding, output_file);
			}
		} else {
			process_message(data_block, processed_block, key_sets, process_mode);
			bytes_written = fwrite(processed_block, 1, 8, output_file);
		}
		memset(data_block, 0, 8);
	}

	free(des_key);
	free(data_block);
	free(processed_block);
	fclose(input_file);
	fclose(output_file);
	printf("解密结束！\n");
	return 0;
}

int main() {
	generateKey();
	encryption();
	decryption();
    return 0;
}

