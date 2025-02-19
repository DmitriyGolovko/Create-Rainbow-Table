#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <openssl/evp.h>
#include <limits.h>

#define MAX_PASSWORD_SIZE 80

void usage(int status) {
	if (status == EXIT_SUCCESS) {
		printf("Grab a list of passwords and create a rainbow table.\n");
		printf("-f file\t\t In file.\n");
		printf("-o file\t\t Out file, default is stdout.\n");
		printf("-v hash\t\t Hash algorithm, any openssl supported hash alogrithm.\n");
		printf("-a\t\t Append to file instead of rewriting it.\n");
		printf("-l lines\t Max lines to hash, by default INT_MAX.");
		exit(status);
	}

	printf("Invalid arguments or flags");
	exit(status);
}

void hash_error(char *message, EVP_MD_CTX *ctx) {
	perror(message);
	EVP_MD_CTX_free(ctx);
	usage(EXIT_FAILURE);
}

/* Converts binary data into hex. */
char *bin_to_hex(const unsigned char *bin, int len) {
	char *out;
	char *hex_ch = "0123456789abcdef";
	
	if (bin == NULL || len == 0)
		return NULL;

	out = (char*)malloc(len * 2 + 1);
	
	for (int i = 0; i < len; i++) {
		out[2 * i] = hex_ch[bin[i] >> 4];
		out[2 * i + 1] = hex_ch[bin[i] & 0x0F];
	}
	out[2 * len] = '\0';
	return out;
}


/*	Create a hash of the password, with specific hash algorithm.
	Digest will be stored in digest argument. */
void gethash(const unsigned char *password, EVP_MD *alg, unsigned char *digest, int digest_len) {
	int password_len = strlen(password);

	EVP_MD_CTX *mdctx;

	if ((mdctx = EVP_MD_CTX_new()) == NULL)
		hash_error("Could not create context for message digest.", mdctx); 

	if (EVP_DigestInit_ex(mdctx, alg, NULL) != 1)
		hash_error("Could not initialize digest. Invalid algorithm.", mdctx);


	if (EVP_DigestUpdate(mdctx, password, password_len) != 1)
		hash_error("Invalid password pointer or password length", mdctx);
	
	if (EVP_DigestFinal_ex(mdctx, digest, &digest_len) != 1)
		hash_error("Invalid digest length.", mdctx);

	EVP_MD_CTX_free(mdctx);
}

/* Use list of passwords to generate a rainbow table of a specific hash. */
void append_table(FILE *list, FILE *out, char *hash, int lines) {
	char *password = (char*)malloc(MAX_PASSWORD_SIZE);

	EVP_MD *alg = EVP_MD_fetch(NULL, hash, NULL);
	const char *alg_name = EVP_MD_name(alg);

	if (alg == NULL) {
		perror("Invalid algorithm.\n");
		exit(EXIT_FAILURE);
	}
	
	int digest_len = EVP_MD_size(alg); //Repeated use of *digest for same algorithm.
	unsigned char *digest = (unsigned char*)OPENSSL_malloc(digest_len);

	int i = 0;
	while (fgets(password, MAX_PASSWORD_SIZE, list) != NULL && i < lines) {
		password[strlen(password) - 1] = '\0'; //Replaces \n
		gethash(password, alg, digest, digest_len);
		fprintf(out, "%s,%s,%s\n", bin_to_hex(digest, digest_len), password, alg_name);	
		i++;
	}

	free(password);	
	OPENSSL_free(digest);
	EVP_MD_free(alg);
}

int main(int argc, char **argv) {	
	int append = 0;
	int lines = INT_MAX; //By default read every line of password list.
	char *hash = NULL;
	char *filename;
	char *outfile = NULL;

	int opt;
	while ((opt = getopt(argc, argv, "al:v:f:o:h")) != -1) {
		switch (opt) {
			case 'a':
				append = 1;
				break;
			case 'l':
				lines = atoi(optarg);
				break;
			case 'v':
				hash = optarg;
				break;
			case 'f':
				filename = optarg;
				break;
			case 'o':
				outfile = optarg;
				break;
			case 'h':
				usage(EXIT_SUCCESS);
				break;
			default:
				usage(EXIT_FAILURE);
		}
	}

	if (optind < argc)
		fprintf(stderr, "Ignoring extra arguments");

	if (hash == NULL) 
		hash = "sha256";
	
	FILE *plist = fopen(filename, "r");
	FILE *rainbow;

	if (outfile == NULL) {
		rainbow = stdout;
	} else {
		rainbow = fopen(outfile, append ? "a" : "w"); //Repeated appends with different algorithms.
	}

	if (plist == NULL || rainbow == NULL) {
		fprintf(stderr, "Error opening file... exiting\n");
		exit(EXIT_FAILURE);
	}

	append_table(plist, rainbow, hash, lines);
	return 0;	
}
