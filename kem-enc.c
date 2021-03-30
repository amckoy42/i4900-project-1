/* kem-enc.c
 * simple encryption utility providing CCA2 security.
 * based on the KEM/DEM hybrid model. */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <fcntl.h>
#include <openssl/sha.h>

#include "ske.h"
#include "rsa.h"
#include "prf.h"

static const char* usage =
"Usage: %s [OPTIONS]...\n"
"Encrypt or decrypt data.\n\n"
"   -i,--in     FILE   read input from FILE.\n"
"   -o,--out    FILE   write output to FILE.\n"
"   -k,--key    FILE   the key.\n"
"   -r,--rand   FILE   use FILE to seed RNG (defaults to /dev/urandom).\n"
"   -e,--enc           encrypt (this is the default action).\n"
"   -d,--dec           decrypt.\n"
"   -g,--gen    FILE   generate new key and write to FILE{,.pub}\n"
"   -b,--BITS   NBITS  length of new key (NOTE: this corresponds to the\n"
"                      RSA key; the symmetric key will always be 256 bits).\n"
"                      Defaults to %lu.\n"
"   --help             show this message and exit.\n";

#define FNLEN 255

enum modes {
	ENC,
	DEC,
	GEN
};

/* Let SK denote the symmetric key.  Then to format ciphertext, we
 * simply concatenate:
 * +------------+----------------+
 * | RSA-KEM(X) | SKE ciphertext |
 * +------------+----------------+
 * NOTE: reading such a file is only useful if you have the key,
 * and from the key you can infer the length of the RSA ciphertext.
 * We'll construct our KEM as KEM(X) := RSA(X)|H(X), and define the
 * key to be SK = KDF(X).  Naturally H and KDF need to be "orthogonal",
 * so we will use different hash functions:  H := SHA256, while
 * KDF := HMAC-SHA512, where the key to the hmac is defined in ske.c
 * (see KDF_KEY).
 * */

#define HASHLEN 32 /* for sha256 */

int kem_encrypt(const char* fnOut, const char* fnIn, RSA_KEY* K)
{
	/* TODO: encapsulate random symmetric key (SK) using RSA and SHA256;
	 * encrypt fnIn with SK; concatenate encapsulation and cihpertext;
	 * write to fnOut. */

	/* create random symmetric key SK */
	size_t rsaLen = rsa_numBytesN(K);
	unsigned char* x = malloc(rsaLen);
	randBytes(x, rsaLen);
	SKE_KEY SK;
	ske_keyGen(&SK, x, rsaLen);

	/* RSA and SHA256 on the random string used to generate SK */
	unsigned char* hashX = malloc(HASHLEN);
	unsigned char* kemBuf = malloc(rsaLen + HASHLEN);
	rsa_encrypt(kemBuf, x, rsaLen, K);
	SHA256(x, rsaLen, hashX);
	free(hashX);
	/* append H(X) after RSA(X) */
	memcpy((kemBuf + rsaLen), hashX, HASHLEN);

	FILE* f = fopen(fnOut, "w+");
	fwrite(kemBuf, 1, (rsaLen + HASHLEN), f);
	fclose(f);

	/* create SKE ciphertext and append to the KEM */

	ske_encrypt_file(fnOut, fnIn, &SK, NULL, (rsaLen + HASHLEN ));

	free(x);
	free(kemBuf);

	return 0;
}

/* NOTE: make sure you check the decapsulation is valid before continuing */
int kem_decrypt(const char* fnOut, const char* fnIn, RSA_KEY* K)
{
	/* TODO: write this. */
	/* step 1: recover the symmetric key */
	/* step 2: check decapsulation */
	/* step 3: derive key from ephemKey and decrypt data. */

	size_t rsaLen = rsa_numBytesN(K);
	/* KEM := RSA(X)|H(X) is first (rsaLen + HASHLEN) bytes of input */
	FILE* f = fopen(fnIn, "r");
	unsigned char* kemBuf = malloc(rsaLen + HASHLEN);
	fread(kemBuf, 1, (rsaLen + HASHLEN), f);
	fclose(f);

	/* RSA decrypt RSA(X) from the KEM to retrieve x */
	unsigned char* x = malloc(rsaLen);
	rsa_decrypt(x, kemBuf, rsaLen, K);

	/* compute H(X) of retrieved X and compare to H(X) from the KEM */
	unsigned char* hashBuf = malloc(HASHLEN);
	SHA256(x, rsaLen, hashBuf);
	for(size_t i = 0; i < HASHLEN; i++){
		if(hashBuf[i] != kemBuf[i+rsaLen]){
			return -1;
		}
	}

	/* generate symmetric key using retrieved X and decrypt */
	SKE_KEY SK;
	ske_keyGen(&SK, x, rsaLen);
	ske_decrypt_file(fnOut, fnIn, &SK, (rsaLen + HASHLEN));

	free(kemBuf);
	free(hashBuf);
	free(x);

	return 0;
}

int main(int argc, char *argv[]) {
	/* define long options */
	static struct option long_opts[] = {
		{"in",      required_argument, 0, 'i'},
		{"out",     required_argument, 0, 'o'},
		{"key",     required_argument, 0, 'k'},
		{"rand",    required_argument, 0, 'r'},
		{"gen",     required_argument, 0, 'g'},
		{"bits",    required_argument, 0, 'b'},
		{"enc",     no_argument,       0, 'e'},
		{"dec",     no_argument,       0, 'd'},
		{"help",    no_argument,       0, 'h'},
		{0,0,0,0}
	};
	/* process options: */
	char c;
	int opt_index = 0;
	char fnRnd[FNLEN+1] = "/dev/urandom";
	fnRnd[FNLEN] = 0;
	char fnIn[FNLEN+1];
	char fnOut[FNLEN+1];
	char fnKey[FNLEN+1];
	memset(fnIn,0,FNLEN+1);
	memset(fnOut,0,FNLEN+1);
	memset(fnKey,0,FNLEN+1);
	int mode = ENC;
	// size_t nBits = 2048;
	size_t nBits = 1024;
	while ((c = getopt_long(argc, argv, "edhi:o:k:r:g:b:", long_opts, &opt_index)) != -1) {
		switch (c) {
			case 'h':
				printf(usage,argv[0],nBits);
				return 0;
			case 'i':
				strncpy(fnIn,optarg,FNLEN);
				break;
			case 'o':
				strncpy(fnOut,optarg,FNLEN);
				break;
			case 'k':
				strncpy(fnKey,optarg,FNLEN);
				break;
			case 'r':
				strncpy(fnRnd,optarg,FNLEN);
				break;
			case 'e':
				mode = ENC;
				break;
			case 'd':
				mode = DEC;
				break;
			case 'g':
				mode = GEN;
				strncpy(fnOut,optarg,FNLEN);
				break;
			case 'b':
				nBits = atol(optarg);
				break;
			case '?':
				printf(usage,argv[0],nBits);
				return 1;
		}
	}

	/* TODO: finish this off.  Be sure to erase sensitive data
	 * like private keys when you're done with them (see the
	 * rsa_shredKey function). */
	switch (mode) {
		case ENC:
			{
			FILE* f = fopen(fnKey, "r");
			RSA_KEY K;
			rsa_readPublic(f, &K);
			kem_encrypt(fnOut, fnIn, &K);
			fclose(f);
			rsa_shredKey(&K);
			break;
			}
		case DEC:
			{
			FILE* f = fopen(fnKey, "r");
			RSA_KEY K;
			rsa_readPrivate(f, &K);
			kem_decrypt(fnOut, fnIn, &K);
			fclose(f);
			rsa_shredKey(&K);
			break;
			}
		case GEN:
			{
			RSA_KEY K;
			rsa_keyGen(nBits, &K);
			FILE* fPriv = fopen(fnOut, "w+");
			rsa_writePrivate(fPriv, &K);
			/* create path to the file for the public key */
			strcat(fnOut, ".pub");
			FILE* fPub = fopen(fnOut, "w+");
			rsa_writePublic(fPub, &K);
			fclose(fPriv);
			fclose(fPub);
			rsa_shredKey(&K);
			break;
			}
		default:
			return 1;
	}

	return 0;
}
