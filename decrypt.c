#include <krb5.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>

#define MAX_ALLOC 1024
#define DEBUG 0

static krb5_context ctx;

void debug_segfault() {
	fprintf(stdout, "\n---\nDEBUG\n---\n");
	fflush(stdout);
}


void handle_error(krb5_error_code code) {
	if (code) {
		const char* errmsg = krb5_get_error_message(ctx, code);
		#if DEBUG
		fprintf(stderr, "%s\n", errmsg);
		fflush(stderr);
		#endif
		krb5_free_error_message(ctx, errmsg);
		exit(1);
	}
}


int main (int argc, char** argv) {
	const char *pass_str;
	const char *salt_str = "OTSECU.COMkrbadmin"; /* default salt */
	krb5_error_code code;
	const char* errmsg;
	unsigned int i = 0; // index

	if (argc != 2 && argc != 3) {
		fprintf(stderr, "Usage: decrypt password [salt]\n");
		exit(1);
	}

	pass_str = argv[1];
	if (argc == 3) {
		salt_str = argv[2]; // get salt from command line
	}

	krb5_init_context(&ctx);

	/*
	Enctype
	*/
	krb5_enctype enctype = ENCTYPE_AES256_CTS_HMAC_SHA1_96; // 18

	/*
	Generate keyblock
	*/
	krb5_keyblock* keyblock;

	krb5_init_keyblock(ctx, enctype, 0, &keyblock);

	krb5_data pwd, salt;
	pwd.data = pass_str;
	pwd.length = strlen(pass_str);

	salt.data = salt_str;
	salt.length = strlen(salt.data);

	code = krb5_c_string_to_key(ctx, enctype, &pwd, &salt, keyblock);
	handle_error(code);

	/* display key */
	#if DEBUG
	fprintf(stdout, "Key: ");
	for (i = 0; i < keyblock->length; ++i) {
		fprintf(stdout, "%02x", keyblock->contents[i]);
	}
	fprintf(stdout, "\nLength: %u\nEnctype: %d\n", keyblock->length, keyblock->enctype);
	fflush(stdout);
	#endif

	/*
	Generate key from keyblock
	This is handled by krb5_c_decrypt();
	*/
	/*
	krb5_key key;
	krb5_k_create_key(ctx, keyblock, &key);
	*/

	/*
	Decrypt ciphertext using key
	*/
	krb5_data cipher, plain;
	unsigned char cipherdata[] = "\xca\xaa\xef\xaa\xf1\xaa\xe3\x29\xbd\x81\x80\x21\x5f\x4f\x33\x72\xb1\x50\x7b\x4b\xf7\xa0\xdf\x31\xdf\xd3\x70\x22\xe7\x1e\xad\x97\x2c\x2b\xce\xee\x97\x76\x19\x2c\x23\x22\x8c\x5a\x12\xc6\xdf\xad\x44\x63\x82\x83\xc6\x09\x7d\x89\xad\x28\x47\x5e\x6a\xe4\xc7\xc7\x53\x3e\xfb\x16\xe8\x6d\xf1\xf3\x93\x35\x04\xc9\xb1\x60\xcd\x49\xdd\xa4\xeb\xa5\xb7\x59\x68\x00\x59\x52\xab\xa6\xaf\xef\x77\x1b\x18\x8c\xd9\x27\x9e\x9c\x17\x70\x48\x5a\xfc\xc2\x64\xda\xdf\x38\xe2\x23\x40\xf9\xf3\x9f\x51\xf2\x75\x67\x06\x58\x75\xdb\x00\x5f\x55\xb1\x5f\x4c\xa0\xc5\xcd\x19\xf4\x34\x9f\xb7\x20\xc8\xfc\x95\x51\xc2\x1b\x66\x6a\xab\x78\x06\xb1\x59\xf7\xc4\xf9\x6d\xb7\x2d\xb5\x0b\xd8\xb2\x02\xaa\xa8\x64\x33\xe1\x4a\x35\x6a\x84\xab\xb6\x9d\x8b\x1e\x4e\x0b\x3d\x15\x0f\xcc\xb0\x1a\x84\xfc\xb2\x0d\x73\x43\x06\x7e\xb0\x81\x2f\xf9\xaa\x12\x05\xb2\x6b\xd7\xdd\x2d\x78\xe0\x88\xfe\xd4\x0a\x99\xab\xf0\x94\x0a\x1e\x96\x95\x67\x2d\xbf\xbb\x93\x75\x0e\x7c\xd5\x9c\x9b\x44\x8f\xfc\x73\x06\x86\xd6\x89\x71\x2e\xa1\x47\x7b\x08\xd4\x07\x08\xff\x75\x99\x49\x89\x1d\xa9\x51\x25\x03\xcf\x20\xcc\x4c\xac\x47\xc9\x8b\x89\x6f\xec\x06\x67\x0b\x4c\x72\xe8\xf6\x49\x50\xce\x1b";
	cipher.data = (unsigned char *) cipherdata;
	cipher.length = (unsigned int) 281;
	
	krb5_enc_data enc_out;
	enc_out.ciphertext = cipher;
	enc_out.enctype = enctype;

	plain.data = malloc(MAX_ALLOC);
	plain.length = MAX_ALLOC;

	/* decryption */
	code = krb5_c_decrypt(ctx, keyblock, KRB5_KEYUSAGE_AS_REP_ENCPART, 0, &enc_out, &plain);
	handle_error(code);

	/* display plain text */
	#if DEBUG
	fprintf(stdout, "Plain [%u]: ", plain.length);
	for (i = 0; i < plain.length; ++i) {
		if (i % 16 == 0) {
			fprintf(stdout, "\n");
		}
		else if (i % 8 == 0) {
			fprintf(stdout, " ");
		}
		fprintf(stdout, "%02x", (unsigned char) plain.data[i]);
	}
	fprintf(stdout, "\n");
	fflush(stdout);
	#endif

	/* cleanup */
	free(plain.data);
	krb5_free_context(ctx);

	return 0;
}
