#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE	(16 * 1024 * 1024)
// #define NODECRYPT
// #define FIXOFFSET

void showhelp_exit() {
	printf(" usage: 3DSFAT16tool [-d|-i] [-o|-n] [NAND] [FAT16] [XORPAD]\n");
	printf("  -d   Dump FAT16 from NAND file\n");
	printf("  -i   Inject FAT16 to NAND file\n");
	printf("  -o   NAND is from O3DS\n");
	printf("  -n   NAND is from N3DS\n\n");
	exit(0);
}

int main( int argc, char** argv )
{
	FILE* fp_in;
	FILE* fp_out;
	FILE* fp_xor;
	unsigned char* bufenc;
	unsigned char* bufxor;
	int dump;
	
	size_t offset = 0x0B930000;
	size_t size = 0x0;
	
	printf("\n3DSFAT16tool (C version) by d0k3\n");
	printf("--------------------------------\n\n");
	
	if(argc < 6) showhelp_exit();
	if(strcmp(argv[1], "-d") == 0) dump = 1;
	else if(strcmp(argv[1], "-i") == 0) dump = 0;
	else showhelp_exit();
	if(strcmp(argv[2], "-o") == 0) size = 0x2F5D0000;
	else if(strcmp(argv[2], "-n") == 0) size = 0x41ED0000;
	else showhelp_exit();
	
	if(dump) {
		printf("dumping & decrypting %s\n from %s\n using %s\n\n", argv[4], argv[3], argv[5]);
	} else {
		printf("injecting & encrypting %s\n to %s\n using %s\n\n", argv[4], argv[3], argv[5]);
	}
	
	fp_xor = fopen(argv[5], "rb");
	if(fp_xor == NULL) {
		printf("open %s failed!\n\n", argv[5]);
		return 0;
	}
	
	if(dump) {
		fp_in = fopen(argv[3], "rb");
		if(fp_in == NULL) {
			printf("open %s failed!\n\n", argv[3]);
			return 0;
		}
		fp_out = fopen(argv[4], "wb");
		if(fp_out == NULL) {
			printf("open %s failed!\n\n", argv[4]);
			return 0;
		}
		#ifndef FIXOFFSET
		fseek(fp_in, offset, SEEK_SET);
		#else
		if(strcmp(argv[2], "-o") == 0) {
			fseek(fp_in, offset + 0x2CA00, SEEK_SET);
			fseek(fp_xor, 0x2CA00, SEEK_SET);
			size -= 0x2CA00;
		} else {
			fseek(fp_in, offset + 0x2AE00, SEEK_SET);
			fseek(fp_xor, 0x2AE00, SEEK_SET);
			size -= 0x2AE00;
		}
		#endif
	} else {
		fp_out = fopen(argv[3], "r+b");
		if(fp_out == NULL) {
			printf("open %s failed!\n\n", argv[3]);
			return 0;
		}
		fp_in = fopen(argv[4], "rb");
		if(fp_in == NULL) {
			printf("open %s failed!\n\n", argv[4]);
			return 0;
		}
		#ifndef FIXOFFSET
		fseek(fp_out, offset, SEEK_SET);
		#else
		if(strcmp(argv[2], "-o") == 0) {
			fseek(fp_out, offset + 0x2CA00, SEEK_SET);
			fseek(fp_xor, 0x2CA00, SEEK_SET);
			size -= 0x2CA00;
		} else {
			fseek(fp_out, offset + 0x2AE00, SEEK_SET);
			fseek(fp_xor, 0x2AE00, SEEK_SET);
			size -= 0x2AE00;
		}
		#endif
	}
	
	bufenc = (unsigned char*) malloc(BUFFER_SIZE);
	bufxor = (unsigned char*) malloc(BUFFER_SIZE);
	if((bufenc == NULL) || (bufxor == NULL)) {
		printf("out of memory");
		return 0;
	}
	
	for(size_t pos = 0; pos < size; ) {
		size_t sizea = 0;
		size_t sizeb = 0;
		#ifndef NODECRYPT
		size_t posx = 0;
		while(true) {
			posx += fread(bufxor + posx, 1, BUFFER_SIZE - posx, fp_xor);
			if(posx < BUFFER_SIZE) fseek(fp_xor, 0, SEEK_SET);
			else break;
		}
		#endif
		sizeb = (size - pos > BUFFER_SIZE) ? BUFFER_SIZE : size - pos;
		sizea = fread(bufenc, 1, sizeb, fp_in);
		if(sizea != sizeb) return 0;
		for(size_t i = 0; i < sizea; i++) bufenc[i] = bufenc[i]^bufxor[i];
		fwrite(bufenc, 1, sizea, fp_out);
		pos += sizea;
		printf("processing... %i%%\r", (pos/100) / (size/(100*100)));
	}
	printf("processing... done!\n\n");
	
	free(bufenc);
	free(bufxor);
	fclose(fp_in);
	fclose(fp_out);
	fclose(fp_xor);
	
	return 1;
}
