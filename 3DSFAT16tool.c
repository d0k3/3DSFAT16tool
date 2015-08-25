#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define OFF_CTR_FIRM         0x0B130000
#define OFF_TWL_FAT16        0x00012E00
#define OFF_CTR_BASE         0x0B930000
#define OFF_CTR_FAT16_O3DS   0x0B95CA00
#define OFF_CTR_FAT16_N3DS   0x0B95AE00

#define BUFFER_SIZE    (16 * 1024 * 1024)
#define FIXOFFSET
// #define NODECRYPT

void showhelp_exit() {
    printf(" usage: 3DSFAT16tool [-d|-i] [NAND] [FAT16] [XORPAD]\n");
    printf("  -d   Dump FAT16 from NAND file\n");
    printf("  -i   Inject FAT16 to NAND file\n");
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
    
    size_t offset;
    size_t size;
    
    printf("\n3DSFAT16tool (C version) by d0k3\n");
    printf("--------------------------------\n\n");
    
    if(argc < 5) showhelp_exit();
    if(strcmp(argv[1], "-d") == 0) dump = 1;
    else if(strcmp(argv[1], "-i") == 0) dump = 0;
    else showhelp_exit();
    
    if(dump) {
        printf("dumping & decrypting %s\n from %s\n using %s\n\n", argv[3], argv[2], argv[4]);
    } else {
        printf("injecting & encrypting %s\n to %s\n using %s\n\n", argv[3], argv[2], argv[4]);
    }
    
    fp_xor = fopen(argv[4], "rb");
    if(fp_xor == NULL) {
        printf("open %s failed!\n\n", argv[4]);
        return 0;
    }
    
    // determine size and type of xorpad
    fseek(fp_xor, 0, SEEK_END);
    size = ftell(fp_xor);
    fseek(fp_xor, 0, SEEK_SET);
    if (size == 0x00800000) { // FIRM xorpad
        offset = OFF_CTR_FIRM;
    } else if ((size >= 0x08FB5200) && (size <= 0x09000000)) { // TWLN xorpad
        size = 0x08FB5200;
        offset = OFF_TWL_FAT16;
    } else if ((size >= 0x2F3E3600) && (size <= 0x2F400000)) { // CTRNAND xorpad (fixed/O3DS)
        size = 0x2F3E3600;
        offset = OFF_CTR_FAT16_O3DS;
    } else if ((size >= 0x2F5D0000) && (size <= 0x2F800000)) { // CTRNAND xorpad (unfixed/O3DS)
        #ifdef FIXOFFSET
        size = 0x2F3E3600;
        offset = OFF_CTR_FAT16_O3DS;
        fseek(fp_xor, OFF_CTR_FAT16_O3DS - OFF_CTR_BASE, SEEK_SET);
        #else
        size = 0x2F5D0000;
        offset = OFF_CTR_BASE;
        #endif
    } else if ((size >= 0x41D2D200) && (size <= 0x41E00000)) { // CTRNAND xorpad (fixed/N3DS)
        size = 0x41D2D200;
        offset = OFF_CTR_FAT16_N3DS;
    } else if ((size >= 0x41ED0000) && (size <= 0x42400000)) { // CTRNAND xorpad (unfixed/N3DS)
        #ifdef FIXOFFSET
        size = 0x41D2D200;
        offset = OFF_CTR_FAT16_N3DS;
        fseek(fp_xor, OFF_CTR_FAT16_N3DS - OFF_CTR_BASE, SEEK_SET);
        #else
        size = 0x41ED0000;
        offset = OFF_CTR_BASE;
        #endif
    } else {
        printf("xorpad has bad size!\n\n");
        return 0;
    }        
    
    
    if(dump) {
        fp_in = fopen(argv[2], "rb");
        if(fp_in == NULL) {
            printf("open %s failed!\n\n", argv[2]);
            return 0;
        }
        fp_out = fopen(argv[3], "wb");
        if(fp_out == NULL) {
            printf("open %s failed!\n\n", argv[3]);
            return 0;
        }
        fseek(fp_in, offset, SEEK_SET);
    } else {
        fp_out = fopen(argv[2], "r+b");
        if(fp_out == NULL) {
            printf("open %s failed!\n\n", argv[2]);
            return 0;
        }
        fp_in = fopen(argv[3], "rb");
        if(fp_in == NULL) {
            printf("open %s failed!\n\n", argv[3]);
            return 0;
        }
        fseek(fp_out, offset, SEEK_SET);
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
