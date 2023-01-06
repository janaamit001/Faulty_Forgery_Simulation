#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <stdlib.h>

#include "crypto_aead.h"
#include "api.h"

#define KAT_SUCCESS          0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR      -3
#define KAT_CRYPTO_FAILURE  -4

#define MAX_FILE_NAME				256
#define MAX_MESSAGE_LENGTH			32
#define MAX_ASSOCIATED_DATA_LENGTH	32
#define number 1


extern unsigned char ftag[ 16 ];
unsigned char tag1[16];



void init_buffer(unsigned char *buffer, unsigned long long numbytes);

void fprint_bstr(FILE *fp, const char *label, const unsigned char *data, unsigned long long length);

int generate_test_vectors();
clock_t start, end;
double cpu_time_used;
int main()
{
	start = clock();
	int ret = generate_test_vectors();

	if (ret != KAT_SUCCESS) {
		fprintf(stderr, "test vector generation failed with code %d\n", ret);
	}

	return ret;
}


void print( unsigned char *m ) {

	/*printf("Ciphertext::\n");
	for( short i = 0; i < 64; ++i )
		printf("%2x ", m[ i ]);
		
	printf("\n\n");*/
	
	printf("Tag::\n");
	for( short i = 0; i < 16; ++i )
		printf("%02x ", m[ i ]);
		
	printf("\n\n");

	return;
}																																												


void shift_rows1(unsigned char *state_bytes)
{
    unsigned char state_;
    
    // first row
    state_ = state_bytes[1];
    state_bytes[1] = state_bytes[5];
    state_bytes[5] = state_bytes[9];
    state_bytes[9] = state_bytes[13];
    state_bytes[13] = state_;
    
    // second row
    state_ = state_bytes[2];
    state_bytes[2] = state_bytes[10];
    state_bytes[10] = state_;
    state_ = state_bytes[6];
    state_bytes[6] = state_bytes[14];
    state_bytes[14] = state_;
    
    // third row
    state_ = state_bytes[15];
    state_bytes[15] = state_bytes[11];
    state_bytes[11] = state_bytes[7];
    state_bytes[7] = state_bytes[3];
    state_bytes[3] = state_;
}


void xor_of_diff_tag( unsigned char state[ ], unsigned char ct1[] ) {

	unsigned char byte[ 16 ];
	short i, j, counter = 0;
	
	for( i = 0; i < 16; ++i ) {
	
		ct1[ i ] = ct1[ i ] ^ state[ i ];
		//++counter;
	}

	return;
}


void print_state( unsigned char st[  ] ) {

	//for( short i = 0; i < 16; ++i ) {
	
		//for( short j = 0; j < 8; ++j ) 
			printf("%02x %02x %02x %02x ", st[0], st[4 ], st[ 8], st[ 12] );
			printf("\n");
			
			printf("%02x %02x %02x %02x ", st[1 ], st[5 ], st[ 9], st[13 ] );
			printf("\n");
			
			printf("%02x %02x %02x %02x ", st[ 2], st[ 6], st[ 10], st[ 14] );
			printf("\n");
			
			printf("%02x %02x %02x %02x ", st[ 3], st[7 ], st[ 11], st[15 ] );
			printf("\n");

	return;
}




int generate_test_vectors()
{
	FILE                *fp;
	char                fileName[MAX_FILE_NAME];
	unsigned char       key[CRYPTO_KEYBYTES] = {0x10, 0x20, 0x30, 0x10, 0x20, 0x30, 0x10, 0x20, 0x30, 0x10, 0x20, 0x30, 0x10, 0x20, 0x30, 0xf1};
	unsigned char		nonce[CRYPTO_NPUBBYTES] = {0x10, 0x20, 0x30, 0x10, 0x20, 0x30, 0x10, 0x20, 0x30, 0x10, 0x20, 0x30, 0x10, 0x20, 0x30, 0xf1};
	unsigned char       msg[MAX_MESSAGE_LENGTH] = {0x10, 0x20, 0x30, 0x10, 0x20, 0x30, 0x10, 0x20, 0x30, 0x10, 0x20, 0x30, 0x10, 0x20, 0x30, 0xf1};
	unsigned char       msg2[MAX_MESSAGE_LENGTH];
	unsigned char		ad[MAX_ASSOCIATED_DATA_LENGTH] = {0x10, 0x20, 0x30, 0x10, 0x20, 0x30, 0x10, 0x20, 0x30, 0x10, 0x20, 0x30, 0x10, 0x20, 0x30, 0xf1};
	unsigned char		ct[MAX_MESSAGE_LENGTH + CRYPTO_ABYTES], ct1[MAX_MESSAGE_LENGTH + CRYPTO_ABYTES];
	//unsigned long long  clen, mlen2;
	//int                 count = 1;
	int                 func_ret, ret_val = KAT_SUCCESS;
	
	unsigned long long mlen, mlen2, clen, adlen;
	unsigned char diff, diff1;
	unsigned char state[ 16 ];
	//unsigned char i1;
	unsigned char count = 0, pos = 0;
	//unsigned char **ddt = diffDistribution(s);
	int i, j, i1, i2, itr, tcount = 0;
	//uint8_t i1;
	
	
	time_t t;
	srand( (unsigned) time( &t ) );

	//init_buffer(key, sizeof(key));
	init_buffer(nonce, sizeof(nonce));
	init_buffer(msg, sizeof(msg));
	init_buffer(ad, sizeof(ad));
	
	mlen = mlen2 = 0;
	adlen = 16;
	clen = 16;
	
	//printDDT( &ddt[ 0 ] );
	
	printf("...............Encryption.....................\n");
	if ( crypto_aead_encrypt(ct, &clen, msg, mlen, ad, adlen, NULL, nonce, key) == 0)
		print(ct);
		
	/*for( i = mlen; i < mlen+32; ++i )
		tag[i-mlen] = ct[i];*/
		
	memcpy(tag1, ct, clen);
		
	if ( crypto_aead_decrypt(msg2, &mlen2, NULL, ct, clen, ad, adlen, nonce, key) == 0) {
	
		print(ct);
		printf("Decryption is successful!!\n\n\n");
	}
	else
		printf("Not successful!!\n\n\n");
	/*copy_ciphertext( ct1, ct );
	print(ct1);	
	if ( crypto_aead_decrypt(msg2, &mlen2, NULL, ct1, clen, ad, adlen, nonce, key) == 0) {
	
		print(ct);
		printf("Decryption1 is successful!!\n\n\n");
	}
	else
		printf("Not successful!!\n\n\n");*/
		
		
		
	count = 0;
	for( itr = 0; itr < 1000; ++itr ) {
	
		pos = 0;
		diff = rand() & 0xff;
		if( diff == 0 )
			diff = rand() & 0xff;
		//diff = 0;
	
		//printf("....................................................faulty forgery by injecting fault at the nibble position (%d,%d)...............................\n\n", pos%4, pos/4);	
		for( i1 = 0; i1 < 1000; ++i1 ) {
		
			//printf("...................................................................................\n\n");
			for( i = 0; i < 16; ++i ) {

				//for( j = 0; j < 4; ++j )
					state[ i ] = 0;
			}
			
			//if(pos%2 == 0)
			state[ pos ] ^= rand() & 0xff;
			
			
			//printf("state difference before sr and mc:\n");
			//print_state( state );
			shift_rows1(state);
			//MixColumn1( state );
			//printf("state difference after sr and mc:\n");
			//print_state( state );
			//copy_ciphertext( ct1, ct );
			memcpy(ct1, ct, clen);
			//printf("non faulty tag::");print(tag1);
			xor_of_diff_tag( state, ct1 );
			//printf("faulty tag difference::");print(ct1);
			//print("in falty ecryption::\n");
			
			//printf("At %d-th query::\n", i1);
			//printf("fault in the dec query\n");	
			if ( faulty_aead_decrypt(msg2, &mlen2, NULL, ct1, clen, ad, adlen, nonce, key, diff, pos ) == 0 ) {
				
				//printf("\n------------------------------------Tag Compare is successful!! at the position position = (%d, %d) with input diff = %x, output diff = %x\n\n", (pos%4), (pos/4),diff,i1);

				//printf("enter into the fun::Recover_state_columnwise\n");
				//Recover_state_columnwise( diff, pos, count, &ddt[ 0 ] );
				//return 0;
				++count;
				
				diff1 = rand() & 0xff;
				while( (diff1 == diff) || (diff1 == 0) )
					diff1 = rand() & 0xff;
				diff = diff1;
			}
				
			//printf("\n\n");
			if(count == number) {
			
				i2 = i1;
				break;
			}							
		}
		tcount += i2;
		printf("...........................iteration number = %d, total count = %d\n\n", itr, tcount);	
		count = 0;
	}
			
	printf("total count = %d\n\n", tcount);		
	end = clock();
	cpu_time_used = ( (double) (end-start))/CLOCKS_PER_SEC;
	int val = tcount/itr;
	printf("Average number of faulty queries to collect %d number of forgeries is %d with time taken = %lf\n\n", number, val, cpu_time_used/itr);
	
	return 0;
}





void fprint_bstr(FILE *fp, const char *label, const unsigned char *data, unsigned long long length)
{    
    fprintf(fp, "%s", label);
        
	for (unsigned long long i = 0; i < length; i++)
		fprintf(fp, "%02X", data[i]);
	    
    fprintf(fp, "\n");
}

void init_buffer(unsigned char *buffer, unsigned long long numbytes)
{
	for (unsigned long long i = 0; i < numbytes; i++)
		buffer[i] = (unsigned char)i;
}
