
#include <stdio.h>  
#include <stdlib.h>     
#include <cstdlib> 
#include <cstdint>
#include <cstring>

#include <string.h>   
#include <iostream>
#include <fstream>
#include <sstream>
#include <iostream>
#include <iomanip>

using namespace std;

#include "Serpent.h"
#include "Serpent_tables.h"
#include "HexConsole.h"


SERPENT::SERPENT()
{
}

SERPENT::~SERPENT()
{
    Security();
}

int      SERPENT::makeKey(unsigned char direction, int keyLen, unsigned char * keyMaterial)
{
	unsigned long i,j;
	unsigned long w[132],k[132];
	int rc , hit;
	keyInstance * key;
  //.

	key = &kschedule;
	
  if(direction != DIR_ENCRYPT &&
     direction != DIR_DECRYPT)
    return BAD_KEY_DIR;

  if(keyLen>256 || keyLen<1)
    return BAD_KEY_MAT;

  key->direction=direction;
  key->keyLen=keyLen;
  //strncpy(key->keyMaterial, keyMaterial, MAX_KEY_SIZE+1);


	// Hard code a 256bit key length. 
	rc=0;
	hit=0;
	while(rc < 8){
		unsigned long A,B,C,D;				
		A = (unsigned long)keyMaterial[hit];
		B = (unsigned long)keyMaterial[hit+1];
		C = (unsigned long)keyMaterial[hit+2];
		D = (unsigned long)keyMaterial[hit+3];
		key->key[rc] = (D<<24)|(C<<16)|(B<<8)|A; // This is a conversion to big endian.
		hit += 4;
		rc++;
	}
	
  
  
  rc = 1;
  if(rc<=0)
    return BAD_KEY_MAT;

  for(i=0; i<keyLen/32; i++)
    w[i]=key->key[i];
  if(keyLen<256)
    w[i]=(key->key[i]&((1L<<((keyLen&31)))-1))|(1L<<((keyLen&31)));
  for(i++; i<8; i++)
    w[i]=0;
  for(i=8; i<16; i++)
    w[i]=ROL(w[i-8]^w[i-5]^w[i-3]^w[i-1]^PHI^(i-8),11);
  for(i=0; i<8; i++)
    w[i]=w[i+8];
  for(i=8; i<132; i++)
    w[i]=ROL(w[i-8]^w[i-5]^w[i-3]^w[i-1]^PHI^i,11);

  RND03(w[  0], w[  1], w[  2], w[  3], k[  0], k[  1], k[  2], k[  3]);
  RND02(w[  4], w[  5], w[  6], w[  7], k[  4], k[  5], k[  6], k[  7]);
  RND01(w[  8], w[  9], w[ 10], w[ 11], k[  8], k[  9], k[ 10], k[ 11]);
  RND00(w[ 12], w[ 13], w[ 14], w[ 15], k[ 12], k[ 13], k[ 14], k[ 15]);
  RND31(w[ 16], w[ 17], w[ 18], w[ 19], k[ 16], k[ 17], k[ 18], k[ 19]);
  RND30(w[ 20], w[ 21], w[ 22], w[ 23], k[ 20], k[ 21], k[ 22], k[ 23]);
  RND29(w[ 24], w[ 25], w[ 26], w[ 27], k[ 24], k[ 25], k[ 26], k[ 27]);
  RND28(w[ 28], w[ 29], w[ 30], w[ 31], k[ 28], k[ 29], k[ 30], k[ 31]);
  RND27(w[ 32], w[ 33], w[ 34], w[ 35], k[ 32], k[ 33], k[ 34], k[ 35]);
  RND26(w[ 36], w[ 37], w[ 38], w[ 39], k[ 36], k[ 37], k[ 38], k[ 39]);
  RND25(w[ 40], w[ 41], w[ 42], w[ 43], k[ 40], k[ 41], k[ 42], k[ 43]);
  RND24(w[ 44], w[ 45], w[ 46], w[ 47], k[ 44], k[ 45], k[ 46], k[ 47]);
  RND23(w[ 48], w[ 49], w[ 50], w[ 51], k[ 48], k[ 49], k[ 50], k[ 51]);
  RND22(w[ 52], w[ 53], w[ 54], w[ 55], k[ 52], k[ 53], k[ 54], k[ 55]);
  RND21(w[ 56], w[ 57], w[ 58], w[ 59], k[ 56], k[ 57], k[ 58], k[ 59]);
  RND20(w[ 60], w[ 61], w[ 62], w[ 63], k[ 60], k[ 61], k[ 62], k[ 63]);
  RND19(w[ 64], w[ 65], w[ 66], w[ 67], k[ 64], k[ 65], k[ 66], k[ 67]);
  RND18(w[ 68], w[ 69], w[ 70], w[ 71], k[ 68], k[ 69], k[ 70], k[ 71]);
  RND17(w[ 72], w[ 73], w[ 74], w[ 75], k[ 72], k[ 73], k[ 74], k[ 75]);
  RND16(w[ 76], w[ 77], w[ 78], w[ 79], k[ 76], k[ 77], k[ 78], k[ 79]);
  RND15(w[ 80], w[ 81], w[ 82], w[ 83], k[ 80], k[ 81], k[ 82], k[ 83]);
  RND14(w[ 84], w[ 85], w[ 86], w[ 87], k[ 84], k[ 85], k[ 86], k[ 87]);
  RND13(w[ 88], w[ 89], w[ 90], w[ 91], k[ 88], k[ 89], k[ 90], k[ 91]);
  RND12(w[ 92], w[ 93], w[ 94], w[ 95], k[ 92], k[ 93], k[ 94], k[ 95]);
  RND11(w[ 96], w[ 97], w[ 98], w[ 99], k[ 96], k[ 97], k[ 98], k[ 99]);
  RND10(w[100], w[101], w[102], w[103], k[100], k[101], k[102], k[103]);
  RND09(w[104], w[105], w[106], w[107], k[104], k[105], k[106], k[107]);
  RND08(w[108], w[109], w[110], w[111], k[108], k[109], k[110], k[111]);
  RND07(w[112], w[113], w[114], w[115], k[112], k[113], k[114], k[115]);
  RND06(w[116], w[117], w[118], w[119], k[116], k[117], k[118], k[119]);
  RND05(w[120], w[121], w[122], w[123], k[120], k[121], k[122], k[123]);
  RND04(w[124], w[125], w[126], w[127], k[124], k[125], k[126], k[127]);
  RND03(w[128], w[129], w[130], w[131], k[128], k[129], k[130], k[131]);

  for(i=0; i<=32; i++)
    for(j=0; j<4; j++)
      key->subkeys[i][j] = k[4*i+j];

  return TRUE;		

}

void     SERPENT::serpent_encrypt(unsigned long * plaintext, unsigned long  * ciphertext )
{
  register unsigned long x0, x1, x2, x3;
  register unsigned long y0, y1, y2, y3;
  unsigned long subkeys[4];  
  //.

  x0=Endianize_Big( plaintext[0] );
  x1=Endianize_Big( plaintext[1] );
  x2=Endianize_Big( plaintext[2] );
  x3=Endianize_Big( plaintext[3] );

  /* Start to encrypt the plaintext x */
  
  
    
 
  quadprep(subkeys  ,  kschedule  ,  0);
  keying(x0, x1, x2, x3, subkeys );
  RND00(x0, x1, x2, x3, y0, y1, y2, y3);
  transform(y0, y1, y2, y3, x0, x1, x2, x3);
  
  quadprep(subkeys  ,  kschedule  ,  1);
  keying(x0, x1, x2, x3, subkeys);
  RND01(x0, x1, x2, x3, y0, y1, y2, y3);
  transform(y0, y1, y2, y3, x0, x1, x2, x3);
  
  quadprep(subkeys  ,  kschedule  ,  2);
  keying(x0, x1, x2, x3, subkeys);
  RND02(x0, x1, x2, x3, y0, y1, y2, y3);
  transform(y0, y1, y2, y3, x0, x1, x2, x3);
  
  quadprep(subkeys  ,  kschedule  ,  3);
  keying(x0, x1, x2, x3, subkeys);
  RND03(x0, x1, x2, x3, y0, y1, y2, y3);
  transform(y0, y1, y2, y3, x0, x1, x2, x3);
  
  quadprep(subkeys  ,  kschedule  ,  4);
  keying(x0, x1, x2, x3, subkeys);
  RND04(x0, x1, x2, x3, y0, y1, y2, y3);
  transform(y0, y1, y2, y3, x0, x1, x2, x3);
  
  quadprep(subkeys  ,  kschedule  ,  5);
  keying(x0, x1, x2, x3, subkeys);
  RND05(x0, x1, x2, x3, y0, y1, y2, y3);
  transform(y0, y1, y2, y3, x0, x1, x2, x3);
  
  quadprep(subkeys  ,  kschedule  ,  6);
  keying(x0, x1, x2, x3, subkeys);
  RND06(x0, x1, x2, x3, y0, y1, y2, y3);
  transform(y0, y1, y2, y3, x0, x1, x2, x3);
  
  quadprep(subkeys  ,  kschedule  ,  7);
  keying(x0, x1, x2, x3, subkeys);
  RND07(x0, x1, x2, x3, y0, y1, y2, y3);
  transform(y0, y1, y2, y3, x0, x1, x2, x3);
  
  
  quadprep(subkeys  ,  kschedule  ,  8);
  keying(x0, x1, x2, x3, subkeys);
  RND08(x0, x1, x2, x3, y0, y1, y2, y3);
  transform(y0, y1, y2, y3, x0, x1, x2, x3);
  
  quadprep(subkeys  ,  kschedule  ,  9);
  keying(x0, x1, x2, x3, subkeys);
  RND09(x0, x1, x2, x3, y0, y1, y2, y3);
  transform(y0, y1, y2, y3, x0, x1, x2, x3);
  
  quadprep(subkeys  ,  kschedule  ,  10);
  keying(x0, x1, x2, x3, subkeys);
  RND10(x0, x1, x2, x3, y0, y1, y2, y3);
  transform(y0, y1, y2, y3, x0, x1, x2, x3);
  
  
  quadprep(subkeys  ,  kschedule  ,  11);
  keying(x0, x1, x2, x3, subkeys);
  RND11(x0, x1, x2, x3, y0, y1, y2, y3);
  transform(y0, y1, y2, y3, x0, x1, x2, x3);
  
  
  quadprep(subkeys  ,  kschedule  , 12);
  keying(x0, x1, x2, x3, subkeys);
  RND12(x0, x1, x2, x3, y0, y1, y2, y3);
  transform(y0, y1, y2, y3, x0, x1, x2, x3);
  
  
  quadprep(subkeys  ,  kschedule  , 13);
  keying(x0, x1, x2, x3, subkeys);
  RND13(x0, x1, x2, x3, y0, y1, y2, y3);
  transform(y0, y1, y2, y3, x0, x1, x2, x3);
  
  
  quadprep(subkeys  ,  kschedule  ,  14);
  keying(x0, x1, x2, x3, subkeys);
  RND14(x0, x1, x2, x3, y0, y1, y2, y3);
  transform(y0, y1, y2, y3, x0, x1, x2, x3);
  
  
  quadprep(subkeys  ,  kschedule  ,  15);
  keying(x0, x1, x2, x3, subkeys);
  RND15(x0, x1, x2, x3, y0, y1, y2, y3);
  transform(y0, y1, y2, y3, x0, x1, x2, x3);
  
  quadprep(subkeys  ,  kschedule  ,  16);
  keying(x0, x1, x2, x3, subkeys);
  RND16(x0, x1, x2, x3, y0, y1, y2, y3);
  transform(y0, y1, y2, y3, x0, x1, x2, x3);
  
  quadprep(subkeys  ,  kschedule  ,  17);
  keying(x0, x1, x2, x3, subkeys);
  RND17(x0, x1, x2, x3, y0, y1, y2, y3);
  transform(y0, y1, y2, y3, x0, x1, x2, x3);
  
  quadprep(subkeys  ,  kschedule  ,  18);
  keying(x0, x1, x2, x3, subkeys);
  RND18(x0, x1, x2, x3, y0, y1, y2, y3);
  transform(y0, y1, y2, y3, x0, x1, x2, x3);
  
  quadprep(subkeys  ,  kschedule  ,  19);
  keying(x0, x1, x2, x3, subkeys);
  RND19(x0, x1, x2, x3, y0, y1, y2, y3);
  transform(y0, y1, y2, y3, x0, x1, x2, x3);
  
  quadprep(subkeys  ,  kschedule  ,  20);
  keying(x0, x1, x2, x3, subkeys);
  RND20(x0, x1, x2, x3, y0, y1, y2, y3);
  transform(y0, y1, y2, y3, x0, x1, x2, x3);
  
  quadprep(subkeys  ,  kschedule  ,  21);
  keying(x0, x1, x2, x3, subkeys);
  RND21(x0, x1, x2, x3, y0, y1, y2, y3);
  transform(y0, y1, y2, y3, x0, x1, x2, x3);
  
  quadprep(subkeys  ,  kschedule  ,  22);
  keying(x0, x1, x2, x3, subkeys);
  RND22(x0, x1, x2, x3, y0, y1, y2, y3);
  transform(y0, y1, y2, y3, x0, x1, x2, x3);
  
  quadprep(subkeys  ,  kschedule  ,  23);
  keying(x0, x1, x2, x3, subkeys);
  RND23(x0, x1, x2, x3, y0, y1, y2, y3);
  transform(y0, y1, y2, y3, x0, x1, x2, x3);
  
  quadprep(subkeys  ,  kschedule  ,  24);
  keying(x0, x1, x2, x3, subkeys);
  RND24(x0, x1, x2, x3, y0, y1, y2, y3);
  transform(y0, y1, y2, y3, x0, x1, x2, x3);
  
  quadprep(subkeys  ,  kschedule  ,  25);
  keying(x0, x1, x2, x3, subkeys);
  RND25(x0, x1, x2, x3, y0, y1, y2, y3);
  transform(y0, y1, y2, y3, x0, x1, x2, x3);
  
  quadprep(subkeys  ,  kschedule  ,  26);
  keying(x0, x1, x2, x3, subkeys);
  RND26(x0, x1, x2, x3, y0, y1, y2, y3);
  transform(y0, y1, y2, y3, x0, x1, x2, x3);
  
  quadprep(subkeys  ,  kschedule  ,  27);
  keying(x0, x1, x2, x3, subkeys);
  RND27(x0, x1, x2, x3, y0, y1, y2, y3);
  transform(y0, y1, y2, y3, x0, x1, x2, x3);
  
  quadprep(subkeys  ,  kschedule  ,  28);
  keying(x0, x1, x2, x3, subkeys);
  RND28(x0, x1, x2, x3, y0, y1, y2, y3);
  transform(y0, y1, y2, y3, x0, x1, x2, x3);
  
  quadprep(subkeys  ,  kschedule  ,  29);
  keying(x0, x1, x2, x3, subkeys);
  RND29(x0, x1, x2, x3, y0, y1, y2, y3);
  transform(y0, y1, y2, y3, x0, x1, x2, x3);
  
  quadprep(subkeys  ,  kschedule  ,  30);
  keying(x0, x1, x2, x3, subkeys);
  RND30(x0, x1, x2, x3, y0, y1, y2, y3);
  transform(y0, y1, y2, y3, x0, x1, x2, x3); 
 
  quadprep(subkeys  ,  kschedule  ,  31);
  keying(x0, x1, x2, x3, subkeys);
  RND31(x0, x1, x2, x3, y0, y1, y2, y3);
  x0 = y0; x1 = y1; x2 = y2; x3 = y3;
  
  quadprep(subkeys  ,  kschedule  ,  32);
  keying(x0, x1, x2, x3, subkeys );
  /* The ciphertext is now in x */

  ciphertext[0] = Endianize_Big(x0);   	// Should we perform endianizing here?
  ciphertext[1] = Endianize_Big(x1);	// Yes.
  ciphertext[2] = Endianize_Big(x2);
  ciphertext[3] = Endianize_Big(x3);
}


void     SERPENT::Serpent_Session( string & asciikey, string & asciiPT ) 
{  
	int w , shri;
	unsigned long uli;	
    unsigned long plaintextB[4];
    unsigned long ciphertextB[4];
	unsigned long ckeyB[8];
	unsigned char keymateria[32];
    string subword;
    string hexword;   
    //.  
    
    
    w=0;
    while(w<4){
    	// Make the plaintext into binary equivalent.
        subword 		= asciiPT.substr (w*8 , 8 );         
        plaintextB[w]	= ASCII2int( subword );	
		w++;	   		
    }
    
    w=0;
    while(w<8){		
		// Make the key into binary equivalent.
		subword  = asciikey.substr (w*8 , 8 );         
        ckeyB[w] = ASCII2int( subword );        
        w++;
    }
    
	
	shri = 0;
	w=0;
    while(w<8){	
		fragmentword( 
			ckeyB[w] , 
			keymateria[shri] , 
			keymateria[shri+1] , 
			keymateria[shri+2] , 
			keymateria[shri+3] 
		)			;
		shri +=4;
        w++;
    }
      
	    
    // *!
    this->makeKey(  DIR_ENCRYPT ,  256 , keymateria );
    this->serpent_encrypt( plaintextB ,  ciphertextB );
    // *!
    
    cout << "____ Serpent encryption session, class ____" << endl;
    cout << "   key=";
    subword = asciikey.substr(0 , 32);
    cout << subword << endl;
    
    cout << "       ";
    subword = asciikey.substr(32 , 32);
    cout << subword << endl;
    
    cout << " plain=";
    cout << asciiPT << endl; 
    
    cout << "cipher="; 
    
	w=0;
    while(w<4){
		HexConsole(  ciphertextB[w] ); 
		w++;
	}    
	
    cout << endl;
    cout << endl; 
}

     
void     SERPENT::Security( void )
{
	int sec , uri;
	
	//.
	kschedule.direction = 0xFF;
	kschedule.keyLen = -29292;
	sec=0;
	while( sec < (MAX_KEY_SIZE+1)) {
		kschedule.keyMaterial[sec] = '?';
		sec++;
	}
	
	sec=0;
	while( sec < 8 ) {
		kschedule.key[sec] = 0xABCD1234;
		sec++;
	}
	
	sec=0;
	while( sec < 4 ) {
		uri =0;
		while(uri<33) {
			kschedule.subkeys[uri][sec] = 0x5678CDEF;
			uri++;
		}
		sec++;
	}	
}

unsigned long  SERPENT::Endianize_Big( unsigned long nist )
{
	unsigned long A,B,C,D;
    unsigned long ret;
    //.
    A = (nist>>24) & (0x00FF);
    B = (nist>>16) & (0x00FF);
    C = (nist>>8 ) & (0x00FF);
    D = (nist)     & (0x00FF);
    
    ret = A | (B<<8) | (C<<16) | (D<<24) ;
    return ret;  
}



// * * //









