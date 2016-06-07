/*

HiroseKDF is a class for a key derivation function. 

It accepts a message of any length up to 511 Megabytes and returns a digest of 256 bits.
The hash function will accept messages whose length is specified at bit-level precision.
When hashing binary data, the supplied length must be given in BITS, not bytes. 
The hash function is derived from a one-way cryptographic compression function.


The OWCC function is described mathematically in the paper titled, 

  "How to Construct Double-Block-Length Hash Functions"  
    	by Shoichi Hirose , (University of Fukui)
*/

/*
Hirose's publication contains neither sourcecode nor pseudocode. Much of what appears here
are my own embellishments required to transform a mere mathematical description to a 
genuine, robust Cryptographic Hash Function.  Details of the embellishments follow.

1.)
HiroseKDF uses the SERPENT block cipher, in substitute of Rijndael/AES.  

2.)
Instead of using a constant 'C', 
there is instead a 128bit counter, which is iterated upon each block.  The length of
the message is placed in a prefix block, along with 'tailing' bits that do not fit 
along a byte boundary. The counter is composed of 3 linear congruential generators,
each acting on a 40-bit integer, all desynchronized with a unique modulus.

3.)
In order to further obfuscate the IV's of the G and H keys, the process continues  
back over the message in two passes. Notice that odd rounds of hashing reverses the 
incoming block and substitutes the  bytes using a non-linear S-box. 

4.)
The number of passes is specified by 'MAXHASHROUNDS'.
You could technically increase this number and recompile, if you really wanted to.
Mathematically speaking, there is no reason to do this. However, some may want
to manipulate this in order to gain the "intentional slowness" -- (a desirable
attribute for key derivation functions.)

5.) 
Although none of the above embellishments appear in the original paper, I have 
made no changes that could impact the security of Hirose's construction.


Saturday, June 04, 2016
10:21:18 PM
*/





#include <stdint.h>
#include <stdio.h>   
#include <string.h>   
#include <stdlib.h>     
#include <stdint.h>

#include <iostream>
#include <string>
#include <cstdlib>


using namespace std;

#include "Serpent.h"
#include "hiroseKDF.h"
#include "DebugFlagsKDF.h"


ubyte8_t hirobytesubs[] = {
0x46,0xFF,0x61,0x74,0x80,0x7E,0xA5,0x87,0x7C,0x4A,
0x40,0x7D,0xF5,0xD7,0x47,0xC2,0x6F,0x35,0x81,0xF4,
0xE6,0x2E,0xD8,0x58,0xCC,0x3B,0xD1,0xC0,0x5A,0xE1,
0x8E,0x42,0xAD,0xC7,0x3D,0xEE,0x08,0xD2,0x8F,0x45,
0x6D,0x07,0x39,0x91,0x14,0x8D,0xB9,0x86,0xFD,0x4B,
0xDF,0x54,0x15,0x9D,0xB2,0xED,0xF0,0x98,0xAB,0x4C,
0x9B,0xEA,0x8A,0xAF,0x0A,0x48,0xAE,0x7B,0x70,0x92,
0x96,0x69,0x7A,0x4E,0xF6,0x2B,0x95,0x30,0xFC,0x84,
0x37,0x9F,0xDB,0xA8,0xFE,0x26,0xD5,0xD9,0xD3,0x24,
0xC6,0x10,0x79,0x6B,0x90,0xBD,0x8C,0xCA,0x72,0x1C,
0x44,0xFA,0xC1,0x78,0xB8,0x93,0x82,0xF9,0x01,0x5E,
0x68,0x83,0x9A,0xBB,0xCD,0x55,0xB0,0x2D,0x0E,0x6A,
0xC4,0xA0,0xBC,0xE0,0xC8,0x56,0x25,0x1D,0x38,0xF1,
0xF2,0x94,0x52,0x41,0x89,0xCF,0x50,0x29,0x85,0xAC,
0x31,0x51,0x60,0x22,0x34,0x33,0x59,0x0F,0x0D,0xDD,
0xA4,0xA2,0x5D,0x04,0x99,0x66,0x9C,0xB7,0x09,0x20,
0xDA,0xA7,0x32,0x64,0x27,0xBF,0x2C,0xC5,0x63,0x13,
0x11,0xD4,0xB1,0x9E,0xE4,0x06,0x3C,0xF3,0x65,0x02,
0x57,0x00,0xCE,0x88,0xEC,0x77,0xE3,0x12,0x5F,0x03,
0x3E,0x1A,0x17,0xDC,0xD6,0x6C,0x36,0xAA,0x1B,0xE9,
0xBE,0x1F,0x28,0xA9,0xC3,0x3A,0x43,0xB5,0x97,0x76,
0xA1,0x21,0xDE,0xE8,0x0C,0x4F,0xB4,0xB6,0x2A,0xE5,
0x8B,0xE2,0xB3,0x49,0x1E,0xA6,0x16,0x3F,0xBA,0x7F,
0x0B,0x05,0xA3,0xEF,0x73,0xFB,0x67,0x18,0x5C,0xC9,
0xF8,0x5B,0xCB,0x71,0x19,0xD0,0x4D,0x23,0x53,0xF7,
0x75,0xEB,0xE7,0x62,0x6E,0x2F  };

uint32_t IV_g[] = {
0xa6f64ae6,	0x618b821e,
0xcd040b3e, 0x78140e75  };

uint32_t IV_h[] = {
0x9756a290, 0x0133ab53,
0x17dde6f2, 0xd95e9c8d  };


HiroseKDF::HiroseKDF()
{
	// //
}

HiroseKDF::~HiroseKDF()
{
	// //
}

void HiroseKDF::HashBinary( ubyte8_t * binmsg , uint32_t msg_length_in_BITS ,  ULint    * digest )
{
	ubyte8_t arrdig[32];
	HashBinary( binmsg , msg_length_in_BITS , arrdig );
	ReturnWordTail( digest , arrdig );
}


void HiroseKDF::HashText( char * txtmsg , ubyte8_t * digest )
{
	uint32_t lenu;
	KDFucpointer cast;
	 //.
	cast = reinterpret_cast<KDFucpointer>( txtmsg );
	lenu = (uint32_t)strlen(txtmsg);
	if( lenu > MAXHMSGLENGTH ) {
		lenu = MAXHMSGLENGTH;
	}
	lenu = lenu*8;
	HashBinary( cast , lenu , digest );
}


void HiroseKDF::HashText( char * txtmsg , ULint    * digest )
{
	ubyte8_t arrdig[32];
	HashText( txtmsg , arrdig );
	ReturnWordTail( digest , arrdig );		
}

void HiroseKDF::HashText( const char * txtmsg  , ubyte8_t * digest )
{
	uint32_t lenu;
	KDFcucpointer cast;
	 //.
	cast = reinterpret_cast<KDFcucpointer>( txtmsg );
	lenu = (uint32_t)strlen(txtmsg);
	if( lenu > MAXHMSGLENGTH ) {
		lenu = MAXHMSGLENGTH;
	}
	lenu = lenu*8;
	HashBinary( cast , lenu , digest );
}


void HiroseKDF::HashText( const char * txtmsg  , ULint    * digest )
{
	ubyte8_t arrdig[32];
	HashText( txtmsg , arrdig );
	ReturnWordTail( digest , arrdig );
}

void HiroseKDF::HashText( std::string & txtmsg , ubyte8_t * digest )
{
	char 		car;
	ubyte8_t 	bincar;
	ubyte8_t * 	sallo;	
	uint32_t 	Ltm , cv;
	 //.
	Ltm = (uint32_t) (  txtmsg.length()  );
	if( Ltm > MAXHMSGLENGTH ) {
		Ltm = MAXHMSGLENGTH;
	}
	
	sallo = new ubyte8_t[Ltm];
	
	for(cv=0;cv<Ltm;cv++){
		car = txtmsg.at( (size_t)cv  );	
		bincar = (ubyte8_t)(car);
		sallo[cv] = bincar;
	}
	
	HashBinary( sallo  , (Ltm*8) , digest );
	
	for(cv=0;cv<Ltm;cv++){
		sallo[cv] = 0x00;	
	}
	delete [] sallo;
	
}

void HiroseKDF::HashText( std::string & txtmsg , ULint    * digest )
{
	ubyte8_t arrdig[32];
	HashText( txtmsg , arrdig );
	ReturnWordTail( digest , arrdig );	
}


void HiroseKDF
::HashBinary( const ubyte8_t * binmsg , uint32_t msg_length_in_BITS ,  ubyte8_t * digest )
{
	int cbi;
	int round, rnd_mod_two;
	uint32_t mb ;
	h_Block Gout;
	h_Block Hout;
	ubyte8_t currblock[16];
	 //.

#ifdef 	KDFSRCDBG
	DHBcalls=0;
	cout << std::dec;
	cout << "msg_length_in_BITS =" << msg_length_in_BITS << endl;
#endif
	 
	 
	BoteSet( Gi , IV_g[0] , IV_g[1] , IV_g[2] , IV_g[3] );
	BoteSet( Hi , IV_h[0] , IV_h[1] , IV_h[2] , IV_h[3] );
	BoteSet( C  , 0 , 0 , 0 , 0 );
	for(cbi =0; cbi < 53; cbi ++){
		IterateConstant ( C );
	}
	
	// Note  'round' is counting off entire rounds of hashing.  
	// A single round covers the entire message from end to end.
	//  This should not be confused with message blocks.
	
	message = binmsg;
	DecoratePad( msg_length_in_BITS ); 
	
	for( round=0;  round < MAXHASHROUNDS ;  round ++ ) {
		
		rnd_mod_two = round%2;
		
		if( rnd_mod_two == 1 ) {
			BoteReverSub(  M_f );
		}
		
		Hirose_roundfxn ( 	M_f , Gi  , Hi  , C   , Gout ,  Hout );
#ifdef 	KDFSRCDBG
		DebugHashBinary ( 	M_f , Gi  , Hi  , C   , Gout ,  Hout );
#endif
		BoteCopy( Gi , Gout ); 
		BoteCopy( Hi , Hout );
		IterateConstant( C );
		
		if( mlen > 7 ) {
			cbi = 0;
			mb = 0;
			while( mb < maxBlen ) {
				currblock[ cbi ] = message[ mb ];
				cbi++;
				if( cbi > 15 ) {
					BytesToBote ( Mi , currblock ,  0 ); 
					if( rnd_mod_two == 1 ) {
						BoteReverSub( Mi );
					}
					Hirose_roundfxn ( 	Mi , Gi  , Hi  , C   , Gout ,  Hout );
#ifdef 	KDFSRCDBG
					DebugHashBinary ( 	Mi , Gi  , Hi  , C   , Gout ,  Hout );
#endif
					BoteCopy( Gi , Gout ); 
					BoteCopy( Hi , Hout );
					IterateConstant( C );
					cbi=0;
				}
				mb++;
			}
			
			if( (cbi > 0) &&  (cbi < 16) ) {
				// The while() loop, above, terminated in the middle of a block.
				//   We need to pad the rest of the block.
				int n=0;
				while( cbi < 16 ) {
					currblock[ cbi ] = StreamPad( n );
					n++;
					cbi++;
				}
				BytesToBote ( Mi , currblock ,  0 ); 
				if( rnd_mod_two == 1 ) {
					BoteReverSub( Mi );
				}
				Hirose_roundfxn ( 	Mi , Gi  , Hi  , C   , Gout ,  Hout );
#ifdef 	KDFSRCDBG
				DebugHashBinary ( 	Mi , Gi  , Hi  , C   , Gout ,  Hout );
#endif
				BoteCopy( Gi , Gout ); 
				BoteCopy( Hi , Hout );
				IterateConstant( C );
				cbi=0;
				
				
			}
			
		}
		
		if( (mlen >0) && (mlen<8) ) {
			// This is no longer a special case.
			//  M_f[] will contain fragments of this message and its length.
		}
	}
	
	BoteToBytes ( digest , Gout , 0 );
	BoteToBytes ( digest , Hout , 16 );
	Security();
}


void HiroseKDF::DebugHashBinary( h_Block & mi , 
	                      h_Block & gi , 
						  h_Block & hi , 
						  h_Block & Crf , 
	                      h_Block & g_out , 
	                      h_Block & h_out )
{
	std::string vv;
	
	DHBcalls++;
	cout << endl << endl;
	cout << std::dec;
	cout << "Hirose_roundfxn()  call no." << DHBcalls << "____________" << endl;
	
	vv = "Mi   = ";
	BlockConsole( vv , mi );
	ASCII_if_KeyType( vv , mi );
	
	vv = "Gi   = ";
	BlockConsole( vv , gi );
	vv = "Hi   = ";
	BlockConsole( vv , hi );
	vv = "C    = ";
	BlockConsole( vv , Crf );
	vv = "Gout = ";
	BlockConsole( vv , g_out );
	vv = "Hout = ";
	BlockConsole( vv , h_out );
	cout << endl;
	
}

void HiroseKDF::BlockConsole( string & varn , h_Block & bote )
{
	int n;
	uint32_t rd;
	
	cout << varn;
	for(n=0;n<4;n++){
		rd = BoteIndex(bote,n);
		HexiWord(rd);
	}
	cout << endl;
}

void HiroseKDF::HexiWord( uint32_t uw )
{
	char wdat[12];
	sprintf( wdat , "%08X", uw );
	cout << wdat;
}

void HiroseKDF::ASCII_if_KeyType( string & varn , h_Block & bote )
{
	int k, keytypes;
	ubyte8_t arrver[16];
	char asc[16];
	 //.
	 
	BoteToBytes ( arrver , bote , 0 );
	keytypes=0;
	for(k=0;k<16;k++){
		if( IsKeyboardtype( arrver[k] ) ) {
			keytypes++;
		}
	}
	
	if( keytypes == 16 ) {
		cout << varn;
		cout << "[";
		for( k =0; k < 16; k++){
			if(  arrver[k] > 31 ){
				asc[k] = (char)arrver[k];
			} else {
				asc[k] = '?';
			}
			cout << (char)(asc[k]);
		}
		cout << "]" << endl;
	}
	

}

void HiroseKDF::Hirose_roundfxn( 
						  h_Block & mi , 
	                      h_Block & gi , 
						  h_Block & hi , 
						  h_Block & Crf , 
	                      h_Block & g_out , 
	                      h_Block & h_out 
						  )
{
	h_Block hb;
	h_Block hi_xor_C;
	//.
	
	BlockCipher ( gi 	, hi , mi , g_out );
	BoteXOR		( hb 	, mi , g_out      );
	BoteCopy	( g_out , hb              );
	
	BoteXOR		( hi_xor_C , hi , Crf );
	BlockCipher ( gi , 	hi_xor_C , mi , h_out );
	BoteXOR		( hb ,  mi , h_out );
	BoteCopy	( h_out , hb );
}


void HiroseKDF::IterateConstant( h_Block & bote )
{
	
/*
[.... .... .... ....]    all bytes in the block
[BWWW WWEE EEER RRRR]    all 40bit counters in the block
[XXXX YYYY UUUU VVVV]    all words in the block. 
*/
	uint64_t Rctr;   // lower counter
	uint64_t Ectr;   // middle counter
	uint64_t Wctr;   // high counter
	uint64_t t , f;      
	uint32_t joker;   // joker 
	uint32_t as, bs, cs, ds;
	uint32_t hiw , low;
	//
	
	// Extract the three counters from the bote block.
	t = (uint64_t)(  bote.U & 0x000000FF );
	t = t << 32;
	f = (uint64_t)bote.V;
	Rctr =  t | f;
	
	f = (uint64_t)(  bote.U >> 8 );
	t = (uint64_t)(  bote.Y & 0x0000FFFF );
	t = t << 24;
	Ectr = t | f;
	
	f = (uint64_t)(  bote.Y >> 16 );
	t = (uint64_t)(  bote.X & 0x00FFFFFF );
	t = t << 16;
	Wctr =  t | f;
	
	joker = (bote.X & 0xFF000000) >> 24;
	
	// Iterate the counters  as linear conqruential generators.
	/* 
	*/
	Wctr =  (Wctr + 0x000000D3BF8B6753ULL)  %  0x000000FFFFFFFFA9ULL;
	Ectr =  (Ectr + 0x000000B5DFA76D35ULL)  %  0x000000FFFFFFFF59ULL;
	Rctr =  (Rctr + 0x000000B3C7976B43ULL)  %  0x000000FFFFFFFF3DULL;
	joker = (joker + 0x13) % 0x100;
	
	// Insert the counters back into the bote block.
	bote.V =  (uint32_t)( Rctr & 0xFFFFFFFF );
	t = (Rctr >> 32) |  (Ectr << 8);
	bote.U = (uint32_t)( t & 0xFFFFFFFF );
	
	t = (Ectr >> 24) | (Wctr << 16);
	bote.Y = (uint32_t)( t & 0xFFFFFFFF );
	
	t = (Wctr >> 16);
	bote.X = (uint32_t)( t & 0xFFFFFFFF )  | (joker<<24);
}



void HiroseKDF::BlockCipher ( h_Block & frontkey , h_Block & backkey , h_Block & PT , h_Block & CT )
{	
	int n , j;
	SERPENT snake; 
	uint32_t bin;
	unsigned long ul_PT[4];
	unsigned long ul_CT[4];
	unsigned char kos[32];
	uint32_t fbwords[8];
	uint32_t kby[4];	
	
	for( n =0;n<4;n++) {
		ul_PT[n] = (unsigned long)( BoteIndex(PT , n) );
		fbwords[n] = BoteIndex(frontkey, n);
	}

	for( n =0;n<4;n++) {
		fbwords[n+4] = BoteIndex(backkey, n);
	}
	
	
	j=0;
	for(n=0;n<8;n++) {
		bin = fbwords[n];
		ChanSplit ( bin , kby[0] , kby[1] , kby[2] , kby[3] );
		kos[j  ] = (unsigned char)kby[0];
		kos[j+1] = (unsigned char)kby[1];
		kos[j+2] = (unsigned char)kby[2];
		kos[j+3] = (unsigned char)kby[3];
	    j +=4;
	}
	
	snake.makeKey( DIR_ENCRYPT , 256 , kos );
	snake.serpent_encrypt( ul_PT , ul_CT  );
	
	BoteSet( CT , 
			(uint32_t)ul_CT[0] , 
			(uint32_t)ul_CT[1] , 
			(uint32_t)ul_CT[2] , 
			(uint32_t)ul_CT[3] );
			
}


void HiroseKDF::DecoratePad( unsigned long int supplen )
{
	/*
	Hirose's  compression function demands that the message length is exactly a multiple of 128 bits,
	 so that the entire message can be broken up into nice blocks all of equal size.
	 That will only be true in an idealized world.  
	 
	 A cryptographic hash function must be sufficiently robust to accept and digest a message length
	 of any amount of bits, including pathological cases, like zero length. 
	 
	 When and if the construction of a block 'runs out' of message material, the rest of the block
	 must be padded with something or another.  
	 
	 DecoratePad() handles the bizarre pathological cases that can arrise with 
	 robust message lengths, specified at bit precision.    
	 
	 Later code will not 'see' these corrections, and perform blissfully AS IF the user supplied
	   a perfectly-sized message.
	*/
	
	
	int n , st;
	int Lstripe , sidx;
	uint32_t tail;
	uint32_t decot;
	h_Block shftblock;
	ubyte8_t transport[16];
	ubyte8_t stripe[16];
	//.
	
	if( supplen  == 0 ) {
		/* 
			Response for the zero-length message.
			The compression function will hash this single h_Block , literally given here as hex bytes.
			{ 00 F0 E0 D0 ,  00 00 00 00 ,  00 00 00 00 , 00 00 00 00 }
		*/
		mlen = 0;
		maxBlen = 0;  
		BoteSet( M_f, 0x00F0E0D0 , 0 , 0 , 0 );
		return;
	}
	
	tail = supplen % 128; 
	if( tail == 0 ) {
		/*
			A miracle has occured.  
			The user supplied a message that is exactly the right size.
		*/
		mlen = supplen;
		maxBlen = supplen / 8;
		//  no messpad[] is needed. It won't be used.
		BoteSet( M_f, (uint32_t)0 , (uint32_t)mlen , (uint32_t)mlen , (uint32_t)mlen );
		return;
	} 
	
	tail = supplen % 8;
	if( (tail == 0) && (supplen > 128)  ) {
		/*
			The user is sane and has supplied a message whose length ends on a byte boundary.
			Since the message is longer than a block, we can directly copy it into the pad.
		*/
		mlen = supplen;
		maxBlen = supplen / 8; 
		BytesToBote ( shftblock , message , 0 ); 
		BoteSet( messpad , shftblock.X , shftblock.Y , shftblock.U , shftblock.V );
		BoteSet( M_f, (uint32_t)0 , (uint32_t)mlen , (uint32_t)mlen , (uint32_t)mlen );
		return;
	}
	
	tail = supplen % 8;
	if( (tail == 0) && (supplen < 128)  ) {
		/*
			The user is sane and has supplied a message whose length ends on a byte boundary.
			The message is shorter than a full block.  We must stripe it into the pad.
		*/
		mlen = supplen;
		maxBlen = supplen / 8; 
		Lstripe = 0;
		st = (int)(  maxBlen ); 
		for( n = 0; n < st ; n++ ){
			stripe[ Lstripe ] = message[n];
			Lstripe ++;
		}
		for( n =0; n < 16; n++ )
		{
			transport[n] = stripe[ (n%Lstripe) ];
		}
		BytesToBote ( messpad , transport , 0 ); 
		BoteSet( M_f, (uint32_t)0 , (uint32_t)mlen , (uint32_t)mlen , (uint32_t)mlen );
		return;
	}
	
	tail = supplen % 8;
	if( (tail > 0) && (supplen > 128)  ) {
		/*
			The user wants a message that ends at a bit location off a byte boundary.
			Since the message is longer than a block, we can easily copy it into the pad.
			However we must create a "padded byte" and add it into the M_f final block.
		*/
		mlen = supplen;
		maxBlen = supplen / 8;    // This will not contain tailing bits.
		BytesToBote ( shftblock , message , 0 ); 
		BoteSet( messpad , shftblock.X , shftblock.Y , shftblock.U , shftblock.V );
		decot = DecorateTail(  message[maxBlen] , tail );
		BoteSet( M_f, decot , (uint32_t)mlen , (uint32_t)mlen , (uint32_t)mlen );
		return;
		
	}
	
	
	tail = supplen % 8;
	if( (tail > 0) ) {
		if(supplen < 8)  {
			/*
				The user is some kind of sadist who wants to hash a message that is shorter
				than 8 bits. 
				*/
			mlen = supplen;
			maxBlen = 0;  // Force the streamer to start using the pad.
			
			//  This section is no longer used.
			//transport[0] = MaskTail( message[0] , tail );
			//for(n=1;n<16;n++){
			//	transport[n] = transport[0];
			//}
			//BytesToBote ( messpad , transport , 0 );
			decot = DecorateTail(  message[0] , tail );
			BoteSet( M_f, decot , (uint32_t)mlen , (uint32_t)mlen , (uint32_t)mlen ); 
			return;
			
		} else {
			/*
				The user wants to hash a messsage whose length L is  8 < L < 128
				In which L does not fall on a byte boundary.
			*/
				mlen = supplen;
				maxBlen = supplen / 8;  // This will not include the 'tailing' bits off the end.
				Lstripe = 0;
				st = (int)(  maxBlen ); 
				for( n = 0; n < st ; n++ ){
					stripe[ Lstripe ] = message[n];
					Lstripe ++;
				}
				for( n =0; n < 16; n++ )
				{
					transport[n] = stripe[ (n%Lstripe) ];
				}
				BytesToBote ( messpad , transport , 0 ); 
				decot = DecorateTail(  message[maxBlen] , tail );
				BoteSet( M_f, decot , (uint32_t)mlen , (uint32_t)mlen , (uint32_t)mlen );
				return;
		}
	}
	
}

uint32_t HiroseKDF::DecorateTail( ubyte8_t tailbox , int count )
{
	uint32_t fw, D;
	D = (uint32_t) (   MaskTail(tailbox , count)  );
	ChanCombine( fw , D,D,D,D );
	return( fw );
}

ubyte8_t HiroseKDF::MaskTail( ubyte8_t tailbox , int sigbits )
{
	
	switch( sigbits ) {
		case 1 : return(  tailbox & 0x80 );		break;
		case 2 : return(  tailbox & 0xC0 );		break;
		case 3 : return(  tailbox & 0xE0 );		break;
		case 4 : return(  tailbox & 0xF0 );		break;
		case 5 : return(  tailbox & 0xF8 );		break;
		case 6 : return(  tailbox & 0xFC );		break;
		case 7 : return(  tailbox & 0xFE );		break;
		case 8 : return(  tailbox & 0xFF );		break;
	}
	
	return tailbox;
}



ubyte8_t HiroseKDF::StreamPad( int locus )
{
	return (
		BoteRead( messpad  , locus ) 
	);	
}


uint32_t HiroseKDF::WordReverse( uint32_t w )
{
	uint32_t ret;
	uint32_t Aq,Bq,Cq,Dq;
	ChanSplit  (  w  , Aq, Bq, Cq, Dq )
	ChanCombine( ret , Dq, Cq, Bq, Aq );
	return ( ret );
}

void HiroseKDF::ReturnWordTail( ULint * wdig , ubyte8_t * bdig )
{
	int w;
	h_Block retbote;
	BytesToBote ( retbote ,  bdig ,  0 );
	for(w=0;w<4;w++){
		wdig[w] = BoteIndex(retbote,w);
	}
	BytesToBote ( retbote ,  bdig ,  16 );
	for(w=0;w<4;w++){
		wdig[w+4] = BoteIndex(retbote,w);
	}
}

void HiroseKDF::BoteReverse( h_Block & bote )
{
	int n;
	uint32_t K;
	uint32_t rr[4]; 
	
	for(n=0;n<4;n++){
		K = BoteIndex(bote, n);
		rr[n] = WordReverse( K );
	}
	bote.X = rr[3];
	bote.Y = rr[2];
	bote.U = rr[1];
	bote.V = rr[0];
}


void HiroseKDF::BoteSubsti(  h_Block & bote )
{
	int n;
	ubyte8_t newb[16];
	ubyte8_t data;
	//.
	
	BoteToBytes( newb , bote , 0 );
	for(n =0; n < 16; n++ ){
		data    = newb[n];
		newb[n] = hirobytesubs[data];
	}
	BytesToBote( bote , newb ,  0 ); 
	
}

void HiroseKDF::BoteReverSub(  h_Block & bote )
{
	BoteReverse( bote );
	BoteSubsti ( bote );
}

void HiroseKDF::BoteCopyPartial( h_Block & dest , h_Block  & src , int beg , int end )
{
	ubyte8_t bversi[16];
	 //.
	BoteToBytes ( bversi , src, 0 );
	BoteCopyPartial( dest , bversi , beg , end );
}

void HiroseKDF::BoteCopyPartial( h_Block & dest , ubyte8_t * src , int beg , int end )
{
	int bcp;
	ubyte8_t arrver[16];
	BoteToBytes( arrver , dest , 0 );
	for(bcp=beg ; bcp <= end;  bcp++) {
		arrver[ bcp ] = src[ bcp ];
	}
	BytesToBote( dest , arrver , 0 );
}

void HiroseKDF::BoteWrite( h_Block & dest , ubyte8_t src , int idx )
{
	ubyte8_t  arrver[16];
	  //.
	BoteToBytes( arrver , dest , 0 );
	arrver[idx] = src;
	BytesToBote( dest , arrver , 0 ); 
}

ubyte8_t HiroseKDF::BoteRead(  h_Block & src , int idx )
{
	ubyte8_t  arrver[16];
	  //.
	BoteToBytes( arrver , src , 0 );
	return(  arrver[idx] ); 
}

void  HiroseKDF::BoteToBytes ( ubyte8_t * dest , h_Block & src, uint32_t oset )
{
	int ixn;
	uint32_t n , j;
	uint32_t bin;
	uint32_t frag[4];
	
	//.
	
	j=oset;
	for(n=0; n < 4; n++){
		ixn = (int)n;
		bin = BoteIndex( src , ixn ); 
		ChanSplit(  bin , frag[0] , frag[1] , frag[2] , frag[3]  );
		dest[j  ] = (ubyte8_t)frag[0];
		dest[j+1] = (ubyte8_t)frag[1];
		dest[j+2] = (ubyte8_t)frag[2];
		dest[j+3] = (ubyte8_t)frag[3];
		j+=4;
	}
}

void HiroseKDF::BytesToBote ( h_Block & dest , ubyte8_t * src , uint32_t oset )
{
	const ubyte8_t * passcnst;
	
	passcnst = src;
	BytesToBote( dest , passcnst , oset ); 
}


void HiroseKDF::BytesToBote ( h_Block & dest , const ubyte8_t * src , uint32_t oset )
{
	uint32_t n , j;
	uint32_t bin;
	uint32_t bwords[4];
	uint32_t frag[4];
	//.
	
	
	j=oset;
	for(n=0; n < 4; n++){
		frag[0] = (uint32_t)src[j  ];
		frag[1] = (uint32_t)src[j+1];
		frag[2] = (uint32_t)src[j+2];
		frag[3] = (uint32_t)src[j+3];
		
		ChanCombine(  bin , frag[0] , frag[1] , frag[2] , frag[3]  );
		bwords[n] = bin;
		j+=4;
	}
	
	BoteSet( dest , bwords[0] , bwords[1] , bwords[2] , bwords[3] );
}


void HiroseKDF::Security( void )
{
	h_Block eraser;
	
	BoteSet( eraser , 0xAAAABBBB , 0xCCCCDDDD , 0xEEEEFFFF , 0x12345678 );
	mlen		=0;
	maxBlen		=0;
	DHBcalls	=0;   // could expose message length.
	BoteCopy( Hi , eraser );
	BoteCopy( Gi , eraser );
	BoteCopy( Mi , eraser );
	BoteCopy( C  , eraser ); // could expose message length
	BoteCopy( messpad , eraser );
	BoteCopy( M_f , eraser );
}


