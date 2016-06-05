/*

HiroseKDF is a class for a key derivation function. 

It accepts a message of any length up to 536 Megabytes and returns a digest of 256 bits.
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




#define ULint						unsigned long int
#define ubyte8_t 					unsigned char
#define ChanSplit(W,a,b,c,d)		{a=(W>>24)&(0xFF);b=(W>>16)&(0xFF);c=(W>>8)&(0xFF);d=(W)&(0xFF);}
#define ChanCombine(W,a,b,c,d)		{W=(a<<24)|(b<<16)|(c<<8)|(d);}
#define BoteSet(B,x,y,u,v)         	{B.X=x;B.Y=y;B.U=u;B.V=v;}
#define h_Block						Blockonetwoeight
#define MAXHASHROUNDS				(2)


typedef unsigned char* KDFucpointer;
typedef const unsigned char* KDFcucpointer;

typedef struct stXYUV {
	uint32_t X;
	uint32_t Y;
	uint32_t U;
	uint32_t V;
} Blockonetwoeight;


class HiroseKDF  {
// Data
public:
	const ubyte8_t * message;
	
private:
	ULint mlen;  // This length is the message length in BITS. 
    ULint maxBlen;  // This is the message length in BYTES. 
    int DHBcalls;
    h_Block Hi;
    h_Block Gi;
    h_Block Mi;
    h_Block C;
    h_Block messpad;
    h_Block M_f;
    

    
    
// Functionality
public:
    HiroseKDF();
    ~HiroseKDF();
    
    void HashBinary( const ubyte8_t * binmsg , uint32_t msg_length_in_BITS ,  ubyte8_t * digest );
    void HashBinary( ubyte8_t * binmsg ,       uint32_t msg_length_in_BITS ,  ULint    * digest );
    void HashText( char * txtmsg , ubyte8_t * digest );
    void HashText( char * txtmsg , ULint    * digest );
    void HashText( const char * txtmsg  , ubyte8_t * digest );
    void HashText( const char * txtmsg  , ULint    * digest );
    void HashText( std::string & txtmsg , ubyte8_t * digest );
    void HashText( std::string & txtmsg , ULint    * digest );
  	void Security( void );
  	
private: 
    void Hirose_roundfxn( h_Block & mi , 
	                      h_Block & gi , 
						  h_Block & hi , 
						  h_Block & Crf , 
	                      h_Block & g_out , 
	                      h_Block & h_out );
	                      
     
    void BlockCipher ( h_Block & frontkey , h_Block & backkey , h_Block & PT , h_Block & CT );
    void IterateConstant( h_Block & bote );
    void DecoratePad( unsigned long int supplen );
    uint32_t DecorateTail( ubyte8_t tailbox , int count ); 
    ubyte8_t MaskTail( ubyte8_t tailbox , int sigbits ); 
    ubyte8_t StreamPad( int locus ); 
    void BoteToBytes ( ubyte8_t * dest , h_Block & src , uint32_t oset );
    void BytesToBote ( h_Block & dest , ubyte8_t * src ,  uint32_t oset ); 
    void BytesToBote ( h_Block & dest , const ubyte8_t * src ,  uint32_t oset );
    void BoteReverse( h_Block & bote );
	void BoteSubsti(  h_Block & bote );
	void BoteReverSub(  h_Block & bote );
	void BoteCopyPartial( h_Block & dest , h_Block  & src , int beg , int end );
	void BoteCopyPartial( h_Block & dest , ubyte8_t * src , int beg , int end );
	void BoteWrite( h_Block & dest , ubyte8_t src , int idx );
	ubyte8_t BoteRead(  h_Block & src , int idx );
	void DebugHashBinary( h_Block & mi , 
	                      h_Block & gi , 
						  h_Block & hi , 
						  h_Block & Crf , 
	                      h_Block & g_out , 
	                      h_Block & h_out );
	void BlockConsole( string & varn , h_Block & bote ); 
	void HexiWord( uint32_t uw );
	void ASCII_if_KeyType( string & varn , h_Block & bote );
	uint32_t WordReverse( uint32_t w );
	void ReturnWordTail( ULint * wdig , ubyte8_t * bdig );
	

	//
	inline void BoteCopy( h_Block & dest , h_Block & src );
    inline void BoteXOR ( h_Block & Rop  , h_Block & Aop , h_Block & Bop );
	inline uint32_t BoteIndex( h_Block & bote , int & idx );
    inline void ChanSplituch( ubyte8_t * uch , uint32_t W );
    inline bool IsKeyboardtype( ubyte8_t ik );
    //
};


inline void HiroseKDF::BoteCopy( h_Block & dest , h_Block & src )
{
	BoteSet(dest , src.X , src.Y , src.U , src.V );
}

inline void HiroseKDF::BoteXOR ( h_Block & Rop  , h_Block & Aop , h_Block & Bop )
{
	Rop.X = Aop.X ^ Bop.X;
	Rop.Y = Aop.Y ^ Bop.Y;
	Rop.U = Aop.U ^ Bop.U;
	Rop.V = Aop.V ^ Bop.V;
}


inline uint32_t HiroseKDF::BoteIndex( h_Block & bote , int & idx )
{
	{
		switch( idx ) 
		{
			case 0: return( bote.X ); break;
			case 1: return( bote.Y ); break;
			case 2: return( bote.U ); break;
			case 3: return( bote.V ); break;
		}
		return 0xEE;
	}
}

inline void HiroseKDF::ChanSplituch( ubyte8_t * uch , uint32_t W )
{
	{
	uint32_t sizeparts[4];
	ChanSplit( W , sizeparts[0] , sizeparts[1] , sizeparts[2] , sizeparts[3] );
	uch[0] = (ubyte8_t)sizeparts[0];
	uch[1] = (ubyte8_t)sizeparts[1];
	uch[2] = (ubyte8_t)sizeparts[2];
	uch[3] = (ubyte8_t)sizeparts[3];
	}
}


inline bool HiroseKDF::IsKeyboardtype( ubyte8_t ik )
{
	int iki = (int) ik;
	
	if( iki > 126) return false;
	
	if( iki < 32 ) {
	
		switch( iki ) {
			case 9 : return true ; break;
			case 10: return true ; break;
			case 13: return true ; break;
			case 27: return true ; break;
			default: return false;
		}
	}
	
	return true; 
}
