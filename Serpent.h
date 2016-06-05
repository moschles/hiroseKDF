/*  aes.h  */

/*  AES Cipher header file for ANSI C Submissions
      Lawrence E. Bassham III
      Computer Security Division
      National Institute of Standards and Technology

      April 15, 1998

    This sample is to assist implementers developing to the Cryptographic 
API Profile for AES Candidate Algorithm Submissions.  Please consult this 
document as a cross-reference.

    ANY CHANGES, WHERE APPROPRIATE, TO INFORMATION PROVIDED IN THIS FILE
MUST BE DOCUMENTED.  CHANGES ARE ONLY APPROPRIATE WHERE SPECIFIED WITH
THE STRING "CHANGE POSSIBLE".  FUNCTION CALLS AND THEIR PARAMETERS CANNOT 
BE CHANGED.  STRUCTURES CAN BE ALTERED TO ALLOW IMPLEMENTERS TO INCLUDE 
IMPLEMENTATION SPECIFIC INFORMATION.
*/

/*  Includes:
	Standard include files
*/

/*  Defines:
	Add any additional defines you need*/
#define     DIR_ENCRYPT     0    /*  Are we encrpyting?  */
#define     DIR_DECRYPT     1    /*  Are we decrpyting?  */
#define     MODE_ECB        1    /*  Are we ciphering in ECB mode?   */
#define     MODE_CBC        2    /*  Are we ciphering in CBC mode?   */
#define     MODE_CFB1       3    /*  Are we ciphering in 1-bit CFB mode? */
#define     TRUE            1
#define     FALSE           0

/*  Error Codes - CHANGE POSSIBLE: inclusion of additional error codes  */
#define     BAD_KEY_DIR        -1  /*  Key direction is invalid, e;g;,		unknown value */
#define     BAD_KEY_MAT        -2  /*  Key material not of correct 	length */
#define     BAD_KEY_INSTANCE   -3  /*  Key passed is not valid  */
#define     BAD_CIPHER_MODE    -4  /*  Params struct passed to cipherInit invalid */
#define     BAD_CIPHER_STATE   -5  /*  Cipher in wrong state (e.g., not initialized) */

/*  CHANGE POSSIBLE:  inclusion of algorithm specific defines  */
#define     MAX_KEY_SIZE	64  /* # of ASCII char's needed to represent a key */
#define     MAX_IV_SIZE		32  /* # of ASCII char's needed to represent an IV  */



/*  The structure for key information */
typedef struct {
      unsigned char  direction;	/*  Key used for encrypting or decrypting? */
      int   keyLen;	/*  Length of the key  */
      char  keyMaterial[MAX_KEY_SIZE+1];  /*  Raw key data in ASCII, e.g.,
      					what the user types or KAT values)*/
      /*  The following parameters are algorithm dependent, replace or
      		add as necessary  */
      unsigned long key[8];             /* The key in binary */
      unsigned long subkeys[33][4];	/* Serpent subkeys */
} keyInstance;



class SERPENT {
// Data
public:
   keyInstance kschedule;   

// Functionality
public:
    SERPENT();
    ~SERPENT();
    int     makeKey(unsigned char direction, int keyLen, unsigned char * keyMaterial);
    void    serpent_encrypt(unsigned long * plaintext, unsigned long  * ciphertext );     
    void    Serpent_Session( string & asciikey, string & asciiPT ) ;
    void    Security( void );
    unsigned long  Endianize_Big( unsigned long nist );
	
	inline void	fragmentword( 
		unsigned long &F , 
		unsigned char &A , 
		unsigned char &B , 
		unsigned char &C , 
		unsigned char &D );        
};

inline void	SERPENT::fragmentword( 
		unsigned long &F , 
		unsigned char &A , 
		unsigned char &B , 
		unsigned char &C , 
		unsigned char &D )
{
	unsigned long x,y,z,w;
	x = (F>>24) & (0x00FF);
	y = (F>>16) & (0x00FF);
	z = (F>>8 ) & (0x00FF);
	w = (F    ) & (0x00FF);
	A = (unsigned char)x;
	B = (unsigned char)y;
	C = (unsigned char)z;
	D = (unsigned char)w;
}


