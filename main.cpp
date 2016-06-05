#include <iostream>
#include <iomanip>

using namespace std;

#include "hiroseKDF.h"


void ConsoleDigest( unsigned char * ucp );
void ConsoleDigest( unsigned long int * ulip );
  

void ConsoleDigest( unsigned char * ucp )
{
	int n;
	int clue;

	cout << "0x ";
	
	for(n=0;n<32;n++){
		clue = (int)(ucp[n]);
		cout << std::hex << std::setw(2) << std::setfill('0');
		cout << clue;
	}
	
	cout << endl;
	cout << std::dec;
}

void ConsoleDigest( unsigned long int * ulip )
{
	int n;

	cout << "0x ";
	
	for(n=0;n<8;n++){
		cout << std::hex << std::setw(8) << std::setfill('0');
		cout << (ulip[n]);
	}
	
	cout << endl;
	cout << std::dec;
}
  
 
// ////////////////////////// //
//     MAIN ENTRY POINT       //
// ////////////////////////// //
int main(int argc, char** argv) {
	
	HiroseKDF 		  hiro;
	ubyte8_t 		  digest[32];
	unsigned long int wordydigest[8];
	unsigned char 	  allzerobits[16] ={0,0,0,0, 0,0,0,0, 
	                                    0,0,0,0, 0,0,0,0 }; 
	                                    
    char        cquickbrown[] = "The quick brown fox jumps over the lazy dog.";
    std::string stdquickbrown = "The quick brown fox jumps over the lazy dog.";
    char        cempty[] 	  = "";
    std::string stdempty 	  = "";
    
    //.
    	// // //
	cout << ".HashText( \"The quick brown fox jumps over the lazy dog.\" , digest );" << endl;
	hiro.HashText( "The quick brown fox jumps over the lazy dog." , digest );
	ConsoleDigest( digest );
	cout << endl; 

	cout << ".HashText( cquickbrown , digest );" << endl;
	hiro.HashText( cquickbrown , digest );
	ConsoleDigest( digest );
	cout << endl; 
	
	cout << ".HashText( stdquickbrown , digest );" << endl;
	hiro.HashText( stdquickbrown , digest );
	ConsoleDigest( digest );
	cout << endl; 
	
	cout << ".HashText( \"\" , digest );" << endl;
	hiro.HashText( "" , digest );
	ConsoleDigest( digest );
	cout << endl; 
	
	cout << ".HashText( cempty , digest );" << endl;
	hiro.HashText( cempty , digest );
	ConsoleDigest( digest );
	cout << endl; 
	
	cout << ".HashText( stdempty , digest );" << endl;
	hiro.HashText( stdempty , digest );
	ConsoleDigest( digest );
	cout << endl; 

	cout << ".HashBinary( allzerobits , 128 , digest );" << endl;
	hiro.HashBinary( allzerobits , 128 , digest );
	ConsoleDigest( digest );
	cout << endl; 
	
	// // //
	
	cout << ".HashText( \"The quick brown fox jumps over the lazy dog.\" , wordydigest );" << endl;
	hiro.HashText( "The quick brown fox jumps over the lazy dog." , wordydigest );
	ConsoleDigest( wordydigest );
	cout << endl; 

	cout << ".HashText( cquickbrown , wordydigest );" << endl;
	hiro.HashText( cquickbrown , wordydigest );
	ConsoleDigest( wordydigest );
	cout << endl; 
	
	cout << ".HashText( stdquickbrown , wordydigest );" << endl;
	hiro.HashText( stdquickbrown , wordydigest );
	ConsoleDigest( wordydigest );
	cout << endl; 
	
	cout << ".HashText( \"\" , wordydigest );" << endl;
	hiro.HashText( "" , wordydigest );
	ConsoleDigest( wordydigest );
	cout << endl; 
	
	cout << ".HashText( cempty , wordydigest );" << endl;
	hiro.HashText( cempty , wordydigest );
	ConsoleDigest( wordydigest );
	cout << endl; 
	
	cout << ".HashText( stdempty , wordydigest );" << endl;
	hiro.HashText( stdempty , wordydigest );
	ConsoleDigest( wordydigest );
	cout << endl; 
	
	cout << ".HashBinary( allzerobits , 128 , wordydigest );" << endl;
	hiro.HashBinary( allzerobits , 128 ,wordydigest );
	ConsoleDigest( wordydigest );
	cout << endl; 
	
	cout << endl;
    
	return 0;
}



