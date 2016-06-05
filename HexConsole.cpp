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

#include "HexConsole.h"

static int const index = std::ios_base::xalloc();

std::ostream& hexify(std::ostream& stream) {
    stream.iword(index) = 1;
    return stream;
}

std::ostream& nohexify(std::ostream& stream) {
    stream.iword(index) = 0;
    return stream;
}
 
std::ostream& operator<< (std::ostream& os, const WrapperType& t) {
    if (os.iword(index))
        return os << std::hex << std::setw(8) << std::setfill('0') << t.getm();
    else
        return os << t.getm();
}

void HexConsole(unsigned long hi)
{
    WrapperType my_int{hi};
    std::cout << hexify << my_int;
}

uint32_t ASCII2int(std::string & hasc)
{    
    uint32_t i;
    std::string prefix = "0x";
    prefix += hasc;
    std::istringstream iss( prefix );
    
    iss >> std::hex >> i;
    return i;
}
