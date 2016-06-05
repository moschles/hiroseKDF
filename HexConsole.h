

struct WrapperType {
    uint32_t _m;
public:
    WrapperType(uint32_t m) : _m(m)
    {
    }

    uint32_t getm() const
    {
        return _m;
    }  
    
};

std::ostream& hexify(std::ostream& stream);
std::ostream& nohexify(std::ostream& stream);
std::ostream& operator<< (std::ostream& os, const WrapperType& t);
void HexConsole(unsigned long hi);
uint32_t ASCII2int(std::string & hasc);

