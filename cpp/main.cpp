#include <iostream>
#include <vector>
#include <string>
#include <cstdint>

#define BYTES std::vector<uint8_t>

BYTES stringToNibbles(const std::string& s) {
    BYTES nibbles;
    
    // Otimização: reservamos o espaço necessário de antemão 
    // Cada char gera 2 nibbles.
    nibbles.reserve(s.length() * 2);

    for (unsigned char b : s) {
        uint8_t high = b >> 4;
        uint8_t low = b & 0x0F;
        
        nibbles.push_back(high);
        nibbles.push_back(low);
    }

    return nibbles;
}

int main(void) {
    BYTES nibbles = stringToNibbles("A");
    for (int n : nibbles) {
        std::cout << n << " ";
    }
    return 0;   
}
