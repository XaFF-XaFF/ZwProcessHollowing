#include <Windows.h>
#include <fstream>
#include <vector>
#include <iostream>

#include "rc4.hpp"

void rc4_setup(struct rc4_state* s, unsigned char* key, int length)
{
    int i, j, k, * m, a;

    s->x = 0;
    s->y = 0;
    m = s->m;

    for (i = 0; i < 256; i++)
    {
        m[i] = i;
    }

    j = k = 0;

    for (i = 0; i < 256; i++)
    {
        a = m[i];
        j = (unsigned char)(j + a + key[k]);
        m[i] = m[j]; m[j] = a;
        if (++k >= length) k = 0;
    }
}

void rc4_crypt(struct rc4_state* s, unsigned char* data, int length)
{
    int i, x, y, * m, a, b;

    x = s->x;
    y = s->y;
    m = s->m;

    for (i = 0; i < length; i++)
    {
        x = (unsigned char)(x + 1); a = m[x];
        y = (unsigned char)(y + a);
        m[x] = b = m[y];
        m[y] = a;
        data[i] ^= m[(unsigned char)(a + b)];
    }

    s->x = x;
    s->y = y;
}

int main()
{
    int option;
    std::string inputPath;
    std::string outputPath;
    std::string key;

    std::cout << "Encrypt : 1 | Decrypt : 2 >> "; std::cin >> option;
    std::cout << "Input path: "; std::cin >> inputPath;
    std::cout << "Output path: "; std::cin >> outputPath;
    std::cout << "Key: "; std::cin >> key;

    std::ifstream input(inputPath, std::ios::binary);
    std::vector<unsigned char> buffer(std::istreambuf_iterator<char>(input), {});

    printf("[+] File size : %d\n", buffer.size());

    struct rc4_state* s;
    s = (struct rc4_state*)malloc(sizeof(struct rc4_state));

    if (option == 1)
    {
        printf("[+] Encrypting...\n");
        rc4_setup(s, (unsigned char*)key.c_str(), key.size());
        rc4_crypt(s, buffer.data(), buffer.size());
    }
    else
    {
        printf("[+] Decrypting...\n");
        rc4_setup(s, (unsigned char*)key.c_str(), key.size());
        rc4_crypt(s, buffer.data(), buffer.size());
    }
    printf("[*] Done!\n");

    std::ofstream output(outputPath, std::ios::binary);
    std::copy(buffer.cbegin(), buffer.cend(),
        std::ostreambuf_iterator<char>(output));
}