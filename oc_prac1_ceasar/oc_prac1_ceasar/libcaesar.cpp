#include "libcaesar.h"

// Статическая переменная для хранения ключа внутри библиотеки
static char g_key = 0;

extern "C" {
    LIBCAESAR_API void set_key(char key) {
        g_key = key;
    }

    LIBCAESAR_API void caesar(void* src, void* dst, int len) {
        unsigned char* s = (unsigned char*)src;
        unsigned char* d = (unsigned char*)dst;
        for (int i = 0; i < len; i++) {
            d[i] = s[i] ^ g_key;
        }
    }
}