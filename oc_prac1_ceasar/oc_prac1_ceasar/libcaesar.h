#pragma once

// Макрос для экспорта функций из DLL
#ifdef LIBCAESAR_EXPORTS
#define LIBCAESAR_API __declspec(dllexport)
#else
#define LIBCAESAR_API __declspec(dllimport)
#endif

extern "C" {
    LIBCAESAR_API void set_key(char key);
    LIBCAESAR_API void caesar(void* src, void* dst, int len);
}