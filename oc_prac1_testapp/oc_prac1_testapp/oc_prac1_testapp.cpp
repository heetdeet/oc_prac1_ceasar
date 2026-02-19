#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h> // Заменяет dlfcn.h в Windows
#include <locale>

// определяем типы функций для указателей
typedef void (*set_key_func)(char);
typedef void (*caesar_func)(void*, void*, int);

int main(int argc, char* argv[]) {
    setlocale(LC_ALL, "rus");
    if (argc != 5) {
        printf("Использование: %s <путь_к_DLL> <ключ> <вход_файл> <выход_файл>\n", argv[0]);
        printf("Пример: oc_prac1_testapp.exe libcaesar.dll K input.txt output.txt\n");
        return 1;
    }

    const char* lib_path = argv[1];
    char key = argv[2][0];
    const char* in_file = argv[3];
    const char* out_file = argv[4];

    printf("Загрузка библиотеки: %s\n", lib_path);

    HINSTANCE hLib = LoadLibraryA(lib_path);
    if (!hLib) {
        fprintf(stderr, "Ошибка загрузки библиотеки (код %lu)\n", GetLastError());
        return 1;
    }

    set_key_func set_key = (set_key_func)GetProcAddress(hLib, "set_key");
    caesar_func caesar = (caesar_func)GetProcAddress(hLib, "caesar");

    if (!set_key || !caesar) {
        fprintf(stderr, "Ошибка получения адресов функций (код %lu)\n", GetLastError());
        FreeLibrary(hLib);
        return 1;
    }

    printf("Функции найдены. Чтение файла: %s\n", in_file);

    FILE* fin = fopen(in_file, "rb");
    if (!fin) {
        perror("Не удалось открыть входной файл");
        FreeLibrary(hLib);
        return 1;
    }

    fseek(fin, 0, SEEK_END);
    long size = ftell(fin);
    fseek(fin, 0, SEEK_SET);

    unsigned char* buffer = (unsigned char*)malloc(size);
    if (!buffer) {
        perror("Ошибка выделения памяти");
        fclose(fin);
        FreeLibrary(hLib);
        return 1;
    }

    size_t read_count = fread(buffer, 1, size, fin);
    fclose(fin);

    if (read_count != (size_t)size) {
        fprintf(stderr, "Ошибка чтения файла\n");
        free(buffer);
        FreeLibrary(hLib);
        return 1;
    }

    printf("Обработка %ld байт с ключом '%c'...\n", size, key);
    set_key(key);
    caesar(buffer, buffer, (int)size); // шифруем на месте (src == dst)

    FILE* fout = fopen(out_file, "wb");
    if (!fout) {
        perror("Не удалось открыть выходной файл");
        free(buffer);
        FreeLibrary(hLib);
        return 1;
    }

    fwrite(buffer, 1, size, fout);
    fclose(fout);

    free(buffer);
    FreeLibrary(hLib);

    printf("Готово! Результат записан в: %s\n", out_file);
    return 0;
}