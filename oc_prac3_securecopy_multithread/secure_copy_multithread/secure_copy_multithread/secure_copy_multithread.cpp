#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <chrono>
#include <string>
#include <queue>
#include <filesystem>
#include <iomanip>
#include <ctime>
#include <cstring>

namespace fs = std::filesystem;
using namespace std::chrono;

// ===================== ТИПЫ =====================
typedef void (*set_key_func)(char);
typedef void (*caesar_func)(void*, void*, int);

// ===================== ЗАЩИЩЁННАЯ ПАМЯТЬ =====================
static LPVOID secure_key_mem = nullptr;
static const SIZE_T KEY_SIZE = 16;
static DWORD old_protect = 0;

// Обработчик нарушения доступа
LONG WINAPI AccessViolationHandler(PEXCEPTION_POINTERS pExceptionInfo)
{
    if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
    {
        std::cerr << "\n[ОШИБКА БЕЗОПАСНОСТИ] EXCEPTION_ACCESS_VIOLATION!\n";
        std::cerr << "Попытка несанкционированной записи в защищённую память!\n";
        std::cerr << "Адрес: " << pExceptionInfo->ExceptionRecord->ExceptionAddress << std::endl;
        std::cerr << "Программа завершена для защиты ключа.\n";
        ExitProcess(1);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

void init_secure_key_memory()
{
    secure_key_mem = VirtualAlloc(NULL, KEY_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!secure_key_mem) {
        std::cerr << "VirtualAlloc failed\n";
        exit(1);
    }
    std::cout << "[SECURE] Память под ключ выделена (16 байт)\n";
}

void set_secure_key(char key)
{
    VirtualProtect(secure_key_mem, KEY_SIZE, PAGE_READWRITE, &old_protect);
    memset(secure_key_mem, 0, KEY_SIZE);
    memcpy(secure_key_mem, &key, 1);
    VirtualProtect(secure_key_mem, KEY_SIZE, PAGE_READONLY, &old_protect);
}

// Правильная функция использования ключа
void use_secure_key(set_key_func set_key)
{
    if (!set_key) return;

    VirtualProtect(secure_key_mem, KEY_SIZE, PAGE_READWRITE, &old_protect);
    set_key(*static_cast<char*>(secure_key_mem));   // передаём ключ в библиотеку
    VirtualProtect(secure_key_mem, KEY_SIZE, PAGE_READONLY, &old_protect);
}

void cleanup_secure_memory()
{
    if (secure_key_mem) {
        VirtualProtect(secure_key_mem, KEY_SIZE, PAGE_READWRITE, &old_protect);
        memset(secure_key_mem, 0, KEY_SIZE);
        VirtualFree(secure_key_mem, 0, MEM_RELEASE);
        secure_key_mem = nullptr;
        std::cout << "[SECURE] Ключ затёрт нулями и память освобождена\n";
    }
}

struct FileStats {
    std::string filename;
    milliseconds duration;
    bool success = false;
    std::string error_msg;
};

enum Mode { MODE_SEQUENTIAL, MODE_PARALLEL, MODE_AUTO };

struct ParallelContext {
    std::queue<std::string> file_queue;
    std::mutex mtx;
    std::condition_variable cv;
    std::vector<FileStats> results;
    std::mutex results_mtx;
    bool all_done = false;
    bool system_error = false;
};

// ===================== ВСПОМОГАТЕЛЬНЫЕ =====================
std::string get_current_time() {
    auto now = system_clock::now();
    auto now_time_t = system_clock::to_time_t(now);
    struct tm timeinfo;
    localtime_s(&timeinfo, &now_time_t);
    char time_str[100];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &timeinfo);
    return std::string(time_str);
}

void log_operation(const std::string& filename, const std::string& status,
    const milliseconds& duration, std::mutex& log_mutex) {
    std::lock_guard<std::mutex> lock(log_mutex);
    std::ofstream logfile("log.txt", std::ios::app);
    if (!logfile) return;
    logfile << "[" << get_current_time() << "] Поток "
        << std::this_thread::get_id() << " | Файл: " << filename
        << " | Статус: " << status << " | Время: " << duration.count() << "мс\n";
}

// ===================== ОБРАБОТКА ФАЙЛА (обновлённая) =====================
FileStats process_single_file(const std::string& input_file, const std::string& output_dir,
    set_key_func set_key, caesar_func caesar, std::mutex& log_mutex) {
    auto start_time = high_resolution_clock::now();
    FileStats stats{};
    stats.filename = input_file;
    stats.success = false;
    try {
        std::string output_file = (fs::path(output_dir) / fs::path(input_file).filename()).string();

        std::ifstream in(input_file, std::ios::binary | std::ios::ate);
        if (!in) throw std::runtime_error("Не удалось открыть входной файл");

        std::streamsize size = in.tellg();
        in.seekg(0, std::ios::beg);
        std::vector<char> buffer(size);
        if (!in.read(buffer.data(), size)) throw std::runtime_error("Ошибка чтения файла");
        in.close();

        use_secure_key(set_key);
        caesar(buffer.data(), buffer.data(), static_cast<int>(size));

        std::ofstream out(output_file, std::ios::binary);
        if (!out.write(buffer.data(), size)) throw std::runtime_error("Ошибка записи файла");

        stats.success = true;
    }
    catch (const std::exception& e) {
        stats.error_msg = e.what();
        std::cerr << "Ошибка обработки файла " << input_file << ": " << e.what() << std::endl;
    }

    auto end_time = high_resolution_clock::now();
    stats.duration = duration_cast<milliseconds>(end_time - start_time);
    log_operation(input_file, stats.success ? "УСПЕХ" : ("ОШИБКА: " + stats.error_msg),
        stats.duration, log_mutex);
    return stats;
}

// ===================== WORKER THREAD =====================
void worker_thread(ParallelContext& ctx, const std::string& output_dir,
    set_key_func set_key, caesar_func caesar, std::mutex& log_mutex, int thread_num) {
    std::cout << "Поток " << thread_num << " (ID: " << std::this_thread::get_id() << ") запущен" << std::endl;
    while (true) {
        std::string filename;
        {
            std::unique_lock<std::mutex> lock(ctx.mtx);
            ctx.cv.wait(lock, [&ctx] { return !ctx.file_queue.empty() || ctx.all_done; });
            if (ctx.all_done && ctx.file_queue.empty()) break;
            if (!ctx.file_queue.empty()) {
                filename = ctx.file_queue.front();
                ctx.file_queue.pop();
            }
            else continue;
        }
        FileStats stats = process_single_file(filename, output_dir, set_key, caesar, log_mutex);
        {
            std::lock_guard<std::mutex> lock(ctx.results_mtx);
            ctx.results.push_back(stats);
            if (!stats.success) ctx.system_error = true;
        }
    }
    std::cout << "Поток " << thread_num << " завершен" << std::endl;
}

// парсинг аргумента --mode
Mode parse_mode_arg(int argc, char* argv[]) {
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--mode=sequential") return MODE_SEQUENTIAL;
        if (arg == "--mode=parallel") return MODE_PARALLEL;
        if (arg == "--mode=auto") return MODE_AUTO;
    }
    return MODE_AUTO;
}

// ===================== process_files =====================
std::vector<FileStats> process_files(const std::vector<std::string>& input_files,
    const std::string& output_dir, set_key_func set_key, caesar_func caesar,
    std::mutex& log_mutex, Mode mode, Mode& used_mode, milliseconds& total_duration) {

    auto start_time = high_resolution_clock::now();
    std::vector<FileStats> results;

    Mode actual_mode = mode;
    if (mode == MODE_AUTO) {
        if (input_files.size() < 5) {
            actual_mode = MODE_SEQUENTIAL;
            std::cout << "Автовыбор: файлов " << input_files.size() << " < 5 -> ПОСЛЕДОВАТЕЛЬНЫЙ режим\n";
        }
        else {
            actual_mode = MODE_PARALLEL;
            std::cout << "Автовыбор: файлов " << input_files.size() << " >= 5 -> ПАРАЛЛЕЛЬНЫЙ режим\n";
        }
    }
    used_mode = actual_mode;

    if (actual_mode == MODE_SEQUENTIAL) {
        std::cout << "\n=== ПОСЛЕДОВАТЕЛЬНЫЙ РЕЖИМ ===\n";
        for (size_t i = 0; i < input_files.size(); ++i) {
            std::cout << "Обработка файла " << (i + 1) << "/" << input_files.size() << ": " << input_files[i] << std::endl;
            FileStats stats = process_single_file(input_files[i], output_dir, set_key, caesar, log_mutex);
            results.push_back(stats);
        }
    }
    else {
        std::cout << "\n=== ПАРАЛЛЕЛЬНЫЙ РЕЖИМ ===\n";
        ParallelContext ctx;
        for (const auto& f : input_files) ctx.file_queue.push(f);

        std::vector<std::thread> threads;
        for (int i = 0; i < 4; ++i) {
            threads.emplace_back(worker_thread, std::ref(ctx), std::ref(output_dir),
                set_key, caesar, std::ref(log_mutex), i + 1);
        }
        ctx.all_done = true;
        ctx.cv.notify_all();
        for (auto& t : threads) t.join();
        results = ctx.results;
    }

    total_duration = duration_cast<milliseconds>(high_resolution_clock::now() - start_time);
    return results;
}

// ===================== MAIN =====================
int main(int argc, char* argv[])
{
    setlocale(LC_ALL, "rus");

    // ===================== ЗАЩИТА ПАМЯТИ =====================
    AddVectoredExceptionHandler(1, AccessViolationHandler);
    init_secure_key_memory();
    atexit(cleanup_secure_memory);

    // Парсинг режима
    Mode mode = parse_mode_arg(argc, argv);
    int start_idx = 1;
    if (argc >= 2 && std::string(argv[1]).find("--mode=") == 0) {
        start_idx = 2;
    }

    // Проверка аргументов
    if (argc - start_idx < 4) {
        std::cerr << "Использование: " << argv[0]
            << " [--mode=sequential|parallel|auto] <путь_к_библиотеке.dll> <файл1> ... <output_dir> <ключ>\n";
        return 1;
    }

    // Парсинг остальных аргументов
    std::string lib_path = argv[start_idx++];
    std::vector<std::string> input_files;
    for (int i = start_idx; i < argc - 2; ++i) {
        input_files.push_back(argv[i]);
    }
    std::string output_dir = argv[argc - 2];
    if (!output_dir.empty() && output_dir.back() == '/') output_dir.pop_back();
    char user_key = argv[argc - 1][0];

    // Сохраняем ключ в защищённую память
    set_secure_key(user_key);

    std::cout << "=========================================\n";
    std::cout << "   SECURE COPY (Защищённая память)\n";
    std::cout << "=========================================\n";
    std::cout << "Ключ успешно сохранён в защищённой памяти\n";

    // ===================== ДЕМОНСТРАЦИЯ ЗАЩИТЫ =====================
   // std::cout << "\n=== ДЕМОНСТРАЦИЯ ЗАЩИТЫ ПАМЯТИ ===\n";
   // std::cout << "Попытка прямой модификации ключа...\n";
   // *(char*)secure_key_mem = 'X';        // проверка
   // std::cout << "Защита работает — запись в защищённую память запрещена!\n\n";

    // Загрузка библиотеки
    HMODULE hLib = LoadLibraryA(lib_path.c_str());
    if (!hLib) {
        std::cerr << "Не удалось загрузить библиотеку. Код ошибки: " << GetLastError() << std::endl;
        return 1;
    }

    set_key_func set_key = (set_key_func)GetProcAddress(hLib, "set_key");
    caesar_func caesar = (caesar_func)GetProcAddress(hLib, "caesar");

    if (!set_key || !caesar) {
        std::cerr << "Не удалось получить адреса функций\n";
        FreeLibrary(hLib);
        return 1;
    }

    std::cout << "Библиотека успешно загружена\n";

    // Создание выходной директории
    try {
        fs::create_directories(output_dir);
        std::cout << "Выходная директория создана: " << output_dir << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "Ошибка создания директории: " << e.what() << std::endl;
    }

    // Лог-файл
    std::mutex log_mutex;
    {
        std::ofstream logfile("log.txt", std::ios::trunc);
        logfile << "=== ЖУРНАЛ SECURE COPY ===\n";
        logfile << "Запуск: " << get_current_time() << "\n";
        logfile << "==========================================\n\n";
    }

    // Проверка файлов
    std::vector<std::string> valid_files;
    for (const auto& file : input_files) {
        if (fs::exists(file)) {
            valid_files.push_back(file);
            std::cout << "Добавлен в очередь: " << file << std::endl;
        }
        else {
            std::cerr << "Предупреждение: Файл не существует: " << file << std::endl;
        }
    }

    if (valid_files.empty()) {
        std::cerr << "Нет файлов для обработки!\n";
        FreeLibrary(hLib);
        return 1;
    }

    // ===================== ЗАПУСК ОБРАБОТКИ =====================
    Mode used_mode;
    milliseconds total_duration;
    std::vector<FileStats> results = process_files(valid_files, output_dir, set_key, caesar,
        log_mutex, mode, used_mode, total_duration);

    // Статистика
    int success_count = 0;
    long long total_file_time_ms = 0;
    for (const auto& stat : results) {
        if (stat.success) success_count++;
        total_file_time_ms += stat.duration.count();
    }
    double avg_time = results.empty() ? 0 : static_cast<double>(total_file_time_ms) / results.size();

    std::cout << "\n=========================================\n";
    std::cout << "ВСЕ ФАЙЛЫ УСПЕШНО ОБРАБОТАНЫ!\n";
    std::cout << "Скопировано файлов: " << success_count << " из " << valid_files.size() << std::endl;
    std::cout << "Общее время: " << total_duration.count() << " мс\n";
    std::cout << "Среднее время на файл: " << std::fixed << std::setprecision(2) << avg_time << " мс\n";
    std::cout << "=========================================\n";

    // ===================== СРАВНИТЕЛЬНАЯ ТАБЛИЦА =====================
    if (mode == MODE_AUTO && valid_files.size() >= 1) {
        std::cout << "\n=== СРАВНИТЕЛЬНАЯ ТАБЛИЦА ===\n";
        Mode alternative = (used_mode == MODE_SEQUENTIAL) ? MODE_PARALLEL : MODE_SEQUENTIAL;
        std::cout << "Запуск альтернативного режима для сравнения...\n";

        std::string alt_output_dir = output_dir + "_alt";
        fs::create_directories(alt_output_dir);

        Mode dummy_mode;
        milliseconds alt_duration;
        process_files(valid_files, alt_output_dir, set_key, caesar, log_mutex,
            alternative, dummy_mode, alt_duration);

        // Вывод сравнения
        std::cout << "\n--- СРАВНЕНИЕ ---\n";
        std::cout << std::left << std::setw(25) << "Показатель"
            << std::setw(20) << (used_mode == MODE_SEQUENTIAL ? "SEQUENTIAL" : "PARALLEL")
            << std::setw(20) << (alternative == MODE_SEQUENTIAL ? "SEQUENTIAL" : "PARALLEL") << std::endl;
        std::cout << std::string(60, '-') << std::endl;
        std::cout << std::left << std::setw(25) << "Общее время (мс)"
            << std::setw(20) << total_duration.count()
            << std::setw(20) << alt_duration.count() << std::endl;
        std::cout << "=========================================\n";

        fs::remove_all(alt_output_dir);
    }

    FreeLibrary(hLib);
    return 0;
}