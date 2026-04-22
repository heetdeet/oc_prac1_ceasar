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
#include <windows.h>

namespace fs = std::filesystem;
using namespace std::chrono;

// константы
const int TIMEOUT_SECONDS = 5;
const int MAX_RETRIES = 3;
const int WORKERS_COUNT = 4;

// типы указателей на функции из библиотеки
typedef void (*set_key_func)(char);
typedef void (*caesar_func)(void*, void*, int);

// структура для хранения статистики по файлу
struct FileStats {
    std::string filename;
    milliseconds duration;
    bool success;
    std::string error_msg;
};

// режимы работы
enum Mode {
    MODE_SEQUENTIAL,
    MODE_PARALLEL,
    MODE_AUTO
};

// структура для контекста параллельной работы
struct ParallelContext {
    std::queue<std::string> file_queue;
    std::mutex mtx;
    std::condition_variable cv;
    std::vector<FileStats> results;
    std::mutex results_mtx;
    bool all_done = false;
    bool system_error = false;
};

// вспомогательная функция для получения текущего времени
std::string get_current_time() {
    auto now = system_clock::now();
    auto now_time_t = system_clock::to_time_t(now);
    struct tm timeinfo;
    localtime_s(&timeinfo, &now_time_t);
    char time_str[100];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &timeinfo);
    return std::string(time_str);
}

// логирование
void log_operation(const std::string& filename, const std::string& status,
    const milliseconds& duration, std::mutex& log_mutex) {
    std::lock_guard<std::mutex> lock(log_mutex);
    std::ofstream logfile("log.txt", std::ios::app);
    if (!logfile) return;

    std::stringstream ss;
    ss << std::this_thread::get_id();
    std::string thread_id = ss.str();

    logfile << "[" << get_current_time() << "] "
        << "Поток " << thread_id << " | "
        << "Файл: " << filename << " | "
        << "Статус: " << status << " | "
        << "Время: " << duration.count() << "мс" << std::endl;
}

// обработка одного файла (возвращает статистику)
FileStats process_single_file(const std::string& input_file,
    const std::string& output_dir,
    char key,
    set_key_func set_key,
    caesar_func caesar,
    std::mutex& log_mutex) {
    auto start_time = high_resolution_clock::now();
    FileStats stats;
    stats.filename = input_file;
    stats.success = false;

    try {
        std::string output_file = (fs::path(output_dir) / fs::path(input_file).filename()).string();

        std::ifstream in(input_file, std::ios::binary | std::ios::ate);
        if (!in) {
            throw std::runtime_error("Не удалось открыть входной файл");
        }

        std::streamsize size = in.tellg();
        in.seekg(0, std::ios::beg);

        std::vector<char> buffer(size);
        if (!in.read(buffer.data(), size)) {
            throw std::runtime_error("Ошибка чтения входного файла");
        }
        in.close();

        set_key(key);
        caesar(buffer.data(), buffer.data(), static_cast<int>(size));

        std::ofstream out(output_file, std::ios::binary);
        if (!out.write(buffer.data(), size)) {
            throw std::runtime_error("Ошибка записи выходного файла");
        }

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

// последовательная обработка
std::vector<FileStats> run_sequential(const std::vector<std::string>& input_files,
    const std::string& output_dir,
    char key,
    set_key_func set_key,
    caesar_func caesar,
    std::mutex& log_mutex) {
    std::cout << "\n=== ПОСЛЕДОВАТЕЛЬНЫЙ РЕЖИМ ===" << std::endl;
    std::vector<FileStats> results;

    for (size_t i = 0; i < input_files.size(); i++) {
        std::cout << "Обработка файла " << (i + 1) << "/" << input_files.size()
            << ": " << input_files[i] << std::endl;

        FileStats stats = process_single_file(input_files[i], output_dir, key,
            set_key, caesar, log_mutex);
        results.push_back(stats);

        std::cout << "  Время: " << stats.duration.count() << " мс"
            << (stats.success ? " [OK]" : " [FAIL]") << std::endl;
    }

    return results;
}

// рабочий поток для параллельного режима
void worker_thread(ParallelContext& ctx, const std::string& output_dir, char key,
    set_key_func set_key, caesar_func caesar, std::mutex& log_mutex,
    int thread_num) {
    std::cout << "Поток " << thread_num << " (ID: " << std::this_thread::get_id() << ") запущен" << std::endl;

    while (true) {
        std::string filename;

        {
            std::unique_lock<std::mutex> lock(ctx.mtx);
            ctx.cv.wait(lock, [&ctx] { return !ctx.file_queue.empty() || ctx.all_done; });

            if (ctx.all_done && ctx.file_queue.empty()) {
                break;
            }

            if (!ctx.file_queue.empty()) {
                filename = ctx.file_queue.front();
                ctx.file_queue.pop();
            }
            else {
                continue;
            }
        }

        std::cout << "Поток " << thread_num << " обрабатывает: " << filename << std::endl;
        FileStats stats = process_single_file(filename, output_dir, key,
            set_key, caesar, log_mutex);

        {
            std::lock_guard<std::mutex> lock(ctx.results_mtx);
            ctx.results.push_back(stats);
            if (!stats.success) {
                ctx.system_error = true;
            }
        }
    }

    std::cout << "Поток " << thread_num << " завершен" << std::endl;
}

// параллельная обработка

std::vector<FileStats> run_parallel(const std::vector<std::string>& input_files,
    const std::string& output_dir,
    char key,
    set_key_func set_key,
    caesar_func caesar,
    std::mutex& log_mutex) {
    std::cout << "\n=== ПАРАЛЛЕЛЬНЫЙ РЕЖИМ ===" << std::endl;
    std::cout << "Количество потоков: " << WORKERS_COUNT << std::endl;

    std::queue<std::string> file_queue;
    std::mutex queue_mutex;
    std::vector<FileStats> results;
    std::mutex results_mutex;
    bool all_done = false;

    // заполняем очередь
    for (const auto& file : input_files) {
        file_queue.push(file);
    }

    std::vector<std::thread> threads;

    // создаём потоки
    for (int i = 0; i < WORKERS_COUNT; i++) {
        threads.emplace_back([&, i]() {
            std::cout << "Поток " << (i + 1) << " (ID: " << std::this_thread::get_id() << ") запущен" << std::endl;

            while (true) {
                std::string filename;

                // захватываем файл из очереди
                {
                    std::lock_guard<std::mutex> lock(queue_mutex);
                    if (file_queue.empty()) {
                        break;
                    }
                    filename = file_queue.front();
                    file_queue.pop();
                }

                std::cout << "Поток " << (i + 1) << " обрабатывает: " << filename << std::endl;
                FileStats stats = process_single_file(filename, output_dir, key,
                    set_key, caesar, log_mutex);

                {
                    std::lock_guard<std::mutex> lock(results_mutex);
                    results.push_back(stats);
                }
            }

            std::cout << "Поток " << (i + 1) << " завершен" << std::endl;
        });
    }

    // ждём завершения всех потоков
    for (auto& t : threads) {
        t.join();
    }

    return results;
}

// фвтоматический выбор режима
Mode auto_select_mode(int file_count) {
    if (file_count < 5) {
        std::cout << "Автовыбор: файлов < 5 -> ПОСЛЕДОВАТЕЛЬНЫЙ режим" << std::endl;
        return MODE_SEQUENTIAL;
    }
    else {
        std::cout << "Автовыбор: файлов >= 5 -> ПАРАЛЛЕЛЬНЫЙ режим" << std::endl;
        return MODE_PARALLEL;
    }
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

// запуск обработки в заданном режиме и возврат времени
milliseconds run_mode(Mode mode, const std::vector<std::string>& files,
    const std::string& output_dir, char key,
    set_key_func set_key, caesar_func caesar,
    std::mutex& log_mutex,
    std::vector<FileStats>& out_results) {
    auto start = high_resolution_clock::now();

    if (mode == MODE_SEQUENTIAL) {
        out_results = run_sequential(files, output_dir, key, set_key, caesar, log_mutex);
    }
    else {
        out_results = run_parallel(files, output_dir, key, set_key, caesar, log_mutex);
    }

    auto end = high_resolution_clock::now();
    return duration_cast<milliseconds>(end - start);
}

int main(int argc, char* argv[]) {
    setlocale(LC_ALL, "rus");

    // парсинг режима
    Mode mode = parse_mode_arg(argc, argv);
    int start_idx = 1;

    if (argc >= 2 && std::string(argv[1]).find("--mode=") == 0) {
        start_idx = 2;
    }

    // проверка аргументов
    if (argc - start_idx < 4) {
        std::cerr << "Использование: " << argv[0]
            << " [--mode=sequential|parallel|auto] <путь_к_библиотеке> <файл1> <файл2> ... <выходная_директория> <ключ>"
            << std::endl;
        return 1;
    }

    // парсинг аргументов
    std::string lib_path = argv[start_idx++];
    std::vector<std::string> input_files;
    for (int i = start_idx; i < argc - 2; i++) {
        input_files.push_back(argv[i]);
    }
    std::string output_dir = argv[argc - 2];
    if (!output_dir.empty() && output_dir.back() == '/') {
        output_dir.pop_back();
    }
    char key = argv[argc - 1][0];

    // автовыбор
    Mode original_mode = mode;
    if (mode == MODE_AUTO) {
        mode = auto_select_mode(static_cast<int>(input_files.size()));
    }

    // вывод информации
    std::cout << "=========================================" << std::endl;
    std::cout << "ЗАПУСК ПРОГРАММЫ SECURE COPY" << std::endl;
    std::cout << "=========================================" << std::endl;
    std::cout << "Режим: " << (mode == MODE_SEQUENTIAL ? "ПОСЛЕДОВАТЕЛЬНЫЙ" : "ПАРАЛЛЕЛЬНЫЙ") << std::endl;
    std::cout << "Путь к библиотеке: " << lib_path << std::endl;
    std::cout << "Входных файлов: " << input_files.size() << std::endl;
    std::cout << "Выходная директория: " << output_dir << std::endl;
    std::cout << "Ключ: " << key << std::endl;
    std::cout << "=========================================" << std::endl;

    // загрузка библиотеки
    std::cout << "Загрузка библиотеки: " << lib_path << std::endl;
    HINSTANCE hLib = LoadLibraryA(lib_path.c_str());
    if (!hLib) {
        std::cerr << "Не удалось загрузить библиотеку. Код ошибки: " << GetLastError() << std::endl;
        return 1;
    }

    set_key_func set_key = (set_key_func)GetProcAddress(hLib, "set_key");
    caesar_func caesar = (caesar_func)GetProcAddress(hLib, "caesar");

    if (!set_key || !caesar) {
        std::cerr << "Не удалось получить адреса функций" << std::endl;
        FreeLibrary(hLib);
        return 1;
    }
    std::cout << "Библиотека успешно загружена" << std::endl;

    // создание выходной директории
    try {
        fs::create_directories(output_dir);
        std::cout << "Выходная директория создана: " << output_dir << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "Ошибка: " << e.what() << std::endl;
        FreeLibrary(hLib);
        return 1;
    }

    // лог-файл
    std::mutex log_mutex;
    {
        std::ofstream logfile("log.txt", std::ios::trunc);
        logfile << "=== ЖУРНАЛ SECURE COPY ===\n";
        logfile << "Запуск: " << get_current_time() << "\n";
        logfile << "==========================================\n\n";
        logfile.close();
    }

    // проверка существования файлов
    std::vector<std::string> valid_files;
    for (const auto& file : input_files) {
        if (fs::exists(file)) {
            valid_files.push_back(file);
            std::cout << "Добавлен в очередь: " << file << std::endl;
        }
        else {
            std::cerr << "Предупреждение: Файл не существует, пропуск: " << file << std::endl;
        }
    }

    if (valid_files.empty()) {
        std::cerr << "Ошибка: нет файлов для обработки!" << std::endl;
        FreeLibrary(hLib);
        return 1;
    }

    // запуск выбранного режима
    std::vector<FileStats> results;
    milliseconds selected_duration = run_mode(mode, valid_files, output_dir, key,
        set_key, caesar, log_mutex, results);

    // подсчёт статистики
    int success_count = 0;
    long long total_file_time_ms = 0;
    for (const auto& stat : results) {
        if (stat.success) success_count++;
        total_file_time_ms += stat.duration.count();
    }
    double avg_time = results.empty() ? 0 : static_cast<double>(total_file_time_ms) / results.size();

    // вывод итогов
    std::cout << "\n=========================================" << std::endl;
    std::cout << "ВСЕ ФАЙЛЫ УСПЕШНО ОБРАБОТАНЫ!" << std::endl;
    std::cout << "Скопировано файлов: " << success_count << " из " << valid_files.size() << std::endl;
    std::cout << "Общее время: " << selected_duration.count() << " мс" << std::endl;
    std::cout << "Среднее время на файл: " << std::fixed << std::setprecision(2) << avg_time << " мс" << std::endl;
    std::cout << "=========================================" << std::endl;

    // СРАВНИТЕЛЬНАЯ ТАБЛИЦА (только в авто-режиме)
    if (original_mode == MODE_AUTO && valid_files.size() >= 2) {
        std::cout << "\n=== СРАВНИТЕЛЬНАЯ ТАБЛИЦА ===" << std::endl;

        Mode alternative = (mode == MODE_SEQUENTIAL) ? MODE_PARALLEL : MODE_SEQUENTIAL;
        std::cout << "Запуск альтернативного режима ("
            << (alternative == MODE_SEQUENTIAL ? "ПОСЛЕДОВАТЕЛЬНЫЙ" : "ПАРАЛЛЕЛЬНЫЙ")
            << ") для сравнения..." << std::endl;

        // создаём новую директорию для альтернативного режима
        std::string alt_output_dir = output_dir + "_alt";
        fs::create_directories(alt_output_dir);

        std::vector<FileStats> alt_results;
        milliseconds alt_duration = run_mode(alternative, valid_files, alt_output_dir, key,
            set_key, caesar, log_mutex, alt_results);

        // подсчёт статистики альтернативного режима
        int alt_success = 0;
        for (const auto& stat : alt_results) {
            if (stat.success) alt_success++;
        }

        std::cout << "\n--- СРАВНЕНИЕ ---" << std::endl;
        std::cout << std::left << std::setw(25) << "Показатель"
            << std::setw(20) << (mode == MODE_SEQUENTIAL ? "SEQUENTIAL" : "PARALLEL")
            << std::setw(20) << (alternative == MODE_SEQUENTIAL ? "SEQUENTIAL" : "PARALLEL") << std::endl;
        std::cout << std::string(60, '-') << std::endl;
        std::cout << std::left << std::setw(25) << "Общее время (мс)"
            << std::setw(20) << selected_duration.count()
            << std::setw(20) << alt_duration.count() << std::endl;
        std::cout << std::left << std::setw(25) << "Обработано файлов"
            << std::setw(20) << success_count
            << std::setw(20) << alt_success << std::endl;

        // ускорение
        double speedup = static_cast<double>(alt_duration.count()) / selected_duration.count();
        std::cout << std::string(60, '-') << std::endl;
        if (speedup > 1.0) {
            std::cout << "Выбранный режим БЫСТРЕЕ в " << std::fixed << std::setprecision(2)
                << speedup << " раз" << std::endl;
        }
        else if (speedup < 1.0) {
            std::cout << "Выбранный режим МЕДЛЕННЕЕ в " << std::fixed << std::setprecision(2)
                << (1.0 / speedup) << " раз" << std::endl;
        }
        else {
            std::cout << "Режимы работают одинаково" << std::endl;
        }
        std::cout << "=========================================" << std::endl;

        // очистка временной директории
        //fs::remove_all(alt_output_dir);
    }

    // итоговая запись в лог
    {
        std::lock_guard<std::mutex> lock(log_mutex);
        std::ofstream logfile("log.txt", std::ios::app);
        logfile << "\n==========================================\n";
        logfile << "Завершение: " << get_current_time() << "\n";
        logfile << "Скопировано файлов: " << success_count << " из " << valid_files.size() << "\n";
        logfile << "Общее время: " << selected_duration.count() << " мс\n";
        logfile << "Среднее время: " << std::fixed << std::setprecision(2) << avg_time << " мс\n";
        logfile << "==========================================\n";
    }

    FreeLibrary(hLib);
    return 0;
}