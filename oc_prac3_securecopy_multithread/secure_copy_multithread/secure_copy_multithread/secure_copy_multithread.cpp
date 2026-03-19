#include <iostream>
#include <fstream>
#include <vector>
#include <thread>
#include <mutex>
#include <chrono>
#include <string>
#include <queue>
#include <filesystem>
#include <iomanip>
#include <ctime>
#include <windows.h>

namespace fs = std::filesystem;
using namespace std::chrono;


const int TIMEOUT_SECONDS = 5;
const int MAX_RETRIES = 3;

typedef void (*set_key_func)(char);
typedef void (*caesar_func)(void*, void*, int);

set_key_func set_key = nullptr;
caesar_func caesar = nullptr;

std::timed_mutex file_mutex;      // для счетчика и очереди файлов
std::mutex log_mutex;             // отдельный мьютекс для логирования

int files_copied = 0;
std::queue<std::string> file_queue;
bool all_files_queued = false;
bool system_error = false;         // Флаг системной ошибки

// Вспомогательная функция для получения текущего времени
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
    const std::chrono::milliseconds& duration) {
    std::lock_guard<std::mutex> lock(log_mutex);

    std::ofstream logfile("log.txt", std::ios::app);
    if (!logfile) return;

    // ID потока
    std::stringstream ss;
    ss << std::this_thread::get_id();
    std::string thread_id = ss.str();

    // запись в лог
    logfile << "[" << get_current_time() << "] "
        << "Поток " << thread_id << " | "
        << "Файл: " << filename << " | "
        << "Статус: " << status << " | "
        << "Время: " << duration.count() << "мс" << std::endl;
}

// ф-ция для безопасного обновления счетчика с таймаутом и повторными попытками
bool update_counter_with_timeout(const std::string& filename) {
    int retry_count = 0;

    while (retry_count < MAX_RETRIES) {
        auto deadline = steady_clock::now() + seconds(TIMEOUT_SECONDS);

        if (file_mutex.try_lock_until(deadline)) {
            // успехом захватили мьютекс
            files_copied++;
            std::cout << "Прогресс: скопировано " << files_copied << " файлов" << std::endl;
            file_mutex.unlock();
            return true;
        }
        else {
            retry_count++;
            std::cerr << "ПРЕДУПРЕЖДЕНИЕ: Возможная взаимоблокировка - поток "
                << std::this_thread::get_id()
                << " ожидает мьютекс более " << TIMEOUT_SECONDS
                << " секунд (попытка " << retry_count
                << " из " << MAX_RETRIES << ")" << std::endl;

            // лог предупреждение
            {
                std::lock_guard<std::mutex> lock(log_mutex);
                std::ofstream logfile("log.txt", std::ios::app);
                logfile << "[" << get_current_time() << "] "
                    << "ПРЕДУПРЕЖДЕНИЕ: Поток " << std::this_thread::get_id()
                    << " не может захватить мьютекс (попытка " << retry_count << ")\n";
            }
        }
    }

    // превышено количество попыток
    std::cerr << "КРИТИЧЕСКАЯ ОШИБКА: Поток " << std::this_thread::get_id()
        << " не может обновить счетчик после " << MAX_RETRIES
        << " попыток. Аварийное завершение потока!" << std::endl;

    // лог критической ошибку
    {
        std::lock_guard<std::mutex> lock(log_mutex);
        std::ofstream logfile("log.txt", std::ios::app);
        logfile << "[" << get_current_time() << "] "
            << "КРИТИЧЕСКАЯ ОШИБКА: Поток " << std::this_thread::get_id()
            << " аварийно завершен из-за невозможности захватить мьютекс\n";
    }

    return false;
}

// ф-ция обработки одного файла
void process_file(const std::string& input_file, const std::string& output_dir, char key) {
    auto start_time = high_resolution_clock::now();
    std::string status = "ОШИБКА";

    try {
        std::string output_file = (fs::path(output_dir) / fs::path(input_file).filename()).string();

        // открываем входной файл
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


        if (input_file.find("slow.txt") != std::string::npos) {
            std::cout << "Обнаружен медленный файл, имитация долгой обработки..." << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(10));
        }

        set_key(key);
        caesar(buffer.data(), buffer.data(), static_cast<int>(size));

        // запись результата
        std::ofstream out(output_file, std::ios::binary);
        if (!out.write(buffer.data(), size)) {
            throw std::runtime_error("Ошибка записи выходного файла");
        }

        status = "УСПЕХ";

        // обновляем счетчик с защитой от зависания
        if (!update_counter_with_timeout(input_file)) {
            status = "ОШИБКА: Невозможно обновить счетчик (системная ошибка)";
            system_error = true;
        }

    }
    catch (const std::exception& e) {
        std::cerr << "Ошибка обработки файла " << input_file << ": " << e.what() << std::endl;
        status = std::string("ОШИБКА: ") + e.what();
    }

    auto end_time = high_resolution_clock::now();
    auto duration = duration_cast<milliseconds>(end_time - start_time);

    log_operation(input_file, status, duration);
}

// ф-ция для безопасного получения файла из очереди
bool get_file_from_queue(std::string& filename, int thread_id) {
    int retry_count = 0;

    while (retry_count < MAX_RETRIES && !system_error) {
        auto deadline = steady_clock::now() + seconds(TIMEOUT_SECONDS);

        if (file_mutex.try_lock_until(deadline)) {
            if (!file_queue.empty()) {
                filename = file_queue.front();
                file_queue.pop();
                file_mutex.unlock();
                return true;
            }
            else if (all_files_queued) {
                file_mutex.unlock();
                return false;  // нет больше файлов
            }
            else {
                file_mutex.unlock();
                std::this_thread::sleep_for(milliseconds(100));
                continue;
            }
        }
        else {
            retry_count++;
            std::cerr << "ПРЕДУПРЕЖДЕНИЕ: Поток " << thread_id
                << " не может получить доступ к очереди (попытка "
                << retry_count << " из " << MAX_RETRIES << ")" << std::endl;

            {
                std::lock_guard<std::mutex> lock(log_mutex);
                std::ofstream logfile("log.txt", std::ios::app);
                logfile << "[" << get_current_time() << "] "
                    << "ПРЕДУПРЕЖДЕНИЕ: Поток " << std::this_thread::get_id()
                    << " не может получить доступ к очереди (попытка "
                    << retry_count << ")\n";
            }
        }
    }

    if (retry_count >= MAX_RETRIES) {
        std::cerr << "КРИТИЧЕСКАЯ ОШИБКА: Поток " << thread_id
            << " не может получить доступ к очереди после " << MAX_RETRIES
            << " попыток. Аварийное завершение потока!" << std::endl;

        {
            std::lock_guard<std::mutex> lock(log_mutex);
            std::ofstream logfile("log.txt", std::ios::app);
            logfile << "[" << get_current_time() << "] "
                << "КРИТИЧЕСКАЯ ОШИБКА: Поток " << std::this_thread::get_id()
                << " аварийно завершен из-за невозможности получить доступ к очереди\n";
        }
    }

    return false;
}

// фция рабочего потока
void worker_thread(const std::string& output_dir, char key, int thread_num) {
    std::cout << "Поток " << thread_num << " (ID: " << std::this_thread::get_id() << ") запущен" << std::endl;

    while (!system_error) {
        std::string filename;

        // пытемся получить файл из очереди
        if (!get_file_from_queue(filename, thread_num)) {
            break;  // завершение потока (нет файлов или ошибка)
        }

        std::cout << "Поток " << thread_num << " обрабатывает файл: " << filename << std::endl;
        process_file(filename, output_dir, key);
    }

    std::cout << "Поток " << thread_num << " завершен" << std::endl;
}

int main(int argc, char* argv[]) {
    setlocale(LC_ALL, "rus");
    if (argc < 4) {
        std::cerr << "Использование: " << argv[0]
            << " <путь_к_библиотеке> <файл1> <файл2> ... <выходная_директория> <ключ>" << std::endl;
        std::cerr << "Пример: " << argv[0]
            << " libcaesar.dll file1.txt file2.txt file3.txt output_dir/ K" << std::endl;
        return 1;
    }

    // парсинг аргументов
    std::string lib_path = argv[1];

    std::vector<std::string> input_files;
    for (int i = 2; i < argc - 2; i++) {
        input_files.push_back(argv[i]);
    }

    std::string output_dir = argv[argc - 2];

    // убираем возможный слеш в конце для единообразия
    if (!output_dir.empty() && output_dir.back() == '/') {
        output_dir.pop_back();
    }

    char key = argv[argc - 1][0];

    std::cout << "=========================================" << std::endl;
    std::cout << "ЗАПУСК ПРОГРАММЫ SECURE COPY (МНОГОПОТОЧНАЯ)" << std::endl;
    std::cout << "=========================================" << std::endl;
    std::cout << "Путь к библиотеке: " << lib_path << std::endl;
    std::cout << "Входных файлов: " << input_files.size() << std::endl;
    std::cout << "Выходная директория: " << output_dir << std::endl;
    std::cout << "Ключ: " << key << std::endl;
    std::cout << "Таймаут мьютекса: " << TIMEOUT_SECONDS << " сек" << std::endl;
    std::cout << "Макс. попыток: " << MAX_RETRIES << std::endl;
    std::cout << "=========================================" << std::endl;

    // 1. ДИНАМИЧЕСКИ ЗАГРУЖАЕМ БИБЛИОТЕКУ
    std::cout << "Загрузка библиотеки: " << lib_path << std::endl;

    HINSTANCE hLib = LoadLibraryA(lib_path.c_str());
    if (!hLib) {
        std::cerr << "Не удалось загрузить библиотеку. Код ошибки: " << GetLastError() << std::endl;
        return 1;
    }

    set_key = (set_key_func)GetProcAddress(hLib, "set_key");
    caesar = (caesar_func)GetProcAddress(hLib, "caesar");

    if (!set_key || !caesar) {
        std::cerr << "Не удалось получить адреса функций. Код ошибки: " << GetLastError() << std::endl;
        FreeLibrary(hLib);
        return 1;
    }

    std::cout << "Библиотека успешно загружена. Функции найдены." << std::endl;

    // 2. СОЗДАЕМ ВЫХОДНУЮ ДИРЕКТОРИЮ
    try {
        fs::create_directories(output_dir);
        std::cout << "Выходная директория создана: " << output_dir << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "Ошибка создания выходной директории: " << e.what() << std::endl;
        FreeLibrary(hLib);
        return 1;
    }

    // 3. ОЧИЩАЕМ/СОЗДАЕМ ЛОГ-ФАЙЛ
    std::ofstream logfile("log.txt", std::ios::trunc);
    logfile << "=== ЖУРНАЛ SECURE COPY (МНОГОПОТОЧНЫЙ) ===\n";
    logfile << "Запуск: " << get_current_time() << "\n";
    logfile << "Библиотека: " << lib_path << "\n";
    logfile << "Выходная директория: " << output_dir << "\n";
    logfile << "Ключ: " << key << "\n";
    logfile << "Таймаут: " << TIMEOUT_SECONDS << " сек\n";
    logfile << "Попыток: " << MAX_RETRIES << "\n";
    logfile << "==========================================\n\n";
    logfile.close();

    // 4. ЗАПОЛНЯЕМ ОЧЕРЕДЬ ФАЙЛОВ
    int files_queued = 0;
    {
        std::lock_guard<std::timed_mutex> lock(file_mutex);
        for (const auto& file : input_files) {
            if (fs::exists(file)) {
                file_queue.push(file);
                std::cout << "Добавлен в очередь: " << file << std::endl;
                files_queued++;
            }
            else {
                std::cerr << "Предупреждение: Файл не существует, пропуск: " << file << std::endl;
                // лог пропущенный файл
                std::lock_guard<std::mutex> log_lock(log_mutex);
                std::ofstream logfile("log.txt", std::ios::app);
                logfile << "[" << get_current_time() << "] Файл не существует, пропущен: " << file << "\n";
            }
        }
        all_files_queued = true;
        std::cout << "Всего файлов в очереди: " << file_queue.size() << std::endl;
    }

    if (files_queued == 0) {
        std::cerr << "Ошибка: нет файлов для обработки!" << std::endl;
        FreeLibrary(hLib);
        return 1;
    }

    // 5. СОЗДАЕМ 3 РАБОЧИХ ПОТОКА
    const int num_threads = 3;
    std::vector<std::thread> threads;

    std::cout << "\nЗапуск " << num_threads << " потоков..." << std::endl;

    auto program_start = high_resolution_clock::now();

    for (int i = 0; i < num_threads; i++) {
        threads.emplace_back(worker_thread, output_dir, key, i + 1);
        std::this_thread::sleep_for(milliseconds(10)); // Небольшая задержка для красивого вывода
    }

    // 6. ЖДЕМ ЗАВЕРШЕНИЯ ВСЕХ ПОТОКОВ
    for (auto& t : threads) {
        t.join();
    }

    auto program_end = high_resolution_clock::now();
    auto total_duration = duration_cast<milliseconds>(program_end - program_start);

    std::cout << "\n=========================================" << std::endl;
    if (system_error) {
        std::cout << "ПРОГРАММА ЗАВЕРШЕНА С ОШИБКАМИ!" << std::endl;
    }
    else {
        std::cout << "ВСЕ ФАЙЛЫ УСПЕШНО ОБРАБОТАНЫ!" << std::endl;
    }
    std::cout << "Скопировано файлов: " << files_copied << " из " << files_queued << std::endl;
    std::cout << "Общее время: " << total_duration.count() << " мс" << std::endl;
    std::cout << "Подробности в файле: " << fs::absolute("log.txt").string() << std::endl;
    std::cout << "=========================================" << std::endl;

    // итоговая запись в лог
    {
        std::lock_guard<std::mutex> log_lock(log_mutex);
        std::ofstream logfile("log.txt", std::ios::app);
        logfile << "\n==========================================\n";
        logfile << "Завершение: " << get_current_time() << "\n";
        logfile << "Скопировано файлов: " << files_copied << " из " << files_queued << "\n";
        logfile << "Общее время: " << total_duration.count() << " мс\n";
        logfile << "Статус: " << (system_error ? "С ОШИБКАМИ" : "УСПЕШНО") << "\n";
        logfile << "==========================================\n";
    }

    // 7. ВЫГРУЖАЕМ БИБЛИОТЕКУ
    FreeLibrary(hLib);

    return system_error ? 1 : 0;
}