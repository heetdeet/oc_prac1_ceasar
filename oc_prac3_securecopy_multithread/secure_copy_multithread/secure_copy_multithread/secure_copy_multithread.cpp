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
#include <random>
#include <algorithm>

namespace fs = std::filesystem;
using namespace std::chrono;

// ===================== ЗАЩИТА S-БЛОКА =====================
static LPVOID secure_sblock_mem = nullptr;
static const SIZE_T SBLOCK_SIZE = 256;
static DWORD sblock_old_protect = 0;

void init_secure_sblock_memory()
{
    secure_sblock_mem = VirtualAlloc(NULL, SBLOCK_SIZE,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);
    if (!secure_sblock_mem) {
        std::cerr << "VirtualAlloc для S-блока failed\n";
        exit(1);
    }
}

void protect_sblock()
{
    VirtualProtect(secure_sblock_mem, SBLOCK_SIZE, PAGE_READONLY, &sblock_old_protect);
}

void unprotect_sblock()
{
    VirtualProtect(secure_sblock_mem, SBLOCK_SIZE, PAGE_READWRITE, &sblock_old_protect);
}

void cleanup_secure_sblock()
{
    if (secure_sblock_mem) {
        unprotect_sblock();
        SecureZeroMemory(secure_sblock_mem, SBLOCK_SIZE);
        VirtualFree(secure_sblock_mem, 0, MEM_RELEASE);
        secure_sblock_mem = nullptr;
    }
}

// ===================== RC4 ШИФРОВАНИЕ =====================
struct RC4State {
    unsigned char* S;  // указатель на защищённую память
    int i, j;
};

// Генерация соли
std::vector<unsigned char> generate_salt(size_t length = 16) {
    std::vector<unsigned char> salt(length); // вектор из 16 байт
    std::random_device rd;
    std::mt19937 gen(rd()); // генератор
    std::uniform_int_distribution<unsigned int> dist(0, 255); // распределение 0-255
    for (auto& b : salt)
        b = static_cast<unsigned char>(dist(gen)); // заполнение случайными битами
    return salt;
}

//инициализация RC4: ключ = мастер_ключ || соль
void rc4_init(RC4State& state, const unsigned char* key, size_t key_len,
    const unsigned char* salt, size_t salt_len)
{
    // объединяем ключ и соль
    std::vector<unsigned char> full_key(key, key + key_len);
    full_key.insert(full_key.end(), salt, salt + salt_len);

    // инициализируем защищённый S-блок
    if (!secure_sblock_mem) {
        init_secure_sblock_memory();
    }

    unprotect_sblock();  // разрешаем запись

    state.S = static_cast<unsigned char*>(secure_sblock_mem);

    // заполнение S-блока
    for (int idx = 0; idx < 256; idx++)
        state.S[idx] = static_cast<unsigned char>(idx);

    // KSA
    int jj = 0;
    size_t fk_len = full_key.size();
    for (int idx = 0; idx < 256; idx++) {
        jj = (jj + state.S[idx] + full_key[idx % fk_len]) & 0xFF;
        std::swap(state.S[idx], state.S[jj]);
    }

    SecureZeroMemory(full_key.data(), full_key.size());

    state.i = 0;
    state.j = 0;

    protect_sblock();  //блокируем от записи
}

// Шифрование/дешифрование
void rc4_process(RC4State& state, const unsigned char* input,
    unsigned char* output, size_t length)
{
    unprotect_sblock();  // нужно модифицировать S-блок

    for (size_t k = 0; k < length; k++) {
        state.i = (state.i + 1) & 0xFF;
        state.j = (state.j + state.S[state.i]) & 0xFF;
        std::swap(state.S[state.i], state.S[state.j]);
        unsigned char keystream_byte = state.S[(state.S[state.i] + state.S[state.j]) & 0xFF];
        output[k] = input[k] ^ keystream_byte;
    }

    protect_sblock();  // блокируем обратно S-блок
}

// ===================== ЗАЩИЩЁННАЯ ПАМЯТЬ =====================
static LPVOID secure_key_mem = nullptr;
static const SIZE_T KEY_SIZE = 256;
static DWORD old_protect = 0;
static SIZE_T actual_key_len = 0;

LONG WINAPI AccessViolationHandler(PEXCEPTION_POINTERS pExceptionInfo)
{
    //проверка нарушения доступа к памяти
    if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
    {
        std::cerr << "\n[ОШИБКА БЕЗОПАСНОСТИ] EXCEPTION_ACCESS_VIOLATION!\n";
        std::cerr << "Попытка несанкционированной записи в защищённую память!\n";
        std::cerr << "Адрес: " << pExceptionInfo->ExceptionRecord->ExceptionAddress << std::endl;
        std::cerr << "Программа завершена для защиты ключа.\n";
        ExitProcess(1); //завершение проги
    }
    return EXCEPTION_CONTINUE_SEARCH; // передача другим обработчикам
}

void init_secure_key_memory() // выделение защищеной памяти
{
    //выделяем 256 байт памяти
    secure_key_mem = VirtualAlloc(NULL, // адресс выделяет система
        KEY_SIZE, //256 байт
        MEM_COMMIT | MEM_RESERVE, // резервируем и фиксируем
        PAGE_READWRITE); // доступ (чтение + запись)
    if (!secure_key_mem) {
        std::cerr << "VirtualAlloc failed\n";
        exit(1);
    }
}

void set_secure_key(const std::string& key)
{
    //снимаем защиту для записи
    VirtualProtect(secure_key_mem, KEY_SIZE, PAGE_READWRITE, &old_protect);
    // очищаем старый ключ
    SecureZeroMemory(secure_key_mem, KEY_SIZE);
    //копируем новый ключ (макс. 256 байт)
    size_t copy_len = min(key.size(), static_cast<size_t>(KEY_SIZE));
    memcpy(secure_key_mem, key.data(), copy_len);
    actual_key_len = copy_len; // сохраняем реальную длину
    //ставим защиту обратно (только чтение)
    VirtualProtect(secure_key_mem, KEY_SIZE, PAGE_READONLY, &old_protect);
}

std::vector<unsigned char> get_secure_key()
{
    //подтверждаем защиту (на всякий случай)
    VirtualProtect(secure_key_mem, KEY_SIZE, PAGE_READONLY, &old_protect);
    //копируем ключ в вектор
    std::vector<unsigned char> key_buf(actual_key_len);
    memcpy(key_buf.data(), secure_key_mem, actual_key_len);
    return key_buf;
}

void cleanup_secure_memory()
{
    if (secure_key_mem) {
        VirtualProtect(secure_key_mem, KEY_SIZE, PAGE_READWRITE, &old_protect);
        SecureZeroMemory(secure_key_mem, KEY_SIZE);
        // освобождаем память
        VirtualFree(secure_key_mem, 0, MEM_RELEASE);
        secure_key_mem = nullptr;
    }
}



// ===================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ДЛЯ ЗАПИСИ/ЧТЕНИЯ =====================
void write_u32_le(std::ofstream& f, uint32_t v) { // запись 32-юитьного числа
    unsigned char b[4];
    b[0] = v & 0xFF;          //младший байт
    b[1] = (v >> 8) & 0xFF;   // 2-й байт
    b[2] = (v >> 16) & 0xFF;  // 3-й байт
    b[3] = (v >> 24) & 0xFF;  //старший байт
    f.write(reinterpret_cast<char*>(b), 4);
}

uint32_t read_u32_le(std::ifstream& f) {
    unsigned char b[4];
    f.read(reinterpret_cast<char*>(b), 4);
    if (f.fail()) return 0;
    // собираем число из байтов
    return (uint32_t)b[0] |  // младший байт
        ((uint32_t)b[1] << 8) |  // 2-й байт
        ((uint32_t)b[2] << 16) |  // 3-й байт
        ((uint32_t)b[3] << 24);   // старший байт
}

// ===================== СТРУКТУРЫ =====================
struct FileStats {
    std::string filename;      // Имя файла
    milliseconds duration;     // Время обработки
    bool success = false;      // Успешно ли обработан
    std::string error_msg;     // Сообщение об ошибке
};

enum Mode { MODE_SEQUENTIAL, MODE_PARALLEL, MODE_AUTO };


struct ParallelContext {
    size_t current_task_index = 0;
    size_t total_tasks = 0;
    std::mutex mtx;
    std::condition_variable cv;
    std::vector<FileStats> results;
    std::mutex results_mtx;
    bool all_done = false;
    std::string image_path;
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

// ===================== ПРОВЕРКА ДУБЛИКАТОВ =====================

bool file_exists_in_image(const std::string& image_path, const std::string& file_name) {
    if (!fs::exists(image_path)) {
        return false; // образ пустой
    }

    std::ifstream in(image_path, std::ios::binary);
    if (!in) return false;

    while (true) {
        uint32_t file_len = read_u32_le(in);
        if (in.fail()) break;
        uint32_t name_len = read_u32_le(in);
        if (in.fail()) break;

        unsigned char salt[16];
        if (!in.read(reinterpret_cast<char*>(salt), 16)) break;

        std::string name(name_len, '\0');
        if (name_len > 0 && !in.read(&name[0], name_len)) break;

        if (name == file_name) {
            in.close();
            return true; // найден дубликат
        }

        if (in.seekg(file_len, std::ios::cur).fail()) break;
    }

    in.close();
    return false;
}

// структура задачи с предвычисленным смещением
struct EncryptionTask {
    std::string input_path;
    std::string stored_name;
    size_t offset_in_image;
    size_t total_size;
};

// ===================== ОБРАБОТКА ФАЙЛА (изменено на RC4 + образ) =====================
FileStats process_single_file_mapped(const EncryptionTask& task,
    const std::string& image_path,
    std::mutex& log_mutex)
{
    auto start_time = high_resolution_clock::now();
    FileStats stats{};
    stats.filename = task.stored_name;
    stats.success = false;

    try {
        // открываем образ для маппинга
        HANDLE hFile = CreateFileA(
            image_path.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );

        if (hFile == INVALID_HANDLE_VALUE) {
            throw std::runtime_error("Не удалось открыть образ");
        }

        // создаём file mapping
        HANDLE hMapping = CreateFileMappingA(
            hFile, NULL, PAGE_READWRITE,
            0, 0, NULL
        );

        if (!hMapping) {
            CloseHandle(hFile);
            throw std::runtime_error("CreateFileMapping failed");
        }

        // маппим нужную область
        LPVOID mapped_view = MapViewOfFile(
            hMapping,
            FILE_MAP_WRITE,
            (DWORD)((task.offset_in_image >> 32) & 0xFFFFFFFF),
            (DWORD)(task.offset_in_image & 0xFFFFFFFF),
            task.total_size
        );

        if (!mapped_view) {
            CloseHandle(hMapping);
            CloseHandle(hFile);
            throw std::runtime_error("MapViewOfFile failed");
        }

        unsigned char* write_ptr = static_cast<unsigned char*>(mapped_view);

        // открываем входной файл
        std::ifstream in(task.input_path, std::ios::binary | std::ios::ate);
        size_t file_size = in.tellg();
        in.seekg(0);

        uint32_t file_size_u32 = static_cast<uint32_t>(file_size);
        uint32_t name_len = static_cast<uint32_t>(task.stored_name.size());

        // генерируем соль
        std::vector<unsigned char> salt = generate_salt(16);

        // получаем ключ
        std::vector<unsigned char> master_key = get_secure_key();

        // инициализируем RC4
        RC4State rc4;
        rc4_init(rc4, master_key.data(), master_key.size(),
            salt.data(), salt.size());
        SecureZeroMemory(master_key.data(), master_key.size());

        // пишем заголовок в mapped memory
        write_ptr[0] = file_size_u32 & 0xFF;
        write_ptr[1] = (file_size_u32 >> 8) & 0xFF;
        write_ptr[2] = (file_size_u32 >> 16) & 0xFF;
        write_ptr[3] = (file_size_u32 >> 24) & 0xFF;
        write_ptr += 4;

        write_ptr[0] = name_len & 0xFF;
        write_ptr[1] = (name_len >> 8) & 0xFF;
        write_ptr[2] = (name_len >> 16) & 0xFF;
        write_ptr[3] = (name_len >> 24) & 0xFF;
        write_ptr += 4;

        memcpy(write_ptr, salt.data(), 16);
        write_ptr += 16;

        memcpy(write_ptr, task.stored_name.data(), name_len);
        write_ptr += name_len;

        //шифрование данных чанками
        if (file_size > 0) {
            const size_t CHUNK_SIZE = 4 * 1024 * 1024;
            std::vector<unsigned char> chunk_plain(CHUNK_SIZE);

            size_t remaining = file_size;
            while (remaining > 0) {
                size_t to_read = min(remaining, CHUNK_SIZE);

                in.read(reinterpret_cast<char*>(chunk_plain.data()), to_read);
                size_t actually_read = in.gcount();

                // шифруем НАПРЯМУЮ в mapped memory
                rc4_process(rc4, chunk_plain.data(), write_ptr, actually_read);

                SecureZeroMemory(chunk_plain.data(), actually_read);

                write_ptr += actually_read;
                remaining -= actually_read;
            }
        }

        SecureZeroMemory(&rc4, sizeof(rc4));

        // сбрасываем на диск
        FlushViewOfFile(mapped_view, task.total_size);

        UnmapViewOfFile(mapped_view);
        CloseHandle(hMapping);
        CloseHandle(hFile);

        stats.success = true;
    }
    catch (const std::exception& e) {
        stats.error_msg = e.what();
    }

    auto end_time = high_resolution_clock::now();
    stats.duration = duration_cast<milliseconds>(end_time - start_time);
    log_operation(task.stored_name, stats.success ? "УСПЕХ" : stats.error_msg,
        stats.duration, log_mutex);

    return stats;
}

// ===================== WORKER THREAD =====================
void worker_thread_mapped(ParallelContext& ctx,
    std::mutex& log_mutex,
    const std::vector<EncryptionTask>& tasks)
{
    while (true) {
        size_t task_index;
        {
            std::unique_lock<std::mutex> lock(ctx.mtx);
            ctx.cv.wait(lock, [&ctx] {
                return ctx.current_task_index < ctx.total_tasks || ctx.all_done;
            });

            if (ctx.current_task_index >= ctx.total_tasks) break;

            task_index = ctx.current_task_index++;
        }

        FileStats stats = process_single_file_mapped(tasks[task_index],
            ctx.image_path,
            log_mutex);

        {
            std::lock_guard<std::mutex> lock(ctx.results_mtx);
            ctx.results.push_back(stats);
        }
    }
}

// предварительное резервирование места в образе
std::vector<EncryptionTask> prepare_tasks(
    const std::vector<std::pair<std::string, std::string>>& files,
    const std::string& image_path)
{
    std::vector<EncryptionTask> tasks;
    size_t current_offset = 0;

    // если образ существует, начинаем с конца
    if (fs::exists(image_path)) {
        current_offset = fs::file_size(image_path);
    }

    for (const auto& [file_path, stored_name] : files) {
        size_t file_size = fs::file_size(file_path);
        size_t name_len = stored_name.size();

        // размер записи: 4 + 4 + 16 + name_len + file_size
        size_t record_size = 4 + 4 + 16 + name_len + file_size;

        EncryptionTask task;
        task.input_path = file_path;
        task.stored_name = stored_name;
        task.offset_in_image = current_offset;
        task.total_size = record_size;

        tasks.push_back(task);
        current_offset += record_size;
    }

    // расширяем файл образа до нужного размера
    {
        std::ofstream out(image_path, std::ios::binary | std::ios::app);
        out.seekp(current_offset - 1);
        out.write("\0", 1);
    }

    return tasks;
}

// ===================== process_files =====================
std::vector<FileStats> process_files(
    const std::vector<std::pair<std::string, std::string>>& files,
    const std::string& image_path,
    std::mutex& log_mutex,
    Mode mode,
    Mode& used_mode,
    milliseconds& total_duration)
{
    auto start_time = high_resolution_clock::now();

    Mode actual_mode = mode;
    if (mode == MODE_AUTO) {
        actual_mode = files.size() < 5 ? MODE_SEQUENTIAL : MODE_PARALLEL;
    }
    used_mode = actual_mode;

    // ПОДГОТОВКА: резервируем место(БЫСТРО, под мьютексом)
    std::vector<EncryptionTask> tasks = prepare_tasks(files, image_path);

    std::vector<FileStats> results;

    if (actual_mode == MODE_SEQUENTIAL) {
        for (const auto& task : tasks) {
            FileStats stats = process_single_file_mapped(task, image_path, log_mutex);
            results.push_back(stats);
        }
    }
    else {
        ParallelContext ctx;
        ctx.image_path = image_path;
        ctx.total_tasks = tasks.size();

        std::vector<std::thread> threads;
        int num_threads = min(5, static_cast<int>(files.size()));

        for (int i = 0; i < num_threads; ++i) {
            threads.emplace_back(worker_thread_mapped,
                std::ref(ctx),
                std::ref(log_mutex),
                std::ref(tasks));
        }

        ctx.cv.notify_all();

        for (auto& t : threads) t.join();

        results = ctx.results;
    }

    total_duration = duration_cast<milliseconds>(
        high_resolution_clock::now() - start_time);

    return results;
}

// ===================== ОПЕРАЦИИ С ОБРАЗОМ =====================

// Список файлов в образе
void image_list(const std::string& image_path) {
    std::ifstream in(image_path, std::ios::binary);
    if (!in) {
        std::cerr << "[ERROR] Образ не найден: " << image_path << "\n";
        return;
    }

    //проверка размера файла
    in.seekg(0, std::ios::end);
    std::streamsize total_size = in.tellg();
    in.seekg(0, std::ios::beg);

    if (total_size == 0) {
        std::cout << "[INFO] Образ пустой\n";
        return;
    }

    struct FileInfo {
        std::string name;
        uint32_t size;
    };
    std::vector<FileInfo> files;

    bool corrupted = false; // флаг повреждения

    while (in.tellg() < total_size) { // проверка позиции
        uint32_t file_len = read_u32_le(in);
        if (in.fail() || in.eof()) break; // проверка EOF

        uint32_t name_len = read_u32_le(in);
        if (in.fail() || in.eof()) {
            corrupted = true;
            break;
        }

        unsigned char salt[16];
        if (!in.read(reinterpret_cast<char*>(salt), 16) || in.gcount() != 16) {
            corrupted = true;
            break;
        }

        // проверка на разумность длины имени
        if (name_len == 0 || name_len > 4096) { // макс 4KB для имени
            corrupted = true;
            break;
        }

        std::string name(name_len, '\0');
        if (!in.read(&name[0], name_len) || in.gcount() != name_len) {
            corrupted = true;
            break;
        }

        // проверка на достаточность данных
        std::streamsize current_pos = in.tellg();
        if (current_pos + file_len > total_size) {
            corrupted = true;
            break;
        }

        if (in.seekg(file_len, std::ios::cur).fail()) {
            corrupted = true;
            break;
        }

        files.push_back({ name, file_len });
    }

    if (corrupted) {
        std::cerr << "[WARNING] Образ повреждён или неполон (найдено файлов: "
            << files.size() << ")\n";
    }

    if (files.empty()) {
        std::cout << "[INFO] Нет корректных записей в образе\n";
        return;
    }

    std::sort(files.begin(), files.end(),
        [](const FileInfo& a, const FileInfo& b) { return a.name < b.name; });

    std::cout << "\n========== СПИСОК ФАЙЛОВ В ОБРАЗЕ ==========\n";
    std::cout << std::left << std::setw(60) << "Имя файла"
        << std::setw(15) << "Размер (байт)" << "\n";
    std::cout << std::string(75, '-') << "\n";

    uint64_t total_files_size = 0;
    for (const auto& f : files) {
        // проверка переполнения
        if (total_files_size > UINT64_MAX - f.size) {
            std::cerr << "[WARNING] Переполнение при подсчёте размера\n";
            break;
        }
        total_files_size += f.size;

        std::cout << std::left << std::setw(60) << f.name
            << std::setw(15) << f.size << "\n";
    }

    std::cout << std::string(75, '-') << "\n";
    std::cout << "Итого файлов: " << files.size() << " | Размер: " << total_files_size << " байт\n";
    std::cout << "==========================================\n\n";
}


// Извлечение файла из образа
bool image_get(const std::string& image_path, const std::string& file_name,
    const std::string& output_path, std::mutex& log_mutex) {
    auto start_time = high_resolution_clock::now();

    std::ifstream in(image_path, std::ios::binary);
    if (!in) {
        std::cerr << "[ERROR] Образ не найден: " << image_path << "\n";
        return false;
    }

    // Размер образа
    in.seekg(0, std::ios::end);
    std::streamsize total_size = in.tellg();
    in.seekg(0, std::ios::beg);

    if (total_size == 0) {
        std::cerr << "[ERROR] Образ пустой\n";
        return false;
    }

    while (in.tellg() < total_size) {
        uint32_t file_len = read_u32_le(in);
        if (in.fail() || in.eof()) break;

        uint32_t name_len = read_u32_le(in);
        if (in.fail() || in.eof()) {
            std::cerr << "[ERROR] Образ повреждён\n";
            return false;
        }

        if (name_len == 0 || name_len > 4096) {
            std::cerr << "[ERROR] Образ повреждён (некорректная длина имени)\n";
            return false;
        }

        unsigned char salt[16];
        if (!in.read(reinterpret_cast<char*>(salt), 16) || in.gcount() != 16) {
            std::cerr << "[ERROR] Образ повреждён (ошибка чтения соли)\n";
            return false;
        }

        std::string name(name_len, '\0');
        if (!in.read(&name[0], name_len) ||
            static_cast<uint32_t>(in.gcount()) != name_len) {
            std::cerr << "[ERROR] Образ повреждён (ошибка чтения имени)\n";
            return false;
        }

        if (name == file_name) {
            // Проверка границ
            std::streamsize current_pos = in.tellg();
            if (current_pos < 0 || current_pos + file_len > total_size) {
                std::cerr << "[ERROR] Образ повреждён (данные за пределами образа)\n";
                return false;
            }

            // Инициализируем RC4
            std::vector<unsigned char> master_key = get_secure_key();
            RC4State rc4;
            rc4_init(rc4, master_key.data(), master_key.size(), salt, 16);
            SecureZeroMemory(master_key.data(), master_key.size());

            // Создаём директории
            fs::path out_p(output_path);
            if (out_p.has_parent_path()) {
                try {
                    fs::create_directories(out_p.parent_path());
                }
                catch (const std::exception& e) {
                    std::cerr << "[ERROR] Не удалось создать директорию: "
                        << e.what() << "\n";
                    SecureZeroMemory(&rc4, sizeof(rc4));
                    return false;
                }
            }

            // Открываем выходной файл
            std::ofstream out(output_path, std::ios::binary);
            if (!out) {
                std::cerr << "[ERROR] Не удалось создать файл: "
                    << output_path << "\n";
                SecureZeroMemory(&rc4, sizeof(rc4));
                return false;
            }

            // Читаем, дешифруем и пишем чанками
            if (file_len > 0) {
                const size_t CHUNK_SIZE = 4 * 1024 * 1024; // 4MB
                std::vector<unsigned char> chunk_cipher(CHUNK_SIZE);
                std::vector<unsigned char> chunk_plain(CHUNK_SIZE);

                uint32_t remaining = file_len;
                bool read_error = false;

                while (remaining > 0) {
                    size_t to_read = min(static_cast<size_t>(remaining), CHUNK_SIZE);

                    if (!in.read(reinterpret_cast<char*>(chunk_cipher.data()), to_read)) {
                        read_error = true;
                        break;
                    }

                    size_t actually_read = static_cast<size_t>(in.gcount());

                    // Дешифруем чанк
                    rc4_process(rc4, chunk_cipher.data(), chunk_plain.data(), actually_read);

                    // Затираем cipher чанк
                    SecureZeroMemory(chunk_cipher.data(), actually_read);

                    // Пишем расшифрованный чанк
                    out.write(reinterpret_cast<const char*>(chunk_plain.data()), actually_read);

                    // Затираем plain чанк
                    SecureZeroMemory(chunk_plain.data(), actually_read);

                    if (out.fail()) {
                        std::cerr << "[ERROR] Ошибка записи (нет места на диске?)\n";
                        out.close();
                        try { fs::remove(output_path); }
                        catch (...) {}
                        SecureZeroMemory(chunk_cipher.data(), chunk_cipher.size());
                        SecureZeroMemory(chunk_plain.data(), chunk_plain.size());
                        SecureZeroMemory(&rc4, sizeof(rc4));
                        return false;
                    }

                    remaining -= static_cast<uint32_t>(actually_read);
                }

                SecureZeroMemory(chunk_cipher.data(), chunk_cipher.size());
                SecureZeroMemory(chunk_plain.data(), chunk_plain.size());

                if (read_error) {
                    std::cerr << "[ERROR] Ошибка чтения данных файла из образа\n";
                    out.close();
                    try { fs::remove(output_path); }
                    catch (...) {}
                    SecureZeroMemory(&rc4, sizeof(rc4));
                    return false;
                }
            }

            SecureZeroMemory(&rc4, sizeof(rc4));
            out.close();

            auto dur = duration_cast<milliseconds>(
                high_resolution_clock::now() - start_time);
            log_operation(file_name, "ИЗВЛЕЧЁН -> " + output_path, dur, log_mutex);
            std::cout << "[SUCCESS] Файл извлечён: " << file_name
                << " -> " << output_path
                << " (" << file_len << " байт)\n";
            return true;
        }
        else {
            // Пропускаем данные файла
            std::streamsize current_pos = in.tellg();
            if (current_pos < 0 || current_pos + file_len > total_size) {
                std::cerr << "[ERROR] Образ повреждён (невозможно пропустить запись)\n";
                return false;
            }
            if (in.seekg(file_len, std::ios::cur).fail()) {
                std::cerr << "[ERROR] Образ повреждён (ошибка навигации)\n";
                return false;
            }
        }
    }

    std::cerr << "[ERROR] Файл не найден в образе: " << file_name << "\n";
    return false;
}

// ===================== СПРАВКА =====================
void print_usage(const char* prog) {
    std::cout << "\nИспользование:\n";
    std::cout << "  " << prog << " -add -key <ключ> -image <образ> <файл1> [файл2] [директория] ...\n";
    std::cout << "  " << prog << " -list -image <образ>\n";
    std::cout << "  " << prog << " -get -image <образ> -key <ключ> -out <выходной_файл> <имя_файла>\n";
    std::cout << "\nПримеры:\n";
    std::cout << "  " << prog << " -add -key secret -image disk.img file1.txt file2.txt in/\n";
    std::cout << "  " << prog << " -list -image disk.img\n";
    std::cout << "  " << prog << " -get -image disk.img -key secret -out result.txt in/file.txt\n";
}

// ===================== MAIN =====================
int main(int argc, char* argv[])
{
    setlocale(LC_ALL, "rus");

    // ===================== ЗАЩИТА ПАМЯТИ =====================
    AddVectoredExceptionHandler(1, AccessViolationHandler);
    init_secure_key_memory();
    init_secure_sblock_memory();
    atexit(cleanup_secure_memory);
    atexit(cleanup_secure_sblock);

    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }

    std::string command = argv[1];
    std::mutex log_mutex;

    // Инициализация лога
    {
        std::ofstream logfile("log.txt", std::ios::app);
        logfile << "\n=== СЕССИЯ: " << get_current_time() << " ===\n";
    }

    std::cout << "=========================================\n";
    std::cout << "   SECURE COPY (RC4 Encryption)\n";
    std::cout << "=========================================\n";

    // -------- ADD: добавление файлов в образ --------
    if (command == "-add") {
        std::string key, image_path;
        std::vector<std::string> input_items;

        // Парсинг аргументов
        for (int i = 2; i < argc; i++) {
            std::string arg = argv[i];
            if (arg == "-key" && i + 1 < argc) {
                key = argv[++i];
            }
            else if (arg == "-image" && i + 1 < argc) {
                image_path = argv[++i];
            }
            else {
                input_items.push_back(arg);
            }
        }

        if (key.empty() || image_path.empty() || input_items.empty()) {
            std::cerr << "[ERROR] Неверные аргументы для -add\n";
            print_usage(argv[0]);
            return 1;
        }

        set_secure_key(key);

        if (key.empty()) {
            std::cerr << "[ERROR] Ключ не может быть пустым\n";
            return 1;
        }

        // Собираем список файлов
        std::vector<std::pair<std::string, std::string>> files;
        for (const auto& item : input_items) {
            try {
                // проверка на недопустимые символы
                if (item.find('\0') != std::string::npos) {
                    std::cerr << "[ERROR] Недопустимый путь: " << item << "\n";
                    continue;
                }
                if (fs::is_directory(item)) {
                    // Добавляем все файлы из директории
                    std::string base_name = fs::path(item).filename().string();
                    for (const auto& entry : fs::recursive_directory_iterator(item)) {
                        if (entry.is_regular_file()) {
                            std::string file_path = entry.path().string();
                            std::string stored_name = base_name + "/" +
                                fs::relative(entry.path(), item).string();
                            std::replace(stored_name.begin(), stored_name.end(), '\\', '/');
                            files.push_back({ file_path, stored_name });
                        }
                    }
                }
                else if (fs::is_regular_file(item)) {
                    // Добавляем один файл
                    files.push_back({ item, fs::path(item).filename().string() });
                }
                else {
                    std::cerr << "[WARNING] Пропущен несуществующий элемент: " << item << "\n";
                }
            }
            catch (const std::exception& e) {
                std::cerr << "[ERROR] Ошибка обработки " << item << ": " << e.what() << "\n";
            }
        }

        if (files.empty()) {
            std::cerr << "[ERROR] Нет файлов для добавления\n";
            return 1;
        }

        std::cout << "[INFO] Найдено файлов: " << files.size() << "\n";
        if (!fs::exists(image_path)) {
            std::cout << "[INFO] Создаётся новый образ: " << image_path << "\n";
        }
        else {
            std::cout << "[INFO] Добавление в существующий образ: " << image_path << "\n";
        }
        std::cout << "[INFO] Образ: " << image_path << "\n";

        // Обработка файлов
        Mode used_mode;
        milliseconds total_duration;
        std::vector<FileStats> results = process_files(files, image_path, log_mutex,
            MODE_AUTO, used_mode, total_duration);

        // Статистика
        int success_count = 0;
        for (const auto& stat : results) {
            if (stat.success) success_count++;
        }

        std::cout << "\n=========================================\n";
        std::cout << "РЕЗУЛЬТАТ ДОБАВЛЕНИЯ\n";
        std::cout << "Добавлено файлов: " << success_count << " из " << files.size() << std::endl;
        std::cout << "Общее время: " << total_duration.count() << " мс\n";
        std::cout << "=========================================\n";
    }
    // -------- LIST: список файлов в образе --------
    else if (command == "-list") {
        std::string image_path;
        for (int i = 2; i < argc; i++) {
            std::string arg = argv[i];
            if (arg == "-image" && i + 1 < argc) {
                image_path = argv[++i];
                break;
            }
        }

        if (image_path.empty()) {
            std::cerr << "[ERROR] Не указан образ (-image)\n";
            print_usage(argv[0]);
            return 1;
        }

        if (!fs::exists(image_path)) {
            std::cerr << "[ERROR] Образ не найден: " << image_path << "\n";
            return 1;
        }

        image_list(image_path);
    }
    // -------- GET: извлечение файла из образа --------
    else if (command == "-get") {
        std::string key, image_path, output_path, file_name;

        for (int i = 2; i < argc; i++) {
            std::string arg = argv[i];
            if (arg == "-key" && i + 1 < argc) {
                key = argv[++i];
            }
            else if (arg == "-image" && i + 1 < argc) {
                image_path = argv[++i];
            }
            else if (arg == "-out" && i + 1 < argc) {
                output_path = argv[++i];
            }
            else if (file_name.empty()) {
                file_name = arg;
            }
        }

        if (key.empty() || image_path.empty() || output_path.empty() || file_name.empty()) {
            std::cerr << "[ERROR] Неверные аргументы для -get\n";
            print_usage(argv[0]);
            return 1;
        }

        if (!fs::exists(image_path)) {
            std::cerr << "[ERROR] Образ не найден: " << image_path << "\n";
            return 1;
        }

        set_secure_key(key);

        if (key.empty()) {
            std::cerr << "[ERROR] Ключ не может быть пустым\n";
            return 1;
        }

        image_get(image_path, file_name, output_path, log_mutex);
    }
    else {
        std::cerr << "[ERROR] Неизвестная команда: " << command << "\n";
        print_usage(argv[0]);
        return 1;
    }

    return 0;
}