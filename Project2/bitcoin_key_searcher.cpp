#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <random>
#include <mutex>
#include <chrono>
#include <iomanip>
#include <unordered_set>
#include <thread>
#include <atomic>
#include <array>
#include <queue>
#include <memory>
#include <immintrin.h> // For SIMD operations
#include <signal.h>    // For signal handling
#include <secp256k1.h> // Replace OpenSSL with libsecp256k1
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/crypto.h>
#include <openssl/err.h>  // Added for error functions
#include <openssl/evp.h>  // Added for EVP functions
#include <openssl/ssl.h>  // Added for SSL functions
#pragma warning(disable : 4996)

// Debug logging macros
#define DEBUG_LOG(x) std::cout << "[DEBUG] " << x << std::endl
#define ERROR_LOG(x) std::cerr << "[ERROR] " << x << std::endl

// Signal handler for crash diagnostics
void signalHandler(int signal) {
    std::cerr << "\n[CRASH] Received signal " << signal << std::endl;
    std::cerr << "Program terminating unexpectedly." << std::endl;
    exit(signal);
}

// Constants for fixed buffer sizes and batch processing
constexpr size_t BATCH_SIZE = 64;
constexpr size_t PRIVKEY_LENGTH = 32;
constexpr size_t PUBKEY_LENGTH = 65;
constexpr size_t HASH_LENGTH_256 = 32;
constexpr size_t HASH_LENGTH_160 = 20;
constexpr size_t ADDRESS_LENGTH = 25;

// Base58 encoding table
static const char* BASE58_CHARS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Pre-computed Base58 table for faster conversion
static uint16_t BASE58_IDX[256] = { 0 };

// Simplified OpenSSL threading - only use mutexes for basic thread safety
static std::vector<std::unique_ptr<std::mutex>> openssl_mutexes;

static void openssl_locking_callback(int mode, int n, const char*, int) {
    if (mode & CRYPTO_LOCK)
        openssl_mutexes[n]->lock();
    else
        openssl_mutexes[n]->unlock();
}

static unsigned long openssl_thread_id_callback(void) {
    return static_cast<unsigned long>(std::hash<std::thread::id>()(std::this_thread::get_id()));
}

// Bloom filter for fast lookups with reduced memory usage
class BloomFilter {
public:
    // Constructor with more reasonable defaults for large address lists
    BloomFilter(size_t expected_items = 1000000, double false_positive_rate = 0.001)
        : m_bits() {
        try {
            // For very large sets, limit the maximum size to control memory usage
            constexpr size_t MAX_BLOOM_SIZE = 1ULL << 30; // 1GB max

            m_size = calculateOptimalSize(expected_items, false_positive_rate);
            if (m_size > MAX_BLOOM_SIZE) {
                DEBUG_LOG("Limiting bloom filter size from " << m_size << " to " << MAX_BLOOM_SIZE << " bits");
                m_size = MAX_BLOOM_SIZE;
            }

            m_hash_count = calculateOptimalHashCount(expected_items, m_size);
            // Limit hash functions to reasonable number for performance
            if (m_hash_count > 10) {
                DEBUG_LOG("Limiting hash functions from " << m_hash_count << " to 10");
                m_hash_count = 10;
            }

            DEBUG_LOG("Allocating bloom filter with " << m_size << " bits");
            m_bits.resize(m_size, false);
            std::cout << "Bloom filter initialized with " << m_size << " bits, " << m_hash_count << " hash functions" << std::endl;
        }
        catch (const std::exception& e) {
            ERROR_LOG("Error creating Bloom filter: " << e.what());
            throw;
        }
    }

    void insert(const std::string& item) {
        for (size_t i = 0; i < m_hash_count; ++i) {
            size_t hash = hash_function(item, i);
            m_bits[hash % m_size] = true;
        }
    }

    bool might_contain(const std::string& item) const {
        for (size_t i = 0; i < m_hash_count; ++i) {
            size_t hash = hash_function(item, i);
            if (!m_bits[hash % m_size]) {
                return false;
            }
        }
        return true;
    }

private:
    size_t m_size;
    size_t m_hash_count;
    std::vector<bool> m_bits;

    // Fast hash function with seed
    size_t hash_function(const std::string& item, size_t seed) const {
        size_t hash = seed;
        for (char c : item) {
            hash = hash * 0x01000193 ^ c;
        }
        return hash;
    }

    size_t calculateOptimalSize(size_t items, double fp_rate) const {
        // Fix for C4146 (unary minus on unsigned type)
        return static_cast<size_t>(static_cast<double>(items) * (-log(fp_rate)) / (log(2) * log(2)));
    }

    size_t calculateOptimalHashCount(size_t items, size_t size) const {
        return static_cast<size_t>(static_cast<double>(size) / items * log(2));
    }
};

// TSV Database class with Bloom filter and secondary lookup
class TSVDatabase {
public:
    TSVDatabase(const std::string& filename) {
        std::cout << "Loading TSV database from: " << filename << std::endl;

        // Open the TSV file
        std::ifstream file(filename, std::ios::binary);
        if (!file.is_open()) {
            throw std::runtime_error("Failed to open TSV database file");
        }

        // Read header line (skip it)
        std::string header;
        std::getline(file, header);

        // Check if header contains expected columns
        if (header.find("address") == std::string::npos || header.find("balance") == std::string::npos) {
            std::cerr << "Warning: TSV file header may not match expected format (address, balance)" << std::endl;
        }

        // Count lines for pre-allocation
        DEBUG_LOG("Counting lines for allocation...");
        std::ifstream count_file(filename, std::ios::binary);
        size_t line_count = 0;
        std::string line;
        while (std::getline(count_file, line) && !line.empty()) {
            line_count++;
            // Show progress every 10M lines
            if (line_count % 10000000 == 0) {
                std::cout << "Counted " << line_count << " lines..." << std::endl;
            }
        }
        count_file.close();
        std::cout << "Found " << line_count << " lines in file, allocating memory..." << std::endl;

        try {
            // Pre-allocate hash sets with the right size
            addresses.reserve(line_count);

            // Create bloom filter with estimated size
            DEBUG_LOG("Creating bloom filter...");
            filter = std::make_unique<BloomFilter>(line_count, 0.001); // Use less strict false positive rate
            DEBUG_LOG("Bloom filter created successfully.");

            // Reset file position
            file.clear();
            file.seekg(0);
            std::getline(file, line); // Skip header again

            // Read addresses and balances
            uint32_t count = 0;
            while (std::getline(file, line) && !line.empty()) {
                std::string address = line.substr(0, line.find('\t'));

                // Store in exact set and bloom filter
                addresses.insert(address);
                filter->insert(address);

                count++;

                // Progress indicator
                if (count % 1000000 == 0) {
                    std::cout << "Loaded " << count << " addresses..." << std::endl;
                }
            }

            std::cout << "Database loaded: " << addresses.size() << " addresses." << std::endl;

            // Initialize Base58 index table
            for (int i = 0; i < 256; i++) {
                BASE58_IDX[i] = 0;
            }
            for (int i = 0; i < 58; i++) {
                BASE58_IDX[(unsigned char)BASE58_CHARS[i]] = i;
            }
        }
        catch (const std::exception& e) {
            ERROR_LOG("Error during database initialization: " << e.what());
            throw;
        }
    }

    // Fast batch check against bloom filter first, then exact match
    bool containsAny(const std::vector<std::string>& addressList) const {
        // First check bloom filter (super fast negative responses)
        for (const auto& address : addressList) {
            if (filter->might_contain(address)) {
                // Only do expensive exact match if bloom filter says it might exist
                if (addresses.find(address) != addresses.end()) {
                    return true;
                }
            }
        }
        return false;
    }

    bool contains(const std::string& address) const {
        // First check bloom filter
        if (!filter->might_contain(address)) {
            return false;
        }
        // Then check exact match
        return addresses.find(address) != addresses.end();
    }

private:
    std::unordered_set<std::string> addresses;
    std::unique_ptr<BloomFilter> filter;
};

// Fixed size buffers for crypto operations
struct SecpPublicKey {
    std::array<uint8_t, PUBKEY_LENGTH> data;
};

struct HashResult {
    std::array<uint8_t, HASH_LENGTH_256> data;
};

struct RipemdResult {
    std::array<uint8_t, HASH_LENGTH_160> data;
};

struct VersionedHash {
    std::array<uint8_t, ADDRESS_LENGTH> data;
};

// Thread-local buffer pool to avoid allocations
thread_local std::array<uint8_t, PUBKEY_LENGTH> tl_pubkey_buffer;
thread_local std::array<uint8_t, HASH_LENGTH_256> tl_hash_buffer;
thread_local std::array<uint8_t, HASH_LENGTH_160> tl_ripemd_buffer;

// Utility functions for cryptocurrency operations
class CryptoUtils {
public:
    static void initialize() {
        std::cout << "Initializing OpenSSL and crypto libraries..." << std::endl;

        // Initialize OpenSSL threading support - FIXED: use a vector of unique_ptrs for mutexes
        size_t n = CRYPTO_num_locks();
        openssl_mutexes.clear();
        for (size_t i = 0; i < n; i++) {
            openssl_mutexes.push_back(std::make_unique<std::mutex>());
        }

        CRYPTO_set_locking_callback(openssl_locking_callback);
        CRYPTO_set_id_callback(openssl_thread_id_callback);

        if (OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS |
            OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL) == 0) {
            ERROR_LOG("Failed to initialize OpenSSL");
            throw std::runtime_error("OpenSSL initialization failed");
        }

        // Add all algorithms
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();

        DEBUG_LOG("Crypto initialization successful.");
        initialized = true;
    }

    static void cleanup() {
        std::cout << "Cleaning up crypto resources..." << std::endl;

        // Clear OpenSSL callbacks
        CRYPTO_set_locking_callback(nullptr);
        CRYPTO_set_id_callback(nullptr);

        // Cleanup OpenSSL
        EVP_cleanup();
        ERR_free_strings();
        CRYPTO_cleanup_all_ex_data();
        initialized = false;
    }

    // Thread-safe context creation
    static secp256k1_context* createContext() {
        if (!initialized) {
            ERROR_LOG("Creating context before CryptoUtils initialization!");
            initialize();
        }

        secp256k1_context* new_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
        if (!new_ctx) {
            ERROR_LOG("Failed to create secp256k1 context");
            throw std::runtime_error("Failed to create secp256k1 context");
        }

        // Initialize random generator for context randomization
        unsigned char rand_seed[32];
        std::random_device rd;
        std::mt19937_64 gen(rd());
        std::uniform_int_distribution<unsigned short> dis(0, 255);

        for (int i = 0; i < 32; ++i) {
            rand_seed[i] = static_cast<unsigned char>(dis(gen));
        }

        // Randomize the context to improve security
        if (!secp256k1_context_randomize(new_ctx, rand_seed)) {
            secp256k1_context_destroy(new_ctx);
            ERROR_LOG("Failed to randomize secp256k1 context");
            throw std::runtime_error("Failed to randomize secp256k1 context");
        }

        return new_ctx;
    }

    // Cleanup context
    static void destroyContext(secp256k1_context* ctx) {
        if (ctx) {
            secp256k1_context_destroy(ctx);
        }
    }

    // Optimized Base58 encode with checksum using pre-computed values
    static std::string base58Encode(const VersionedHash& data) {
        try {
            std::array<uint8_t, ADDRESS_LENGTH + 4> buffer;
            std::memcpy(buffer.data(), data.data.data(), ADDRESS_LENGTH);

            std::array<uint8_t, HASH_LENGTH_256> hash1;
            SHA256(data.data.data(), ADDRESS_LENGTH, hash1.data());

            std::array<uint8_t, HASH_LENGTH_256> hash2;
            SHA256(hash1.data(), HASH_LENGTH_256, hash2.data());
            std::memcpy(buffer.data() + ADDRESS_LENGTH, hash2.data(), 4);

            char result[128] = { 0 };
            size_t resultLen = 0;
            size_t leadingZeros = 0;
            while (leadingZeros < ADDRESS_LENGTH + 4 && buffer[leadingZeros] == 0) {
                leadingZeros++;
            }

            int carry, j;
            for (size_t i = leadingZeros; i < ADDRESS_LENGTH + 4; i++) {
                carry = buffer[i];
                for (j = 0; j < resultLen; j++) {
                    carry += 58 * result[j];
                    result[j] = carry % 256;
                    carry /= 256;
                }
                while (carry > 0) {
                    result[resultLen++] = carry % 256;
                    carry /= 256;
                }
            }

            for (j = 0; j < static_cast<int>(resultLen) / 2; j++) {
                char tmp = result[j];
                result[j] = result[resultLen - 1 - j];
                result[resultLen - 1 - j] = tmp;
            }

            std::string base58;
            base58.reserve(resultLen + leadingZeros);
            for (size_t i = 0; i < leadingZeros; i++) {
                base58 += '1';
            }
            for (size_t i = 0; i < resultLen; i++) {
                base58 += BASE58_CHARS[static_cast<unsigned char>(result[i])];
            }

            return base58;
        }
        catch (const std::exception& e) {
            std::cerr << "Error in base58Encode: " << e.what() << std::endl;
            return "ERROR";
        }
    }

    // Fast SHA-256 hash with fixed output buffer
    static void sha256(const uint8_t* data, size_t len, uint8_t* output) {
        SHA256(data, len, output);
    }

    // Fast RIPEMD-160 hash with fixed output buffer
    static void ripemd160(const uint8_t* data, size_t len, uint8_t* output) {
        RIPEMD160(data, len, output);
    }

    // Get global secp context
    static secp256k1_context* getContext() {
        if (!ctx) {
            ctx = createContext();
        }
        return ctx;
    }

private:
    static secp256k1_context* ctx;
    static bool initialized;
};

// Static initialization
secp256k1_context* CryptoUtils::ctx = nullptr;
bool CryptoUtils::initialized = false;

// Object pool for address generation
template<typename T>
class ObjectPool {
public:
    ObjectPool(size_t size) : pool_size(size) {
        for (size_t i = 0; i < size; ++i) {
            pool.push(std::make_unique<T>());
        }
    }

    // Delete copy constructor and copy assignment operator to prevent copying
    ObjectPool(const ObjectPool&) = delete;
    ObjectPool& operator=(const ObjectPool&) = delete;

    std::unique_ptr<T> acquire() {
        std::lock_guard<std::mutex> lock(mutex);
        if (pool.empty()) {
            return std::make_unique<T>();
        }
        auto obj = std::move(pool.front());
        pool.pop();
        return obj;
    }

    void release(std::unique_ptr<T> obj) {
        std::lock_guard<std::mutex> lock(mutex);
        if (pool.size() < pool_size) {
            pool.push(std::move(obj));
        }
    }

private:
    size_t pool_size;
    std::mutex mutex;
    std::queue<std::unique_ptr<T>> pool;
};

// Class to generate keys and addresses
class CryptoAddressGenerator {
public:
    CryptoAddressGenerator() : seckey{ 0 }, pubkey{ 0 } {
        // Create a private key of zeros initially
        memset(seckey, 0, PRIVKEY_LENGTH);
    }

    ~CryptoAddressGenerator() {
        // Clear sensitive data
        memset(seckey, 0, PRIVKEY_LENGTH);
        memset(pubkey, 0, PUBKEY_LENGTH);
    }

    // Generate random private key directly as bytes
    void generateRandomPrivateKey(uint8_t* output) {
        // Use high-quality randomness
        static thread_local std::random_device rd;
        static thread_local std::mt19937_64 gen(rd());
        static thread_local std::uniform_int_distribution<uint64_t> dis;

        // Fill with random bytes efficiently
        uint64_t* output64 = reinterpret_cast<uint64_t*>(output);
        for (size_t i = 0; i < PRIVKEY_LENGTH / 8; ++i) {
            output64[i] = dis(gen);
        }

        // Ensure private key is valid for secp256k1
        while (!secp256k1_ec_seckey_verify(CryptoUtils::getContext(), output)) {
            output64[0] = dis(gen);
        }
    }

    // Convert private key to hex for storage/display
    std::string getPrivateKeyHex() {
        std::string hexKey;
        hexKey.reserve(PRIVKEY_LENGTH * 2); // Pre-allocate for performance

        for (int i = 0; i < PRIVKEY_LENGTH; i++) {
            char hex[3];
            snprintf(hex, sizeof(hex), "%02x", seckey[i]);
            hexKey += hex;
        }

        return hexKey;
    }

    // Generate addresses for all cryptocurrencies at once (optimized batch version)
    std::vector<std::string> generateAllAddresses() {
        std::vector<std::string> addresses(6);  // BTC, BCH, DASH, DOGE, LTC, ETH

        // Generate a new random private key
        generateRandomPrivateKey(seckey);

        // Get public key using libsecp256k1 (much faster than OpenSSL)
        secp256k1_pubkey pubkey_struct;
        if (!secp256k1_ec_pubkey_create(CryptoUtils::getContext(), &pubkey_struct, seckey)) {
            throw std::runtime_error("Failed to create public key");
        }

        // Serialize the public key in uncompressed format
        size_t pubkey_len = PUBKEY_LENGTH;
        secp256k1_ec_pubkey_serialize(
            CryptoUtils::getContext(),
            pubkey,
            &pubkey_len,
            &pubkey_struct,
            SECP256K1_EC_UNCOMPRESSED
        );

        // SHA-256 hash of public key
        uint8_t sha256_hash[HASH_LENGTH_256];
        CryptoUtils::sha256(pubkey, PUBKEY_LENGTH, sha256_hash);

        // RIPEMD-160 hash of SHA-256 hash
        uint8_t ripemd_hash[HASH_LENGTH_160];
        CryptoUtils::ripemd160(sha256_hash, HASH_LENGTH_256, ripemd_hash);

        // Create versioned hashes for each coin
        VersionedHash vhBtc, vhDash, vhDoge;
        // Bitcoin (BTC) address - version byte 0x00
        vhBtc.data[0] = 0x00;
        std::memcpy(vhBtc.data.data() + 1, ripemd_hash, HASH_LENGTH_160);
        addresses[0] = CryptoUtils::base58Encode(vhBtc);

        // Bitcoin Cash (BCH) address - same as Bitcoin for legacy format
        addresses[1] = addresses[0];

        // Dash address - version byte 0x4C
        vhDash.data[0] = 0x4C;
        std::memcpy(vhDash.data.data() + 1, ripemd_hash, HASH_LENGTH_160);
        addresses[2] = CryptoUtils::base58Encode(vhDash);

        // Dogecoin address - version byte 0x1E
        vhDoge.data[0] = 0x1E;
        std::memcpy(vhDoge.data.data() + 1, ripemd_hash, HASH_LENGTH_160);
        addresses[3] = CryptoUtils::base58Encode(vhDoge);

        // Litecoin address - version byte 0x30
        VersionedHash vhLtc;
        vhLtc.data[0] = 0x30;
        std::memcpy(vhLtc.data.data() + 1, ripemd_hash, HASH_LENGTH_160);
        addresses[4] = CryptoUtils::base58Encode(vhLtc);

        // Ethereum address
        uint8_t eth_hash[HASH_LENGTH_256];
        CryptoUtils::sha256(pubkey + 1, PUBKEY_LENGTH - 1, eth_hash); // Keccak-256 placeholder
        std::string ethAddress = "0x";
        ethAddress.reserve(42); // 0x + 40 hex chars
        for (size_t i = HASH_LENGTH_256 - 20; i < HASH_LENGTH_256; i++) {
            char hex[3];
            snprintf(hex, sizeof(hex), "%02x", eth_hash[i]);
            ethAddress += hex;
        }
        addresses[5] = ethAddress;

        return addresses;
    }

private:
    uint8_t seckey[PRIVKEY_LENGTH];
    uint8_t pubkey[PUBKEY_LENGTH];
};

// Class for searching for valuable addresses
class KeySearcher {
public:
    KeySearcher(const std::string& tsv_file, int num_threads) :
        db(tsv_file),
        num_threads(num_threads),
        running(true),
        total_keys_checked(0),
        keys_per_second(0),
        found_keys(0)
    {
        output_file.open("found_keys.txt");
        if (!output_file.is_open()) {
            throw std::runtime_error("Failed to open output file");
        }
    }

    ~KeySearcher() {
        if (output_file.is_open()) {
            output_file.close();
        }
    }

    // Start searching with the specified number of threads
    void run() {
        std::cout << "Starting search with " << num_threads << " threads..." << std::endl;

        // Start statistics thread
        std::thread stats_thread(&KeySearcher::updateStats, this);

        // Start worker threads
        std::vector<std::thread> threads;
        for (int i = 0; i < num_threads; i++) {
            threads.push_back(std::thread(&KeySearcher::searchThread, this));
        }

        // Wait for threads to complete
        for (auto& thread : threads) {
            thread.join();
        }

        // Stop and join stats thread
        running = false;
        stats_thread.join();

        std::cout << "Search completed. Found " << found_keys << " keys." << std::endl;
    }

    // Stop the search
    void stop() {
        running = false;
    }

private:
    TSVDatabase db;
    int num_threads;
    std::atomic<bool> running;
    std::atomic<uint64_t> total_keys_checked;
    std::atomic<uint64_t> keys_per_second;
    std::atomic<int> found_keys;
    std::ofstream output_file;
    std::mutex output_mutex;

    // Thread function to update statistics
    void updateStats() {
        uint64_t prev_count = 0;
        auto start_time = std::chrono::high_resolution_clock::now();

        while (running) {
            std::this_thread::sleep_for(std::chrono::seconds(1));

            auto current_time = std::chrono::high_resolution_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(current_time - start_time).count();
            if (elapsed > 0) {
                uint64_t current_count = total_keys_checked;
                keys_per_second = (current_count - prev_count);
                prev_count = current_count;

                std::cout << "\rKeys checked: " << current_count
                    << " (" << keys_per_second << " keys/sec) | Found: "
                    << found_keys << "          " << std::flush;
            }
        }
    }

    // Worker thread function for searching keys
    void searchThread() {
        CryptoAddressGenerator generator;

        // Increase batch size for fewer repeated operations
        static const size_t batchSize = 256;
        std::vector<std::vector<std::string>> addressesVec(batchSize);

        while (running) {
            // Generate addresses in batches
            for (size_t i = 0; i < batchSize; ++i) {
                addressesVec[i] = generator.generateAllAddresses(); 
            }

            // Check each batch item
            for (size_t i = 0; i < batchSize; ++i) {
                if (db.containsAny(addressesVec[i])) {
                    std::lock_guard<std::mutex> lock(output_mutex);
                    output_file << "Private Key: " << generator.getPrivateKeyHex() << std::endl;
                    output_file << "BTC: " << addressesVec[i][0] << std::endl;
                    output_file << "BCH: " << addressesVec[i][1] << std::endl;
                    output_file << "DASH: " << addressesVec[i][2] << std::endl;
                    output_file << "DOGE: " << addressesVec[i][3] << std::endl;
                    output_file << "LTC: " << addressesVec[i][4] << std::endl;
                    output_file << "ETH: " << addressesVec[i][5] << std::endl;
                    output_file << "----------------------------" << std::endl;
                    // Remove frequent flushes: flush only on intervals
                }
                found_keys++;
                total_keys_checked++;
            }
        }
    }
};

// Main function
int main(int argc, char* argv[]) {
    try {
        if (argc < 2) {
            std::cerr << "Usage: " << argv[0] << " <tsv_file> [num_threads]" << std::endl;
            return 1;
        }

        std::string tsv_file = argv[1];
        int num_threads = std::thread::hardware_concurrency();

        if (argc >= 3) {
            num_threads = std::stoi(argv[2]);
        }

        std::cout << "Bitcoin Key Searcher" << std::endl;
        std::cout << "============================" << std::endl;

        // Register signal handler for crash diagnostics
        signal(SIGSEGV, signalHandler);
        signal(SIGABRT, signalHandler);
        signal(SIGFPE, signalHandler);
        signal(SIGILL, signalHandler);
        signal(SIGINT, signalHandler);

        KeySearcher searcher(tsv_file, num_threads);
        searcher.run();

    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
