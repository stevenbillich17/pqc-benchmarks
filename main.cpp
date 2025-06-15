#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include <memory>
#include <fstream>
#include <iomanip>
#include <numeric>
#include <map>

#include <botan/auto_rng.h>
#include <botan/version.h>
#include <botan/exceptn.h>
#include <botan/hex.h>

#include <botan/rsa.h>
#include <botan/sphincsplus.h>
#include <botan/sp_parameters.h>
#include <botan/pk_ops.h>

// ====================================================================
// DATA STRUCTURE & UTILITIES
// ====================================================================
struct BenchmarkResults {
    std::string algo_name;
    std::vector<double> public_key_sizes;
    std::vector<double> private_key_sizes;
    std::vector<double> signature_sizes;
    std::vector<double> keygen_times;
    std::vector<double> signing_times;
};

std::vector<uint8_t> get_message_from_file(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    file.seekg(0, std::ios::end);
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> buffer(size);
    file.read(reinterpret_cast<char*>(buffer.data()), size);
    return buffer;
}

void generate_message_file(const std::string& filename, size_t message_length) {
    std::cout << "Generating test message file '" << filename << "' (" << message_length / 1024.0 << " KB)..." << std::endl;
    std::ofstream file(filename, std::ios::binary);
    Botan::AutoSeeded_RNG rng;
    std::vector<uint8_t> message(message_length);
    rng.randomize(message);
    file.write(reinterpret_cast<const char*>(message.data()), message.size());
}

// ====================================================================
// CORE BENCHMARKING FUNCTIONS
// ====================================================================

std::unique_ptr<Botan::Private_Key> create_key(const std::string& algo_name, Botan::RandomNumberGenerator& rng) {
    if (algo_name == "rsa/3072") return std::make_unique<Botan::RSA_PrivateKey>(rng, 3072);
    if (algo_name == "rsa/4096") return std::make_unique<Botan::RSA_PrivateKey>(rng, 4096);
    if (algo_name == "sphincs+-sha256-128s-simple") {
        auto params = Botan::Sphincs_Parameters::create(Botan::Sphincs_Parameter_Set::SLHDSA128Small, Botan::Sphincs_Hash_Type::Sha256);
        return std::make_unique<Botan::SphincsPlus_PrivateKey>(rng, params);
    }
    if (algo_name == "sphincs+-sha256-192s-simple") {
        auto params = Botan::Sphincs_Parameters::create(Botan::Sphincs_Parameter_Set::SLHDSA192Small, Botan::Sphincs_Hash_Type::Sha256);
        return std::make_unique<Botan::SphincsPlus_PrivateKey>(rng, params);
    }
    throw std::runtime_error("Unsupported algorithm in create_key: " + algo_name);
}

void run_size_test(BenchmarkResults& results, const std::string& padding_scheme) {
    Botan::AutoSeeded_RNG rng;
    auto key = create_key(results.algo_name, rng);
    auto pub_key = key->public_key();
    std::vector<uint8_t> message(100, 'A');
    auto signer = key->create_signature_op(rng, padding_scheme, "base");
    signer->update(message);
    auto signature = signer->sign(rng);
    results.public_key_sizes.push_back(pub_key->public_key_bits().size());
    results.private_key_sizes.push_back(key->private_key_bits().size());
    results.signature_sizes.push_back(signature.size());
}

void run_keygen_test(BenchmarkResults& results, int iterations) {
    Botan::AutoSeeded_RNG rng;
    auto start_time = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) { create_key(results.algo_name, rng); }
    auto end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> duration_ms = end_time - start_time;
    results.keygen_times.push_back(duration_ms.count() / iterations);
}

void run_signing_test(BenchmarkResults& results, const std::string& padding_scheme, int iterations, const std::vector<uint8_t>& message) {
    Botan::AutoSeeded_RNG rng;
    auto key = create_key(results.algo_name, rng);
    auto start_time = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        auto signer = key->create_signature_op(rng, padding_scheme, "base");
        signer->update(message);
        auto signature = signer->sign(rng);
        (void)signature;
    }
    auto end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> duration_ms = end_time - start_time;
    results.signing_times.push_back(duration_ms.count() / iterations);
}

void print_summary(const BenchmarkResults& results, int keygen_iterations, int sign_iterations) {
    auto average = [](const std::vector<double>& v) {
        if (v.empty()) return 0.0;
        return std::accumulate(v.begin(), v.end(), 0.0) / v.size();
    };
    std::cout << "============== ON AVERAGE " << results.algo_name << " ==============" << std::endl;
    std::cout << std::fixed << std::setprecision(4);
    std::cout << "  Public Key Size:      " << average(results.public_key_sizes) << " bytes" << std::endl;
    std::cout << "  Private Key Size:     " << average(results.private_key_sizes) << " bytes" << std::endl;
    std::cout << "  Signature Size:       " << average(results.signature_sizes) << " bytes" << std::endl;
    std::cout << "  Key Generation Time:  " << average(results.keygen_times) << " ms/key" << std::endl;
    std::cout << "  Signing Time:         " << average(results.signing_times) << " ms/signature" << std::endl;
    std::cout << "==========================================================" << std::endl << std::endl;
}

void benchmark_signing_by_size(const std::string& algo_name, const std::string& padding_scheme, int iterations) {
    std::cout << "\n--- NEW BENCHMARK: Impact of Message Size on Signing Time for " << algo_name << " ---" << std::endl;
    
    std::map<size_t, std::string> message_files = {
        {100, "message_100B.txt"},
        {1024, "message_1KB.txt"},
        {1024 * 1024, "message_1MB.txt"}
    };

    Botan::AutoSeeded_RNG rng;
    auto key = create_key(algo_name, rng);

    for(const auto& [size, filename] : message_files) {
        std::ifstream file(filename);
        if(!file.good()) { generate_message_file(filename, size); }
        auto message = get_message_from_file(filename);

        auto start_time = std::chrono::high_resolution_clock::now();
        for(int i = 0; i < iterations; ++i) {
            auto signer = key->create_signature_op(rng, padding_scheme, "base");
            signer->update(message);
            auto signature = signer->sign(rng);
        }
        auto end_time = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> duration_ms = end_time - start_time;
        
        std::cout << "  Message Size: " << std::setw(7) << (double)size/1024.0 << " KB | Average Signing Time: " 
                  << std::fixed << std::setprecision(4) << duration_ms.count() / iterations << " ms" << std::endl;
    }
    std::cout << "--------------------------------------------------------------------------" << std::endl;
}

void benchmark_by_security_level() {
    std::cout << "\n--- NEW BENCHMARK: Impact of Security Level ---" << std::endl;
    const int RUNS = 5;
    const int KEYGEN_ITER = 10;
    const int SIGN_ITER = 30;
    const std::vector<uint8_t> message(256, 'B');

    // --- Higher Security Level Config ---
    const std::string RSA_HIGH = "rsa/4096";
    const std::string SPHINCS_HIGH = "sphincs+-sha256-192s-simple";
    
    BenchmarkResults rsa_results, sphincs_results;
    rsa_results.algo_name = RSA_HIGH;
    sphincs_results.algo_name = SPHINCS_HIGH;

    for(int i = 0; i < RUNS; ++i) {
        std::cout << "\rExecuting Security Level Run " << i + 1 << " of " << RUNS << "..." << std::flush;
        run_size_test(rsa_results, "PKCS1v15(SHA-256)");
        run_keygen_test(rsa_results, KEYGEN_ITER);
        run_signing_test(rsa_results, "PKCS1v15(SHA-256)", SIGN_ITER, message);
        
        run_size_test(sphincs_results, "");
        run_keygen_test(sphincs_results, KEYGEN_ITER);
        run_signing_test(sphincs_results, "", SIGN_ITER, message);
    }
    std::cout << "\nSecurity Level runs completed." << std::endl << std::endl;

    print_summary(rsa_results, KEYGEN_ITER, SIGN_ITER);
    print_summary(sphincs_results, KEYGEN_ITER, SIGN_ITER);
    std::cout << "---------------------------------------------------" << std::endl;
}


// ====================================================================
// MAIN FUNCTION
// ====================================================================
int main() {
    std::cout << "Using Botan version: " << Botan::version_string() << std::endl << std::endl;

    std::cout << "--- BASELINE BENCHMARK @ 128-bit Security ---" << std::endl;
    {
        const int TOTAL_RUNS = 5;
        const int KEYGEN_ITERATIONS = 30;
        const int SIGN_ITERATIONS = 50;
        
        BenchmarkResults rsa_results, sphincs_results;
        rsa_results.algo_name = "rsa/3072";
        sphincs_results.algo_name = "sphincs+-sha256-128s-simple";
        const std::vector<uint8_t> message(256, 'A');

        for(int run = 1; run <= TOTAL_RUNS; ++run) {
            std::cout << "\rExecuting Baseline Run " << run << " of " << TOTAL_RUNS << "..." << std::flush;
            run_size_test(rsa_results, "PKCS1v15(SHA-256)");
            run_keygen_test(rsa_results, KEYGEN_ITERATIONS);
            run_signing_test(rsa_results, "PKCS1v15(SHA-256)", SIGN_ITERATIONS, message);
            
            run_size_test(sphincs_results, "");
            run_keygen_test(sphincs_results, KEYGEN_ITERATIONS);
            run_signing_test(sphincs_results, "", SIGN_ITERATIONS, message);
        }
        std::cout << "\nBaseline runs completed." << std::endl << std::endl;
        print_summary(rsa_results, KEYGEN_ITERATIONS, SIGN_ITERATIONS);
        print_summary(sphincs_results, KEYGEN_ITERATIONS, SIGN_ITERATIONS);
    }

    benchmark_by_security_level();
    
    const int MSG_SIZE_ITERATIONS = 20;
    benchmark_signing_by_size("rsa/3072", "PKCS1v15(SHA-256)", MSG_SIZE_ITERATIONS);
    benchmark_signing_by_size("sphincs+-sha256-128s-simple", "", MSG_SIZE_ITERATIONS);

    return 0;
}