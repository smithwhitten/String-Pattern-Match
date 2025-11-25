// String Pattern IDS experiment harness
// Compile (MSVC): cl /EHsc /std:c++17 algorithms.cpp /Fe:ids_runner.exe
// Compile (GCC) : g++ -std=c++17 -O2 algorithms.cpp -o ids_runner
// Example run   : ids_runner.exe --algo horspool --data Friday-WorkingHours-Morning.pcap_ISCX.csv ^
//                                    --patterns signatures.txt --text-bytes 5MB --pattern-count 10 --trials 5

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

namespace {

constexpr std::uint64_t RK_MOD  = 1'000'000'007ULL;
constexpr std::uint64_t RK_BASE = 256ULL;

// ----------------------------------------------------------------------------- //
// Utility helpers
// ----------------------------------------------------------------------------- //

std::string trim(const std::string &s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

std::vector<std::string> split_row(const std::string &line) {
    std::vector<std::string> cols;
    if (line.find('\t') != std::string::npos) {
        std::stringstream ss(line);
        std::string cell;
        while (std::getline(ss, cell, '\t')) cols.push_back(trim(cell));
    } else {
        // CSV format: split by comma
        std::stringstream ss(line);
        std::string cell;
        while (std::getline(ss, cell, ',')) cols.push_back(trim(cell));
    }
    return cols;
}

std::string to_upper_copy(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    return s;
}

bool parse_size_argument(const std::string &token, size_t &value_out) {
    if (token.empty()) return false;
    std::string upper = to_upper_copy(token);
    size_t multiplier = 1;

    auto ends_with = [](const std::string &str, const std::string &suffix) {
        return str.size() >= suffix.size() &&
               str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
    };

    if (ends_with(upper, "KB")) {
        multiplier = 1024ull;
        upper.erase(upper.size() - 2);
    } else if (ends_with(upper, "MB")) {
        multiplier = 1024ull * 1024ull;
        upper.erase(upper.size() - 2);
    } else if (ends_with(upper, "GB")) {
        multiplier = 1024ull * 1024ull * 1024ull;
        upper.erase(upper.size() - 2);
    }

    try {
        size_t numeric = static_cast<size_t>(std::stoll(upper));
        value_out = numeric * multiplier;
        return true;
    } catch (...) {
        return false;
    }
}

enum class AlgorithmType {
    BruteForce,
    KMP,
    HashLexicon,
    Trie,
    Horspool,
    RabinKarp
};

bool parse_algorithm(const std::string &name, AlgorithmType &algo) {
    std::string upper = to_upper_copy(name);
    if (upper == "BRUTE" || upper == "BRUTEFORCE") {
        algo = AlgorithmType::BruteForce;
        return true;
    }
    if (upper == "KMP") {
        algo = AlgorithmType::KMP;
        return true;
    }
    if (upper == "HASH" || upper == "HASHLEXICON" || upper == "LEXICON") {
        algo = AlgorithmType::HashLexicon;
        return true;
    }
    if (upper == "TRIE") {
        algo = AlgorithmType::Trie;
        return true;
    }
    if (upper == "HORSPOOL" || upper == "BOYERMOORE" || upper == "BM") {
        algo = AlgorithmType::Horspool;
        return true;
    }
    if (upper == "RABIN" || upper == "RABINKARP" || upper == "RK") {
        algo = AlgorithmType::RabinKarp;
        return true;
    }
    return false;
}

std::string algorithm_to_string(AlgorithmType algo) {
    switch (algo) {
        case AlgorithmType::BruteForce: return "BruteForce";
        case AlgorithmType::KMP: return "KMP";
        case AlgorithmType::HashLexicon: return "HashLexicon";
        case AlgorithmType::Trie: return "Trie";
        case AlgorithmType::Horspool: return "Horspool";
        case AlgorithmType::RabinKarp: return "RabinKarp";
    }
    return "Unknown";
}

// ----------------------------------------------------------------------------- //
// Data structures for experiment pipeline
// ----------------------------------------------------------------------------- //

struct ExperimentConfig {
    std::string data_file    = "Friday-WorkingHours-Morning.pcap_ISCX.csv";
    std::string pattern_file = "signatures.txt";
    size_t text_bytes        = 1024ull * 1024ull;
    size_t pattern_count     = std::numeric_limits<size_t>::max();
    int trials               = 5;
    bool quiet               = false;
    std::string output_csv;
    AlgorithmType algorithm  = AlgorithmType::BruteForce;
};

struct RowSample {
    std::string text;
    bool is_malicious = false;
};

struct Counters {
    long long char_comparisons = 0;
    long long hash_operations  = 0;
    long long token_checks     = 0;
};

struct TrialMetrics {
    double seconds             = 0.0;
    long long char_comparisons = 0;
    long long hash_operations  = 0;
    long long token_checks     = 0;
    long long matches          = 0;
    long long true_positives   = 0;
    long long false_positives() const { return matches - true_positives; }
};

struct KMPPattern {
    std::string pattern;
    std::vector<int> lps;
};

struct HorspoolPattern {
    std::string pattern;
    std::array<int, 256> shift{};
};

struct HashLexiconPattern {
    std::vector<std::string> tokens;
};

struct RKGroup {
    size_t length = 0;
    std::uint64_t high_base = 1;
    std::vector<std::string> patterns;
    std::unordered_map<std::uint64_t, std::vector<size_t>> bucket;
};

struct TrieNode {
    std::array<int, 256> next{};
    bool terminal = false;
    TrieNode() { next.fill(-1); }
};

struct PreparedMatcher {
    AlgorithmType type = AlgorithmType::BruteForce;
    std::vector<std::string> raw_patterns;

    std::vector<KMPPattern> kmp;
    std::vector<HorspoolPattern> horspool;
    std::vector<HashLexiconPattern> hash_lexicon;
    std::vector<RKGroup> rk_groups;
    std::vector<TrieNode> trie_nodes;
};

std::vector<int> build_lps(const std::string &pattern) {
    std::vector<int> lps(pattern.size(), 0);
    size_t len = 0;
    for (size_t i = 1; i < pattern.size(); ++i) {
        while (len > 0 && pattern[i] != pattern[len]) {
            len = static_cast<size_t>(lps[len - 1]);
        }
        if (pattern[i] == pattern[len]) {
            ++len;
            lps[i] = static_cast<int>(len);
        }
    }
    return lps;
}

std::uint64_t pow_mod(std::uint64_t base, size_t exp) {
    std::uint64_t result = 1;
    while (exp > 0) {
        if (exp & 1ULL) result = (result * base) % RK_MOD;
        base = (base * base) % RK_MOD;
        exp >>= 1ULL;
    }
    return result;
}

std::vector<std::string> tokenize(const std::string &text) {
    std::vector<std::string> tokens;
    std::string current;
    for (char ch : text) {
        if (std::isalnum(static_cast<unsigned char>(ch))) {
            current.push_back(ch);
        } else {
            if (!current.empty()) {
                tokens.push_back(current);
                current.clear();
            }
        }
    }
    if (!current.empty()) tokens.push_back(current);
    return tokens;
}

void trie_insert(std::vector<TrieNode> &nodes, const std::string &pattern) {
    int node = 0;
    for (char ch : pattern) {
        unsigned char idx = static_cast<unsigned char>(ch);
        int next = nodes[node].next[idx];
        if (next == -1) {
            nodes[node].next[idx] = static_cast<int>(nodes.size());
            nodes.emplace_back();
            next = nodes[node].next[idx];
        }
        node = next;
    }
    nodes[node].terminal = true;
}

PreparedMatcher prepare_matcher(AlgorithmType type, const std::vector<std::string> &patterns) {
    PreparedMatcher matcher;
    matcher.type = type;
    matcher.raw_patterns = patterns;

    switch (type) {
        case AlgorithmType::BruteForce:
            break;

        case AlgorithmType::KMP: {
            for (const auto &pat : patterns) {
                if (pat.empty()) continue;
                matcher.kmp.push_back({pat, build_lps(pat)});
            }
            break;
        }

        case AlgorithmType::HashLexicon: {
            for (const auto &pat : patterns) {
                auto tokens = tokenize(pat);
                if (!tokens.empty()) matcher.hash_lexicon.push_back({tokens});
            }
            break;
        }

        case AlgorithmType::Trie: {
            matcher.trie_nodes.emplace_back(); // root
            for (const auto &pat : patterns) {
                if (pat.empty()) continue;
                trie_insert(matcher.trie_nodes, pat);
            }
            break;
        }

        case AlgorithmType::Horspool: {
            for (const auto &pat : patterns) {
                if (pat.empty()) continue;
                HorspoolPattern hp;
                hp.pattern = pat;
                hp.shift.fill(static_cast<int>(pat.size()));
                for (size_t i = 0; i + 1 < pat.size(); ++i) {
                    hp.shift[static_cast<unsigned char>(pat[i])] = static_cast<int>(pat.size() - 1 - i);
                }
                matcher.horspool.push_back(hp);
            }
            break;
        }

        case AlgorithmType::RabinKarp: {
            std::unordered_map<size_t, RKGroup> grouped;
            for (const auto &pat : patterns) {
                if (pat.empty()) continue;
                size_t len = pat.size();
                auto &group = grouped[len];
                if (group.length == 0) {
                    group.length = len;
                    group.high_base = (len > 0) ? pow_mod(RK_BASE, len - 1) : 1;
                }
                size_t index = group.patterns.size();
                group.patterns.push_back(pat);
                std::uint64_t hash = 0;
                for (char ch : pat) {
                    hash = (hash * RK_BASE + static_cast<unsigned char>(ch)) % RK_MOD;
                }
                group.bucket[hash].push_back(index);
            }
            for (auto &kv : grouped) matcher.rk_groups.push_back(std::move(kv.second));
            break;
        }
    }

    return matcher;
}

// ----------------------------------------------------------------------------- //
// Matching implementations
// ----------------------------------------------------------------------------- //

bool brute_force_contains(const std::string &text,
                          const std::string &pattern,
                          Counters &counters) {
    size_t n = text.size();
    size_t m = pattern.size();
    if (m == 0 || m > n) return false;

    for (size_t i = 0; i + m <= n; ++i) {
        size_t j = 0;
        while (j < m) {
            ++counters.char_comparisons;
            if (text[i + j] != pattern[j]) break;
            ++j;
        }
        if (j == m) return true;
    }
    return false;
}

bool kmp_contains(const std::string &text,
                  const KMPPattern &pat,
                  Counters &counters) {
    size_t n = text.size();
    size_t m = pat.pattern.size();
    if (m == 0 || m > n) return false;

    size_t i = 0;
    size_t j = 0;
    while (i < n) {
        ++counters.char_comparisons;
        if (text[i] == pat.pattern[j]) {
            ++i;
            ++j;
            if (j == m) return true;
        } else if (j != 0) {
            j = static_cast<size_t>(pat.lps[j - 1]);
        } else {
            ++i;
        }
    }
    return false;
}

bool horspool_contains(const std::string &text,
                       const HorspoolPattern &pat,
                       Counters &counters) {
    size_t m = pat.pattern.size();
    size_t n = text.size();
    if (m == 0 || m > n) return false;

    size_t i = m - 1;
    while (i < n) {
        size_t k = 0;
        while (k < m) {
            ++counters.char_comparisons;
            char pattern_ch = pat.pattern[m - 1 - k];
            char text_ch    = text[i - k];
            if (pattern_ch != text_ch) break;
            ++k;
        }
        if (k == m) return true;
        unsigned char last_char = static_cast<unsigned char>(text[i]);
        i += pat.shift[last_char];
    }
    return false;
}

bool trie_contains(const std::string &text,
                   const std::vector<TrieNode> &nodes,
                   Counters &counters) {
    if (nodes.empty()) return false;
    const size_t n = text.size();
    for (size_t i = 0; i < n; ++i) {
        int node = 0;
        for (size_t j = i; j < n; ++j) {
            ++counters.char_comparisons;
            unsigned char idx = static_cast<unsigned char>(text[j]);
            int next = nodes[node].next[idx];
            if (next == -1) break;
            node = next;
            if (nodes[node].terminal) return true;
        }
    }
    return false;
}

bool hash_lexicon_contains(const std::string &text,
                           const std::vector<HashLexiconPattern> &patterns,
                           Counters &counters) {
    if (patterns.empty()) return false;
    auto tokens = tokenize(text);
    if (tokens.empty()) return false;

    for (const auto &pat : patterns) {
        const auto &ptoks = pat.tokens;
        if (ptoks.empty() || ptoks.size() > tokens.size()) continue;
        for (size_t i = 0; i + ptoks.size() <= tokens.size(); ++i) {
            bool match = true;
            for (size_t j = 0; j < ptoks.size(); ++j) {
                ++counters.token_checks;
                if (tokens[i + j] != ptoks[j]) {
                    match = false;
                    break;
                }
            }
            if (match) return true;
        }
    }
    return false;
}

bool rk_group_contains(const std::string &text,
                       const RKGroup &group,
                       Counters &counters) {
    const size_t m = group.length;
    const size_t n = text.size();
    if (m == 0 || m > n) return false;

    auto check_bucket = [&](std::uint64_t hash, size_t start) -> bool {
        auto it = group.bucket.find(hash);
        if (it == group.bucket.end()) return false;
        for (size_t idx : it->second) {
            const std::string &pattern = group.patterns[idx];
            bool equal = true;
            for (size_t j = 0; j < m; ++j) {
                ++counters.char_comparisons;
                if (text[start + j] != pattern[j]) {
                    equal = false;
                    break;
                }
            }
            if (equal) return true;
        }
        return false;
    };

    std::uint64_t hash = 0;
    for (size_t i = 0; i < m; ++i) {
        hash = (hash * RK_BASE + static_cast<unsigned char>(text[i])) % RK_MOD;
        ++counters.hash_operations;
    }
    if (check_bucket(hash, 0)) return true;

    for (size_t i = m; i < n; ++i) {
        std::uint64_t outgoing =
            (static_cast<std::uint64_t>(static_cast<unsigned char>(text[i - m])) * group.high_base) % RK_MOD;
        hash = (hash + RK_MOD - outgoing) % RK_MOD;
        hash = (hash * RK_BASE + static_cast<unsigned char>(text[i])) % RK_MOD;
        counters.hash_operations += 2;
        size_t start = i - m + 1;
        if (check_bucket(hash, start)) return true;
    }
    return false;
}

bool rabin_karp_contains(const std::string &text,
                         const std::vector<RKGroup> &groups,
                         Counters &counters) {
    for (const auto &group : groups) {
        if (rk_group_contains(text, group, counters)) return true;
    }
    return false;
}

bool match_row(const RowSample &row,
               const PreparedMatcher &matcher,
               Counters &counters) {
    switch (matcher.type) {
        case AlgorithmType::BruteForce:
            for (const auto &pat : matcher.raw_patterns) {
                if (pat.empty()) continue;
                if (brute_force_contains(row.text, pat, counters)) return true;
            }
            return false;

        case AlgorithmType::KMP:
            for (const auto &pat : matcher.kmp) {
                if (kmp_contains(row.text, pat, counters)) return true;
            }
            return false;

        case AlgorithmType::HashLexicon:
            return hash_lexicon_contains(row.text, matcher.hash_lexicon, counters);

        case AlgorithmType::Trie:
            return trie_contains(row.text, matcher.trie_nodes, counters);

        case AlgorithmType::Horspool:
            for (const auto &pat : matcher.horspool) {
                if (horspool_contains(row.text, pat, counters)) return true;
            }
            return false;

        case AlgorithmType::RabinKarp:
            return rabin_karp_contains(row.text, matcher.rk_groups, counters);
    }
    return false;
}

// ----------------------------------------------------------------------------- //
// IO helpers
// ----------------------------------------------------------------------------- //

void print_usage() {
    std::cout << "Usage: ids_runner [options]\n"
              << "  --algo <brute|kmp|hash|trie|horspool|rabin>\n"
              << "  --data <path>                 CSV dataset to scan\n"
              << "  --patterns <path>             Signature list (one per line)\n"
              << "  --text-bytes <N|NKB|NMB|NGB>  Approximate text budget per run\n"
              << "  --pattern-count <N>           Limit number of patterns loaded\n"
              << "  --trials <N>                  Repeat experiment N times\n"
              << "  --output <path>               Write trial metrics to CSV file\n"
              << "  --quiet                       Suppress informational prints\n"
              << "  --help                        Show this help message\n";
}

bool parse_arguments(int argc, char **argv, ExperimentConfig &config, bool &show_help) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            show_help = true;
            print_usage();
            return false;
        } else if (arg == "--algo") {
            if (i + 1 >= argc) { std::cerr << "Missing value for --algo\n"; return false; }
            if (!parse_algorithm(argv[++i], config.algorithm)) {
                std::cerr << "Invalid algorithm name\n";
                return false;
            }
        } else if (arg == "--data") {
            if (i + 1 >= argc) { std::cerr << "Missing value for --data\n"; return false; }
            config.data_file = argv[++i];
        } else if (arg == "--patterns") {
            if (i + 1 >= argc) { std::cerr << "Missing value for --patterns\n"; return false; }
            config.pattern_file = argv[++i];
        } else if (arg == "--text-bytes") {
            if (i + 1 >= argc) { std::cerr << "Missing value for --text-bytes\n"; return false; }
            size_t val = 0;
            if (!parse_size_argument(argv[++i], val)) {
                std::cerr << "Invalid value for --text-bytes\n";
                return false;
            }
            config.text_bytes = val;
        } else if (arg == "--pattern-count") {
            if (i + 1 >= argc) { std::cerr << "Missing value for --pattern-count\n"; return false; }
            try {
                config.pattern_count = static_cast<size_t>(std::stoll(argv[++i]));
            } catch (...) {
                std::cerr << "Invalid value for --pattern-count\n";
                return false;
            }
        } else if (arg == "--trials") {
            if (i + 1 >= argc) { std::cerr << "Missing value for --trials\n"; return false; }
            try {
                config.trials = std::stoi(argv[++i]);
            } catch (...) {
                std::cerr << "Invalid value for --trials\n";
                return false;
            }
            if (config.trials <= 0) {
                std::cerr << "--trials must be positive\n";
                return false;
            }
        } else if (arg == "--output") {
            if (i + 1 >= argc) { std::cerr << "Missing value for --output\n"; return false; }
            config.output_csv = argv[++i];
        } else if (arg == "--quiet") {
            config.quiet = true;
        } else {
            std::cerr << "Unknown argument: " << arg << "\n";
            return false;
        }
    }
    return true;
}

bool load_patterns(const ExperimentConfig &config, std::vector<std::string> &patterns) {
    std::ifstream pin(config.pattern_file);
    if (!pin.is_open()) {
        std::cerr << "Failed to open pattern file: " << config.pattern_file << "\n";
        return false;
    }

    std::string line;
    while (std::getline(pin, line)) {
        auto cleaned = trim(line);
        if (cleaned.empty()) continue;
        patterns.push_back(to_upper_copy(cleaned));
        if (patterns.size() >= config.pattern_count) break;
    }

    if (patterns.empty()) {
        std::cerr << "No patterns loaded from " << config.pattern_file << "\n";
        return false;
    }
    return true;
}

bool label_is_malicious(const std::string &label_raw) {
    if (label_raw.empty()) return false;
    return to_upper_copy(label_raw) != "BENIGN";
}

std::string build_row_text(const std::vector<std::string> &cols) {
    std::string text;
    for (const auto &col : cols) {
        if (!col.empty()) {
            if (!text.empty()) text.push_back(' ');
            text += to_upper_copy(col);
        }
    }
    return text;
}

bool load_rows(const ExperimentConfig &config,
               std::vector<RowSample> &rows,
               size_t &bytes_consumed,
               size_t &rows_skipped,
               bool quiet) {
    std::ifstream fin(config.data_file);
    if (!fin.is_open()) {
        std::cerr << "Failed to open data file: " << config.data_file << "\n";
        return false;
    }

    std::string header_line;
    if (!std::getline(fin, header_line)) {
        std::cerr << "Data file appears empty: " << config.data_file << "\n";
        return false;
    }

    auto header_cols = split_row(header_line);
    std::unordered_map<std::string, int> col_idx;
    for (size_t i = 0; i < header_cols.size(); ++i) {
        col_idx[header_cols[i]] = static_cast<int>(i);
    }

    auto find_col = [&](const std::string &variants) -> int {
        std::stringstream ss(variants);
        std::string token;
        while (std::getline(ss, token, '|')) {
            token = trim(token);
            auto it = col_idx.find(token);
            if (it != col_idx.end()) return it->second;
        }
        return -1;
    };

    int idx_label = find_col("Label|label");

    const size_t WARN_LIMIT = 20;
    size_t warning_count = 0;
    size_t total_rows = 0;
    size_t total_bytes = 0;
    std::string line;

    while (std::getline(fin, line)) {
        if (trim(line).empty()) continue;
        ++total_rows;
        auto cols = split_row(line);
        if (cols.size() < header_cols.size()) {
            if (warning_count < WARN_LIMIT && !quiet) {
                std::cerr << "Warning: row " << total_rows
                          << " has fewer columns than header; padding missing values.\n";
                if (warning_count + 1 == WARN_LIMIT) {
                    std::cerr << "Further short-row warnings will be suppressed.\n";
                }
            }
            ++warning_count;
            cols.resize(header_cols.size());
        }

        std::string text = build_row_text(cols);
        if (text.empty()) {
            ++rows_skipped;
            continue;
        }

        size_t prospective = total_bytes + text.size();
        if (config.text_bytes > 0 && prospective > config.text_bytes) break;

        total_bytes = prospective;
        bool malicious = false;
        if (idx_label != -1 && idx_label < static_cast<int>(cols.size())) {
            malicious = label_is_malicious(cols[idx_label]);
        }
        rows.push_back({std::move(text), malicious});
    }

    bytes_consumed = total_bytes;
    if (!quiet) {
        std::cout << "Rows loaded: " << rows.size() << " (skipped " << rows_skipped << ")\n";
        std::cout << "Bytes budget used: " << bytes_consumed << "\n";
    }
    return !rows.empty();
}

void write_csv(const ExperimentConfig &config, const std::vector<TrialMetrics> &trials) {
    if (config.output_csv.empty()) return;
    std::ofstream out(config.output_csv);
    if (!out.is_open()) {
        std::cerr << "Failed to open output CSV for writing: " << config.output_csv << "\n";
        return;
    }

    out << "trial,execution_seconds,char_comparisons,hash_operations,token_checks,"
           "matches,true_positives,false_positives\n";
    for (size_t i = 0; i < trials.size(); ++i) {
        out << (i + 1) << ','
            << std::fixed << std::setprecision(6) << trials[i].seconds << ','
            << trials[i].char_comparisons << ','
            << trials[i].hash_operations << ','
            << trials[i].token_checks << ','
            << trials[i].matches << ','
            << trials[i].true_positives << ','
            << trials[i].false_positives() << '\n';
    }
}

} // namespace

int main(int argc, char **argv) {
    ExperimentConfig config;
    bool show_help = false;
    if (!parse_arguments(argc, argv, config, show_help)) {
        return show_help ? 0 : 1;
    }

    std::vector<std::string> patterns;
    if (!load_patterns(config, patterns)) return 1;
    if (!config.quiet) {
        std::cout << "Algorithm: " << algorithm_to_string(config.algorithm) << "\n";
        std::cout << "Patterns loaded: " << patterns.size() << "\n";
    }

    std::vector<RowSample> rows;
    size_t bytes_consumed = 0;
    size_t rows_skipped = 0;
    if (!load_rows(config, rows, bytes_consumed, rows_skipped, config.quiet)) return 1;

    if (!config.quiet) {
        std::cout << "Running " << config.trials << " trial(s) with "
                  << rows.size() << " rows and " << patterns.size() << " pattern(s).\n";
    }

    PreparedMatcher matcher = prepare_matcher(config.algorithm, patterns);

    std::vector<TrialMetrics> trial_results;
    trial_results.reserve(static_cast<size_t>(config.trials));

    for (int t = 0; t < config.trials; ++t) {
        TrialMetrics metrics;
        auto start = std::chrono::high_resolution_clock::now();

        for (const auto &row : rows) {
            Counters counters;
            bool found = match_row(row, matcher, counters);
            metrics.char_comparisons += counters.char_comparisons;
            metrics.hash_operations  += counters.hash_operations;
            metrics.token_checks     += counters.token_checks;
            if (found) {
                ++metrics.matches;
                if (row.is_malicious) ++metrics.true_positives;
            }
        }

        auto end = std::chrono::high_resolution_clock::now();
        metrics.seconds = std::chrono::duration<double>(end - start).count();
        trial_results.push_back(metrics);

        if (!config.quiet) {
            std::cout << "Trial " << (t + 1) << ": "
                      << std::fixed << std::setprecision(4) << metrics.seconds << " s, "
                      << "comparisons=" << metrics.char_comparisons
                      << ", hash_ops=" << metrics.hash_operations
                      << ", token_checks=" << metrics.token_checks
                      << ", matches=" << metrics.matches
                      << ", true_positives=" << metrics.true_positives
                      << ", false_positives=" << metrics.false_positives() << '\n';
        }
    }

    if (!trial_results.empty()) {
        double total_time = 0.0;
        long long total_comparisons = 0;
        long long total_hash_ops    = 0;
        long long total_token_checks = 0;
        long long total_matches     = 0;
        long long total_true        = 0;

        for (const auto &m : trial_results) {
            total_time        += m.seconds;
            total_comparisons += m.char_comparisons;
            total_hash_ops    += m.hash_operations;
            total_token_checks += m.token_checks;
            total_matches     += m.matches;
            total_true        += m.true_positives;
        }

        double count = static_cast<double>(trial_results.size());
        std::cout << "\nAverages over " << trial_results.size() << " trial(s):\n";
        std::cout << "  Execution time (s): " << std::fixed << std::setprecision(4)
                  << (total_time / count) << '\n';
        std::cout << "  Character comparisons: "
                  << static_cast<long long>(total_comparisons / trial_results.size())
                  << " (avg)\n";
        std::cout << "  Hash operations: "
                  << static_cast<long long>(total_hash_ops / trial_results.size())
                  << " (avg)\n";
        std::cout << "  Token checks: "
                  << static_cast<long long>(total_token_checks / trial_results.size())
                  << " (avg)\n";
        std::cout << "  Matches: "
                  << static_cast<long long>(total_matches / trial_results.size())
                  << " (avg)\n";
        std::cout << "  True positives: "
                  << static_cast<long long>(total_true / trial_results.size())
                  << " (avg)\n";
        std::cout << "  False positives: "
                  << static_cast<long long>((total_matches - total_true) / trial_results.size())
                  << " (avg)\n";
    }

    write_csv(config, trial_results);
    return 0;
}


