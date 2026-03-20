/*
 * MIT License
 *
 * Copyright (c) 2025 Sentinel Contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * Sentinel — Advanced Port Scanner v3.0
 *
 * Build:
 *   g++ -std=c++17 -O2 -pthread -o sentinel sentinel.cpp
 *
 * Root required for SYN and UDP scans (raw sockets).
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * COMPLETE FIX HISTORY  (v1.0 → v3.0)
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * ── v2.0 fixes (carried forward) ─────────────────────────────────────────────
 * FIX-01  Double-mutex deadlock in print_result / submit_batch.
 * FIX-02  SYN scan: recvfrom reply validated against target IP + port.
 * FIX-03  rand() → per-thread std::mt19937 (thread-safe, better entropy).
 * FIX-04  inet_ntoa → thread-safe inet_ntop throughout.
 * FIX-05  CIDR mask: unsigned shift literal (1u) avoids signed UB.
 * FIX-06  print_progress static local → std::atomic<int> member.
 * FIX-07  Signal handler only touches atomic flag (async-signal-safe).
 * FIX-08  ICMP/IP packet buffers declared alignas(4).
 * FIX-09  TTL OS detection normalises to nearest initial value (64/128/255).
 * FIX-10  get_ttl uses IP_TTL getsockopt instead of hard-coded 64.
 * FIX-11  Rate limiting per-packet (inside loop) not per-batch.
 * FIX-12  Vuln matching: structured VulnRecord with banner-prefix compare.
 *
 * ── v2.1 fixes (carried forward) ─────────────────────────────────────────────
 * FIX-13  Lock-order inversion: merged into single io_mutex_.
 * FIX-14  std::localtime → POSIX localtime_r (thread-safe).
 * FIX-15  start_time/end_time wrapped in SafeTimePoint (shared_mutex).
 * FIX-16  ping sweep: heap-allocated shared state, explicit lambda captures.
 * FIX-17  ThreadPool::stop_ → std::atomic<bool>.
 * FIX-18  grab_banner: partial-send retry loop + MSG_NOSIGNAL.
 * FIX-19  udp_scan ICMP reply: source IP validated against target.
 * FIX-20  expand_cidr: correct /32 and /31 handling.
 *
 * ── v3.0 new fixes ────────────────────────────────────────────────────────────
 * FIX-21  icmp_ping: reply source IP now validated; per-thread unique ICMP
 *         echo ID generated from ThreadRng to avoid cross-thread reply theft.
 *         (CLASS A1, CLASS E1)
 *
 * FIX-22  TokenBucket::consume_one: missing decrement after sleep+relock
 *         repaired via a spin-wait loop -- never skips a token.
 *         (CLASS A3)
 *
 * FIX-23  tcp_connect: fcntl(F_GETFL) error handled; socket closed on
 *         failure; POLLHUP/POLLERR revents checked before POLLOUT path.
 *         (CLASS B1)
 *
 * FIX-24  send_syn / send_rst: inet_pton return value checked; function
 *         returns false on failure so caller can fall back to connect scan.
 *         (CLASS B2)
 *
 * FIX-25  udp_scan: POLLERR/POLLHUP on either fd sets status "error" and
 *         breaks early rather than leaving "open|filtered".
 *         (CLASS B3)
 *
 * FIX-26  Bounds-checked ihl offset helper (ihl_offset) used before every
 *         TCP/ICMP header cast; malformed/truncated packets are discarded.
 *         Applies to syn_scan, udp_scan, icmp_ping.
 *         (CLASS C1, C2, C3)
 *
 * FIX-27  expand_cidr: /0 and large subnets capped at MAX_CIDR_HOSTS=65536
 *         to prevent 4-billion-entry allocation.
 *         (CLASS C5)
 *
 * FIX-28  setup_signal_handler called BEFORE perform_ping_sweep so Ctrl+C
 *         is always handled gracefully.
 *         (CLASS D1)
 *
 * FIX-29  Signal handler uses memory_order_release for g_stop_signal to
 *         guarantee prompt visibility across all threads.
 *         (CLASS D2)
 *
 * FIX-30  syn_scan ephemeral source port tracked via per-scanner atomic
 *         counter (round-robin across 16 384 ephemeral ports) to eliminate
 *         port collisions under high thread counts.
 *         (CLASS E2)
 *
 * FIX-31  get_ttl for TCP connect scan: IP_TTL getsockopt returns local
 *         send-TTL, not remote. FIX-10 was logically wrong. Corrected: TTL
 *         is read from the raw IP header only for SYN/ICMP paths where a
 *         raw socket is available. tcp_connect sets ttl=0 and os_hint=""
 *         to avoid misleading "Linux/Unix/macOS" for every host.
 *         (CLASS E4)
 *
 * FIX-32  ThreadRng seed hardened: xor of random_device output with
 *         thread-local counter and steady_clock nanos to guarantee distinct
 *         seeds even when random_device is deterministic.
 *         (CLASS F3)
 *
 * FIX-33  ThreadPool enqueue: std::bind replaced with capturing lambda.
 *         (CLASS F4)
 *
 * FIX-34  ArgParser: exit() replaced with exception throws; all stoi() calls
 *         wrapped with try/catch providing user-friendly error messages.
 *         (CLASS F5, C6)
 *
 * FIX-35  Input validation: timeout_ms clamped to [1, 30000]; num_threads
 *         clamped to [1, 1024]; rate_limit validated > 0; thread count 0
 *         corrected to hardware_concurrency before ThreadPool construction.
 *         (CLASS G1, G2)
 *
 * FIX-36  Backpressure: submit_batch waits when pending queue exceeds
 *         num_threads * 4 to cap unbounded memory growth.
 *         (CLASS G3)
 * ─────────────────────────────────────────────────────────────────────────────
 */

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <fstream>
#include <functional>
#include <future>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <queue>
#include <random>
#include <shared_mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
#include <cctype>
#include <csignal>
#include <cstring>

// POSIX / Linux
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

// ============================================================================
// Compile-time constants
// ============================================================================

static constexpr size_t   MAX_CIDR_HOSTS   = 65536;   // FIX-27
static constexpr int      MIN_TIMEOUT_MS   = 1;        // FIX-35
static constexpr int      MAX_TIMEOUT_MS   = 30000;    // FIX-35
static constexpr int      MAX_THREADS      = 1024;     // FIX-35
static constexpr uint16_t EPH_PORT_BASE    = 49152;    // FIX-30
static constexpr uint16_t EPH_PORT_COUNT   = 16384;    // FIX-30

// ============================================================================
// Global signal state
// ============================================================================

static std::atomic<bool> g_stop_signal{false};

// ============================================================================
// FIX-32 — Hardened per-thread PRNG
// ============================================================================

namespace ThreadRng {

    // FIX-32: xor random_device with thread-local counter + clock nanos
    // so even a deterministic random_device gives distinct seeds per thread.
    static thread_local std::mt19937 engine = [] {
        static std::atomic<uint64_t> thread_counter{0};
        uint64_t ctr   = thread_counter.fetch_add(1, std::memory_order_relaxed);
        uint64_t nanos = static_cast<uint64_t>(
            std::chrono::steady_clock::now().time_since_epoch().count());
        std::random_device rd;
        uint64_t rdev  = (static_cast<uint64_t>(rd()) << 32) | rd();
        std::seed_seq seq{
            static_cast<uint32_t>(rdev),
            static_cast<uint32_t>(rdev >> 32),
            static_cast<uint32_t>(nanos),
            static_cast<uint32_t>(nanos >> 32),
            static_cast<uint32_t>(ctr)
        };
        return std::mt19937(seq);
    }();

    inline uint32_t u32() {
        return std::uniform_int_distribution<uint32_t>{}(engine);
    }
    inline uint16_t u16() {
        return static_cast<uint16_t>(u32() & 0xFFFF);
    }
    inline uint16_t range16(uint16_t lo, uint16_t hi) {
        return static_cast<uint16_t>(
            std::uniform_int_distribution<uint32_t>{lo, hi}(engine));
    }
}

// ============================================================================
// FIX-22 — Per-packet Token Bucket (correct spin-wait)
// ============================================================================

class TokenBucket {
public:
    explicit TokenBucket(size_t rate_per_second)
        : rate_(rate_per_second > 0 ? rate_per_second : 1)
        , tokens_(rate_per_second > 0 ? rate_per_second : 1)
        , last_refill_(std::chrono::steady_clock::now()) {}

    // FIX-22: loop until a token is actually acquired
    void consume_one() {
        while (true) {
            std::unique_lock<std::mutex> lk(mu_);
            refill();
            if (tokens_ >= 1) {
                --tokens_;
                return;
            }
            // Compute exact sleep for one token, then retry
            double need_us = 1'000'000.0 / static_cast<double>(rate_);
            lk.unlock();
            std::this_thread::sleep_for(
                std::chrono::microseconds(static_cast<long>(need_us)));
        }
    }

private:
    size_t     rate_;
    size_t     tokens_;
    std::chrono::steady_clock::time_point last_refill_;
    std::mutex mu_;

    void refill() {
        auto now     = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
                           now - last_refill_);
        size_t n = static_cast<size_t>(
            static_cast<double>(elapsed.count()) * rate_ / 1'000'000.0);
        if (n > 0) {
            tokens_      = std::min(tokens_ + n, rate_);
            last_refill_ = now;
        }
    }
};

// ============================================================================
// FIX-17 + FIX-33 — Thread Pool
// ============================================================================

class ThreadPool {
public:
    // FIX-36: expose pending count for backpressure
    size_t pending() const {
        std::lock_guard<std::mutex> lk(mu_);
        return tasks_.size();
    }

    explicit ThreadPool(size_t n) : stop_(false) {
        if (n == 0) n = 1;
        for (size_t i = 0; i < n; ++i) {
            workers_.emplace_back([this] {
                for (;;) {
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lk(mu_);
                        cv_consumer_.wait(lk, [this] {
                            return stop_.load(std::memory_order_acquire)
                                   || !tasks_.empty();
                        });
                        if (stop_.load(std::memory_order_acquire)
                                && tasks_.empty()) return;
                        task = std::move(tasks_.front());
                        tasks_.pop();
                    }
                    cv_producer_.notify_one(); // FIX-36: wake backpressure waiter
                    try { task(); }
                    catch (const std::exception& e) {
                        std::cerr << "[pool] " << e.what() << '\n';
                    }
                }
            });
        }
    }

    // FIX-33: lambda instead of std::bind; FIX-36: backpressure cap
    template<class F>
    std::future<void> enqueue(F&& f, size_t max_pending = SIZE_MAX) {
        auto task = std::make_shared<std::packaged_task<void()>>(
            std::forward<F>(f));
        auto fut = task->get_future();
        {
            std::unique_lock<std::mutex> lk(mu_);
            if (stop_.load(std::memory_order_relaxed))
                throw std::runtime_error("enqueue on stopped ThreadPool");
            // FIX-36: block if queue is too deep
            cv_producer_.wait(lk, [&] {
                return tasks_.size() < max_pending
                    || stop_.load(std::memory_order_relaxed);
            });
            tasks_.emplace([task]{ (*task)(); });
        }
        cv_consumer_.notify_one();
        return fut;
    }

    ~ThreadPool() {
        stop_.store(true, std::memory_order_release);
        cv_consumer_.notify_all();
        cv_producer_.notify_all();
        for (auto& w : workers_)
            if (w.joinable()) w.join();
    }

private:
    std::vector<std::thread>          workers_;
    std::queue<std::function<void()>> tasks_;
    mutable std::mutex                mu_;
    std::condition_variable           cv_consumer_;
    std::condition_variable           cv_producer_; // FIX-36
    std::atomic<bool>                 stop_;
};

// ============================================================================
// FIX-15 — Thread-safe time_point wrapper
// ============================================================================

class SafeTimePoint {
public:
    using TP = std::chrono::steady_clock::time_point;

    void set(TP tp) {
        std::unique_lock<std::shared_mutex> lk(mu_);
        val_   = tp;
        ready_ = true;
    }
    TP get() const {
        std::shared_lock<std::shared_mutex> lk(mu_);
        return val_;
    }
    bool is_ready() const {
        std::shared_lock<std::shared_mutex> lk(mu_);
        return ready_;
    }

private:
    mutable std::shared_mutex mu_;
    TP   val_{};
    bool ready_{false};
};

// ============================================================================
// Data structures
// ============================================================================

struct ScanResult {
    std::string target;
    int         port{0};
    std::string protocol{"tcp"};
    std::string status{"closed"};
    std::string service;
    std::string banner;
    std::string hostname;
    int         response_time_ms{0};
    int         ttl{0};         // 0 = unavailable (TCP connect path)
    std::string os_hint;        // "" = unavailable
    std::chrono::system_clock::time_point timestamp;
};

struct ScanOptions {
    std::vector<std::string> targets;
    std::vector<int>         ports;
    int         start_port{1};
    int         end_port{1024};
    int         num_threads{0};       // 0 → hardware_concurrency*2
    int         timeout_ms{200};
    std::string output_file;
    std::string output_format{"text"};
    bool        verbose{false};
    bool        udp_scan{false};
    bool        syn_scan{false};
    bool        service_detection{true};
    bool        banner_grab{false};
    bool        reverse_dns{false};
    bool        icmp_ping{true};
    bool        randomize_ports{false};
    int         rate_limit{0};
    std::vector<int> exclude_ports;
    bool        cidr_support{false};
    bool        json_output{false};
    bool        csv_output{false};
    bool        continuous_mode{false};
    int         scan_interval_sec{60};
    bool        vulnerability_check{false};
};

struct ScanStatistics {
    std::atomic<uint64_t> total_ports{0};
    std::atomic<uint64_t> scanned_ports{0};
    std::atomic<uint64_t> open_ports{0};
    std::atomic<uint64_t> closed_ports{0};
    std::atomic<uint64_t> filtered_ports{0};
    std::atomic<uint64_t> timeouts{0};
    std::atomic<uint64_t> errors{0};
    SafeTimePoint start_time;
    SafeTimePoint end_time;

    void reset() {
        total_ports = scanned_ports = open_ports = closed_ports = 0;
        filtered_ports = timeouts = errors = 0;
        start_time.set(std::chrono::steady_clock::now());
    }

    double progress() const {
        uint64_t total = total_ports.load(std::memory_order_relaxed);
        uint64_t done  = scanned_ports.load(std::memory_order_relaxed);
        return total == 0 ? 0.0 : (100.0 * done) / total;
    }

    double packets_per_second() const {
        auto now     = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                           now - start_time.get());
        if (elapsed.count() == 0) return 0.0;
        return static_cast<double>(
            scanned_ports.load(std::memory_order_relaxed)) / elapsed.count();
    }
};

// ============================================================================
// TCP pseudo-header (GCC packed; Linux-only tool — acceptable)
// ============================================================================

struct PseudoHeader {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t  zero;
    uint8_t  protocol;
    uint16_t tcp_len;
} __attribute__((packed));

// ============================================================================
// FIX-14 — Thread-safe timestamp
// ============================================================================

static std::string current_time_ts() {
    auto t = std::chrono::system_clock::to_time_t(
                 std::chrono::system_clock::now());
    struct tm tm_buf{};
    localtime_r(&t, &tm_buf);
    std::ostringstream ss;
    ss << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

// ============================================================================
// FIX-26 — Bounds-checked IP header offset helper
// ============================================================================

// Returns pointer to the transport header (TCP/ICMP) that begins after the
// IP header, or nullptr if the packet is too short.
template<typename TransportHdr>
static const TransportHdr* ihl_cast(const char* buf, int bytes) {
    if (bytes < static_cast<int>(sizeof(struct iphdr))) return nullptr;
    const auto* ip  = reinterpret_cast<const struct iphdr*>(buf);
    int ip_len = static_cast<int>(ip->ihl) * 4;
    if (ip_len < static_cast<int>(sizeof(struct iphdr))) return nullptr;
    if (bytes < ip_len + static_cast<int>(sizeof(TransportHdr))) return nullptr;
    return reinterpret_cast<const TransportHdr*>(buf + ip_len);
}

// ============================================================================
// Main Scanner
// ============================================================================

class Sentinel {
public:
    explicit Sentinel(ScanOptions opts)
        : opts_(std::move(opts))
        , last_progress_pct_(-1)
        , next_src_port_(EPH_PORT_BASE)  // FIX-30
    {
        // FIX-35: validate and normalise options before anything else
        validate_options();

        pool_ = std::make_unique<ThreadPool>(
            static_cast<size_t>(opts_.num_threads));
        if (opts_.rate_limit > 0)
            token_bucket_ = std::make_unique<TokenBucket>(
                static_cast<size_t>(opts_.rate_limit));

        initialize();
    }

    void scan() {
        stats_.reset();
        print_banner();

        // FIX-28: signal handler installed BEFORE ping sweep
        setup_signal_handler();

        if (opts_.icmp_ping)
            perform_ping_sweep();

        {
            std::lock_guard<std::mutex> lk(io_mutex_);
            std::cout << "\n[+] Scanning " << targets_.size()
                      << " target(s), " << ports_.size() << " port(s)\n"
                      << "[+] Threads:  " << opts_.num_threads << '\n';
            if (opts_.rate_limit > 0)
                std::cout << "[+] Rate:     " << opts_.rate_limit << " pps\n";
        }

        stats_.total_ports =
            static_cast<uint64_t>(targets_.size()) * ports_.size();

        // FIX-36: backpressure cap = threads * 4
        const size_t MAX_PENDING =
            static_cast<size_t>(opts_.num_threads) * 4;
        const size_t BATCH = 250;

        std::vector<std::pair<std::string,int>> batch;
        std::vector<std::future<void>>          futures;

        for (const auto& tgt : targets_) {
            for (int p : ports_) {
                if (should_exclude(p)) continue;
                batch.emplace_back(tgt, p);
                if (batch.size() >= BATCH) {
                    submit_batch(batch, futures, MAX_PENDING);
                    batch.clear();
                }
            }
        }
        if (!batch.empty())
            submit_batch(batch, futures, MAX_PENDING);

        for (auto& f : futures) {
            try { f.get(); }
            catch (const std::exception& e) {
                std::lock_guard<std::mutex> lk(io_mutex_);
                std::cerr << "[!] Batch error: " << e.what() << '\n';
            }
        }

        stats_.end_time.set(std::chrono::steady_clock::now());
        print_statistics();
        save_results();
    }

    void stop() {
        g_stop_signal.store(true, std::memory_order_release);
    }

private:
    ScanOptions                    opts_;
    std::unique_ptr<ThreadPool>    pool_;
    std::unique_ptr<TokenBucket>   token_bucket_;
    ScanStatistics                 stats_;
    std::vector<std::string>       targets_;
    std::vector<int>               ports_;
    std::vector<ScanResult>        results_;
    mutable std::mutex             io_mutex_;
    std::atomic<int>               last_progress_pct_;
    // FIX-30: collision-free ephemeral port allocation
    std::atomic<uint16_t>          next_src_port_;

    // ── service map ──────────────────────────────────────────────────────────

    const std::map<int,std::string> svc_ = {
        {20,"FTP-data"},{21,"FTP"},{22,"SSH"},{23,"Telnet"},
        {25,"SMTP"},{53,"DNS"},{67,"DHCP"},{68,"DHCP"},
        {69,"TFTP"},{80,"HTTP"},{110,"POP3"},{111,"RPC"},
        {123,"NTP"},{135,"MSRPC"},{137,"NetBIOS"},{138,"NetBIOS"},
        {139,"NetBIOS"},{143,"IMAP"},{161,"SNMP"},{162,"SNMP"},
        {179,"BGP"},{389,"LDAP"},{443,"HTTPS"},{445,"SMB"},
        {465,"SMTPS"},{514,"Syslog"},{515,"LPD"},{587,"SMTP"},
        {631,"IPP"},{636,"LDAPS"},{873,"Rsync"},
        {993,"IMAPS"},{995,"POP3S"},{1080,"SOCKS"},
        {1194,"OpenVPN"},{1433,"MSSQL"},{1521,"Oracle"},
        {1701,"L2TP"},{1723,"PPTP"},{1812,"RADIUS"},{1813,"RADIUS"},
        {2049,"NFS"},{2181,"ZooKeeper"},{2375,"Docker"},{2376,"Docker"},
        {3128,"Squid"},{3306,"MySQL"},{3389,"RDP"},{3690,"SVN"},
        {4444,"Metasploit"},{4500,"IPsec"},{5060,"SIP"},{5061,"SIP"},
        {5222,"XMPP"},{5432,"PostgreSQL"},{5800,"VNC"},{5900,"VNC"},
        {5984,"CouchDB"},{6000,"X11"},{6379,"Redis"},
        {6667,"IRC"},{7000,"Cassandra"},{8080,"HTTP-Alt"},
        {8443,"HTTPS-Alt"},{8500,"Consul"},{9000,"Hadoop"},
        {9092,"Kafka"},{9200,"Elasticsearch"},{9300,"Elasticsearch"},
        {9418,"Git"},{10000,"Webmin"},{11211,"Memcached"},
        {15672,"RabbitMQ"},{27017,"MongoDB"},{50070,"Hadoop"},
    };

    struct VulnRecord {
        std::string service;
        std::string banner_prefix;
        std::string cve_id;
        std::string description;
    };

    const std::vector<VulnRecord> vuln_db_ = {
        {"SSH",  "SSH-2.0-OpenSSH_7.2", "CVE-2016-6210",
         "OpenSSH 7.2 username enumeration via timing side-channel"},
        {"SSH",  "SSH-2.0-OpenSSH_7.1", "CVE-2016-0777",
         "OpenSSH < 7.2 roaming info leak (UseRoaming)"},
        {"HTTP", "Apache/2.4.49",       "CVE-2021-41773",
         "Apache 2.4.49 path-traversal/RCE"},
        {"HTTP", "Apache/2.4.50",       "CVE-2021-42013",
         "Apache 2.4.50 path-traversal bypass of CVE-2021-41773"},
        {"FTP",  "220 ProFTPD 1.3.5",   "CVE-2015-3306",
         "ProFTPD 1.3.5 mod_copy unauthenticated file copy"},
        {"SMTP", "220 Exim 4.87",       "CVE-2017-16943",
         "Exim 4.87 use-after-free in string_format"},
    };

    // ── FIX-35: validate / normalise options ─────────────────────────────────

    void validate_options() {
        if (opts_.timeout_ms < MIN_TIMEOUT_MS)
            opts_.timeout_ms = MIN_TIMEOUT_MS;
        if (opts_.timeout_ms > MAX_TIMEOUT_MS)
            opts_.timeout_ms = MAX_TIMEOUT_MS;

        if (opts_.num_threads <= 0)
            opts_.num_threads = static_cast<int>(
                std::thread::hardware_concurrency() * 2);
        if (opts_.num_threads < 1)    opts_.num_threads = 1;
        if (opts_.num_threads > MAX_THREADS) opts_.num_threads = MAX_THREADS;

        if (opts_.scan_interval_sec <= 0) opts_.scan_interval_sec = 60;
    }

    // ── initialisation ───────────────────────────────────────────────────────

    void initialize() {
        if (opts_.targets.empty())
            throw std::runtime_error("No targets specified");
        expand_targets();
        parse_port_ranges();
        if (opts_.randomize_ports)
            std::shuffle(ports_.begin(), ports_.end(), ThreadRng::engine);
    }

    void expand_targets() {
        for (const auto& t : opts_.targets) {
            if (t.find('/') != std::string::npos && opts_.cidr_support) {
                auto hosts = expand_cidr(t);
                targets_.insert(targets_.end(), hosts.begin(), hosts.end());
            } else if (is_valid_ip(t)) {
                targets_.push_back(t);
            } else {
                std::lock_guard<std::mutex> lk(io_mutex_);
                std::cerr << "[!] Invalid IP, skipping: " << t << '\n';
            }
        }
        if (targets_.empty())
            throw std::runtime_error("No valid targets found");
    }

    // FIX-20 + FIX-27
    std::vector<std::string> expand_cidr(const std::string& cidr) {
        std::vector<std::string> result;
        auto slash = cidr.find('/');
        if (slash == std::string::npos) { result.push_back(cidr); return result; }

        std::string base = cidr.substr(0, slash);
        int prefix = 0;
        try { prefix = std::stoi(cidr.substr(slash + 1)); }
        catch (...) { return result; }
        if (prefix < 0 || prefix > 32) return result;

        struct in_addr addr{};
        if (inet_pton(AF_INET, base.c_str(), &addr) != 1) return result;

        uint32_t ip    = ntohl(addr.s_addr);
        uint32_t mask  = (prefix == 0) ? 0u : ~((1u << (32 - prefix)) - 1u);
        uint32_t net   = ip & mask;
        uint32_t bcast = net | ~mask;

        auto push = [&](uint32_t h) {
            struct in_addr ha{};
            ha.s_addr = htonl(h);
            char buf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ha, buf, sizeof(buf));
            result.emplace_back(buf);
        };

        if (prefix == 32) { push(net);  return result; }
        if (prefix == 31) { push(net); push(bcast); return result; }

        // FIX-27: cap expansion to prevent billion-entry allocation
        uint32_t host_count = bcast - net - 1;
        if (host_count > MAX_CIDR_HOSTS) {
            std::cerr << "[!] CIDR /" << prefix
                      << " has " << host_count
                      << " hosts; capped at " << MAX_CIDR_HOSTS << '\n';
            host_count = static_cast<uint32_t>(MAX_CIDR_HOSTS);
        }
        for (uint32_t i = 0; i < host_count; ++i)
            push(net + 1 + i);

        return result;
    }

    static bool is_valid_ip(const std::string& ip) {
        struct in_addr  a4{};
        struct in6_addr a6{};
        return inet_pton(AF_INET,  ip.c_str(), &a4) == 1 ||
               inet_pton(AF_INET6, ip.c_str(), &a6) == 1;
    }

    void parse_port_ranges() {
        if (!opts_.ports.empty()) {
            ports_ = opts_.ports;
        } else {
            for (int p = opts_.start_port; p <= opts_.end_port; ++p)
                if (p > 0 && p <= 65535) ports_.push_back(p);
        }
        std::sort(ports_.begin(), ports_.end());
        ports_.erase(std::unique(ports_.begin(), ports_.end()), ports_.end());
    }

    bool should_exclude(int p) const {
        return std::find(opts_.exclude_ports.begin(),
                         opts_.exclude_ports.end(), p)
               != opts_.exclude_ports.end();
    }

    // FIX-28 + FIX-29
    void setup_signal_handler() {
        struct sigaction sa{};
        sa.sa_handler = [](int) {
            // FIX-29: release order ensures prompt cross-thread visibility
            g_stop_signal.store(true, std::memory_order_release);
            const char msg[] = "\n[!] Interrupted. Stopping...\n";
            ::write(STDERR_FILENO, msg, sizeof(msg) - 1);
        };
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_RESTART;
        sigaction(SIGINT,  &sa, nullptr);
        sigaction(SIGTERM, &sa, nullptr);
    }

    // ── FIX-21: ICMP ping with source validation + unique ID ─────────────────

    void perform_ping_sweep() {
        {
            std::lock_guard<std::mutex> lk(io_mutex_);
            std::cout << "\n[*] ICMP ping sweep...\n";
        }

        auto alive     = std::make_shared<std::vector<std::string>>();
        auto alive_mtx = std::make_shared<std::mutex>();

        std::vector<std::future<void>> futs;
        futs.reserve(targets_.size());

        for (const auto& t : targets_) {
            futs.push_back(pool_->enqueue(
                [this, t, alive, alive_mtx] {
                    if (icmp_ping(t)) {
                        {
                            std::lock_guard<std::mutex> lk(*alive_mtx);
                            alive->push_back(t);
                        }
                        if (opts_.verbose) {
                            std::lock_guard<std::mutex> ilk(io_mutex_);
                            std::cout << "  [+] " << t << " is up\n";
                        }
                    }
                },
                static_cast<size_t>(opts_.num_threads) * 4
            ));
        }

        std::exception_ptr first_exc;
        for (auto& f : futs) {
            try { f.get(); }
            catch (...) { if (!first_exc) first_exc = std::current_exception(); }
        }
        if (first_exc) std::rethrow_exception(first_exc);

        std::lock_guard<std::mutex> lk(io_mutex_);
        if (!alive->empty()) {
            targets_ = *alive;
            std::cout << "[+] " << targets_.size() << " host(s) up\n";
        } else {
            std::cout << "[-] No hosts responded; continuing anyway...\n";
        }
    }

    // FIX-21 + FIX-26: source IP validated; unique per-thread echo ID;
    //                   bounds-checked IP/ICMP header parsing
    bool icmp_ping(const std::string& target) {
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock < 0) return true; // no CAP_NET_RAW → assume up

        struct timeval tv{1, 0};
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        // FIX-21: unique echo ID per thread call to avoid cross-thread theft
        uint16_t echo_id = ThreadRng::u16();

        alignas(4) char packet[64]{};
        auto* icm             = reinterpret_cast<struct icmphdr*>(packet);
        icm->type             = ICMP_ECHO;
        icm->code             = 0;
        icm->un.echo.id       = htons(echo_id);
        icm->un.echo.sequence = htons(1);
        icm->checksum         = 0;
        icm->checksum         = checksum(
            reinterpret_cast<const uint16_t*>(packet),
            static_cast<int>(sizeof(packet)));

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        if (inet_pton(AF_INET, target.c_str(), &addr.sin_addr) != 1) {
            close(sock); return false;
        }

        if (sendto(sock, packet, sizeof(packet), 0,
                   reinterpret_cast<struct sockaddr*>(&addr),
                   sizeof(addr)) <= 0) {
            close(sock); return true;
        }

        // Poll + read loop: discard non-matching replies
        for (int attempt = 0; attempt < 8; ++attempt) {
            struct pollfd pfd{sock, POLLIN, 0};
            if (poll(&pfd, 1, 1000) <= 0) break;

            alignas(4) char buf[256]{};
            struct sockaddr_in reply{};
            socklen_t rlen = sizeof(reply);
            int bytes = recvfrom(sock, buf, sizeof(buf), 0,
                                 reinterpret_cast<struct sockaddr*>(&reply),
                                 &rlen);
            if (bytes <= 0) break;

            // FIX-21: validate source IP
            char src_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &reply.sin_addr, src_str, sizeof(src_str));
            if (std::string(src_str) != target) continue;

            // FIX-26: bounds-checked header access
            const auto* rep = ihl_cast<struct icmphdr>(buf, bytes);
            if (!rep) continue;

            if (rep->type != ICMP_ECHOREPLY) continue;

            // FIX-21: verify echo ID to reject stolen replies
            if (ntohs(rep->un.echo.id) != echo_id) continue;

            close(sock);
            return true;
        }

        close(sock);
        return false;
    }

    // ── source IP discovery ──────────────────────────────────────────────────

    uint32_t discover_source_ip(const std::string& target) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) return INADDR_ANY;

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port   = htons(53);
        if (inet_pton(AF_INET, target.c_str(), &addr.sin_addr) != 1) {
            close(sock); return INADDR_ANY;
        }
        if (connect(sock, reinterpret_cast<struct sockaddr*>(&addr),
                    sizeof(addr)) < 0) {
            close(sock); return INADDR_ANY;
        }
        struct sockaddr_in local{};
        socklen_t llen = sizeof(local);
        getsockname(sock, reinterpret_cast<struct sockaddr*>(&local), &llen);
        close(sock);
        return local.sin_addr.s_addr;
    }

    // ── FIX-30: collision-free ephemeral port ────────────────────────────────

    uint16_t alloc_src_port() {
        uint16_t offset = next_src_port_.fetch_add(1, std::memory_order_relaxed)
                          % EPH_PORT_COUNT;
        return static_cast<uint16_t>(EPH_PORT_BASE + offset);
    }

    // ── batch submission ─────────────────────────────────────────────────────

    void submit_batch(const std::vector<std::pair<std::string,int>>& batch,
                      std::vector<std::future<void>>& futures,
                      size_t max_pending)
    {
        futures.push_back(pool_->enqueue(
            [this, batch] {
                for (const auto& [tgt, port] : batch) {
                    if (g_stop_signal.load(std::memory_order_acquire)) break;

                    if (token_bucket_)
                        token_bucket_->consume_one();

                    ScanResult res;
                    try {
                        if (opts_.syn_scan)      res = syn_scan(tgt, port);
                        else if (opts_.udp_scan) res = udp_scan(tgt, port);
                        else                     res = tcp_connect(tgt, port);

                        update_stats(res);

                        if (res.status == "open" || opts_.verbose) {
                            std::lock_guard<std::mutex> lk(io_mutex_);
                            results_.push_back(res);
                            print_result_nolock(res);
                        }
                    } catch (const std::exception& e) {
                        ++stats_.errors;
                        if (opts_.verbose) {
                            std::lock_guard<std::mutex> lk(io_mutex_);
                            std::cerr << "    [!] " << tgt << ':' << port
                                      << " – " << e.what() << '\n';
                        }
                    }
                    ++stats_.scanned_ports;
                    if (stats_.scanned_ports % 100 == 0) print_progress();
                }
            },
            max_pending
        ));
    }

    // ── FIX-23 + FIX-31: TCP connect scan ────────────────────────────────────

    ScanResult tcp_connect(const std::string& tgt, int port) {
        ScanResult r;
        r.target    = tgt;
        r.port      = port;
        r.protocol  = "tcp";
        r.timestamp = std::chrono::system_clock::now();

        auto t0  = std::chrono::steady_clock::now();
        int  sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) { ++stats_.errors; return r; }

        // FIX-23: check fcntl error
        int fl = fcntl(sock, F_GETFL, 0);
        if (fl < 0) {
            close(sock);
            ++stats_.errors;
            return r;
        }
        if (fcntl(sock, F_SETFL, fl | O_NONBLOCK) < 0) {
            close(sock);
            ++stats_.errors;
            return r;
        }

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port   = htons(static_cast<uint16_t>(port));
        if (inet_pton(AF_INET, tgt.c_str(), &addr.sin_addr) != 1) {
            close(sock); ++stats_.errors; return r;
        }

        connect(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));

        struct pollfd pfd{sock, POLLOUT | POLLERR | POLLHUP, 0};
        int pr = poll(&pfd, 1, opts_.timeout_ms);

        r.response_time_ms = static_cast<int>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - t0).count());

        // FIX-23: check POLLERR/POLLHUP explicitly before POLLOUT
        if (pr > 0 && !(pfd.revents & (POLLERR | POLLHUP))
                   &&  (pfd.revents & POLLOUT)) {
            int err = 0;
            socklen_t el = sizeof(err);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &el);

            if (err == 0) {
                r.status = "open";
                // FIX-31: TTL unavailable on TCP connect socket; leave 0/"".
                r.ttl     = 0;
                r.os_hint = "";

                if (opts_.service_detection) r.service  = lookup_service(port);
                if (opts_.banner_grab)       r.banner   = grab_banner(sock, port);
                if (opts_.vulnerability_check && !r.banner.empty())
                    check_vulns(r);
                if (opts_.reverse_dns)       r.hostname = rdns(tgt);
            }
        } else if (pr == 0) {
            r.status = "timeout";
            ++stats_.timeouts;
        } else {
            r.status = "filtered";
        }

        close(sock);
        return r;
    }

    // ── FIX-24 + FIX-26 + FIX-30: SYN scan ──────────────────────────────────

    ScanResult syn_scan(const std::string& tgt, int port) {
        ScanResult r;
        r.target    = tgt;
        r.port      = port;
        r.protocol  = "tcp";
        r.status    = "filtered";
        r.timestamp = std::chrono::system_clock::now();

        int ssock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        int rsock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (ssock < 0 || rsock < 0) {
            if (ssock >= 0) close(ssock);
            if (rsock >= 0) close(rsock);
            ++stats_.errors;
            return tcp_connect(tgt, port);
        }

        int one = 1;
        setsockopt(ssock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

        uint32_t src_ip = discover_source_ip(tgt);
        if (src_ip == INADDR_ANY) {
            close(ssock); close(rsock);
            return tcp_connect(tgt, port);
        }

        // FIX-30: round-robin ephemeral port (no collision)
        uint16_t src_port = alloc_src_port();
        uint32_t seq_num  = ThreadRng::u32();

        auto t0 = std::chrono::steady_clock::now();

        // FIX-24: check inet_pton in send_syn
        if (!send_syn(ssock, src_ip, tgt, src_port, port, seq_num)) {
            close(ssock); close(rsock);
            return tcp_connect(tgt, port);
        }

        struct timeval tv{0, static_cast<suseconds_t>(opts_.timeout_ms * 1000)};
        setsockopt(rsock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        alignas(4) char buf[256]{};
        bool timed_out = true;

        for (int attempt = 0; attempt < 8; ++attempt) {
            struct sockaddr_in ra{};
            socklen_t rlen = sizeof(ra);
            int bytes = recvfrom(rsock, buf, sizeof(buf), 0,
                                 reinterpret_cast<struct sockaddr*>(&ra), &rlen);
            if (bytes <= 0) break;

            // Source IP check
            char ra_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ra.sin_addr, ra_str, sizeof(ra_str));
            if (std::string(ra_str) != tgt) continue;

            // FIX-26: bounds-checked TCP header
            const auto* tcp = ihl_cast<struct tcphdr>(buf, bytes);
            if (!tcp) continue;

            if (ntohs(tcp->source) != static_cast<uint16_t>(port)) continue;
            if (ntohs(tcp->dest)   != src_port) continue;

            timed_out = false;
            r.response_time_ms = static_cast<int>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - t0).count());

            if (tcp->syn && tcp->ack) {
                r.status = "open";
                // Raw recv: IP header available — real TTL
                const auto* ip = reinterpret_cast<const struct iphdr*>(buf);
                r.ttl     = ip->ttl;
                r.os_hint = os_from_ttl(r.ttl);
                send_rst(ssock, src_ip, tgt, src_port, port,
                         const_cast<struct tcphdr*>(tcp));
                if (opts_.service_detection) r.service  = lookup_service(port);
                if (opts_.reverse_dns)       r.hostname = rdns(tgt);
            } else if (tcp->rst) {
                r.status = "closed";
            }
            break;
        }

        if (timed_out) ++stats_.timeouts;

        close(ssock);
        close(rsock);
        return r;
    }

    // FIX-24: returns bool; false on inet_pton failure
    bool send_syn(int sock, uint32_t src_ip, const std::string& dst,
                  uint16_t src_port, int dst_port, uint32_t seq)
    {
        alignas(4) char pkt[sizeof(struct iphdr) + sizeof(struct tcphdr)]{};
        auto* ip  = reinterpret_cast<struct iphdr*>(pkt);
        auto* tcp = reinterpret_cast<struct tcphdr*>(
                        pkt + sizeof(struct iphdr));

        ip->ihl = 5; ip->version = 4;
        ip->tot_len  = htons(sizeof(pkt));
        ip->id       = htons(ThreadRng::u16());
        ip->ttl      = 64;
        ip->protocol = IPPROTO_TCP;
        ip->saddr    = src_ip;
        // FIX-24
        if (inet_pton(AF_INET, dst.c_str(), &ip->daddr) != 1) return false;

        tcp->source = htons(src_port);
        tcp->dest   = htons(static_cast<uint16_t>(dst_port));
        tcp->seq    = htonl(seq);
        tcp->doff   = 5;
        tcp->syn    = 1;
        tcp->window = htons(5840);
        tcp->check  = tcp_checksum(ip, tcp);
        ip->check   = checksum(reinterpret_cast<const uint16_t*>(ip),
                                static_cast<int>(sizeof(struct iphdr)));

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        if (inet_pton(AF_INET, dst.c_str(), &addr.sin_addr) != 1) return false;
        sendto(sock, pkt, sizeof(pkt), 0,
               reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
        return true;
    }

    void send_rst(int sock, uint32_t src_ip, const std::string& dst,
                  uint16_t src_port, int dst_port, struct tcphdr* rtcp)
    {
        alignas(4) char pkt[sizeof(struct iphdr) + sizeof(struct tcphdr)]{};
        auto* ip  = reinterpret_cast<struct iphdr*>(pkt);
        auto* tcp = reinterpret_cast<struct tcphdr*>(
                        pkt + sizeof(struct iphdr));

        ip->ihl = 5; ip->version = 4;
        ip->tot_len  = htons(sizeof(pkt));
        ip->id       = htons(ThreadRng::u16());
        ip->ttl      = 64;
        ip->protocol = IPPROTO_TCP;
        ip->saddr    = src_ip;
        if (inet_pton(AF_INET, dst.c_str(), &ip->daddr) != 1) return;

        tcp->source = htons(src_port);
        tcp->dest   = htons(static_cast<uint16_t>(dst_port));
        tcp->seq    = rtcp->ack_seq; // already network byte order
        tcp->doff   = 5;
        tcp->rst    = 1;
        tcp->window = htons(5840);
        tcp->check  = tcp_checksum(ip, tcp);
        ip->check   = checksum(reinterpret_cast<const uint16_t*>(ip),
                                static_cast<int>(sizeof(struct iphdr)));

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        if (inet_pton(AF_INET, dst.c_str(), &addr.sin_addr) != 1) return;
        sendto(sock, pkt, sizeof(pkt), 0,
               reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
    }

    // ── FIX-25 + FIX-26 + FIX-19: UDP scan ──────────────────────────────────

    ScanResult udp_scan(const std::string& tgt, int port) {
        ScanResult r;
        r.target    = tgt;
        r.port      = port;
        r.protocol  = "udp";
        r.status    = "open|filtered";
        r.timestamp = std::chrono::system_clock::now();

        auto t0   = std::chrono::steady_clock::now();
        int usock = socket(AF_INET, SOCK_DGRAM,  0);
        int isock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (usock < 0 || isock < 0) {
            if (usock >= 0) close(usock);
            if (isock >= 0) close(isock);
            ++stats_.errors;
            return r;
        }

        fcntl(usock, F_SETFL, O_NONBLOCK);
        fcntl(isock, F_SETFL, O_NONBLOCK);

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port   = htons(static_cast<uint16_t>(port));
        if (inet_pton(AF_INET, tgt.c_str(), &addr.sin_addr) != 1) {
            close(usock); close(isock);
            ++stats_.errors;
            return r;
        }

        sendto(usock, nullptr, 0, 0,
               reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));

        // FIX-25: watch for POLLERR/POLLHUP too
        struct pollfd pfds[2]{
            {isock, POLLIN | POLLERR | POLLHUP, 0},
            {usock, POLLIN | POLLERR | POLLHUP, 0}
        };
        int pr = poll(pfds, 2, opts_.timeout_ms);

        r.response_time_ms = static_cast<int>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - t0).count());

        if (pr > 0) {
            // FIX-25: error conditions
            if ((pfds[0].revents | pfds[1].revents) & (POLLERR | POLLHUP)) {
                r.status = "error";
                close(usock); close(isock);
                return r;
            }

            if (pfds[0].revents & POLLIN) {
                alignas(4) char buf[256]{};
                struct sockaddr_in ra{};
                socklen_t rlen = sizeof(ra);
                int bytes = recvfrom(isock, buf, sizeof(buf), 0,
                                     reinterpret_cast<struct sockaddr*>(&ra),
                                     &rlen);
                if (bytes > 0) {
                    // FIX-19: source IP validation
                    char ra_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &ra.sin_addr, ra_str, sizeof(ra_str));
                    if (std::string(ra_str) == tgt) {
                        // FIX-26: bounds-checked ICMP header
                        const auto* icm =
                            ihl_cast<struct icmphdr>(buf, bytes);
                        if (icm && icm->type == 3 && icm->code == 3) {
                            r.status = "closed";
                            ++stats_.closed_ports;
                        }
                    }
                }
            }
            if (pfds[1].revents & POLLIN) {
                r.status = "open";
                if (opts_.service_detection) r.service = lookup_service(port);
                if (opts_.banner_grab) {
                    alignas(4) char buf[1024]{};
                    int n = recv(usock, buf, sizeof(buf) - 1, 0);
                    if (n > 0) { buf[n] = '\0'; r.banner = clean_banner(buf); }
                }
            }
        } else if (pr == 0) {
            ++stats_.timeouts;
        }

        close(usock);
        close(isock);
        return r;
    }

    // ── checksum helpers ─────────────────────────────────────────────────────

    static uint16_t checksum(const uint16_t* buf, int len) {
        uint32_t sum = 0;
        while (len > 1) { sum += *buf++; len -= 2; }
        if (len == 1) sum += *reinterpret_cast<const uint8_t*>(buf);
        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);
        return static_cast<uint16_t>(~sum);
    }

    uint16_t tcp_checksum(struct iphdr* ip, struct tcphdr* tcp) {
        PseudoHeader ph{};
        ph.src_addr = ip->saddr;
        ph.dst_addr = ip->daddr;
        ph.zero     = 0;
        ph.protocol = IPPROTO_TCP;
        ph.tcp_len  = htons(sizeof(struct tcphdr));
        alignas(4) char buf[sizeof(PseudoHeader) + sizeof(struct tcphdr)]{};
        memcpy(buf,              &ph,  sizeof(ph));
        memcpy(buf + sizeof(ph), tcp,  sizeof(struct tcphdr));
        return checksum(reinterpret_cast<const uint16_t*>(buf), sizeof(buf));
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    static std::string os_from_ttl(int ttl) {
        int initial = (ttl <= 64) ? 64 : (ttl <= 128) ? 128 : 255;
        switch (initial) {
            case 64:  return "Linux/Unix/macOS";
            case 128: return "Windows";
            default:  return "Network Device/Cisco";
        }
    }

    std::string lookup_service(int port) const {
        auto it = svc_.find(port);
        return it != svc_.end() ? it->second : "unknown";
    }

    std::string grab_banner(int sock, int port) {
        int fl = fcntl(sock, F_GETFL, 0);
        if (fl >= 0) fcntl(sock, F_SETFL, fl & ~O_NONBLOCK);

        std::string probe;
        if (port == 80 || port == 8080 || port == 8000 || port == 8008)
            probe = "HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n";
        else if (port == 25 || port == 587)
            probe = "EHLO localhost\r\n";
        else if (port == 110)
            probe = "QUIT\r\n";
        else if (port == 21 || port == 22 || port == 23)
            probe = "";
        else
            probe = "\r\n";

        if (!probe.empty()) {
            size_t sent_total = 0;
            while (sent_total < probe.size()) {
                ssize_t n = send(sock,
                                 probe.c_str() + sent_total,
                                 probe.size()  - sent_total,
                                 MSG_NOSIGNAL);
                if (n < 0) {
                    if (errno == EINTR) continue;
                    return {};
                }
                sent_total += static_cast<size_t>(n);
            }
        }

        struct timeval tv{0, static_cast<suseconds_t>(opts_.timeout_ms * 1000)};
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        alignas(4) char buf[4096]{};
        int n = recv(sock, buf, sizeof(buf) - 1, 0);
        if (n > 0) { buf[n] = '\0'; return clean_banner(buf); }
        return {};
    }

    static std::string clean_banner(const char* raw) {
        std::string out;
        for (const char* p = raw; *p; ++p) {
            unsigned char c = static_cast<unsigned char>(*p);
            out += (std::isprint(c) || c == '\n' || c == '\r') ? *p : '.';
        }
        return out;
    }

    std::string rdns(const std::string& ip) {
        struct sockaddr_in a{};
        a.sin_family = AF_INET;
        if (inet_pton(AF_INET, ip.c_str(), &a.sin_addr) != 1) return {};
        char host[NI_MAXHOST];
        if (getnameinfo(reinterpret_cast<struct sockaddr*>(&a), sizeof(a),
                        host, sizeof(host), nullptr, 0, NI_NAMEREQD) == 0)
            return host;
        return {};
    }

    void check_vulns(ScanResult& r) {
        for (const auto& v : vuln_db_) {
            if (r.service != v.service) continue;
            if (r.banner.compare(0, v.banner_prefix.size(),
                                 v.banner_prefix) == 0)
                r.banner += " [" + v.cve_id + ": " + v.description + "]";
        }
    }

    // ── statistics & output ──────────────────────────────────────────────────

    void update_stats(const ScanResult& r) {
        if      (r.status == "open")     ++stats_.open_ports;
        else if (r.status == "closed")   ++stats_.closed_ports;
        else if (r.status == "filtered") ++stats_.filtered_ports;
        else if (r.status == "timeout")  ++stats_.timeouts;
        else if (r.status == "error")    ++stats_.errors;
    }

    void print_banner() {
        std::lock_guard<std::mutex> lk(io_mutex_);
        std::cout <<
            "\n"
            "  ╔════════════════════════════════════════════════╗\n"
            "  ║              S E N T I N E L                   ║\n"
            "  ║        Advanced Port Scanner v3.0              ║\n"
            "  ║     Production-Ready Network Security Tool     ║\n"
            "  ╚════════════════════════════════════════════════╝\n\n";
    }

    void print_progress() {
        int pct      = static_cast<int>(stats_.progress());
        int expected = last_progress_pct_.load(std::memory_order_relaxed);
        if (pct % 5 != 0 || pct == expected) return;
        if (!last_progress_pct_.compare_exchange_strong(expected, pct)) return;

        std::lock_guard<std::mutex> lk(io_mutex_);
        std::cout << "\r[*] Progress: " << std::setw(3) << pct << "% ["
                  << std::string(static_cast<size_t>(pct / 2), '=')
                  << std::string(static_cast<size_t>(50 - pct / 2), ' ')
                  << "] "
                  << stats_.scanned_ports.load(std::memory_order_relaxed)
                  << '/' << stats_.total_ports.load(std::memory_order_relaxed)
                  << " (" << std::fixed << std::setprecision(1)
                  << stats_.packets_per_second() << " pps)" << std::flush;
    }

    void print_result_nolock(const ScanResult& r) {
        std::cout << "\n[+] " << std::left  << std::setw(15) << r.target
                  << ':'      << std::right << std::setw(5)  << r.port
                  << '/'      << r.protocol
                  << "  "     << std::setw(12) << r.status;
        if (!r.service.empty())     std::cout << "  " << r.service;
        if (r.response_time_ms > 0) std::cout << "  [" << r.response_time_ms << "ms]";
        if (!r.os_hint.empty())     std::cout << "  OS:" << r.os_hint;
        if (!r.hostname.empty())    std::cout << "  (" << r.hostname << ')';
        if (!r.banner.empty()) {
            std::cout << "\n      Banner: " << r.banner.substr(0, 120);
            if (r.banner.size() > 120) std::cout << "...";
        }
        std::cout << '\n';
    }

    void print_statistics() {
        if (!stats_.end_time.is_ready()) return;
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            stats_.end_time.get() - stats_.start_time.get());

        std::lock_guard<std::mutex> lk(io_mutex_);
        std::cout <<
            "\n\n"
            "╔════════════════════════════════════════════════════════╗\n"
            "║                    SCAN STATISTICS                     ║\n"
            "╠════════════════════════════════════════════════════════╣\n";
        auto row = [](const char* lbl, auto val) {
            std::cout << "║  " << std::left  << std::setw(24) << lbl
                      << std::right << std::setw(32) << val  << "║\n";
        };
        row("Total ports scanned:", stats_.total_ports.load());
        row("Open ports:",          stats_.open_ports.load());
        row("Closed ports:",        stats_.closed_ports.load());
        row("Filtered ports:",      stats_.filtered_ports.load());
        row("Timeouts:",            stats_.timeouts.load());
        row("Errors:",              stats_.errors.load());
        row("Scan duration (s):",   elapsed.count());
        std::cout << "╚════════════════════════════════════════════════════════╝\n";
    }

    void save_results() {
        if (opts_.output_file.empty()) return;
        std::ofstream f(opts_.output_file);
        if (!f) {
            std::cerr << "[!] Cannot open: " << opts_.output_file << '\n';
            return;
        }
        if      (opts_.json_output || opts_.output_format == "json") save_json(f);
        else if (opts_.csv_output  || opts_.output_format == "csv")  save_csv(f);
        else                                                          save_text(f);
        std::cout << "[+] Results → " << opts_.output_file << '\n';
    }

    void save_json(std::ofstream& f) {
        f << "{\n  \"scan_timestamp\":\"" << current_time_ts() << "\",\n"
          << "  \"statistics\":{"
          << "\"total\":"     << stats_.total_ports
          << ",\"open\":"     << stats_.open_ports
          << ",\"closed\":"   << stats_.closed_ports
          << ",\"filtered\":" << stats_.filtered_ports
          << ",\"timeouts\":" << stats_.timeouts
          << ",\"errors\":"   << stats_.errors << "},\n"
          << "  \"results\":[\n";
        for (size_t i = 0; i < results_.size(); ++i) {
            const auto& r = results_[i];
            f << "    {\"target\":\""  << je(r.target)      << "\","
              << "\"port\":"           << r.port             << ","
              << "\"protocol\":\""     << r.protocol         << "\","
              << "\"status\":\""       << r.status           << "\","
              << "\"service\":\""      << je(r.service)      << "\","
              << "\"banner\":\""       << je(r.banner)       << "\","
              << "\"hostname\":\""     << je(r.hostname)     << "\","
              << "\"response_ms\":"    << r.response_time_ms << ","
              << "\"ttl\":"            << r.ttl              << ","
              << "\"os_hint\":\""      << je(r.os_hint)      << "\"}";
            if (i + 1 < results_.size()) f << ',';
            f << '\n';
        }
        f << "  ]\n}\n";
    }

    void save_csv(std::ofstream& f) {
        f << "timestamp,target,port,protocol,status,service,"
             "banner,hostname,ms,ttl,os\n";
        for (const auto& r : results_) {
            f << current_time_ts() << ','
              << r.target << ',' << r.port << ',' << r.protocol << ','
              << r.status << ",\"" << ce(r.service)  << "\",\""
              << ce(r.banner)      << "\",\"" << ce(r.hostname) << "\","
              << r.response_time_ms << ',' << r.ttl << ",\""
              << r.os_hint << "\"\n";
        }
    }

    void save_text(std::ofstream& f) {
        f << "Sentinel Scan Results — " << current_time_ts() << "\n"
          << "==========================================\n\n";
        for (const auto& r : results_) {
            if (r.status != "open") continue;
            f << "PORT " << r.port << '/' << r.protocol << " OPEN  " << r.service;
            if (!r.os_hint.empty())  f << "  OS:" << r.os_hint;
            if (!r.hostname.empty()) f << "  (" << r.hostname << ')';
            f << '\n';
            if (!r.banner.empty())   f << "  Banner: " << r.banner << '\n';
            f << '\n';
        }
    }

    static std::string je(const std::string& s) {
        std::string o;
        for (unsigned char c : s) {
            switch (c) {
                case '"':  o += "\\\""; break;
                case '\\': o += "\\\\"; break;
                case '\n': o += "\\n";  break;
                case '\r': o += "\\r";  break;
                case '\t': o += "\\t";  break;
                default:
                    if (c < 0x20) {
                        char b[8]; snprintf(b, 8, "\\u%04x", c); o += b;
                    } else {
                        o += static_cast<char>(c);
                    }
            }
        }
        return o;
    }

    static std::string ce(const std::string& s) {
        std::string o;
        for (char c : s) { if (c == '"') o += "\"\""; else o += c; }
        return o;
    }
};

// ============================================================================
// FIX-34 — Argument Parser (exceptions instead of exit; stoi wrapped)
// ============================================================================

class ArgParser {
public:
    static ScanOptions parse(int argc, char* argv[]) {
        ScanOptions o;
        if (argc < 2) { help(); throw std::runtime_error("No arguments"); }

        for (int i = 1; i < argc; ++i) {
            std::string a = argv[i];

            // FIX-34: next() throws instead of calling exit()
            auto next = [&]() -> const char* {
                if (++i < argc) return argv[i];
                throw std::runtime_error(
                    std::string("Missing argument for ") + a);
            };

            if      (a=="-h"||a=="--help")    { help(); throw std::runtime_error("help"); }
            else if (a=="-t"||a=="--target")   parse_targets(next(), o);
            else if (a=="-p"||a=="--ports")    parse_ports(next(), o);
            else if (a=="--threads")           o.num_threads  = safe_stoi(next(), a);
            else if (a=="--timeout")           o.timeout_ms   = safe_stoi(next(), a);
            else if (a=="-o"||a=="--output")   o.output_file  = next();
            else if (a=="-f"||a=="--format") {
                o.output_format = next();
                if (o.output_format=="json") o.json_output = true;
                if (o.output_format=="csv")  o.csv_output  = true;
            }
            else if (a=="-v"||a=="--verbose")  o.verbose            = true;
            else if (a=="--udp")               o.udp_scan           = true;
            else if (a=="--syn")               o.syn_scan           = true;
            else if (a=="--no-service")        o.service_detection  = false;
            else if (a=="--banner")            o.banner_grab        = true;
            else if (a=="--dns")               o.reverse_dns        = true;
            else if (a=="--no-ping")           o.icmp_ping          = false;
            else if (a=="--randomize")         o.randomize_ports    = true;
            else if (a=="--rate")              o.rate_limit         = safe_stoi(next(), a);
            else if (a=="--exclude")           parse_ports(next(), o, true);
            else if (a=="--cidr")              o.cidr_support       = true;
            else if (a=="--continuous") {
                o.continuous_mode   = true;
                o.scan_interval_sec = safe_stoi(next(), a);
            }
            else if (a=="--vuln")              o.vulnerability_check = true;
            else {
                std::cerr << "[!] Unknown option: " << a << '\n';
            }
        }

        if (o.targets.empty())
            throw std::runtime_error("No targets specified (use -t)");
        return o;
    }

private:
    // FIX-34: user-friendly stoi wrapper
    static int safe_stoi(const char* s, const std::string& opt) {
        try { return std::stoi(s); }
        catch (const std::exception&) {
            throw std::runtime_error(
                "Invalid integer '" + std::string(s) +
                "' for option " + opt);
        }
    }

    static void help() {
        std::cout << R"(
╔═══════════════════════════════════════════════════════════════╗
║                SENTINEL v3.0 — Help                          ║
╚═══════════════════════════════════════════════════════════════╝

USAGE:  sentinel [options]

REQUIRED:
  -t, --target <ip|file>    Target IP(s), comma-separated or file
  -p, --ports  <range>      Ports: 1-1000,80,443,8080-8090

SCAN TYPES:
  --syn                     SYN stealth (requires root)
  --udp                     UDP scan    (requires root)
  (default: TCP connect)

PERFORMANCE:
  --threads <n>             Worker threads  [1-1024, default: nCPU*2]
  --timeout <ms>            Per-port timeout [1-30000, default: 200]
  --rate    <pps>           Rate limit (packets/sec)
  --randomize               Shuffle port order

OUTPUT:
  -o, --output <file>       Write results to file
  -f, --format <fmt>        text | json | csv
  -v, --verbose             Verbose mode

DISCOVERY:
  --no-ping                 Skip ICMP ping sweep
  --banner                  Grab service banners
  --dns                     Reverse DNS lookup

ADVANCED:
  --exclude <range>         Exclude ports
  --cidr                    CIDR notation (/32, /31, max 65536 hosts)
  --continuous <sec>        Repeat scan every N seconds
  --vuln                    Banner-based CVE check

EXAMPLES:
  sentinel -t 192.168.1.1 -p 1-1000
  sudo sentinel -t 10.0.0.1 -p 22,80,443 --syn --banner --dns
  sentinel -t 192.168.1.0/24 -p 1-1024 --cidr
  sentinel -t hosts.txt -p 1-65535 --threads 200 --rate 5000
  sentinel -t 10.0.0.1 -p 1-1000 --vuln --banner -o out.json -f json
  sentinel -t 10.0.0.1 -p 22,80,443 --continuous 60
)";
    }

    static void parse_targets(const char* input, ScanOptions& o) {
        std::ifstream f(input);
        if (f.good()) {
            std::string line;
            while (std::getline(f, line)) {
                line = trim(line);
                if (!line.empty() && line[0] != '#')
                    o.targets.push_back(line);
            }
        } else {
            std::istringstream ss(input);
            std::string item;
            while (std::getline(ss, item, ',')) {
                item = trim(item);
                if (!item.empty()) o.targets.push_back(item);
            }
        }
    }

    static void parse_ports(const char* input, ScanOptions& o,
                             bool exclude = false) {
        std::istringstream ss(input);
        std::string tok;
        while (std::getline(ss, tok, ',')) {
            tok = trim(tok);
            if (tok.empty()) continue;
            auto dash = tok.find('-');
            try {
                if (dash != std::string::npos) {
                    int lo = std::stoi(tok.substr(0, dash));
                    int hi = std::stoi(tok.substr(dash + 1));
                    if (lo > hi) std::swap(lo, hi);
                    for (int p = lo; p <= hi; ++p)
                        if (p > 0 && p <= 65535)
                            (exclude ? o.exclude_ports : o.ports).push_back(p);
                } else {
                    int p = std::stoi(tok);
                    if (p > 0 && p <= 65535)
                        (exclude ? o.exclude_ports : o.ports).push_back(p);
                }
            } catch (const std::exception&) {
                std::cerr << "[!] Invalid port token: " << tok << '\n';
            }
        }
    }

    static std::string trim(const std::string& s) {
        auto b = s.find_first_not_of(" \t\r\n");
        if (b == std::string::npos) return {};
        return s.substr(b, s.find_last_not_of(" \t\r\n") - b + 1);
    }
};

// ============================================================================
// Entry point
// ============================================================================

int main(int argc, char* argv[]) {
    try {
        ScanOptions opts;
        try {
            opts = ArgParser::parse(argc, argv);
        } catch (const std::runtime_error& e) {
            // "help" exception is benign
            std::string w = e.what();
            if (w != "help" && w != "No arguments")
                std::cerr << "[!] Argument error: " << w << '\n';
            return (w == "help") ? 0 : 1;
        }

        if ((opts.syn_scan || opts.udp_scan) && geteuid() != 0) {
            std::cerr << "[!] SYN/UDP require root. "
                         "Falling back to TCP connect.\n";
            opts.syn_scan = opts.udp_scan = false;
        }

        // Raise fd limit
        struct rlimit rl{};
        if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
            rl.rlim_cur = std::min(static_cast<rlim_t>(65535), rl.rlim_max);
            setrlimit(RLIMIT_NOFILE, &rl);
        }

        if (opts.continuous_mode) {
            int n = 1;
            while (!g_stop_signal.load(std::memory_order_acquire)) {
                std::cout << "\n[ Scan #" << n++ << " ]\n";
                Sentinel s(opts);
                s.scan();
                if (g_stop_signal.load(std::memory_order_acquire)) break;
                std::cout << "[*] Next scan in "
                          << opts.scan_interval_sec << "s…\n";
                std::this_thread::sleep_for(
                    std::chrono::seconds(opts.scan_interval_sec));
            }
        } else {
            Sentinel s(opts);
            s.scan();
        }

    } catch (const std::exception& e) {
        std::cerr << "[!] Fatal: " << e.what() << '\n';
        return 1;
    }

    std::cout << "\n[*] Sentinel finished.\n";
    return 0;
}
