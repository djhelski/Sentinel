#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <queue>
#include <chrono>
#include <stdexcept>
#include <csignal>
#include <atomic>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <map>
#include <iomanip>
#include <regex>
#include <condition_variable>
#include <functional>
#include <future>
#include <random>
#include <memory>
#include <cctype>

// POSIX/Linux headers
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <errno.h>
#include <cstring>
#include <netdb.h>
#include <ifaddrs.h>
#include <sys/time.h>
#include <sys/resource.h>

// ============================================================================
// Global variables and forward declarations
// ============================================================================

class Sentinel;
static std::atomic<bool> g_stop_signal{false};
static Sentinel* g_sentinel_ptr{nullptr};

// ============================================================================
// Data structures
// ============================================================================

struct ScanResult {
    std::string target;
    int port{0};
    std::string protocol{"tcp"};
    std::string status{"closed"};
    std::string service;
    std::string banner;
    std::string hostname;
    int response_time_ms{0};
    int ttl{0};
    std::string os_hint;
    std::chrono::system_clock::time_point timestamp;
};

struct ScanOptions {
    std::vector<std::string> targets;
    std::vector<int> ports;
    int start_port{1};
    int end_port{1024};
    int num_threads{0};
    int timeout_ms{200};
    int max_retries{2};
    std::string output_file;
    std::string output_format{"text"};
    bool verbose{false};
    bool udp_scan{false};
    bool syn_scan{false};
    bool service_detection{true};
    bool banner_grab{false};
    bool reverse_dns{false};
    bool icmp_ping{true};
    bool randomize_ports{false};
    int rate_limit{0};
    std::vector<int> exclude_ports;
    bool os_detection{false};
    bool cidr_support{false};
    bool json_output{false};
    bool csv_output{false};
    bool continuous_mode{false};
    int scan_interval_sec{60};
    bool vulnerability_check{false};
    bool mac_lookup{false};
    bool geoip{false};
};

struct ScanStatistics {
    std::atomic<uint64_t> total_ports{0};
    std::atomic<uint64_t> scanned_ports{0};
    std::atomic<uint64_t> open_ports{0};
    std::atomic<uint64_t> closed_ports{0};
    std::atomic<uint64_t> filtered_ports{0};
    std::atomic<uint64_t> timeouts{0};
    std::atomic<uint64_t> errors{0};
    std::chrono::steady_clock::time_point start_time;
    std::chrono::steady_clock::time_point end_time;
    
    void reset() {
        total_ports = 0;
        scanned_ports = 0;
        open_ports = 0;
        closed_ports = 0;
        filtered_ports = 0;
        timeouts = 0;
        errors = 0;
        start_time = std::chrono::steady_clock::now();
    }
    
    double progress() const {
        if (total_ports == 0) return 0.0;
        return (100.0 * scanned_ports) / total_ports;
    }
    
    double packets_per_second() const {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start_time);
        if (elapsed.count() == 0) return 0.0;
        return static_cast<double>(scanned_ports) / elapsed.count();
    }
};

// ============================================================================
// Token Bucket for rate limiting
// ============================================================================

class TokenBucket {
public:
    explicit TokenBucket(size_t rate_per_second) 
        : rate_(rate_per_second), tokens_(rate_per_second) {
        last_refill_ = std::chrono::steady_clock::now();
    }
    
    bool consume(size_t tokens = 1) {
        std::lock_guard<std::mutex> lock(mutex_);
        refill();
        
        if (tokens_ >= tokens) {
            tokens_ -= tokens;
            return true;
        }
        
        // Not enough tokens, calculate wait time
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(now - last_refill_);
        double need_us = (1000000.0 * tokens) / rate_;
        
        if (elapsed.count() < need_us) {
            auto wait_us = static_cast<long>(need_us - elapsed.count());
            std::this_thread::sleep_for(std::chrono::microseconds(wait_us));
        }
        
        refill();
        if (tokens_ >= tokens) {
            tokens_ -= tokens;
            return true;
        }
        
        return false;
    }

private:
    size_t rate_;
    size_t tokens_;
    std::chrono::time_point<std::chrono::steady_clock> last_refill_;
    std::mutex mutex_;
    
    void refill() {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(now - last_refill_);
        
        size_t new_tokens = (elapsed.count() * rate_) / 1000000;
        if (new_tokens > 0) {
            tokens_ = std::min(tokens_ + new_tokens, rate_);
            last_refill_ = now;
        }
    }
};

// ============================================================================
// Thread Pool with modern C++ features
// ============================================================================

class ThreadPool {
public:
    explicit ThreadPool(size_t num_threads) 
        : stop_(false) {
        
        // Set thread names for debugging
        for (size_t i = 0; i < num_threads; ++i) {
            workers_.emplace_back([this, i] {
                while (true) {
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lock(queue_mutex_);
                        condition_.wait(lock, [this] { 
                            return stop_ || !tasks_.empty(); 
                        });
                        
                        if (stop_ && tasks_.empty()) {
                            return;
                        }
                        
                        task = std::move(tasks_.front());
                        tasks_.pop();
                    }
                    
                    try {
                        task();
                    } catch (const std::exception& e) {
                        std::cerr << "Thread pool task exception: " << e.what() << std::endl;
                    }
                }
            });
        }
    }

    template<class F, class... Args>
    auto enqueue(F&& f, Args&&... args) 
        -> std::future<typename std::invoke_result_t<F, Args...>> {
        
        using return_type = typename std::invoke_result_t<F, Args...>;
        
        auto task = std::make_shared<std::packaged_task<return_type()>>(
            std::bind(std::forward<F>(f), std::forward<Args>(args)...)
        );
        
        std::future<return_type> result = task->get_future();
        
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            if (stop_) {
                throw std::runtime_error("enqueue on stopped ThreadPool");
            }
            tasks_.emplace([task]() { (*task)(); });
        }
        condition_.notify_one();
        return result;
    }
    
    size_t pending_tasks() const {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        return tasks_.size();
    }
    
    ~ThreadPool() {
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            stop_ = true;
        }
        condition_.notify_all();
        
        for (std::thread& worker : workers_) {
            if (worker.joinable()) {
                worker.join();
            }
        }
    }

private:
    std::vector<std::thread> workers_;
    std::queue<std::function<void()>> tasks_;
    mutable std::mutex queue_mutex_;
    std::condition_variable condition_;
    bool stop_;
};

// ============================================================================
// TCP Pseudo Header for checksum calculation
// ============================================================================

struct PseudoHeader {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t zero;
    uint8_t protocol;
    uint16_t tcp_len;
} __attribute__((packed));

// ============================================================================
// Main Scanner Class
// ============================================================================

class Sentinel {
public:
    explicit Sentinel(ScanOptions options) 
        : opts_(std::move(options))
        , pool_(opts_.num_threads > 0 ? opts_.num_threads : std::thread::hardware_concurrency() * 2)
        , token_bucket_(opts_.rate_limit > 0 ? opts_.rate_limit : 1000000) {
        
        initialize();
    }
    
    ~Sentinel() {
        cleanup();
    }
    
    void scan() {
        try {
            stats_.reset();
            stats_.start_time = std::chrono::steady_clock::now();
            
            print_banner();
            
            if (opts_.icmp_ping) {
                perform_ping_sweep();
            }
            
            setup_signal_handler();
            
            std::cout << "\n[+] Starting scan of " << targets_.size() 
                      << " target(s) for " << ports_.size() << " ports" << std::endl;
            std::cout << "[+] Using " << pool_.pending_tasks() << " threads" << std::endl;
            
            if (opts_.rate_limit > 0) {
                std::cout << "[+] Rate limit: " << opts_.rate_limit << " packets/sec" << std::endl;
            }
            
            stats_.total_ports = targets_.size() * ports_.size();
            
            // Batch processing for better performance
            const size_t BATCH_SIZE = 250;
            std::vector<std::pair<std::string, int>> batch;
            std::vector<std::future<void>> futures;
            
            for (const auto& target : targets_) {
                for (int port : ports_) {
                    if (should_exclude_port(port)) continue;
                    
                    batch.emplace_back(target, port);
                    
                    if (batch.size() >= BATCH_SIZE) {
                        submit_batch(batch, futures);
                        batch.clear();
                    }
                }
            }
            
            if (!batch.empty()) {
                submit_batch(batch, futures);
            }
            
            // Wait for all tasks to complete
            for (auto& f : futures) {
                f.get();
            }
            
            stats_.end_time = std::chrono::steady_clock::now();
            
            print_statistics();
            save_results();
            
        } catch (const std::exception& e) {
            std::cerr << "\n[!] Scan error: " << e.what() << std::endl;
        }
    }
    
    void stop() {
        g_stop_signal = true;
    }

private:
    ScanOptions opts_;
    ThreadPool pool_;
    TokenBucket token_bucket_;
    ScanStatistics stats_;
    
    std::vector<std::string> targets_;
    std::vector<int> ports_;
    std::vector<ScanResult> results_;
    std::mutex results_mutex_;
    std::atomic<int> active_batches_{0};
    std::condition_variable batches_done_cv_;
    
    // Service signatures
    const std::map<int, std::string> service_signatures_ = {
        {20, "FTP-data"}, {21, "FTP"}, {22, "SSH"}, {23, "Telnet"},
        {25, "SMTP"}, {53, "DNS"}, {67, "DHCP"}, {68, "DHCP"},
        {69, "TFTP"}, {80, "HTTP"}, {110, "POP3"}, {111, "RPC"},
        {123, "NTP"}, {135, "MSRPC"}, {137, "NetBIOS"}, {138, "NetBIOS"},
        {139, "NetBIOS"}, {143, "IMAP"}, {161, "SNMP"}, {162, "SNMP"},
        {179, "BGP"}, {389, "LDAP"}, {443, "HTTPS"}, {445, "SMB"},
        {465, "SMTPS"}, {514, "Syslog"}, {515, "LPD"}, {587, "SMTP"},
        {631, "IPP"}, {636, "LDAPS"}, {873, "Rsync"}, {989, "FTP-data"},
        {990, "FTP"}, {993, "IMAPS"}, {995, "POP3S"}, {1080, "SOCKS"},
        {1194, "OpenVPN"}, {1433, "MSSQL"}, {1521, "Oracle"}, {1701, "L2TP"},
        {1723, "PPTP"}, {1812, "RADIUS"}, {1813, "RADIUS"}, {2049, "NFS"},
        {2082, "cPanel"}, {2083, "cPanel"}, {2086, "WHM"}, {2087, "WHM"},
        {2181, "ZooKeeper"}, {2375, "Docker"}, {2376, "Docker"}, {2483, "Oracle"},
        {2484, "Oracle"}, {3128, "Squid"}, {3260, "iSCSI"}, {3306, "MySQL"},
        {3389, "RDP"}, {3690, "SVN"}, {4333, "SQL"}, {4444, "Metasploit"},
        {4500, "IPsec"}, {4567, "Cassandra"}, {5000, "UPnP"}, {5001, "UPnP"},
        {5060, "SIP"}, {5061, "SIP"}, {5143, "Redis"}, {5222, "XMPP"},
        {5223, "XMPP"}, {5269, "XMPP"}, {5432, "PostgreSQL"}, {5555, "Android"},
        {5631, "pcAnywhere"}, {5632, "pcAnywhere"}, {5800, "VNC"}, {5900, "VNC"},
        {5901, "VNC"}, {5902, "VNC"}, {5984, "CouchDB"}, {6000, "X11"},
        {6001, "X11"}, {6379, "Redis"}, {6660, "IRC"}, {6661, "IRC"},
        {6662, "IRC"}, {6663, "IRC"}, {6664, "IRC"}, {6665, "IRC"},
        {6666, "IRC"}, {6667, "IRC"}, {6668, "IRC"}, {6669, "IRC"},
        {7000, "Cassandra"}, {7001, "Cassandra"}, {7199, "Cassandra"},
        {8000, "HTTP"}, {8008, "HTTP"}, {8009, "AJP"}, {8010, "HTTP"},
        {8042, "Hadoop"}, {8080, "HTTP-Alt"}, {8081, "HTTP"}, {8082, "HTTP"},
        {8086, "InfluxDB"}, {8087, "InfluxDB"}, {8088, "HTTP"}, {8090, "HTTP"},
        {8140, "Puppet"}, {8181, "HTTP"}, {8443, "HTTPS-Alt"}, {8500, "Consul"},
        {8600, "Consul"}, {8888, "HTTP"}, {8983, "Solr"}, {9000, "Hadoop"},
        {9042, "Cassandra"}, {9092, "Kafka"}, {9100, "HP JetDirect"},
        {9160, "Cassandra"}, {9200, "Elasticsearch"}, {9300, "Elasticsearch"},
        {9418, "Git"}, {9876, "Redis"}, {9999, "HTTP"}, {10000, "Webmin"},
        {11211, "Memcached"}, {11214, "Memcached"}, {11215, "Memcached"},
        {15672, "RabbitMQ"}, {15692, "RabbitMQ"}, {16010, "HBase"},
        {16379, "Redis"}, {16579, "Redis"}, {18080, "HTTP"}, {20000, "HTTP"},
        {25565, "Minecraft"}, {27017, "MongoDB"}, {27018, "MongoDB"},
        {27019, "MongoDB"}, {28017, "MongoDB"}, {30718, "Redis"},
        {34701, "Redis"}, {50000, "SAP"}, {50070, "Hadoop"}, {50075, "Hadoop"},
        {50090, "Hadoop"}, {60000, "Redis"}, {60010, "HBase"}, {61613, "Redis"},
        {61614, "Redis"}
    };
    
    // ========================================================================
    // Initialization
    // ========================================================================
    
    void initialize() {
        validate_targets();
        parse_port_ranges();
        expand_targets();
        
        if (opts_.randomize_ports) {
            shuffle_ports();
        }
        
        if (opts_.verbose) {
            std::cout << "[Debug] Initialized with " << targets_.size() 
                      << " targets and " << ports_.size() << " ports" << std::endl;
        }
    }
    
    void cleanup() {
        // Close any open sockets, free resources
    }
    
    void validate_targets() {
        if (opts_.targets.empty()) {
            throw std::runtime_error("No targets specified");
        }
    }
    
    void expand_targets() {
        for (const auto& target : opts_.targets) {
            if (target.find('/') != std::string::npos && opts_.cidr_support) {
                auto expanded = expand_cidr(target);
                targets_.insert(targets_.end(), expanded.begin(), expanded.end());
            } else {
                if (is_valid_ip(target)) {
                    targets_.push_back(target);
                } else {
                    std::cerr << "[!] Warning: Invalid IP address: " << target << std::endl;
                }
            }
        }
        
        if (targets_.empty()) {
            throw std::runtime_error("No valid targets found");
        }
    }
    
    std::vector<std::string> expand_cidr(const std::string& cidr) {
        std::vector<std::string> result;
        
        size_t slash_pos = cidr.find('/');
        if (slash_pos == std::string::npos) {
            result.push_back(cidr);
            return result;
        }
        
        std::string base_ip = cidr.substr(0, slash_pos);
        int prefix = std::stoi(cidr.substr(slash_pos + 1));
        
        if (prefix < 0 || prefix > 32) return result;
        
        struct in_addr addr;
        if (inet_pton(AF_INET, base_ip.c_str(), &addr) != 1) {
            return result;
        }
        
        uint32_t ip = ntohl(addr.s_addr);
        uint32_t mask = prefix == 0 ? 0 : ~((1 << (32 - prefix)) - 1);
        uint32_t network = ip & mask;
        uint32_t broadcast = network | ~mask;
        
        uint32_t host_min = network + 1;
        uint32_t host_max = broadcast - 1;
        
        for (uint32_t host = host_min; host <= host_max; ++host) {
            struct in_addr host_addr;
            host_addr.s_addr = htonl(host);
            result.push_back(inet_ntoa(host_addr));
        }
        
        return result;
    }
    
    bool is_valid_ip(const std::string& ip) {
        struct sockaddr_in sa;
        struct sockaddr_in6 sa6;
        
        return (inet_pton(AF_INET, ip.c_str(), &sa) == 1) ||
               (inet_pton(AF_INET6, ip.c_str(), &sa6) == 1);
    }
    
    void parse_port_ranges() {
        if (!opts_.ports.empty()) {
            ports_ = opts_.ports;
        } else {
            for (int port = opts_.start_port; port <= opts_.end_port; ++port) {
                if (port > 0 && port <= 65535) {
                    ports_.push_back(port);
                }
            }
        }
        
        // Remove duplicates
        std::sort(ports_.begin(), ports_.end());
        ports_.erase(std::unique(ports_.begin(), ports_.end()), ports_.end());
    }
    
    void shuffle_ports() {
        std::random_device rd;
        std::mt19937 g(rd());
        std::shuffle(ports_.begin(), ports_.end(), g);
    }
    
    bool should_exclude_port(int port) {
        return std::find(opts_.exclude_ports.begin(), opts_.exclude_ports.end(), port) 
               != opts_.exclude_ports.end();
    }
    
    void setup_signal_handler() {
        struct sigaction sa;
        sa.sa_handler = [](int) { 
            g_stop_signal = true; 
            std::cout << "\n[!] Received interrupt signal. Stopping gracefully..." << std::endl;
        };
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        sigaction(SIGINT, &sa, nullptr);
        sigaction(SIGTERM, &sa, nullptr);
    }
    
    // ========================================================================
    // Ping Sweep
    // ========================================================================
    
    void perform_ping_sweep() {
        std::cout << "\n[*] Performing ICMP ping sweep..." << std::endl;
        
        std::vector<std::string> alive_hosts;
        std::mutex alive_mutex;
        std::vector<std::future<void>> futures;
        
        for (const auto& target : targets_) {
            futures.push_back(pool_.enqueue([this, target, &alive_hosts, &alive_mutex]() {
                if (icmp_ping(target)) {
                    std::lock_guard<std::mutex> lock(alive_mutex);
                    alive_hosts.push_back(target);
                    
                    if (opts_.verbose) {
                        std::cout << "  [+] Host " << target << " is up" << std::endl;
                    }
                } else if (opts_.verbose) {
                    std::cout << "  [-] Host " << target << " is down" << std::endl;
                }
            }));
        }
        
        for (auto& f : futures) {
            f.get();
        }
        
        if (!alive_hosts.empty()) {
            targets_ = alive_hosts;
            std::cout << "[+] " << targets_.size() << " hosts are up" << std::endl;
        } else {
            std::cout << "[-] No hosts are up. Continuing scan anyway..." << std::endl;
        }
    }
    
    bool icmp_ping(const std::string& target) {
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock < 0) {
            if (opts_.verbose) {
                std::cerr << "    [!] Raw socket failed (need root): " << strerror(errno) << std::endl;
            }
            return true; // Assume host is up
        }
        
        // Set timeout
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        
        // Construct ICMP echo request
        char packet[64] = {0};
        struct icmphdr* icmp = (struct icmphdr*)packet;
        icmp->type = ICMP_ECHO;
        icmp->code = 0;
        icmp->un.echo.id = htons(getpid() & 0xFFFF);
        icmp->un.echo.sequence = htons(1);
        icmp->checksum = 0;
        icmp->checksum = icmp_checksum((unsigned short*)packet, sizeof(packet));
        
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        inet_pton(AF_INET, target.c_str(), &addr.sin_addr);
        
        // Send ping
        if (sendto(sock, packet, sizeof(packet), 0, 
                   (struct sockaddr*)&addr, sizeof(addr)) <= 0) {
            close(sock);
            return true;
        }
        
        // Receive reply
        char buffer[256];
        struct sockaddr_in reply_addr;
        socklen_t addr_len = sizeof(reply_addr);
        
        int bytes = recvfrom(sock, buffer, sizeof(buffer), 0, 
                             (struct sockaddr*)&reply_addr, &addr_len);
        
        close(sock);
        
        if (bytes > 0) {
            struct iphdr* ip = (struct iphdr*)buffer;
            struct icmphdr* icmp_reply = (struct icmphdr*)(buffer + (ip->ihl * 4));
            
            return (icmp_reply->type == ICMP_ECHOREPLY);
        }
        
        return false;
    }
    
    unsigned short icmp_checksum(unsigned short* buf, int len) {
        unsigned long sum = 0;
        
        while (len > 1) {
            sum += *buf++;
            len -= 2;
        }
        
        if (len == 1) {
            sum += *(unsigned char*)buf;
        }
        
        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);
        
        return (unsigned short)(~sum);
    }
    
    // ========================================================================
    // Source IP discovery
    // ========================================================================
    
    uint32_t discover_source_ip(const std::string& target) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) {
            return INADDR_ANY;
        }
        
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(53); // DNS port
        inet_pton(AF_INET, target.c_str(), &addr.sin_addr);
        
        // Connect to target (doesn't send any data)
        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(sock);
            return INADDR_ANY;
        }
        
        struct sockaddr_in local_addr;
        socklen_t local_len = sizeof(local_addr);
        
        if (getsockname(sock, (struct sockaddr*)&local_addr, &local_len) < 0) {
            close(sock);
            return INADDR_ANY;
        }
        
        close(sock);
        return local_addr.sin_addr.s_addr;
    }
    
    // ========================================================================
    // Batch processing
    // ========================================================================
    
    void submit_batch(const std::vector<std::pair<std::string, int>>& batch,
                      std::vector<std::future<void>>& futures) {
        
        // Apply rate limiting
        if (opts_.rate_limit > 0) {
            token_bucket_.consume(batch.size());
        }
        
        active_batches_++;
        
        futures.push_back(pool_.enqueue([this, batch]() {
            for (const auto& [target, port] : batch) {
                if (g_stop_signal) break;
                
                ScanResult result;
                
                try {
                    if (opts_.syn_scan) {
                        result = syn_scan_port(target, port);
                    } else if (opts_.udp_scan) {
                        result = udp_scan_port(target, port);
                    } else {
                        result = tcp_connect_scan(target, port);
                    }
                    
                    update_statistics(result);
                    
                    if (result.status == "open" || opts_.verbose) {
                        std::lock_guard<std::mutex> lock(results_mutex_);
                        results_.push_back(result);
                        
                        if (opts_.verbose || result.status == "open") {
                            print_result(result);
                        }
                    }
                    
                } catch (const std::exception& e) {
                    stats_.errors++;
                    if (opts_.verbose) {
                        std::cerr << "    [!] Error scanning " << target << ":" 
                                  << port << " - " << e.what() << std::endl;
                    }
                }
                
                stats_.scanned_ports++;
                
                if (opts_.verbose && stats_.scanned_ports % 100 == 0) {
                    print_progress();
                }
            }
            
            active_batches_--;
            batches_done_cv_.notify_one();
        }));
    }
    
    // ========================================================================
    // TCP Connect Scan
    // ========================================================================
    
    ScanResult tcp_connect_scan(const std::string& target, int port) {
        ScanResult result;
        result.target = target;
        result.port = port;
        result.protocol = "tcp";
        result.timestamp = std::chrono::system_clock::now();
        
        auto start = std::chrono::steady_clock::now();
        
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            stats_.errors++;
            return result;
        }
        
        // Set non-blocking
        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);
        
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, target.c_str(), &addr.sin_addr);
        
        connect(sock, (struct sockaddr*)&addr, sizeof(addr));
        
        struct pollfd pfd;
        pfd.fd = sock;
        pfd.events = POLLOUT;
        
        int poll_res = poll(&pfd, 1, opts_.timeout_ms);
        
        auto end = std::chrono::steady_clock::now();
        result.response_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        
        if (poll_res > 0 && (pfd.revents & POLLOUT)) {
            int so_error;
            socklen_t len = sizeof(so_error);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
            
            if (so_error == 0) {
                result.status = "open";
                result.ttl = get_ttl(sock);
                result.os_hint = detect_os(result.ttl);
                
                if (opts_.service_detection) {
                    result.service = detect_service(port);
                }
                
                if (opts_.banner_grab) {
                    result.banner = grab_banner(sock, port);
                    
                    if (opts_.vulnerability_check && !result.banner.empty()) {
                        check_vulnerabilities(result);
                    }
                }
                
                if (opts_.reverse_dns) {
                    result.hostname = reverse_dns(target);
                }
                
                if (opts_.geoip) {
                    // GeoIP lookup would go here
                }
                
                if (opts_.mac_lookup) {
                    // MAC lookup would go here
                }
            }
        } else if (poll_res == 0) {
            result.status = "timeout";
            stats_.timeouts++;
        } else {
            result.status = "filtered";
        }
        
        close(sock);
        return result;
    }
    
    // ========================================================================
    // SYN Scan (Stealth)
    // ========================================================================
    
    ScanResult syn_scan_port(const std::string& target, int port) {
        ScanResult result;
        result.target = target;
        result.port = port;
        result.protocol = "tcp";
        result.status = "filtered";
        result.timestamp = std::chrono::system_clock::now();
        
        // Send socket
        int send_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (send_sock < 0) {
            stats_.errors++;
            return tcp_connect_scan(target, port); // Fallback
        }
        
        // Receive socket
        int recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (recv_sock < 0) {
            close(send_sock);
            stats_.errors++;
            return tcp_connect_scan(target, port);
        }
        
        int one = 1;
        setsockopt(send_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
        
        // Discover source IP
        uint32_t src_ip = discover_source_ip(target);
        if (src_ip == INADDR_ANY) {
            close(send_sock);
            close(recv_sock);
            return tcp_connect_scan(target, port);
        }
        
        // Send SYN packet
        auto start = std::chrono::steady_clock::now();
        send_syn_packet(send_sock, src_ip, target, port);
        
        // Set receive timeout
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = opts_.timeout_ms * 1000;
        setsockopt(recv_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        
        // Receive response
        char buffer[256];
        struct sockaddr_in reply_addr;
        socklen_t addr_len = sizeof(reply_addr);
        
        int bytes = recvfrom(recv_sock, buffer, sizeof(buffer), 0,
                             (struct sockaddr*)&reply_addr, &addr_len);
        
        auto end = std::chrono::steady_clock::now();
        result.response_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        
        if (bytes > 0) {
            struct iphdr* ip = (struct iphdr*)buffer;
            struct tcphdr* tcp = (struct tcphdr*)(buffer + (ip->ihl * 4));
            
            if (tcp->syn && tcp->ack) {
                result.status = "open";
                result.ttl = ip->ttl;
                result.os_hint = detect_os(result.ttl);
                
                // Send RST to close connection
                send_rst_packet(send_sock, src_ip, target, port, tcp);
                
                if (opts_.service_detection) {
                    result.service = detect_service(port);
                }
                
                if (opts_.reverse_dns) {
                    result.hostname = reverse_dns(target);
                }
                
            } else if (tcp->rst) {
                result.status = "closed";
            }
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            result.status = "filtered";
            stats_.timeouts++;
        }
        
        close(send_sock);
        close(recv_sock);
        return result;
    }
    
    void send_syn_packet(int sock, uint32_t src_ip, const std::string& dst_ip, int dst_port) {
        char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)] = {0};
        
        struct iphdr* ip = (struct iphdr*)packet;
        struct tcphdr* tcp = (struct tcphdr*)(packet + sizeof(struct iphdr));
        
        // IP header
        ip->ihl = 5;
        ip->version = 4;
        ip->tos = 0;
        ip->tot_len = htons(sizeof(packet));
        ip->id = htons(rand() & 0xFFFF);
        ip->frag_off = 0;
        ip->ttl = 64;
        ip->protocol = IPPROTO_TCP;
        ip->check = 0;
        ip->saddr = src_ip;
        inet_pton(AF_INET, dst_ip.c_str(), &ip->daddr);
        
        // TCP header
        tcp->source = htons(12345 + (rand() % 10000));
        tcp->dest = htons(dst_port);
        tcp->seq = htonl(rand());
        tcp->ack_seq = 0;
        tcp->doff = 5;
        tcp->syn = 1;
        tcp->window = htons(5840);
        tcp->check = 0;
        tcp->urg_ptr = 0;
        
        // TCP checksum
        tcp->check = tcp_checksum(ip, tcp);
        
        // IP checksum
        ip->check = ip_checksum((unsigned short*)ip, sizeof(struct iphdr));
        
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        inet_pton(AF_INET, dst_ip.c_str(), &addr.sin_addr);
        
        sendto(sock, packet, sizeof(packet), 0, (struct sockaddr*)&addr, sizeof(addr));
    }
    
    void send_rst_packet(int sock, uint32_t src_ip, const std::string& dst_ip, 
                         int dst_port, struct tcphdr* received_tcp) {
        char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)] = {0};
        
        struct iphdr* ip = (struct iphdr*)packet;
        struct tcphdr* tcp = (struct tcphdr*)(packet + sizeof(struct iphdr));
        
        // IP header
        ip->ihl = 5;
        ip->version = 4;
        ip->tos = 0;
        ip->tot_len = htons(sizeof(packet));
        ip->id = htons(rand() & 0xFFFF);
        ip->frag_off = 0;
        ip->ttl = 64;
        ip->protocol = IPPROTO_TCP;
        ip->check = 0;
        ip->saddr = src_ip;
        inet_pton(AF_INET, dst_ip.c_str(), &ip->daddr);
        
        // TCP header with RST
        tcp->source = received_tcp->dest;
        tcp->dest = received_tcp->source;
        tcp->seq = received_tcp->ack_seq;
        tcp->ack_seq = 0;
        tcp->doff = 5;
        tcp->rst = 1;
        tcp->window = htons(5840);
        
        // Calculate checksums
        tcp->check = tcp_checksum(ip, tcp);
        ip->check = ip_checksum((unsigned short*)ip, sizeof(struct iphdr));
        
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        inet_pton(AF_INET, dst_ip.c_str(), &addr.sin_addr);
        
        sendto(sock, packet, sizeof(packet), 0, (struct sockaddr*)&addr, sizeof(addr));
    }
    
    // ========================================================================
    // UDP Scan
    // ========================================================================
    
    ScanResult udp_scan_port(const std::string& target, int port) {
        ScanResult result;
        result.target = target;
        result.port = port;
        result.protocol = "udp";
        result.status = "open|filtered";
        result.timestamp = std::chrono::system_clock::now();
        
        auto start = std::chrono::steady_clock::now();
        
        // UDP socket
        int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (udp_sock < 0) {
            stats_.errors++;
            return result;
        }
        
        // ICMP socket for unreachable messages
        int icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (icmp_sock < 0) {
            close(udp_sock);
            stats_.errors++;
            return result;
        }
        
        // Set non-blocking
        fcntl(udp_sock, F_SETFL, O_NONBLOCK);
        fcntl(icmp_sock, F_SETFL, O_NONBLOCK);
        
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, target.c_str(), &addr.sin_addr);
        
        // Send empty UDP packet
        sendto(udp_sock, NULL, 0, 0, (struct sockaddr*)&addr, sizeof(addr));
        
        // Poll for response
        struct pollfd pfds[2];
        pfds[0].fd = icmp_sock;
        pfds[0].events = POLLIN;
        pfds[1].fd = udp_sock;
        pfds[1].events = POLLIN;
        
        int poll_res = poll(pfds, 2, opts_.timeout_ms);
        
        auto end = std::chrono::steady_clock::now();
        result.response_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        
        if (poll_res > 0) {
            if (pfds[0].revents & POLLIN) {
                // ICMP response
                char buffer[256];
                struct sockaddr_in reply_addr;
                socklen_t addr_len = sizeof(reply_addr);
                
                int bytes = recvfrom(icmp_sock, buffer, sizeof(buffer), 0,
                                     (struct sockaddr*)&reply_addr, &addr_len);
                
                if (bytes > 0) {
                    struct iphdr* ip = (struct iphdr*)buffer;
                    struct icmphdr* icmp = (struct icmphdr*)(buffer + (ip->ihl * 4));
                    
                    // Port unreachable
                    if (icmp->type == 3 && icmp->code == 3) {
                        result.status = "closed";
                        stats_.closed_ports++;
                    }
                }
            }
            
            if (pfds[1].revents & POLLIN) {
                // UDP response received
                result.status = "open";
                
                if (opts_.service_detection) {
                    result.service = detect_service(port);
                }
                
                if (opts_.banner_grab) {
                    char buffer[1024];
                    int bytes = recv(udp_sock, buffer, sizeof(buffer) - 1, 0);
                    if (bytes > 0) {
                        buffer[bytes] = '\0';
                        result.banner = buffer;
                    }
                }
            }
        } else if (poll_res == 0) {
            stats_.timeouts++;
        }
        
        close(udp_sock);
        close(icmp_sock);
        return result;
    }
    
    // ========================================================================
    // Checksum calculations
    // ========================================================================
    
    unsigned short ip_checksum(unsigned short* buf, int len) {
        unsigned long sum = 0;
        
        while (len > 1) {
            sum += *buf++;
            len -= 2;
        }
        
        if (len == 1) {
            sum += *(unsigned char*)buf;
        }
        
        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);
        
        return (unsigned short)(~sum);
    }
    
    unsigned short tcp_checksum(struct iphdr* ip, struct tcphdr* tcp) {
        PseudoHeader psh;
        psh.src_addr = ip->saddr;
        psh.dst_addr = ip->daddr;
        psh.zero = 0;
        psh.protocol = IPPROTO_TCP;
        psh.tcp_len = htons(sizeof(struct tcphdr));
        
        char pseudo_packet[sizeof(PseudoHeader) + sizeof(struct tcphdr)] = {0};
        memcpy(pseudo_packet, &psh, sizeof(PseudoHeader));
        memcpy(pseudo_packet + sizeof(PseudoHeader), tcp, sizeof(struct tcphdr));
        
        return ip_checksum((unsigned short*)pseudo_packet, sizeof(pseudo_packet));
    }
    
    // ========================================================================
    // Helper functions
    // ========================================================================
    
    int get_ttl(int sock) {
        struct sockaddr_in peer;
        socklen_t peer_len = sizeof(peer);
        if (getpeername(sock, (struct sockaddr*)&peer, &peer_len) == 0) {
            // Can't get TTL directly from socket, would need raw socket
            return 64; // Default guess
        }
        return 64;
    }
    
    std::string detect_os(int ttl) {
        if (ttl <= 64) return "Linux/Unix";
        if (ttl <= 128) return "Windows";
        if (ttl <= 255) return "Network Device";
        return "Unknown";
    }
    
    std::string detect_service(int port) {
        auto it = service_signatures_.find(port);
        if (it != service_signatures_.end()) {
            return it->second;
        }
        return "unknown";
    }
    
   std::string grab_banner(int sock, int port) {
    // [DJ] Banner süresini TCP timeout ile aynı yapalım
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);
    
    char buffer[4096] = {0};
    
    // Port'a özel probe
    std::string probe;
    if (port == 80 || port == 8080 || port == 8000) {
        probe = "HEAD / HTTP/1.0\r\n\r\n";
    } else if (port == 21) {
        // FTP - just wait
    } else if (port == 25) {
        probe = "EHLO localhost\r\n";
    } else if (port == 110) {
        probe = "USER test\r\n";
    } else if (port == 443) {
        return "";  // HTTPS ayrı
    } else if (port == 22) {
        // SSH banner
    } else {
        probe = "\r\n";
    }
    
    if (!probe.empty()) {
        send(sock, probe.c_str(), probe.length(), 0);
    }
    
    // Change the wait second
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = opts_.timeout_ms * 1000;  // Ana timeout'u kullan!
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    int bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
    if (bytes > 0) {
        buffer[bytes] = '\0';
        return clean_banner(buffer);
    }
    
    return "";
}
    
    std::string clean_banner(const std::string& banner) {
        std::string result;
        for (char c : banner) {
            if (std::isprint(static_cast<unsigned char>(c)) || c == '\n' || c == '\r') {
                result += c;
            } else {
                result += '.';
            }
        }
        return result;
    }
    
    std::string reverse_dns(const std::string& ip) {
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);
        
        char host[NI_MAXHOST];
        if (getnameinfo((struct sockaddr*)&addr, sizeof(addr), 
                        host, sizeof(host), NULL, 0, NI_NAMEREQD) == 0) {
            return host;
        }
        
        return "";
    }

// [DJ] Bu hissəni tələsik yazmışam, sonra düzəldəcəm
// TODO: Real CVE database əlavə et
// FIXME: Sadəcə nümunə üçündür
    
    void check_vulnerabilities(ScanResult& result) {
        // Simple version-based vulnerability checks
        if (result.service == "SSH" && !result.banner.empty()) {
            if (result.banner.find("OpenSSH_7.2") != std::string::npos) {
                result.banner += " [VULNERABLE: CVE-2016-6210]";
            }
        }
        
        if (result.service == "HTTP" && !result.banner.empty()) {
            if (result.banner.find("Apache/2.4.49") != std::string::npos) {
                result.banner += " [VULNERABLE: CVE-2021-41773]";
            }
        }
    }
    
    // ========================================================================
    // Statistics and output
    // ========================================================================
    
    void update_statistics(const ScanResult& result) {
        if (result.status == "open") stats_.open_ports++;
        else if (result.status == "closed") stats_.closed_ports++;
        else if (result.status == "filtered") stats_.filtered_ports++;
        else if (result.status == "timeout") stats_.timeouts++;
    }
    
    void print_banner() {
        std::cout << "\n";
        std::cout << "  ╔════════════════════════════════════════════════╗\n";
        std::cout << "  ║              S E N T I N E L                   ║\n";
        std::cout << "  ║        Advanced Port Scanner v1.0              ║\n";
        std::cout << "  ║     Production-Ready Network Security Tool     ║\n";
        std::cout << "  ╚════════════════════════════════════════════════╝\n";
        std::cout << "\n";
    }
    
    void print_progress() {
        static int last_percent = -1;
        int percent = static_cast<int>(stats_.progress());
        
        if (percent != last_percent && percent % 5 == 0) {
            std::cout << "\r[*] Progress: " << std::setw(3) << percent << "% "
                      << "[" << std::string(percent / 2, '=') 
                      << std::string(50 - percent / 2, ' ') << "] "
                      << stats_.scanned_ports << "/" << stats_.total_ports
                      << " ports (" << std::fixed << std::setprecision(1) 
                      << stats_.packets_per_second() << " pps)" << std::flush;
            last_percent = percent;
        }
    }
    
    void print_result(const ScanResult& result) {
        std::lock_guard<std::mutex> lock(results_mutex_);
        
        std::cout << "\n[+] " << std::left << std::setw(15) << result.target
                  << ":" << std::right << std::setw(5) << result.port << "/" 
                  << result.protocol << "  " << std::setw(10) << result.status;
        
        if (!result.service.empty()) {
            std::cout << "  " << result.service;
        }
        
        if (result.response_time_ms > 0) {
            std::cout << "  [" << result.response_time_ms << "ms]";
        }
        
        if (!result.hostname.empty()) {
            std::cout << "  (" << result.hostname << ")";
        }
        
        if (!result.banner.empty()) {
            std::cout << "\n      Banner: " << result.banner.substr(0, 100);
            if (result.banner.length() > 100) std::cout << "...";
        }
        
        std::cout << std::endl;
    }
    
    void print_statistics() {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            stats_.end_time - stats_.start_time);
        
        std::cout << "\n\n";
        std::cout << "╔════════════════════════════════════════════════════════╗\n";
        std::cout << "║                    SCAN STATISTICS                     ║\n";
        std::cout << "╠════════════════════════════════════════════════════════╣\n";
        std::cout << "║  Total ports scanned: " << std::setw(35) << std::left 
                  << stats_.total_ports.load() << "║\n";
        std::cout << "║  Open ports:           " << std::setw(35) 
                  << stats_.open_ports.load() << "║\n";
        std::cout << "║  Closed ports:         " << std::setw(35) 
                  << stats_.closed_ports.load() << "║\n";
        std::cout << "║  Filtered ports:       " << std::setw(35) 
                  << stats_.filtered_ports.load() << "║\n";
        std::cout << "║  Timeouts:             " << std::setw(35) 
                  << stats_.timeouts.load() << "║\n";
        std::cout << "║  Errors:               " << std::setw(35) 
                  << stats_.errors.load() << "║\n";
        std::cout << "║  Scan duration:        " << std::setw(35) 
                  << std::to_string(elapsed.count()) + " seconds" << "║\n";
        std::cout << "║  Packets/sec:          " << std::setw(35) 
                  << std::fixed << std::setprecision(1) 
                  << stats_.packets_per_second() << "║\n";
        std::cout << "╚════════════════════════════════════════════════════════╝\n";
    }
    
    void save_results() {
        if (opts_.output_file.empty()) return;
        
        std::ofstream file(opts_.output_file);
        if (!file.is_open()) {
            std::cerr << "\n[!] Cannot open output file: " << opts_.output_file << std::endl;
            return;
        }
        
        if (opts_.output_format == "json" || opts_.json_output) {
            save_json(file);
        } else if (opts_.output_format == "csv" || opts_.csv_output) {
            save_csv(file);
        } else {
            save_text(file);
        }
        
        std::cout << "\n[+] Results saved to: " << opts_.output_file << std::endl;
    }
    
    void save_json(std::ofstream& file) {
        file << "{\n";
        file << "  \"scan_timestamp\": \"" << current_time() << "\",\n";
        file << "  \"statistics\": {\n";
        file << "    \"total_ports\": " << stats_.total_ports << ",\n";
        file << "    \"open_ports\": " << stats_.open_ports << ",\n";
        file << "    \"closed_ports\": " << stats_.closed_ports << ",\n";
        file << "    \"filtered_ports\": " << stats_.filtered_ports << ",\n";
        file << "    \"timeouts\": " << stats_.timeouts << "\n";
        file << "  },\n";
        file << "  \"results\": [\n";
        
        for (size_t i = 0; i < results_.size(); ++i) {
            const auto& r = results_[i];
            file << "    {\n";
            file << "      \"target\": \"" << json_escape(r.target) << "\",\n";
            file << "      \"port\": " << r.port << ",\n";
            file << "      \"protocol\": \"" << r.protocol << "\",\n";
            file << "      \"status\": \"" << r.status << "\",\n";
            file << "      \"service\": \"" << json_escape(r.service) << "\",\n";
            file << "      \"banner\": \"" << json_escape(r.banner) << "\",\n";
            file << "      \"hostname\": \"" << json_escape(r.hostname) << "\",\n";
            file << "      \"response_time_ms\": " << r.response_time_ms << ",\n";
            file << "      \"os_hint\": \"" << r.os_hint << "\"\n";
            file << "    }";
            if (i < results_.size() - 1) file << ",";
            file << "\n";
        }
        
        file << "  ]\n}\n";
    }
    
    void save_csv(std::ofstream& file) {
        file << "timestamp,target,port,protocol,status,service,banner,hostname,response_time_ms,os_hint\n";
        
        for (const auto& r : results_) {
            file << current_time() << ","
                 << r.target << ","
                 << r.port << ","
                 << r.protocol << ","
                 << r.status << ","
                 << "\"" << csv_escape(r.service) << "\","
                 << "\"" << csv_escape(r.banner) << "\","
                 << "\"" << r.hostname << "\","
                 << r.response_time_ms << ","
                 << "\"" << r.os_hint << "\"\n";
        }
    }
    
    void save_text(std::ofstream& file) {
        file << "Sentinel Scan Results - " << current_time() << "\n";
        file << "========================================\n\n";
        
        for (const auto& r : results_) {
            if (r.status == "open") {
                file << "PORT " << r.port << "/" << r.protocol 
                     << " - " << r.status << " - " << r.service << "\n";
                if (!r.banner.empty()) {
                    file << "  Banner: " << r.banner << "\n";
                }
                if (!r.hostname.empty()) {
                    file << "  Hostname: " << r.hostname << "\n";
                }
                file << "\n";
            }
        }
    }
    
    std::string current_time() {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }
    
    std::string json_escape(const std::string& s) {
        std::string result;
        for (char c : s) {
            switch (c) {
                case '"': result += "\\\""; break;
                case '\\': result += "\\\\"; break;
                case '\b': result += "\\b"; break;
                case '\f': result += "\\f"; break;
                case '\n': result += "\\n"; break;
                case '\r': result += "\\r"; break;
                case '\t': result += "\\t"; break;
                default:
                    if (static_cast<unsigned char>(c) < 0x20) {
                        char buf[8];
                        snprintf(buf, sizeof(buf), "\\u%04x", c);
                        result += buf;
                    } else {
                        result += c;
                    }
            }
        }
        return result;
    }
    
    std::string csv_escape(const std::string& s) {
        std::string result;
        for (char c : s) {
            if (c == '"') {
                result += "\"\"";
            } else {
                result += c;
            }
        }
        return result;
    }
};

// ============================================================================
// Command Line Argument Parser
// ============================================================================

class ArgumentParser {
public:
    static ScanOptions parse(int argc, char* argv[]) {
        ScanOptions opts;
        
        if (argc < 2) {
            print_help();
            exit(1);
        }
        
        opts.num_threads = std::thread::hardware_concurrency() * 2;
        
        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            
            if (arg == "--help" || arg == "-h") {
                print_help();
                exit(0);
            }
            else if (arg == "--target" || arg == "-t") {
                if (++i < argc) parse_targets(argv[i], opts);
            }
            else if (arg == "--ports" || arg == "-p") {
                if (++i < argc) parse_ports(argv[i], opts);
            }
            else if (arg == "--threads") {
                if (++i < argc) opts.num_threads = std::stoi(argv[i]);
            }
            else if (arg == "--timeout") {
                if (++i < argc) opts.timeout_ms = std::stoi(argv[i]);
            }
            else if (arg == "--output" || arg == "-o") {
                if (++i < argc) opts.output_file = argv[i];
            }
            else if (arg == "--format" || arg == "-f") {
                if (++i < argc) {
                    opts.output_format = argv[i];
                    if (opts.output_format == "json") opts.json_output = true;
                    if (opts.output_format == "csv") opts.csv_output = true;
                }
            }
            else if (arg == "--verbose" || arg == "-v") {
                opts.verbose = true;
            }
            else if (arg == "--udp") {
                opts.udp_scan = true;
            }
            else if (arg == "--syn") {
                opts.syn_scan = true;
            }
            else if (arg == "--no-service") {
                opts.service_detection = false;
            }
            else if (arg == "--banner") {
                opts.banner_grab = true;
            }
            else if (arg == "--dns") {
                opts.reverse_dns = true;
            }
            else if (arg == "--no-ping") {
                opts.icmp_ping = false;
            }
            else if (arg == "--randomize") {
                opts.randomize_ports = true;
            }
            else if (arg == "--rate") {
                if (++i < argc) opts.rate_limit = std::stoi(argv[i]);
            }
            else if (arg == "--exclude") {
                if (++i < argc) parse_ports(argv[i], opts, true);
            }
            else if (arg == "--os-detect") {
                opts.os_detection = true;
            }
            else if (arg == "--cidr") {
                opts.cidr_support = true;
            }
            else if (arg == "--continuous") {
                opts.continuous_mode = true;
                if (++i < argc) opts.scan_interval_sec = std::stoi(argv[i]);
            }
            else if (arg == "--vuln") {
                opts.vulnerability_check = true;
            }
            else if (arg == "--geoip") {
                opts.geoip = true;
            }
        }
        
        if (opts.targets.empty()) {
            std::cerr << "Error: No targets specified\n";
            print_help();
            exit(1);
        }
        
        return opts;
    }

private:
    static void print_help() {
        std::cout << R"(
╔════════════════════════════════════════════════════════════════╗
║                    SENTINEL - Help Menu                       ║
║              Advanced Port Scanner v1.0                ║
╚════════════════════════════════════════════════════════════════╝

USAGE:
  sentinel [options]

REQUIRED OPTIONS:
  -t, --target <ip>         Target IP address(es) (comma-separated or file)
  -p, --ports <range>       Port range (e.g., 1-1000,80,443,8080-8090)

SCAN TYPES:
  --syn                     SYN stealth scan (requires root)
  --udp                     UDP scan (requires root)
  (default: TCP connect scan)

PERFORMANCE:
  --threads <num>           Number of threads (default: CPU cores * 2)
  --timeout <ms>            Timeout in milliseconds (default: 200)
  --rate <num>              Rate limit (packets per second)
  --randomize               Randomize port scan order

OUTPUT:
  -o, --output <file>       Output file
  -f, --format <format>     Output format: text, json, csv
  -v, --verbose             Verbose output

DISCOVERY:
  --no-ping                  Skip ICMP ping discovery
  --banner                   Grab service banners
  --dns                      Reverse DNS lookup
  --os-detect                OS fingerprinting
  --service                  Service detection (default: on)

ADVANCED:
  --exclude <range>         Ports to exclude
  --cidr                     Enable CIDR notation support
  --continuous [seconds]    Continuous scanning mode
  --vuln                     Check for known vulnerabilities
  --geoip                    GeoIP lookup

MISC:
  -h, --help                 Show this help

EXAMPLES:
  # Basic TCP scan
  sentinel -t 192.168.1.1 -p 1-1000

  # SYN stealth scan with banner grabbing
  sudo sentinel -t 10.0.0.1 -p 22,80,443 --syn --banner --dns

  # Multiple targets with CIDR
  sentinel -t 192.168.1.0/24 -p 1-1024 --cidr

  # High-performance scan
  sentinel -t targets.txt -p 1-65535 --threads 100 --rate 1000

  # Vulnerability scan with JSON output
  sentinel -t 192.168.1.1 -p 1-1000 --vuln --banner -o scan.json -f json

  # Continuous monitoring
  sentinel -t 192.168.1.1 -p 22,80,443 --continuous 60

)";
    }
    
    static void parse_targets(const std::string& input, ScanOptions& opts) {
        std::ifstream file(input);
        if (file.good()) {
            std::string line;
            while (std::getline(file, line)) {
                line = trim(line);
                if (!line.empty() && line[0] != '#') {
                    opts.targets.push_back(line);
                }
            }
        } else {
            std::stringstream ss(input);
            std::string item;
            while (std::getline(ss, item, ',')) {
                item = trim(item);
                if (!item.empty()) {
                    opts.targets.push_back(item);
                }
            }
        }
    }
    
    static void parse_ports(const std::string& input, ScanOptions& opts, bool exclude = false) {
        std::stringstream ss(input);
        std::string token;
        
        while (std::getline(ss, token, ',')) {
            token = trim(token);
            size_t dash_pos = token.find('-');
            
            if (dash_pos != std::string::npos) {
                int start = std::stoi(token.substr(0, dash_pos));
                int end = std::stoi(token.substr(dash_pos + 1));
                
                if (start > end) std::swap(start, end);
                
                for (int port = start; port <= end; ++port) {
                    if (port > 0 && port <= 65535) {
                        if (exclude) opts.exclude_ports.push_back(port);
                        else opts.ports.push_back(port);
                    }
                }
            } else {
                int port = std::stoi(token);
                if (port > 0 && port <= 65535) {
                    if (exclude) opts.exclude_ports.push_back(port);
                    else opts.ports.push_back(port);
                }
            }
        }
    }
    
    static std::string trim(const std::string& s) {
        size_t start = s.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) return "";
        size_t end = s.find_last_not_of(" \t\r\n");
        return s.substr(start, end - start + 1);
    }
};

// ============================================================================
// Main function
// ============================================================================

int main(int argc, char* argv[]) {
    try {
        auto options = ArgumentParser::parse(argc, argv);
        
        // Check for root requirements
        if ((options.syn_scan || options.udp_scan) && geteuid() != 0) {
            std::cerr << "\n[!] Warning: SYN/UDP scans require root privileges.\n";
            std::cerr << "    Falling back to TCP connect scan.\n";
            options.syn_scan = false;
            options.udp_scan = false;
        }
        
        // Increase file descriptor limit
        struct rlimit rl;
        if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
            rl.rlim_cur = std::min(static_cast<rlim_t>(65535), rl.rlim_max);
            setrlimit(RLIMIT_NOFILE, &rl);
        }
        
        // Continuous mode
        if (options.continuous_mode) {
            int scan_count = 1;
            while (!g_stop_signal) {
                std::cout << "\n[ Scan #" << scan_count++ << " starting... ]\n";
                
                Sentinel scanner(options);
                scanner.scan();
                
                if (g_stop_signal) break;
                
                std::cout << "\n[*] Waiting " << options.scan_interval_sec 
                          << " seconds before next scan...\n";
                std::this_thread::sleep_for(std::chrono::seconds(options.scan_interval_sec));
            }
        } else {
            Sentinel scanner(options);
            scanner.scan();
        }
        
    } catch (const std::exception& e) {
        std::cerr << "\n[!] Fatal error: " << e.what() << std::endl;
        return 1;
    }
    
    std::cout << "\n[*] Sentinel scan completed.\n";
    return 0;
}
