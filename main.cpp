#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <unordered_set>
#include <random>
#include <chrono>
#include <queue>
#include <array>
#include <memory>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <unordered_map>
#include <exception>
#include <algorithm>
#include <mutex>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
using socket_t = SOCKET;
#define CLOSE_SOCKET closesocket
#define poll WSAPoll
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
using socket_t = int;
#define CLOSE_SOCKET close
#define INVALID_SOCKET -1
#endif

class BencodeBuilder {
public:
    std::string dict_start() { return "d"; }
    std::string dict_end() { return "e"; }
    std::string list_start() { return "l"; }
    std::string list_end() { return "e"; }

    std::string encode_string(const std::string &str) {
        return std::to_string(str.length()) + ":" + str;
    }

    std::string encode_int(int64_t val) {
        return "i" + std::to_string(val) + "e";
    }
};

class DHTNode {
public:
    std::string node_id;
    std::string ip;
    uint16_t port;

    DHTNode() : node_id(), ip(), port(0) {
    }

    DHTNode(const std::string &id, const std::string &ip_addr, uint16_t p)
        : node_id(id), ip(ip_addr), port(p) {
    }
};

struct PendingGetPeers {
    std::string info_hash;
    std::string target_ip;
    uint16_t target_port;
};

struct Subspace {
    std::queue<std::pair<int, std::string> > zone_queue; // bit_len, prefix
    std::queue<DHTNode> node_queue;
    std::mutex mux;
};

class DHTScraper {
private:
    socket_t sock_v4{INVALID_SOCKET};
    socket_t sock_v6{INVALID_SOCKET};
    std::string primary_node_id;
    std::vector<std::string> my_node_ids;
    std::atomic<uint64_t> hashes_scraped{0};
    std::atomic<uint64_t> packets_sent{0};
    std::atomic<uint64_t> packets_received{0};
    std::atomic<uint64_t> send_failures{0};
    std::atomic<bool> running{true};

    std::unordered_set<std::string> discovered_hashes;
    std::unordered_set<std::string> contacted_nodes;

    std::vector<DHTNode> known_nodes;
    std::unordered_set<std::string> known_ids;
    std::unordered_map<std::string, PendingGetPeers> pending_get_peers;

    BencodeBuilder bencode;

    static constexpr size_t BUFFER_SIZE = 65536;
    static constexpr int SEND_BUFFER_SIZE = 4 * 1024 * 1024;
    static constexpr int RECV_BUFFER_SIZE = 4 * 1024 * 1024;

    const int num_subspaces;
    const int sends_per_cycle;
    const int samples_per_node;
    const int finds_per_node;
    const int getpeers_per_node;
    const int delay_ns;
    const int max_depth;
    const int top_bits;

    std::vector<Subspace> subspaces;

    std::mutex send_mutex;
    std::mutex known_mutex;
    std::mutex pending_mutex;
    std::mutex discovered_mutex;
    std::mutex contacted_mutex;

    void precise_delay_ns(long long ns) {
        auto start = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::nanoseconds(ns);
        while (std::chrono::high_resolution_clock::now() - start < duration) {
            // busy wait
        }
    }

    int get_subspace(const std::string &id) {
        if (id.empty()) return 0;
        uint8_t first_byte = static_cast<uint8_t>(id[0]);
        return (first_byte >> (8 - top_bits)) & ((1 << top_bits) - 1);
    }

    std::string get_sender_id() {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        std::uniform_int_distribution<size_t> dis(0, my_node_ids.size() - 1);
        return my_node_ids[dis(gen)];
    }

    std::string generate_random_id(size_t length = 20) {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        static std::uniform_int_distribution<uint8_t> dis(0, 255);

        std::string id(length, 0);
        for (size_t i = 0; i < length; ++i) {
            id[i] = static_cast<char>(dis(gen));
        }
        return id;
    }

    void add_bit(bool bit, std::string &prefix, int &bit_len) {
        int byte_idx = bit_len / 8;
        int bit_pos = 7 - (bit_len % 8);
        uint8_t bit_val = bit ? (1u << bit_pos) : 0u;
        bit_len++;
        if (byte_idx < static_cast<int>(prefix.size())) {
            prefix[byte_idx] = static_cast<char>(static_cast<uint8_t>(prefix[byte_idx]) | bit_val);
        } else {
            prefix += static_cast<char>(bit_val);
        }
    }

    std::string generate_with_prefix(int bit_len, const std::string &prefix) {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        static std::uniform_int_distribution<uint8_t> dis(0, 255);

        std::string target = prefix;
        int prefix_bytes = (bit_len + 7) / 8;
        int extra_bits = bit_len % 8;
        if (extra_bits > 0) {
            uint8_t mask = (1u << (8 - extra_bits)) - 1;
            uint8_t current_last = static_cast<uint8_t>(target.back());
            uint8_t random_low = dis(gen) & mask;
            target.back() = static_cast<char>((current_last & ~mask) | random_low);
        }
        int remaining = 20 - prefix_bytes;
        for (int i = 0; i < remaining; ++i) {
            target += static_cast<char>(dis(gen));
        }
        return target;
    }

    std::string generate_target(int subspace_idx) {
        auto &sub = subspaces[subspace_idx];
        std::lock_guard<std::mutex> lock(sub.mux);
        if (sub.zone_queue.empty()) {
            return generate_random_id(20);
        }
        auto [bit_len, prefix] = sub.zone_queue.front();
        sub.zone_queue.pop();
        std::string target = generate_with_prefix(bit_len, prefix);
        if (bit_len < max_depth) {
            std::string p0 = prefix;
            int b0 = bit_len;
            add_bit(false, p0, b0);
            sub.zone_queue.push({b0, p0});
            std::string p1 = prefix;
            int b1 = bit_len;
            add_bit(true, p1, b1);
            sub.zone_queue.push({b1, p1});
        }
        return target;
    }

    std::string flip_bit(const std::string &id, int bit_index) {
        if (id.size() != 20 || bit_index < 0 || bit_index >= 160) {
            return generate_random_id(20);
        }
        std::string new_id = id;
        int byte_idx = bit_index / 8;
        int bit_pos = 7 - (bit_index % 8);
        uint8_t &byte = reinterpret_cast<uint8_t &>(new_id[byte_idx]);
        byte ^= (1u << bit_pos);
        return new_id;
    }

    std::string xor_distance(const std::string &a, const std::string &b) {
        if (a.size() != 20 || b.size() != 20) return "";
        std::string res(20, 0);
        for (size_t i = 0; i < 20; ++i) {
            res[i] = a[i] ^ b[i];
        }
        return res;
    }

    std::vector<DHTNode> get_closest(const std::string &target, int k, bool want_v6 = false) {
        std::vector<DHTNode> candidates;
        bool is_v6 = want_v6;
        {
            std::lock_guard<std::mutex> lock(known_mutex);
            for (const auto &n: known_nodes) {
                if ((n.ip.find(':') != std::string::npos) == is_v6) {
                    candidates.push_back(n);
                }
            }
        }
        auto cmp = [&target, this](const DHTNode &a, const DHTNode &b) {
            return xor_distance(a.node_id, target) < xor_distance(b.node_id, target);
        };
        if (candidates.size() > static_cast<size_t>(k)) {
            std::partial_sort(candidates.begin(), candidates.begin() + k, candidates.end(), cmp);
            candidates.resize(k);
        } else {
            std::sort(candidates.begin(), candidates.end(), cmp);
        }
        return candidates;
    }

    std::string make_compact(const std::vector<DHTNode> &nodes, bool is_v6) {
        std::string compact;
        for (const auto &n: nodes) {
            compact += n.node_id;
            if (is_v6) {
                struct in6_addr ip_struct;
                inet_pton(AF_INET6, n.ip.c_str(), &ip_struct);
                compact.append(reinterpret_cast<const char *>(ip_struct.s6_addr), 16);
            } else {
                struct in_addr ip_struct;
                inet_pton(AF_INET, n.ip.c_str(), &ip_struct);
                compact.append(reinterpret_cast<const char *>(&ip_struct.s_addr), 4);
            }
            uint16_t p = htons(n.port);
            compact.append(reinterpret_cast<const char *>(&p), 2);
        }
        return compact;
    }

    std::string extract_string(const std::string &data, const std::string &encoded_key, size_t start_pos = 0) {
        size_t pos = data.find(encoded_key, start_pos);
        if (pos == std::string::npos) return "";
        pos += encoded_key.length();
        size_t colon_pos = data.find(':', pos);
        if (colon_pos == std::string::npos) return "";
        std::string len_str = data.substr(pos, colon_pos - pos);
        int len = 0;
        try {
            len = std::stoi(len_str);
        } catch (...) {
            return "";
        }
        pos = colon_pos + 1;
        if (pos + len > data.length()) return "";
        return data.substr(pos, len);
    }

    bool is_valid_ip(const std::string &ip) {
        if (ip.empty()) return false;
        bool is_v6 = ip.find(':') != std::string::npos;
        if (is_v6) {
            if (ip.substr(0, 5) == "fe80:") return false;
            if (ip == "::") return false;
        } else {
            if (ip == "0.0.0.0" || ip.find("127.") == 0 || ip.find("10.") == 0 || ip.find("192.168.") == 0 || ip.
                find("224.") == 0) return false;
        }
        return true;
    }

    void add_known(const DHTNode &node) {
        std::lock_guard<std::mutex> lock(known_mutex);
        if (node.node_id.empty() || node.ip.empty() || node.port == 0 || !is_valid_ip(node.ip)) return;
        if (known_ids.insert(node.node_id).second) {
            known_nodes.push_back(node);
        }
    }

    std::string create_find_node_query(const std::string &target_id, const std::string &transaction_id) {
        std::string sender_id = get_sender_id();
        std::string query = bencode.dict_start();
        query += bencode.encode_string("a") + bencode.dict_start();
        query += bencode.encode_string("id") + bencode.encode_string(sender_id);
        query += bencode.encode_string("target") + bencode.encode_string(target_id);
        query += bencode.dict_end();
        query += bencode.encode_string("q") + bencode.encode_string("find_node");
        query += bencode.encode_string("t") + bencode.encode_string(transaction_id);
        query += bencode.encode_string("y") + bencode.encode_string("q");
        query += bencode.dict_end();
        return query;
    }

    std::string create_get_peers_query(const std::string &info_hash, const std::string &transaction_id) {
        std::string sender_id = get_sender_id();
        std::string query = bencode.dict_start();
        query += bencode.encode_string("a") + bencode.dict_start();
        query += bencode.encode_string("id") + bencode.encode_string(sender_id);
        query += bencode.encode_string("info_hash") + bencode.encode_string(info_hash);
        query += bencode.dict_end();
        query += bencode.encode_string("q") + bencode.encode_string("get_peers");
        query += bencode.encode_string("t") + bencode.encode_string(transaction_id);
        query += bencode.encode_string("y") + bencode.encode_string("q");
        query += bencode.dict_end();
        return query;
    }

    std::string create_sample_infohashes_query(const std::string &target_id, const std::string &transaction_id) {
        std::string sender_id = get_sender_id();
        std::string query = bencode.dict_start();
        query += bencode.encode_string("a") + bencode.dict_start();
        query += bencode.encode_string("id") + bencode.encode_string(sender_id);
        query += bencode.encode_string("target") + bencode.encode_string(target_id);
        query += bencode.dict_end();
        query += bencode.encode_string("q") + bencode.encode_string("sample_infohashes");
        query += bencode.encode_string("t") + bencode.encode_string(transaction_id);
        query += bencode.encode_string("y") + bencode.encode_string("q");
        query += bencode.dict_end();
        return query;
    }

    std::string create_announce_peer_query(const std::string &info_hash, const std::string &token,
                                           const std::string &transaction_id) {
        std::string sender_id = get_sender_id();
        std::string query = bencode.dict_start();
        query += bencode.encode_string("a") + bencode.dict_start();
        query += bencode.encode_string("id") + bencode.encode_string(sender_id);
        query += bencode.encode_string("implied_port") + bencode.encode_int(1);
        query += bencode.encode_string("info_hash") + bencode.encode_string(info_hash);
        query += bencode.encode_string("port") + bencode.encode_int(0);
        query += bencode.encode_string("token") + bencode.encode_string(token);
        query += bencode.dict_end();
        query += bencode.encode_string("q") + bencode.encode_string("announce_peer");
        query += bencode.encode_string("t") + bencode.encode_string(transaction_id);
        query += bencode.encode_string("y") + bencode.encode_string("q");
        query += bencode.dict_end();
        return query;
    }

    std::vector<DHTNode> resolve_host(const std::string &host, uint16_t port) {
        std::vector<DHTNode> nodes;
#ifdef _WIN32
        ADDRINFOA hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;
        ADDRINFOA *res = nullptr;
        char portstr[16];
        snprintf(portstr, sizeof(portstr), "%u", port);
        int rv = getaddrinfo(host.c_str(), portstr, &hints, &res);
        if (rv != 0) {
            std::cerr << "getaddrinfo failed for " << host << ": " << rv << "\n";
            return nodes;
        }
#else
        addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;
        addrinfo *res = nullptr;
        char portstr[16];
        snprintf(portstr, sizeof(portstr), "%u", port);
        int rv = getaddrinfo(host.c_str(), portstr, &hints, &res);
        if (rv != 0) {
            std::cerr << "getaddrinfo failed for " << host << ": " << gai_strerror(rv) << "\n";
            return nodes;
        }
#endif
        for (addrinfo *p = res; p; p = p->ai_next) {
            char buf[INET6_ADDRSTRLEN] = {0};
            uint16_t resolved_port = 0;
            if (p->ai_family == AF_INET) {
                sockaddr_in *s = reinterpret_cast<sockaddr_in *>(p->ai_addr);
                if (inet_ntop(AF_INET, &s->sin_addr, buf, INET_ADDRSTRLEN) == nullptr) {
                    continue;
                }
                resolved_port = ntohs(s->sin_port);
            } else if (p->ai_family == AF_INET6) {
                sockaddr_in6 *s = reinterpret_cast<sockaddr_in6 *>(p->ai_addr);
                if (inet_ntop(AF_INET6, &s->sin6_addr, buf, INET6_ADDRSTRLEN) == nullptr) {
                    continue;
                }
                resolved_port = ntohs(s->sin6_port);
            } else {
                continue;
            }
            std::string ip = buf;
            nodes.emplace_back(generate_random_id(), ip, resolved_port);
        }
#ifdef _WIN32
        freeaddrinfo(res);
#else
        freeaddrinfo(res);
#endif
        return nodes;
    }

    bool send_to_node_checked(const std::string &message, const std::string &ip, uint16_t port) {
        if (!is_valid_ip(ip)) {
            return false;
        }

        struct sockaddr_storage addr{};
        int family = (ip.find(':') != std::string::npos) ? AF_INET6 : AF_INET;
        if (family == AF_INET6 && sock_v6 == INVALID_SOCKET) {
            return false;
        }
        addr.ss_family = family;
        socklen_t addrlen;
        if (family == AF_INET) {
            sockaddr_in *sin = reinterpret_cast<sockaddr_in *>(&addr);
            sin->sin_port = htons(port);
#ifdef _WIN32
            if (InetPtonA(AF_INET, ip.c_str(), &sin->sin_addr) != 1) {
#else
                if (inet_pton(AF_INET, ip.c_str(), &sin->sin_addr) != 1) {
#endif
                return false;
            }
            addrlen = sizeof(sockaddr_in);
        } else {
            sockaddr_in6 *sin6 = reinterpret_cast<sockaddr_in6 *>(&addr);
            sin6->sin6_port = htons(port);
#ifdef _WIN32
            if (InetPtonA(AF_INET6, ip.c_str(), &sin6->sin6_addr) != 1) {
#else
                if (inet_pton(AF_INET6, ip.c_str(), &sin6->sin6_addr) != 1) {
#endif
                return false;
            }
            addrlen = sizeof(sockaddr_in6);
        }

        socket_t send_sock = (family == AF_INET6) ? sock_v6 : sock_v4;

        int retry_count = 0;
        const int max_retries = 3;

        std::lock_guard<std::mutex> lock(send_mutex);
        while (retry_count < max_retries && running) {
            int sent = sendto(send_sock,
#ifdef _WIN32
                              message.c_str(),
#else
                              message.data(),
#endif
                              static_cast<int>(message.size()), 0, reinterpret_cast<struct sockaddr *>(&addr), addrlen);

            if (sent > 0) {
                packets_sent++;
                return true;
            }

#ifdef _WIN32
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK) {
                retry_count++;
                std::this_thread::sleep_for(std::chrono::milliseconds(5 * retry_count));
                continue;
            } else {
                send_failures++;
                return false;
            }
#else
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                retry_count++;
                std::this_thread::sleep_for(std::chrono::milliseconds(5 * retry_count));
                continue;
            } else {
                send_failures++;
                return false;
            }
#endif
        }

        send_failures++;
        return false;
    }

    std::string extract_info_hash(const std::string &data, size_t start_pos) {
        const std::string info_hash_key = "9:info_hash";
        size_t pos = data.find(info_hash_key, start_pos);
        if (pos != std::string::npos) {
            pos += info_hash_key.length();
            size_t colon = data.find(':', pos);
            if (colon != std::string::npos) {
                std::string len_str = data.substr(pos, colon - pos);
                int length = 0;
                try {
                    length = std::stoi(len_str);
                } catch (...) {
                    return "";
                }
                pos = colon + 1;
                if (pos + length <= data.length() && length == 20) {
                    return data.substr(pos, 20);
                }
            }
        }
        return "";
    }

    std::vector<DHTNode> extract_nodes(const std::string &data, bool is_v6) {
        std::vector<DHTNode> nodes;
        const std::string nodes_key = is_v6 ? "6:nodes6" : "5:nodes";
        size_t pos = data.find(nodes_key);

        if (pos != std::string::npos) {
            pos += nodes_key.length();
            size_t colon = data.find(':', pos);
            if (colon != std::string::npos && colon < pos + 10) {
                std::string len_str = data.substr(pos, colon - pos);
                int length = 0;
                try {
                    length = std::stoi(len_str);
                } catch (...) {
                    return nodes;
                }
                pos = colon + 1;

                int node_size = is_v6 ? 38 : 26;
                if (pos + length <= data.length() && length % node_size == 0) {
                    for (int i = 0; i < length; i += node_size) {
                        std::string node_id = data.substr(pos + i, 20);
                        char ip_buf[INET6_ADDRSTRLEN] = {0};
                        uint16_t port;
                        if (is_v6) {
                            struct in6_addr ip_struct;
                            std::memcpy(ip_struct.s6_addr, data.data() + pos + i + 20, 16);
                            inet_ntop(AF_INET6, &ip_struct, ip_buf, INET6_ADDRSTRLEN);
                            std::memcpy(&port, data.data() + pos + i + 36, 2);
                        } else {
                            struct in_addr ip_struct;
                            std::memcpy(&ip_struct.s_addr, data.data() + pos + i + 20, 4);
                            inet_ntop(AF_INET, &ip_struct, ip_buf, INET_ADDRSTRLEN);
                            std::memcpy(&port, data.data() + pos + i + 24, 2);
                        }
                        port = ntohs(port);
                        std::string ip = ip_buf;
                        if (is_valid_ip(ip)) {
                            nodes.emplace_back(node_id, ip, port);
                        }
                    }
                }
            }
        }
        return nodes;
    }

    std::vector<std::string> extract_samples(const std::string &data) {
        std::vector<std::string> samples;
        const std::string samples_key = "7:samples";
        size_t pos = data.find(samples_key);

        if (pos != std::string::npos) {
            pos += samples_key.length();
            size_t colon = data.find(':', pos);
            if (colon != std::string::npos && colon < pos + 10) {
                std::string len_str = data.substr(pos, colon - pos);
                int length = 0;
                try {
                    length = std::stoi(len_str);
                } catch (...) {
                    return samples;
                }
                pos = colon + 1;

                if (pos + length <= data.length() && length % 20 == 0) {
                    for (int i = 0; i < length; i += 20) {
                        std::string hash = data.substr(pos + i, 20);
                        samples.push_back(hash);
                    }
                }
            }
        }
        return samples;
    }

    bool process_receive(socket_t recv_sock) {
        std::vector<char> buffer(BUFFER_SIZE);
        struct sockaddr_storage sender_addr{};
        socklen_t addr_len = sizeof(sender_addr);

        int received = recvfrom(recv_sock, buffer.data(), static_cast<int>(buffer.size()), 0,
                                reinterpret_cast<struct sockaddr *>(&sender_addr), &addr_len);

        if (received <= 0) {
#ifdef _WIN32
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK || err == WSAEINTR) {
                return false;
            } else if (!running) {
                return false;
            } else {
                return false;
            }
#else
            if (errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR) {
                return false;
            } else if (!running) {
                return false;
            } else {
                return false;
            }
#endif
        }

        packets_received++;
        std::string data(buffer.data(), received);

        unsigned short family = sender_addr.ss_family;
        void *in_addr_ptr = (family == AF_INET)
                                ? static_cast<void *>(&(reinterpret_cast<sockaddr_in *>(&sender_addr)->sin_addr))
                                : static_cast<void *>(&(reinterpret_cast<sockaddr_in6 *>(&sender_addr)->sin6_addr));
        char ip_buf[INET6_ADDRSTRLEN];
        inet_ntop(family, in_addr_ptr, ip_buf, sizeof(ip_buf));
        std::string sender_ip = ip_buf;

        uint16_t sender_port = ntohs((family == AF_INET)
                                         ? reinterpret_cast<sockaddr_in *>(&sender_addr)->sin_port
                                         : reinterpret_cast<sockaddr_in6 *>(&sender_addr)->sin6_port);

        bool sender_is_v6 = (family == AF_INET6);

        try {
            // Extract hash if present
            std::string hash = extract_info_hash(data, 0);
            if (!hash.empty()) {
                std::lock_guard<std::mutex> lock(discovered_mutex);
                if (discovered_hashes.insert(hash).second) {
                    hashes_scraped++;
                }
            }

            // Extract samples if present
            auto sample_hashes = extract_samples(data);
            if (!sample_hashes.empty()) {
                std::lock_guard<std::mutex> lock(discovered_mutex);
                for (const auto &sh: sample_hashes) {
                    if (discovered_hashes.insert(sh).second) {
                        hashes_scraped++;
                    }
                }
            }

            // Extract nodes if present
            auto nodes_v4 = extract_nodes(data, false);
            auto nodes_v6 = extract_nodes(data, true);
            std::vector<DHTNode> all_nodes;
            all_nodes.reserve(nodes_v4.size() + nodes_v6.size());
            all_nodes.insert(all_nodes.end(), nodes_v4.begin(), nodes_v4.end());
            all_nodes.insert(all_nodes.end(), nodes_v6.begin(), nodes_v6.end());
            if (!all_nodes.empty()) {
                for (auto &node: all_nodes) {
                    std::string node_key = node.ip + ":" + std::to_string(node.port);
                    bool inserted = false;
                    {
                        std::lock_guard<std::mutex> lock(contacted_mutex);
                        inserted = contacted_nodes.insert(node_key).second;
                    }
                    if (inserted) {
                        int sub_idx = get_subspace(node.node_id);
                        auto &sub = subspaces[sub_idx];
                        std::lock_guard<std::mutex> slock(sub.mux);
                        sub.node_queue.push(std::move(node));
                    }
                    add_known(node);
                }
            }

            // Parse and respond if query
            size_t y_pos = data.find("1:y1:");
            if (y_pos != std::string::npos) {
                char y_type = data[y_pos + 4];
                std::string tid = extract_string(data, "1:t", 0);
                if (tid.empty()) return true;

                if (y_type == 'q') {
                    // Query
                    std::string q = extract_string(data, "1:q", 0);
                    size_t a_pos = data.find("1:a" + bencode.dict_start());
                    std::string sender_id = extract_string(data, "2:id", a_pos);

                    if (!sender_id.empty()) {
                        add_known(DHTNode(sender_id, sender_ip, sender_port));
                    }

                    std::string resp;
                    if (q == "ping") {
                        resp = bencode.dict_start();
                        resp += bencode.encode_string("r") + bencode.dict_start();
                        resp += bencode.encode_string("id") + bencode.encode_string(get_sender_id());
                        resp += bencode.dict_end();
                        resp += bencode.encode_string("t") + bencode.encode_string(tid);
                        resp += bencode.encode_string("y") + bencode.encode_string("r");
                        resp += bencode.dict_end();
                    } else if (q == "find_node" || q == "sample_infohashes") {
                        std::string target = extract_string(data, "6:target", a_pos);
                        if (target.empty()) return true;
                        auto closest = get_closest(target, 8, sender_is_v6);
                        std::string nodes_compact = make_compact(closest, sender_is_v6);
                        resp = bencode.dict_start();
                        resp += bencode.encode_string("r") + bencode.dict_start();
                        resp += bencode.encode_string("id") + bencode.encode_string(get_sender_id());
                        resp += bencode.encode_string(sender_is_v6 ? "nodes6" : "nodes") + bencode.encode_string(
                            nodes_compact);
                        resp += bencode.dict_end();
                        resp += bencode.encode_string("t") + bencode.encode_string(tid);
                        resp += bencode.encode_string("y") + bencode.encode_string("r");
                        resp += bencode.dict_end();
                    } else if (q == "get_peers") {
                        std::string info_hash = extract_string(data, "9:info_hash", a_pos);
                        if (info_hash.empty()) return true;
                        auto closest = get_closest(info_hash, 8, sender_is_v6);
                        std::string nodes_compact = make_compact(closest, sender_is_v6);
                        std::string token = generate_random_id(2);
                        resp = bencode.dict_start();
                        resp += bencode.encode_string("r") + bencode.dict_start();
                        resp += bencode.encode_string("id") + bencode.encode_string(get_sender_id());
                        resp += bencode.encode_string("token") + bencode.encode_string(token);
                        resp += bencode.encode_string(sender_is_v6 ? "nodes6" : "nodes") + bencode.encode_string(
                            nodes_compact);
                        resp += bencode.dict_end();
                        resp += bencode.encode_string("t") + bencode.encode_string(tid);
                        resp += bencode.encode_string("y") + bencode.encode_string("r");
                        resp += bencode.dict_end();
                    } else if (q == "announce_peer") {
                        resp = bencode.dict_start();
                        resp += bencode.encode_string("r") + bencode.dict_start();
                        resp += bencode.encode_string("id") + bencode.encode_string(get_sender_id());
                        resp += bencode.dict_end();
                        resp += bencode.encode_string("t") + bencode.encode_string(tid);
                        resp += bencode.encode_string("y") + bencode.encode_string("r");
                        resp += bencode.dict_end();
                    }

                    if (!resp.empty()) {
                        send_to_node_checked(resp, sender_ip, sender_port);
                    }
                } else if (y_type == 'r') {
                    // Response
                    size_t r_pos = data.find("1:r" + bencode.dict_start());
                    std::string sender_id = extract_string(data, "2:id", r_pos);
                    if (!sender_id.empty()) {
                        add_known(DHTNode(sender_id, sender_ip, sender_port));
                    }

                    // Check for token and send announce if pending
                    std::string token = extract_string(data, "5:token", r_pos);
                    if (!token.empty()) {
                        std::lock_guard<std::mutex> lock(pending_mutex);
                        auto it = pending_get_peers.find(tid);
                        if (it != pending_get_peers.end()) {
                            std::string new_tid = generate_random_id(2);
                            std::string announce = create_announce_peer_query(it->second.info_hash, token, new_tid);
                            send_to_node_checked(announce, it->second.target_ip, it->second.target_port);
                            pending_get_peers.erase(it);
                        }
                    }
                }
            }
        } catch (...) {
            // Skip invalid packets
        }
        return true;
    }

    bool process_send(int subspace_idx) {
        auto &sub = subspaces[subspace_idx];
        DHTNode node;
        {
            std::lock_guard<std::mutex> lock(sub.mux);
            if (sub.node_queue.empty()) {
                return false;
            }
            node = sub.node_queue.front();
            sub.node_queue.pop();
        }

        if (node.ip.empty()) {
            return false;
        }

        std::vector<std::string> sample_targets;
        std::vector<std::string> get_peers_hashes;
        for (int j = 0; j < samples_per_node; ++j) {
            sample_targets.push_back(generate_target(subspace_idx));
        }
        for (int j = 0; j < getpeers_per_node; ++j) {
            get_peers_hashes.push_back(generate_target(subspace_idx));
        }

        // For find_node, use flip_bit targets
        static thread_local std::random_device rd;
        static thread_local std::mt19937 gen(rd());
        std::uniform_int_distribution<int> bit_dis(0, 31); // Focus on higher-level splits

        std::vector<std::string> find_targets;
        for (int j = 0; j < finds_per_node; ++j) {
            int m = bit_dis(gen);
            find_targets.push_back(flip_bit(node.node_id, m));
        }

        // Send sample_infohashes
        for (int j = 0; j < samples_per_node; ++j) {
            std::string tid = generate_random_id(2);
            std::string target = sample_targets[j];
            std::string sample_query = create_sample_infohashes_query(target, tid);
            send_to_node_checked(sample_query, node.ip, node.port);
        }

        // Send find_node with flip_bit targets
        for (int j = 0; j < finds_per_node; ++j) {
            std::string tid = generate_random_id(2);
            std::string target = find_targets[j];
            std::string find_query = create_find_node_query(target, tid);
            send_to_node_checked(find_query, node.ip, node.port);
        }

        // Send get_peers
        for (int j = 0; j < getpeers_per_node; ++j) {
            std::string info_hash = get_peers_hashes[j];
            std::string tid = generate_random_id(2);
            std::string get_query = create_get_peers_query(info_hash, tid);
            {
                std::lock_guard<std::mutex> lock(pending_mutex);
                if (send_to_node_checked(get_query, node.ip, node.port)) {
                    pending_get_peers[tid] = {info_hash, node.ip, node.port};
                }
            }
        }

        precise_delay_ns(delay_ns);
        return true;
    }

    void stats_display() {
        static auto start = std::chrono::steady_clock::now();
        static uint64_t last_hashes = 0;

        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start).count();

        uint64_t current_hashes = hashes_scraped.load();
        uint64_t hashes_per_sec = current_hashes - last_hashes;
        last_hashes = current_hashes;

        size_t qsize = 0;
        size_t known_size;
        for (auto &sub: subspaces) {
            std::lock_guard<std::mutex> lock(sub.mux);
            qsize += sub.node_queue.size();
        }
        {
            std::lock_guard<std::mutex> lock(known_mutex);
            known_size = known_nodes.size();
        }

        std::cout << "\r[" << elapsed << "s] "
                << "Hashes: " << current_hashes
                << " | Rate: " << hashes_per_sec << "/s"
                << " | Sent: " << packets_sent.load()
                << " | Recv: " << packets_received.load()
                << " | Queue: " << qsize
                << " | Known: " << known_size
                << " | Failed: " << send_failures.load()
                << "      " << std::flush;
    }

public:
    DHTScraper(int ns, int spc, int sam, int fin, int gp, int del, int md, int tb)
        : num_subspaces(ns), sends_per_cycle(spc), samples_per_node(sam), finds_per_node(fin),
          getpeers_per_node(gp), delay_ns(del), max_depth(md), top_bits(tb), subspaces(ns) {
#ifdef _WIN32
        WSADATA wsa_data;
        if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
            throw std::runtime_error("WSAStartup failed");
        }
#endif

        // Create IPv4 socket
        sock_v4 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock_v4 == INVALID_SOCKET) {
            throw std::runtime_error("Failed to create IPv4 socket");
        }

#ifndef _WIN32
        int flags = fcntl(sock_v4, F_GETFL, 0);
        if (flags >= 0) fcntl(sock_v4, F_SETFL, flags | O_NONBLOCK);
#else
        u_long mode = 1;
        ioctlsocket(sock_v4, FIONBIO, &mode);
#endif

        int yes = 1;
        setsockopt(sock_v4, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<char *>(&yes), sizeof(yes));

        int sndbuf = SEND_BUFFER_SIZE;
        setsockopt(sock_v4, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<char *>(&sndbuf), sizeof(sndbuf));

        int rcvbuf = RECV_BUFFER_SIZE;
        setsockopt(sock_v4, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<char *>(&rcvbuf), sizeof(rcvbuf));

        struct sockaddr_in bind_addr{};
        bind_addr.sin_family = AF_INET;
        bind_addr.sin_addr.s_addr = INADDR_ANY;
        bind_addr.sin_port = htons(6881);

        if (bind(sock_v4, reinterpret_cast<struct sockaddr *>(&bind_addr), sizeof(bind_addr)) < 0) {
            std::cerr << "Bind to 6881 failed for IPv4, falling back to ephemeral port\n";
            bind_addr.sin_port = htons(0);
            if (bind(sock_v4, reinterpret_cast<struct sockaddr *>(&bind_addr), sizeof(bind_addr)) < 0) {
#ifdef _WIN32
                int err = WSAGetLastError();
                std::cerr << "bind failed err=" << err << "\n";
#else
                perror("bind");
#endif
                CLOSE_SOCKET(sock_v4);
                sock_v4 = INVALID_SOCKET;
                throw std::runtime_error("bind failed for IPv4");
            }
        }

        // Create IPv6 socket
        sock_v6 = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
        if (sock_v6 == INVALID_SOCKET) {
            std::cerr << "Failed to create IPv6 socket, continuing with IPv4 only\n";
        } else {
#ifndef _WIN32
            int flags6 = fcntl(sock_v6, F_GETFL, 0);
            if (flags6 >= 0) fcntl(sock_v6, F_SETFL, flags6 | O_NONBLOCK);
#else
            u_long mode6 = 1;
            ioctlsocket(sock_v6, FIONBIO, &mode6);
#endif

            setsockopt(sock_v6, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<char *>(&yes), sizeof(yes));

            setsockopt(sock_v6, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<char *>(&sndbuf), sizeof(sndbuf));

            setsockopt(sock_v6, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<char *>(&rcvbuf), sizeof(rcvbuf));

            int v6only = 1;
            setsockopt(sock_v6, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<char *>(&v6only), sizeof(v6only));

            struct sockaddr_in6 bind_addr6{};
            bind_addr6.sin6_family = AF_INET6;
            bind_addr6.sin6_addr = in6addr_any;
            bind_addr6.sin6_port = htons(6881);

            if (bind(sock_v6, reinterpret_cast<struct sockaddr *>(&bind_addr6), sizeof(bind_addr6)) < 0) {
                std::cerr << "Bind to 6881 failed for IPv6, falling back to ephemeral port\n";
                bind_addr6.sin6_port = htons(0);
                if (bind(sock_v6, reinterpret_cast<struct sockaddr *>(&bind_addr6), sizeof(bind_addr6)) < 0) {
#ifdef _WIN32
                    int err = WSAGetLastError();
                    std::cerr << "bind failed err=" << err << "\n";
#else
                    perror("bind");
#endif
                    CLOSE_SOCKET(sock_v6);
                    sock_v6 = INVALID_SOCKET;
                }
            }
        }

        // Generate staggered node IDs for Sybil attack
        for (int i = 0; i < 256; ++i) {
            std::string id = generate_random_id(20);
            id[0] = static_cast<char>(i);
            my_node_ids.push_back(id);
        }
        primary_node_id = my_node_ids[0];
    }

    ~DHTScraper() {
        running = false;
        if (sock_v4 != INVALID_SOCKET) {
            CLOSE_SOCKET(sock_v4);
        }
        if (sock_v6 != INVALID_SOCKET) {
            CLOSE_SOCKET(sock_v6);
        }
#ifdef _WIN32
        WSACleanup();
#endif
    }

    void bootstrap() {
        std::vector<std::pair<std::string, uint16_t> > bootstrap_hosts = {
            {"router.bittorrent.com", 6881},
            {"dht.transmissionbt.com", 6881},
            {"router.utorrent.com", 6881},
            {"dht.libtorrent.org", 25401},
            {"dht.aelitis.com", 6881},
            {"bootstrap.jami.net", 4222},
            {"dht.anomos.info", 5033},
            {"router.bitcomet.com", 6881},
            {"router.silotis.us", 6881},
            {"ntp.juliusbeckmann.de", 6881},
            {"mgts.ivth.ru", 57858},
            {"sorcerer.leentje.org", 49786},
            {"libertalia.space", 50005},
            {"milda.intelib.org", 51413},
            {"tox.abilinski.com", 33445},
            {"tox.kurnevsky.net", 33445},
            {"tox2.abilinski.com", 33445},
            {"tox1.mf-net.eu", 33445},
            {"tox01.ky0uraku.xyz", 33445},
            {"tox4.plastiras.org", 33445},
            {"tox3.plastiras.org", 33445},
            {"tox2.mf-net.eu", 33445},
            {"kusoneko.moe", 33445},
            {"tox.initramfs.io", 33445},
            {"tox3.mf-net.eu", 33445},
            {"tox.plastiras.org", 33445},
            {"tox.hidemybits.com", 443},
            {"tox4.mf-net.eu", 33445},
            {"tox2.plastiras.org", 33445},
            {"tox02.ky0uraku.xyz", 33445},
            {"104.131.131.82", 4001}, // From IPFS
            // Additional from Tox sources
            {"144.217.167.73", 33445},
            {"45.32.184.23", 33445},
            {"188.225.9.167", 33445},
            {"3.0.24.15", 33445},
            {"104.225.141.59", 43334},
            {"139.162.110.188", 33445},
            {"172.105.109.31", 33445},
            {"91.146.66.26", 33445},
            {"172.104.215.182", 33445},
            {"45.134.88.121", 33445},
            {"205.185.115.131", 53},
            {"46.101.197.175", 33445},
            {"5.19.249.240", 38296},
            {"122.116.39.151", 33445},
            {"173.232.195.131", 33445},
            {"198.98.49.206", 33445},
            {"193.168.141.224", 33445},
            {"188.214.122.30", 33445},
            {"194.36.190.71", 33445},
            {"62.183.96.32", 33445},
            {"141.11.229.155", 33445},
            {"43.198.227.166", 33445},
            {"95.181.230.108", 33445},
            {"188.245.84.166", 33445},
            // Additional from BitTorrent sources (minor overlaps resolved)
            {"router.bitcomet.net", 6881}, // Variant from some lists
            // Additional from IPFS (parsed hosts; ports default to 4001 where resolved)
            {"bootstrap.libp2p.io", 4001} // DNS resolves to multiple IPs, but using domain for flexibility
        };

        for (const auto &[host, port]: bootstrap_hosts) {
            auto resolved_nodes = resolve_host(host, port);
            if (resolved_nodes.empty()) {
                std::cerr << "No addresses for " << host << ", skipping\n";
                continue;
            }
            for (auto &node: resolved_nodes) {
                std::string node_key = node.ip + ":" + std::to_string(node.port);
                bool inserted = false;
                {
                    std::lock_guard<std::mutex> lock(contacted_mutex);
                    inserted = contacted_nodes.insert(node_key).second;
                }
                if (inserted) {
                    int sub_idx = get_subspace(node.node_id);
                    auto &sub = subspaces[sub_idx];
                    std::lock_guard<std::mutex> slock(sub.mux);
                    sub.node_queue.push(node);
                }
                add_known(node);
                std::cout << "Bootstrap resolved " << host << " -> " << node.ip << ":" << node.port << "\n";
            }
        }

        std::cout << "Bootstrapped with initial nodes\n";

        // Initialize zone_queues for each subspace
        for (int b = 0; b < num_subspaces; ++b) {
            std::string prefix("");
            int bit_len = 0;
            for (int bit = 0; bit < top_bits; ++bit) {
                bool val = (b & (1 << (top_bits - 1 - bit))) != 0;
                add_bit(val, prefix, bit_len);
            }
            auto &sub = subspaces[b];
            std::lock_guard<std::mutex> lock(sub.mux);
            sub.zone_queue.push({bit_len, prefix});
        }
    }

    void run() {
        bootstrap();

        std::cout << "DHT Scraper running... Press Enter to stop.\n";

        std::thread input_thread([]() {
            std::cin.get();
        });

        std::vector<std::thread> send_threads;
        for (int i = 0; i < num_subspaces; ++i) {
            send_threads.emplace_back([this, i]() {
                while (this->running) {
                    if (this->process_send(i)) {
                        // continue
                    } else {
                        std::this_thread::sleep_for(std::chrono::milliseconds(1));
                    }
                }
            });
        }

        auto last_stats = std::chrono::steady_clock::now();
        auto last_hop = std::chrono::steady_clock::now();

        while (running) {
            struct pollfd pfd[2]{};
            int num_fds = 1;
            pfd[0].fd = sock_v4;
            pfd[0].events = POLLIN;
            if (sock_v6 != INVALID_SOCKET) {
                pfd[1].fd = sock_v6;
                pfd[1].events = POLLIN;
                num_fds = 2;
            }
            int ret = poll(pfd, num_fds, 0);

            if (ret > 0) {
                for (int i = 0; i < num_fds; ++i) {
                    if (pfd[i].revents & POLLIN) {
                        while (process_receive(pfd[i].fd)) {
                        }
                    }
                }
            }

            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::minutes>(now - last_hop).count() >= 30) {
                for (auto &id: my_node_ids) {
                    id = generate_random_id(20);
                }
                last_hop = now;
            }

            if (std::chrono::duration_cast<std::chrono::seconds>(now - last_stats).count() >= 1) {
                stats_display();
                last_stats = now;
            }

            if (ret <= 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }

            if (!input_thread.joinable()) {
                running = false;
            }
        }

        if (input_thread.joinable()) {
            input_thread.join();
        }

        for (auto &t: send_threads) {
            t.join();
        }

        std::cout << "\nFinal Statistics:\n";
        std::cout << "Total Hashes Discovered: " << hashes_scraped.load() << "\n";
        std::cout << "Packets Sent: " << packets_sent.load() << "\n";
        std::cout << "Packets Received: " << packets_received.load() << "\n";
        std::cout << "Send Failures: " << send_failures.load() << "\n";
    }
};

int main(int argc, char *argv[]) {
    std::unordered_map<std::string, std::string> args;
    for (int i = 1; i < argc; i += 2) {
        if (i + 1 < argc) {
            args[argv[i]] = argv[i + 1];
        }
    }

    int num_subspaces = 4;
    int sends_per_cycle = 5;
    int samples_per_node = 25;
    int finds_per_node = 25;
    int getpeers_per_node = 5;
    int delay_ns = 2000000;
    int max_depth = 25;
    int top_bits = 2;

    if (args.count("--num-subspaces")) num_subspaces = std::stoi(args["--num-subspaces"]);
    if (args.count("--sends-per-cycle")) sends_per_cycle = std::stoi(args["--sends-per-cycle"]);
    if (args.count("--samples-per-node")) samples_per_node = std::stoi(args["--samples-per-node"]);
    if (args.count("--finds-per-node")) finds_per_node = std::stoi(args["--finds-per-node"]);
    if (args.count("--getpeers-per-node")) getpeers_per_node = std::stoi(args["--getpeers-per-node"]);
    if (args.count("--delay-ns")) delay_ns = std::stoi(args["--delay-ns"]);
    if (args.count("--max-depth")) max_depth = std::stoi(args["--max-depth"]);
    if (args.count("--top-bits")) top_bits = std::stoi(args["--top-bits"]);

    try {
        DHTScraper scraper(num_subspaces, sends_per_cycle, samples_per_node, finds_per_node, getpeers_per_node,
                           delay_ns, max_depth, top_bits);
        scraper.run();
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}