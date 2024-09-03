#include <sys/statvfs.h>
#include <string>
#include <unistd.h>
#include <cstdlib>

#include <iostream>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctime>

#include <fstream>
#include <sstream>
#include <vector>
#include <algorithm>
#include <numeric>
#include <utility>
#include <boost/algorithm/string.hpp>
#include <boost/asio.hpp>
#include <boost/unordered_map.hpp>
#include <thread>

// Initial system / stat agent for linux


typedef unsigned long int ulong;

void signalHandler(int signal) {
    exit(EXIT_SUCCESS);
}

void daemonize() {
    pid_t pid = fork();

    if (pid < 0) {
        std::cerr << "Error: Fork1 failed." << std::endl;
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    if (setsid() < 0) {
        std::cerr << "Error: setsid failed." << std::endl;
        exit(EXIT_FAILURE);
    }

    pid = fork();

    if (pid < 0) {
        std::cerr << "Error: Fork2 failed." << std::endl;
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    umask(0);

    if (chdir("/") < 0) {
        std::cerr << "Error: chdir failed." << std::endl;
        exit(EXIT_FAILURE);
    }

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    open("/dev/null", O_RDONLY);
    open("/dev/null", O_WRONLY);
    open("/dev/null", O_WRONLY);

    signal(SIGTERM, signalHandler);
    signal(SIGINT, signalHandler);
}

uint64_t time_current_seconds() {
    using namespace std::chrono;
    return duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
}

uint64_t time_current_milliseconds() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}


std::string exec_command(const char * cmd) {
    std::array<char, 1024 * 20> buffer{};
    std::string result;

    std::unique_ptr<FILE, int(*)(FILE*)> pipe(popen(cmd, "r"), static_cast<int(*)(FILE*)>(pclose));
    if (!pipe) {
        throw std::runtime_error("Cannot run command [" + std::string(cmd) + "]");
    }

    while (fgets(buffer.data(), buffer.size() - 1, pipe.get()) != nullptr) {
        result += std::string(buffer.data());
    }
    return result;
}

/** string & json tools */
std::string trim(const std::string &str) {
    auto blanks = " \t\n\r\f\v";
    size_t start = str.find_first_not_of(blanks);
    if (start == std::string::npos) {
        return "";
    }
    size_t end = str.find_last_not_of(blanks);
    return str.substr(start, end - start + 1);
}


std::string join(const std::vector<std::string> & parts, const std::string & delemiter) {
    return std::accumulate(std::next(parts.begin()), parts.end(), parts[0],
                           [&delemiter](std::string a, std::string b) {
                               return a + delemiter + b;
                           }
    );
}

std::vector<std::string> split(const std::string & line, const std::string & separator) {
    std::vector<std::string> result;
    boost::split(result, line, boost::is_any_of(separator));
    return result;
}

std::vector<std::string> split_trim(const std::string & line, const std::string & separator) {
    std::vector<std::string> result;
    boost::split(result, line, boost::is_any_of(separator), boost::token_compress_on);
    return result;
}

std::string as_json_string(std::vector<std::pair<std::string, std::string>> & fields) {
    std::vector<std::string> data;
    for (const auto& item : fields) {
        auto name = item.first;
        auto value = item.second;
        boost::replace_all(value, "\"", "\\\"");

        auto result_str = "\"" + name + "\"";
        result_str += ":";
        result_str += "\"" + value + "\"";
        data.push_back(result_str);
    }
    auto result =  join(data, ",");
    return "{" + result + "}";
}

std::string actual_hostname;
std::string get_hostname() {
    if (!actual_hostname.empty()) {
        return actual_hostname;
    }
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        actual_hostname = std::string(hostname);
    }
    return actual_hostname;
}


std::string inject_common_data(const std::string & action, const std::string & data) {
    return "{"
           "\"action\":   \"monitor-" + action + "\""
            ",\"host\":"  "\"" + get_hostname() + "\""
            ",\"time\":"  "\"" + std::to_string(time(0)) + "\""
            ",\"data\":" + data +
           "}";
}


struct NetworkStats {
    std::string name;
    unsigned long rx_bytes;
    unsigned long tx_bytes;
};


std::vector<NetworkStats> network_start_status;
uint64_t time_network_start;

std::vector<NetworkStats> getNetworkStats() {
    std::ifstream net_dev("/proc/net/dev");
    std::vector<NetworkStats> result;
    bool reade_for_process = false;
    std::string line;

    while (std::getline(net_dev, line)) {
        if (! reade_for_process) {
            reade_for_process = line.find("compressed") != std::string::npos;
            continue;
        }
        char name[31];
        unsigned long rx_bytes, tx_bytes;
        std::sscanf(line.c_str(), "%30s %lu %*s %*s %*s %*s %*s %*s %*s %lu", name, &rx_bytes, &tx_bytes);
        result.push_back(NetworkStats{name, rx_bytes, tx_bytes});
    }

    return result;
}


std::string network_usage() {
    std::vector<std::string>  result;

    if (network_start_status.empty()) {
        network_start_status = getNetworkStats();
        time_network_start = time_current_milliseconds();
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }

    auto network_stop_status = getNetworkStats();
    auto time_network_stop = time_current_milliseconds();
    float duration = (time_network_stop - time_network_start) / 1000;

    time_network_start = time_network_stop;

    for (ulong i=0; i<network_start_status.size(); i++) {
        auto n1 = network_start_status[i];
        auto n2 = network_stop_status[i];
        result.push_back(
          "{ \"name\":\""       + n1.name + "\""
        + ", \"read\":"         + std::to_string((n2.rx_bytes - n1.rx_bytes) / duration)
        + ", \"transfer\":"     + std::to_string((n2.tx_bytes - n1.tx_bytes) / duration) + "}");
    }
    return "[" + join(result, ",") + "]";
}

std::string network_usage_report(std::string hostname) {
    auto net = network_usage();
    return inject_common_data("net", net);
}


std::string getMeminfo() {
    std::ifstream file("/proc/meminfo");
    int count_processed_lines = 20;
    std::vector<std::string> result;

    for (int i = 0; i < count_processed_lines; i++) {
        std::string line;
        std::getline(file, line);
        std::istringstream iss(line);

        std::string name;
        unsigned long long value;
        iss >> name >> value;
        result.push_back("{\"" + name + "\":" + std::to_string(value) + "}");
    }
    return "[" + join(result, ",") + "]";
}

std::string memory_report(std::string hostname) {
    auto memory = getMeminfo();
    return inject_common_data("memory", memory);
}

std::string getUptime() {
    std::ifstream file("/proc/uptime");
    std::string line;
    std::getline(file, line);
    std::istringstream iss(line);

    unsigned long long uptime, idletime;
    iss >> uptime >> idletime;
    return std::to_string(uptime);
}


struct CPUStats {
    uint64_t user;
    uint64_t nice;
    uint64_t system;
    uint64_t idle;
    uint64_t iowait;
    uint64_t irq;
    uint64_t softirq;
    uint64_t steal;
};


std::vector<CPUStats> readCPUStats(int nproc) {
    std::ifstream file("/proc/stat");
    std::vector<CPUStats> result;

    for (int i=0; i< nproc +1; i++) {   // first line which contains overall CPU stats
        std::string line;
        std::getline(file, line);
        std::istringstream iss(line);
        std::string cpu;
        unsigned long long user, nice, system, idle, iowait, irq, softirq, steal;
        iss >> cpu >> user >> nice >> system >> idle >> iowait >> irq >> softirq >> steal;
        result.push_back(CPUStats{user, nice, system, idle, iowait, irq, softirq, steal});
    }
    return result;
}

float calculateCPUUsage(const CPUStats& start, const CPUStats& end) {
    auto prevIdle = start.idle + start.iowait;
    auto idle = end.idle + end.iowait;
    auto prevNonIdle = start.user + start.nice + start.system + start.irq + start.softirq + start.steal;
    auto nonIdle = end.user + end.nice + end.system + end.irq + end.softirq + end.steal;

    auto prevTotal = prevIdle + prevNonIdle;
    auto total = idle + nonIdle;

    auto totald = total - prevTotal;
    auto idled = idle - prevIdle;

    float cpu_percentage = ((totald - idled) / (float)totald) * 100;
    return cpu_percentage;
}

static int nproc = 0;
std::vector<CPUStats> cpu_start_status;

std::string cpu_usage() {
    std::vector<std::string> result;

    if (nproc <=0) {
        nproc = atoi(exec_command("nproc").c_str());
        std::cout << "\n";
    }
    nproc = nproc > 0 ? nproc : 1;
    if (cpu_start_status.empty()) {
        cpu_start_status = readCPUStats(nproc);
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }

    std::vector<CPUStats> cpu_stop_status = readCPUStats(nproc);

    for (int i=0; i<nproc+1; i++) {
        result.push_back(std::to_string(calculateCPUUsage(cpu_start_status[i], cpu_stop_status[i])));
    }

    return "[" + join(result, ",") + "]";
}

std::string get_loadavg() {
    double ld[3];
    getloadavg(ld, 3);
    return "[" + std::to_string(ld[0]) + "," + std::to_string(ld[1]) + "," + std::to_string(ld[2]) + "]";
}

std::string cpu_usage_report(std::string & hostname) {
    auto cpu_data = cpu_usage();
    auto loadavg = get_loadavg();
    auto uptime = getUptime();

    auto data = "{"
                        "\"cpu\":" + cpu_data + ""
                        ",\"uptime\":"    + uptime + ""
                        ",\"loadavg\":"   + loadavg
                     + "}";

    return inject_common_data("cpu", data);
}


std::string disk_space(std::string & mount_point_str) {
    std::vector<std::string> result;

    std::vector<std::string> mount_points = split_trim(mount_point_str.empty() ? "/" : mount_point_str, ";");

    for (auto path : mount_points) {
        struct statvfs buf;
        if (statvfs(path.c_str(), &buf) == 0) {
            auto total = buf.f_blocks * buf.f_frsize;
            auto free = buf.f_bfree * buf.f_frsize;
            auto used = total - free;
            auto usage = used * 100 / total;

            result.push_back("{"
                               "\"mounted\":" "\"" + path + "\""
                             + ",\"total\":" + std::to_string(total)
                             + ",\"free\":" + std::to_string(free)
                             + ",\"usage\":" + std::to_string(usage)
                             + "}");
        }
    }
    return inject_common_data("disk", "[" + join(result, ",") + "]");
}


std::vector<std::pair<std::string, std::string>>
parse_command_line_ps(const std::string & input, int marker, const std::vector<std::string> & names) {
    std::istringstream iss(input);
    std::string part;
    std::vector<std::string> parts;
    std::vector<std::string> command_line_parts;
    std::vector<std::pair<std::string, std::string>> param_values;


    for (int i=0; i<100; i++) {
        if (iss >> part) {
            if (i < marker) {
                auto value = part;
                param_values.push_back(std::pair(names[i], part));

            } else {
                boost::replace_all(part, "\\", "\\\\");
                command_line_parts.push_back(part);
            }
        }
    }
    if (!command_line_parts.empty()) {
        auto cmd = join(command_line_parts, " ");
        param_values.push_back(std::pair(names[marker], cmd));
    }

    return param_values;
}

std::vector<std::pair<std::string, int>>
command_line_blanks_posit(const std::string & input,
                          const std::vector<std::string> & names) {
    std::vector<std::pair<std::string, int>> result;

    for (auto name : names) {
        int idx = input.find(name);
        result.push_back(std::pair(name, idx));
    }
    return result;
}
std::vector<std::pair<std::string, std::string>>
command_line_blanks_posit_parse(const std::string & input, std::vector<std::pair<std::string, int>> & names) {
    std::vector<std::pair<std::string, std::string>> result;

    std::string param_name = "";
    int start = -1;

    for (auto item : names) {
        auto name = item.first;
        int idx = item.second;
        if (start != -1) {
            auto value = trim(input.substr (start, idx - start));
            result.push_back(std::pair(param_name, value));
            param_name = name;
            start = idx;
            continue;
        }
        start = idx;
        param_name = name;
    }
    result.push_back(std::pair(param_name, input.substr (start, input.size())));
    return result;
}

class PerformSender {
private:
    boost::asio::ip::udp::endpoint endpoint_;
    boost::asio::ip::udp::socket socket_;
    boost::asio::system_timer timer_;
    unsigned timeout_;
    bool print_sent_message_;
    std::string params_;

    std::string message_;
    boost::unordered_map<std::string, uint64_t> times_;
    boost::unordered_map<std::string, uint64_t> timeouts_;
    boost::unordered_map<std::string, std::string> extra_params_;
public:
    PerformSender(boost::asio::io_context& ioc,
                           unsigned timeout_sec,
                           const boost::asio::ip::address& multicast_address,
                           short unsigned port,
                           const std::string & params,
                           bool print_sent_message)
            : endpoint_{multicast_address, port}
            , socket_{ioc, endpoint_.protocol()}
            , timer_(ioc)
            , timeout_{timeout_sec}
            , print_sent_message_{print_sent_message} {

        if (params.find("--actions=") != std::string::npos) {
            params_ = params.substr(strlen("--actions="), 1000);
        }
        std::cout << "Statistics endpoint: " << multicast_address << ":" << port << "\n";
        std::cout << "Requested statistics:\n";
        for (auto & name_str: split_trim(params_, ",")) {
            auto param_val = split_trim(name_str, ":");
            std::string name;
            if (!param_val.empty()) {
                name = param_val[0];
                uint64_t value = param_val.size() > 1 ? atoi(param_val[1].c_str()) : timeout_;
                timeouts_[name] = value;
                times_[name] = 0;
                auto separator = name.size() > strlen("disk") ? "\t" : "\t\t";
                std::cout << "  " << name << ":" << separator << value << "\t sec timeout";
            }
            if (name_str.find("[") != std::string::npos && name_str.find("]") != std::string::npos) {
                auto pozit = name_str.find("[");
                auto extra_params = name_str.substr(pozit + 1, name_str.size() - pozit -2);
                extra_params_[name] = extra_params;
                std::cout << "\t[" << extra_params << "]";
            }
            std::cout << "\n";
        }

        send_message_and_next(compose_message("start"));
    }

    std::vector<std::string>
    process_lines(const std::vector<std::string> & lines, const std::vector<std::string> & names) {
        std::vector<std::string> result;
        auto idxs = command_line_blanks_posit(lines.at(0), names);
        for (ulong n = 1; n < lines.size(); n++) {
            auto & line = lines.at(n);
            if (!line.empty()) {
                auto data = command_line_blanks_posit_parse(line, idxs);
                result.push_back(as_json_string(data));
            }
        }
        return result;
    }

    std::string compose_message(std::string message_type) {
        auto hostname = get_hostname();
        std::string action = message_type;
        const char * command = nullptr;

        times_[message_type] = time_current_seconds();

        if (message_type == "start") {
            return cpu_usage_report(hostname);
        }
        if (message_type == "cpu" ) {
            return cpu_usage_report(hostname);
        }
        if (message_type == "net" ) {
            return network_usage_report(hostname);
        }
        if (message_type == "memory" ) {
            return memory_report(hostname);
        }
        if (message_type == "disk") {
            return disk_space(extra_params_[message_type]);
        }
        if (message_type == "docker") {
            auto docker_info = exec_command("docker ps --no-trunc -a");
            if (!docker_info.empty()) {
                std::vector<std::string> res;
                boost::replace_all(docker_info, "CONTAINER ID", "CONTAINER_ID");
                const auto names = split("CONTAINER_ID,IMAGE,COMMAND,CREATED,STATUS,PORTS,NAMES", ",");
                const auto lines = split(docker_info, "\n");

                auto result = process_lines(lines, names);
                return inject_common_data(action, "[" + join(result, ",") + "]");
            }
        }
        if (message_type == "python") {
            command = "ps -eo pcpu,pmem,pid,ppid,user,etime,command | grep python";
            action = "python";
            message_type = "_ps";
        }
        if (message_type == "ps") {
            command = "ps -eo pcpu,pmem,pid,ppid,user,etime,command";
            action = "ps";
            message_type = "_ps";
        }
        if (message_type == "_ps") {
            auto ps_info = exec_command(command);
            const auto names = split("PCPU,PMEM,PID,PPID,USER,ELAPSED,COMMAND", ",");
            const auto lines = split(ps_info, "\n");

            std::vector<std::string> result;
            for (ulong n = 1; n < lines.size(); n++) {
                auto & line = lines.at(n);
                if (!line.empty()) {
                    auto data = parse_command_line_ps(line, 6, names);
                    result.push_back(as_json_string(data));
                }
            }
            return inject_common_data(action, "[" + join(result, ",") + "]");
        }
        if (message_type == "df") {
            auto df_info = exec_command("df -l");
            const auto lines = split(df_info, "\n");
            auto header_line = lines.at(0);
            boost::replace_all(header_line, "Mounted on", "Mounted_on");
            auto names = split_trim(header_line, " ");
            std::string mount_point_str = extra_params_[message_type];
            std::vector<std::string> mount_points = split_trim(mount_point_str, ";");

            std::vector<std::string> result;
            for (ulong i=1; i<lines.size(); i++) {
                if (lines.at(i).empty()) {
                    break;
                }

                std::vector<std::pair<std::string, std::string>> data;
                auto values = split_trim(lines.at(i), " ");
                if (!mount_points.empty()) {
                    auto & mount_point = values[5];
                    if (count(mount_points.begin(), mount_points.end(), mount_point) <= 0) {
                        continue;   // skip this disk
                    }
                }
                for (ulong j=0; j<names.size(); j++) {
                    data.push_back(std::pair(names[j], values[j]));
                }
                result.push_back(as_json_string(data));
            }
            return inject_common_data(action, "[" + join(result, ",") + "]");
        }
        return "INVALID MODE";
    }

    void send_message(std::string message) {
        if (print_sent_message_) {
            std::cout << message << "\n\n";
        }
        socket_.async_send_to(boost::asio::buffer(message), endpoint_,
                              [this](const boost::system::error_code& ec, size_t bytes_recvd){ handle_and_do_noting(ec, bytes_recvd); });
    }

    void send_message_and_next(std::string message) {
        std::cout << "start sending data....\n";
        if (print_sent_message_) {
            std::cout << message << "\n\n";
        }
        socket_.async_send_to(boost::asio::buffer(message), endpoint_,
                              [this](const boost::system::error_code& ec, size_t bytes_recvd){ handle_send_to(ec, bytes_recvd); });
        std::this_thread::sleep_for(std::chrono::milliseconds(1 * 1000));
    }

    static void handle_and_do_noting(const boost::system::error_code& ec, size_t bytes_recvd) {
    }

    void handle_send_to(const boost::system::error_code& ec, size_t bytes_recvd) {
        if (!ec) {
            timer_.expires_from_now(std::chrono::seconds{timeout_});
            timer_.async_wait([this](const boost::system::error_code &ec) { handle_timeout(ec); });
        }
        else {
            std::cout << "ERROR (" << ec << ")\n";
        }
    }

    bool need_start(std::string action, uint64_t current_time) {
        if (timeouts_.find(action) != timeouts_.end()) {
            auto last_started = times_[action];
            auto timeout = timeouts_[action];
            return last_started == 0 || last_started + timeout  < current_time;
        }
        return false;
    }

    void handle_timeout(const boost::system::error_code& ec) {
        while (true) {
            uint64_t current_time = time_current_seconds();
            if (need_start("disk", current_time))   send_message(compose_message("disk"));
            if (need_start("docker", current_time)) send_message(compose_message("docker"));
            if (need_start("ps", current_time))     send_message(compose_message("ps"));
            if (need_start("df", current_time))     send_message(compose_message("df"));
            if (need_start("net", current_time))    send_message(compose_message("net"));
            if (need_start("memory", current_time)) send_message(compose_message("memory"));
            if (need_start("python", current_time)) send_message(compose_message("python"));
            if (need_start("cpu", current_time))    send_message(compose_message("cpu"));

            std::this_thread::sleep_for(std::chrono::milliseconds(1 * 1000));
        }
    }
};


void usage_massage(const char * pname) {
    std::cerr << "usage:" << pname << " <multicast group / UDP IP > <port> <default_timeout_sec> [--actions=\"cpu:N,disk:N[<mount1;mount2;..>],df:N[<mount1;..>],ps:N,python:N,docker:N\"]  [-d | -p]\n";
}

int main(int argc, char* argv[]) {
    try {
        if (argc < 4) {
            usage_massage(argv[0]);
            return EXIT_FAILURE;
        }
        auto address = argv[1];
        auto port = argv[2];
        auto timeout_sec = argv[3];
        bool need_daemonize = false;
        bool self_print = false;
        auto params = "\"cpu:5,disk:120[/],df:120[/],ps:30,net:20,memory:30,python:30,docker:120\"";

        if (argc > 4 && std::string(argv[4]).find("--actions=") == 0) {
            params = argv[4];
        }

        if (argc > 5) {
            if (std::string(argv[5]) == "-d") {
                need_daemonize = true;
            }
            else if (std::string(argv[5]) == "-p") {
                self_print = true;
            }
            else {
                std::cout << "unrecognised key '" << std::string(argv[5]) << "'\n";
                usage_massage(argv[0]);
                return EXIT_FAILURE;
            }
        }

        std::cout << "\"" << argv[0] << "\" started. \n";
        std::cout << "address: [" << address << "]   port: [" << port << "] default timeout: [" << timeout_sec << "] sec; " <<  params << "\n";

        if (need_daemonize) {
            std::cout << "Run as daemon...\n";
            daemonize();
        }

        boost::asio::io_context ioc;
        PerformSender sender(ioc, atoi(timeout_sec), boost::asio::ip::address::from_string(address), (short unsigned)atoi(port), params, self_print);
        ioc.run();
    }
    catch (std::exception& e) {
        std::cerr << "std::exception: " << e.what() << '\n';
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}


int _main(int argc, char* argv[]) {
    try {

        auto address = "127.0.0.1";
        auto port = "20008";
        auto timeout_sec = "1";

        auto params = "--actions=\"cpu:60,disk:30[/;/data],memory\"";
        boost::asio::io_context ioc;
        PerformSender sender(ioc, atoi(timeout_sec),
                          boost::asio::ip::address::from_string(address),
                      (short unsigned)atoi(port), params, true);
        ioc.run();
    }
    catch (std::exception& e) {
        std::cerr << "std::exception: " << e.what() << '\n';
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
