#include <regex>
#include <iostream>
#include <iomanip>
#include <chrono>
#include <cstdlib>
#include <unordered_map>

typedef std::chrono::system_clock::time_point timestamp_t;
typedef uint64_t handler_id_t;
typedef uint64_t socket_id_t;

inline double
getDouble(std::smatch const& sm, size_t i)
{
    return std::strtod(sm[i].str().c_str(), nullptr);
}

inline timestamp_t
getTimestamp(std::smatch const& sm, size_t i)
{
    double s = getDouble(sm, i);
    return timestamp_t(std::chrono::microseconds((uint64_t)(s * 1000000.0)));
}

inline uint64_t
getMicros(timestamp_t const& t)
{
    return std::chrono::duration_cast<std::chrono::microseconds>(t.time_since_epoch()).count();
}

inline uint64_t
getMicroDelta(timestamp_t const& curr, timestamp_t const& prev)
{
    if (prev == timestamp_t())
    {
        return 0;
    }
    else
    {
        return std::chrono::duration_cast<std::chrono::microseconds>(curr - prev).count();
    }
}

inline uint64_t
getU64(std::smatch const& sm, size_t i)
{
    return std::strtoull(sm[i].str().c_str(), nullptr, 0);
}

typedef enum {
    socket_read_handler,
    socket_write_handler,
    work_handler,
    invalid_handler
} handler_type_t;

struct handler_info
{
    handler_info(handler_type_t t, timestamp_t born) : type(t), birth(born) {}
    handler_info() {}
    handler_type_t type{invalid_handler};
    timestamp_t birth;
    timestamp_t issued;
    timestamp_t entered;
    timestamp_t exited;
    char const *getTypeName() const {
        switch (type) {
        case socket_read_handler:
            return "socket-read";
        case socket_write_handler:
            return "socket-write";
        case work_handler:
            return "work";
        case invalid_handler:
        default:
            return "invalid";
        }
    }
    bool isSocket() const {
        return type == socket_read_handler || type == socket_write_handler;
    }
    bool isRead() const {
        return type == socket_read_handler;
    }
    uint64_t sinceCreated(timestamp_t now) const {
        return getMicroDelta(now, birth);
    }
    uint64_t sinceIssued(timestamp_t now) const {
        return getMicroDelta(now, issued);
    }
    uint64_t sinceEntered(timestamp_t now) const {
        return getMicroDelta(now, entered);
    }
    size_t retries{0};
    size_t errors{0};
};

int main()
{
    auto debug = true;
    auto r = std::regex("^@asio\\|(\\d+\\.\\d+)\\|(\\d*)([><\\.\\*])(\\d+)\\|(.*)$",
                        std::regex::ECMAScript);

    auto socket_call_birth_regex =
        std::regex("^@asio\\|(\\d+\\.\\d+)\\|(\\d+)\\*(\\d+)"
                   "\\|socket@(0x[[:xdigit:]]+)\\.async_(send|receive)$",
                   std::regex::ECMAScript);

    auto context_post_birth_regex =
        std::regex("^@asio\\|(\\d+\\.\\d+)\\|(\\d+)\\*(\\d+)\\|io_context.*$",
                   std::regex::ECMAScript);

    auto socket_call_issue_regex =
        std::regex("^@asio\\|(\\d+\\.\\d+)\\|\\.(\\d+)"
                   "\\|non_blocking_(send|recv),ec=(?:asio\\.)?system:(\\d+),bytes_transferred=(\\d+)$",
                   std::regex::ECMAScript);

    auto handler_entry_exit_regex =
        std::regex("^@asio\\|(\\d+\\.\\d+)\\|([><])(\\d+)\\|.*$",
                   std::regex::ECMAScript);

    timestamp_t prev_timestamp;

    std::unordered_map<handler_id_t,handler_info> handlers;
    bool in_handler = false;

    while (std::cin)
    {
        std::string line;
        std::getline(std::cin, line);
        std::smatch m;
        if (std::regex_search(line, m, socket_call_birth_regex))
        {
            timestamp_t timestamp = getTimestamp(m, 1);
            handler_id_t parent = getU64(m, 2);
            handler_id_t child = getU64(m, 3);
            socket_id_t socket = getU64(m, 4);
            bool send = (m[5].str() == "send");
            handlers[child] = handler_info(send ? socket_write_handler : socket_read_handler,
                                           timestamp);
            if (debug)
            {
                std::cout << '[' << getMicros(timestamp) << ']'
                          << " +" << std::left << std::setw(8)
                          << getMicroDelta(timestamp, prev_timestamp)
                          << (in_handler ? "\t\t" : "")
                          << " create new socket-" <<  (send ? "send" : "recv")
                          << " handler " << child
                          << " for socket " << socket
                          << std::endl;
            }
            prev_timestamp = timestamp;
        }
        else if (std::regex_search(line, m, context_post_birth_regex))
        {
            timestamp_t timestamp = getTimestamp(m, 1);
            handler_id_t parent = getU64(m, 2);
            handler_id_t child = getU64(m, 3);
            handlers[child] = handler_info(work_handler, timestamp);
            if (debug)
            {
                std::cout << '[' << getMicros(timestamp) << ']'
                          << " +" << std::left << std::setw(8)
                          << getMicroDelta(timestamp, prev_timestamp)
                          << (in_handler ? "\t\t" : "")
                          << " post new work handler " << child
                          << std::endl;
            }
            prev_timestamp = timestamp;
        }
        else if (std::regex_search(line, m, socket_call_issue_regex))
        {
            timestamp_t timestamp = getTimestamp(m, 1);
            handler_id_t handler = getU64(m, 2);
            bool send = (m[3].str() == "send");
            uint64_t err = getU64(m, 4);
            uint64_t bytes = getU64(m, 5);
            if (debug)
            {
                auto const& h = handlers[handler];
                std::cout << '[' << getMicros(timestamp) << ']'
                          << " +" << std::left << std::setw(8)
                          << getMicroDelta(timestamp, prev_timestamp)
                          << (in_handler ? "\t\t" : "")
                          << " issue socket-" << (send ? "send" : "recv") << " syscall"
                          << ", handler:" << handler
                          << ", err:" << err
                          << ", bytes:" << bytes
                          << ", sinceCreated:" << h.sinceCreated(timestamp) << "us"
                          << std::endl;
            }
            if (err == 0)
            {
                handlers[handler].issued = timestamp;
            }
            else if (err == 11) // EAGAIN
            {
                handlers[handler].retries++;
            }
            else
            {
                handlers[handler].errors++;
            }
            prev_timestamp = timestamp;
        }
        else if (std::regex_search(line, m, handler_entry_exit_regex))
        {
            timestamp_t timestamp = getTimestamp(m, 1);
            bool entry = (m[2].str().at(0) == '>');
            handler_id_t handler = getU64(m, 3);
            in_handler = entry;
            if (debug)
            {
                auto const& h = handlers[handler];
                std::cout << '[' << getMicros(timestamp) << ']'
                          << " +" << std::left << std::setw(8)
                          << getMicroDelta(timestamp, prev_timestamp);

                if (entry)
                {
                    std::cout << " >>> enter " << h.getTypeName() << " handler " << handler
                              << " (" << h.sinceCreated(timestamp) << "usec since creation";
                    if (h.isSocket())
                    {
                        std::cout << ", " <<  h.sinceIssued(timestamp) << "usec since issue";
                        if (h.retries != 0)
                        {
                            std::cout << ", " << h.retries << " retries";
                        }
                        if (h.errors != 0)
                        {
                            std::cout << ", " << h.errors << " errors";
                        }
                    }
                    std::cout << ")"
                              << std::endl;
                }
                else
                {
                    std::cout << " <<< exit " << h.getTypeName() << " handler " << handler
                              << " (" << h.sinceCreated(timestamp) << "usec since creation"
                              << ", " << h.sinceEntered(timestamp) << "usec since entry)"
                              << std::endl;
                }
            }
            if (in_handler)
            {
                handlers[handler].entered = timestamp;
            }
            else
            {
                handlers.erase(handler);
            }
            prev_timestamp = timestamp;
        }
    }
}
