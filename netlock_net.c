/*
 * NetLock networking helper.
 * Enumerate IPv4 addresses, prefer 192.x, bind/connect broadband :8000.
 * Build:
 *   gcc -O2 -shared -fPIC -o netlock_net.so netlock_net.c
 *   gcc -O2 -shared -o netlock_net.dll netlock_net.c -lws2_32   (MinGW)
 */
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#else
#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define NL_EXPORT __declspec(dllexport)
#else
#define NL_EXPORT
#endif

#define NL_BROADBAND_PORT 8000
#define NL_MAX_IFACES 32
#define NL_MAX_IP 64

typedef struct {
    char name[64];
    char ip[NL_MAX_IP];
    char netmask[NL_MAX_IP];
    int is_192;
    int is_loopback;
} NlIface;

static int g_ready = 0;

static int nl_init(void) {
#ifdef _WIN32
    if (!g_ready) {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
            return -1;
        g_ready = 1;
    }
#else
    g_ready = 1;
#endif
    return 0;
}

static int starts_192(const char *ip) {
    return ip && ip[0] == '1' && ip[1] == '9' && ip[2] == '2' && ip[3] == '.';
}

NL_EXPORT int nl_broadband_port(void) {
    return NL_BROADBAND_PORT;
}

NL_EXPORT int nl_list_ifaces(NlIface *out, int max_n) {
    int n = 0;
    if (nl_init() != 0 || !out || max_n <= 0)
        return -1;
    if (max_n > NL_MAX_IFACES)
        max_n = NL_MAX_IFACES;

#ifdef _WIN32
    ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    ULONG buf_len = 15000;
    IP_ADAPTER_ADDRESSES *addrs = NULL;
    DWORD ga_rc = ERROR_BUFFER_OVERFLOW;
    for (int attempt = 0; attempt < 4; attempt++) {
        addrs = (IP_ADAPTER_ADDRESSES *)malloc(buf_len);
        if (!addrs)
            return -1;
        ga_rc = GetAdaptersAddresses(AF_INET, flags, NULL, addrs, &buf_len);
        if (ga_rc == NO_ERROR)
            break;
        free(addrs);
        addrs = NULL;
        if (ga_rc != ERROR_BUFFER_OVERFLOW)
            return -1;
    }
    if (!addrs || ga_rc != NO_ERROR)
        return -1;
    for (IP_ADAPTER_ADDRESSES *a = addrs; a && n < max_n; a = a->Next) {
        for (IP_ADAPTER_UNICAST_ADDRESS *u = a->FirstUnicastAddress; u && n < max_n; u = u->Next) {
            if (!u->Address.lpSockaddr || u->Address.lpSockaddr->sa_family != AF_INET)
                continue;
            struct sockaddr_in *sin = (struct sockaddr_in *)u->Address.lpSockaddr;
            NlIface *row = &out[n];
            memset(row, 0, sizeof(*row));
            WideCharToMultiByte(CP_UTF8, 0, a->FriendlyName, -1, row->name, sizeof(row->name) - 1, NULL, NULL);
            inet_ntop(AF_INET, &sin->sin_addr, row->ip, sizeof(row->ip));
            row->is_192 = starts_192(row->ip);
            row->is_loopback = (ntohl(sin->sin_addr.s_addr) >> 24) == 127;
            n++;
        }
    }
    free(addrs);
#else
    struct ifaddrs *ifaddr = NULL;
    if (getifaddrs(&ifaddr) != 0)
        return -1;
    for (struct ifaddrs *ifa = ifaddr; ifa && n < max_n; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
            continue;
        struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
        NlIface *row = &out[n];
        memset(row, 0, sizeof(*row));
        snprintf(row->name, sizeof(row->name), "%s", ifa->ifa_name);
        inet_ntop(AF_INET, &sin->sin_addr, row->ip, sizeof(row->ip));
        if (ifa->ifa_netmask && ifa->ifa_netmask->sa_family == AF_INET) {
            struct sockaddr_in *mask = (struct sockaddr_in *)ifa->ifa_netmask;
            inet_ntop(AF_INET, &mask->sin_addr, row->netmask, sizeof(row->netmask));
        }
        row->is_192 = starts_192(row->ip);
        row->is_loopback = (ntohl(sin->sin_addr.s_addr) >> 24) == 127;
        n++;
    }
    freeifaddrs(ifaddr);
#endif
    return n;
}

NL_EXPORT int nl_best_192(char *ip_out, int ip_len, char *name_out, int name_len) {
    NlIface rows[NL_MAX_IFACES];
    int n = nl_list_ifaces(rows, NL_MAX_IFACES);
    if (n < 0)
        return -1;
    int pick = -1;
    for (int i = 0; i < n; i++) {
        if (rows[i].is_192 && !rows[i].is_loopback) {
            pick = i;
            break;
        }
    }
    if (pick < 0)
        return 0;
    if (ip_out && ip_len > 0) {
        snprintf(ip_out, ip_len, "%s", rows[pick].ip);
    }
    if (name_out && name_len > 0) {
        snprintf(name_out, name_len, "%s", rows[pick].name);
    }
    return 1;
}

NL_EXPORT int nl_bind_192_port(const char *ip, int port) {
    if (nl_init() != 0)
        return -1;
    int p = port > 0 ? port : NL_BROADBAND_PORT;
    int fd;
#ifdef _WIN32
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET)
        return -1;
    BOOL reuse = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(reuse));
    fd = (int)s;
#else
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    int reuse = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
#endif
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)p);
    if (ip && ip[0] && starts_192(ip))
        inet_pton(AF_INET, ip, &addr.sin_addr);
    else
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
#ifdef _WIN32
    if (bind((SOCKET)fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        closesocket((SOCKET)fd);
        return -1;
    }
    closesocket((SOCKET)fd);
#else
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    close(fd);
#endif
    return 0;
}

NL_EXPORT int nl_connect_broadband(const char *ip, int port, int timeout_ms) {
    if (nl_init() != 0 || !ip || !ip[0])
        return -1;
    int p = port > 0 ? port : NL_BROADBAND_PORT;
#ifdef _WIN32
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET)
        return -1;
    DWORD ms = timeout_ms > 0 ? (DWORD)timeout_ms : 3000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&ms, sizeof(ms));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&ms, sizeof(ms));
#else
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)
        return -1;
    struct timeval tv;
    int ms = timeout_ms > 0 ? timeout_ms : 3000;
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)p);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
#ifdef _WIN32
        closesocket(s);
#else
        close(s);
#endif
        return -1;
    }
#ifdef _WIN32
    int rc = connect(s, (struct sockaddr *)&addr, sizeof(addr));
    closesocket(s);
#else
    int rc = connect(s, (struct sockaddr *)&addr, sizeof(addr));
    close(s);
#endif
    return rc == 0 ? 1 : 0;
}

NL_EXPORT const char *nl_version(void) {
    return "netlock_net 1.0";
}
