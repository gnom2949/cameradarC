/* Cam.h v1
 * The header for cameradar written on C
 * SPDX-License-Identifier: GNU General Public License v3
*/
#ifndef C_CAM_RADAR_H
#define C_CAM_RADAR_H

// === Macroses === //
#ifdef DEBUG
#define DBG_IP (var) sslog (false,  COL_YLW, "DEBUG", #var " = '%s' (0x%08x)", var, *(uint32_t*)(var))
#else
#define DBG_IP (var) ((void)0)
#endif
#define COL_RED "\033[31m"
#define COL_GRN  "\033[32m"
#define COL_YLW   "\033[33m"
#define COL_BLU    "\033[34m"
#define COL_PRPL    "\033[35m"
#define COL_CYAN     "\033[36m"
#define COL_DEF         "\033[0m"
#define COL_BR_RED     "\033[41m"
// === End === //

// === Includes === //
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <fcntl.h>
#include <getopt.h>
#include <string.h>
#include <curl/curl.h>
#include <json-c/json.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdarg.h>
#include <imm/IntMemoryManager.h>
// === End === //

// === Structs and enums === //
typedef struct {
  uint16_t  port;
  bool      is_open;
  bool      is_camera; // if RTSP detected
  bool      needs_auth; // if cam responded by xml or http within 401 or Unauthorized
  char      service[64]; // RTSP OPEN, RTSP AUTH, etc.
  char      path[128]; // path for RTSP
} ScanResult;

typedef struct {
  ScanResult *results;
  int count;
  int cap;
  pthread_mutex_t mutex;
} ResultCtx;

typedef struct {
  uint32_t   ipAddr;
  uint16_t   port;
  bool       is_open;
  double     resT;
  int        timeout_ms;
  char       service[32];
  bool       doBrute;
  bool       doVuln;
  ResultCtx *result_ctx;
} radarType;

typedef struct {
  char       loginfild[64];
  char       passfild[128];
  radarType* target;
} rtspInst;

typedef struct {
  char  login[64];
  char  pass[128];
} BrutePair;

struct MemBuf {
  char   *memory;
  size_t size;
};

typedef struct {
  char        msg[512];
  atomic_bool active;
  atomic_bool found;
  atomic_bool pause;
  pthread_mutex_t found_mutex;
} aConf;

typedef enum {
  PORT_CLOSE,
  PORT_OPEN,
  PORT_FILTER,      // filtered, close by firewall
  PORT_OPEN_FILTER, // if output state equals: 'open|filtered'
} PState;

typedef struct {
  uint16_t port;
  PState   state;
  char     service[64];
  char     version[128];
} PInfo;

typedef struct {
  uint32_t ipAddr;
  char     ipStr[INET_ADDRSTRLEN];
  PInfo    *ports;
  int      count;
  int      cap;
} NmRes;

// === End === //

extern aConf globA;
int spawnSock (radarType* target);
bool portCheck (radarType* target);
char* ipToString (radarType* target);
void* scanim (void* arg);
bool check4Cam (int sockfd, radarType* target, ScanResult *out_result);
bool loadCensysKey (radarType* target);
bool bruteforce (radarType* target);
void parseJson (const char *jString);
void bsfEncode (const char* input, char* output);
void sslog (bool verbose_only, const char* color, const char* label, const char* msg, ...);
void* threadScan (void* arg);
void result_init (ResultCtx *ctx, int cap);
void result_add (ResultCtx *ctx, ScanResult *res);
void result_print_summary (ResultCtx *ctx, const char *ip);
void result_free (ResultCtx *ctx);
bool export_result_json (ResultCtx  *ctx, const char *ip, const char *filename);
bool parse_www_xml (const char *xml_file, NmRes *res, bool ambiguous_include);
PState parse_port_state (const char *state_string);
void nmap_parser_add (NmRes *res, uint16_t port, PState state, const char *service, const char *version);
void nmap_parser_init (NmRes *res);
bool ran_nmap (const char *target_ip, const char *port_range, const char *xml_output, bool fast_mode);
void nmap_parser_free (NmRes *res);
int check4File (const char *path);
bool check4Right (bool use_syn_scan);
bool restart_with_sudo(int argc, char *argv[]);
char* input_prompt (const char *prompt,
                    aConf      *cfg,
                    char       *buf,
                    size_t      bufsize);


extern const char* const rtspPath[];
extern const size_t rtspPcount;
extern bool crc_verbose_mode;
extern const char *crc_export_json;
extern bool ambiguous_include;
extern bool crc_nmap_connect;

#endif
