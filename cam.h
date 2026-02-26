/* Cam.h v1
 * The header for cameradar written on C
 * No license
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <fcntl.h>
#include <getopt.h>
#include <string.h>
#include <curl/curl.h>
#include <json-c/json.h>

#ifndef C_CAM_RADAR_H
#define C_CAM_RADAR_H
#define COL_RED "\033[31m"
#define COL_GRN  "\033[32m"
#define COL_YLW   "\033[33m"
#define COL_BLU    "\033[34m"
#define COL_PRPL    "\033[35m"
#define COL_CYAN     "\033[36m"
#define COL_DEF       "\033[0m"
#define COL_BR_RED     "\033[41m"

typedef struct {
  uint32_t ipAddr;
  uint16_t port;
  bool is_open;
  double resT;
  int timeout_ms;
  char service[32];
} radarType;

typedef struct {
  char loginfild[64];
  char passfild[128];
  radarType* target;
} rtspInst;

typedef struct {
  char login[64];
  char pass[128];
} BrutePair;

typedef struct {
  char id[64];
  char secret[64];
} censysAuth;

int spawnSock (radarType* target);
bool portCheck (radarType* target);
char* ipToString (radarType* target);
void scanim (void);
bool check4Cam (int sockfd, radarType* target);
bool loadCensysKey (censysAuth* auth, radarType* target);
bool bruteforce (radarType* target);

#endif
