/* main.c
 * The main of Cameradar on C
 * SPDX-License-Identifier: GNU General Public License v3
 */

#include "cam.h"
bool ambiguous_include = false;
bool use_nmap = false;
const char *nmap_xml_file = NULL;
bool nmap_fast = false;
char port_range_string[64] = {0};
char temp_xml[] = "/tmp/gnom2949/cameradar_nmap_XXXXXX.xml";

int spawnSock (radarType* target)
{
  int sockfd;
  struct sockaddr_in addr;
  struct timeval timeout;
  
  sockfd = socket (AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    sslog (false, COL_RED, "ERROR", "socket failed");
    return -1;
  }
  
  int flags = fcntl (sockfd, F_GETFL, 0);
  fcntl (sockfd, F_SETFL, flags | O_NONBLOCK);
  
  addr.sin_family = AF_INET;
  addr.sin_port = htons (target->port);
  addr.sin_addr.s_addr = target->ipAddr;
  
  connect (sockfd, (struct sockaddr*)&addr, sizeof (addr));

  fd_set wset;
  FD_ZERO (&wset);
  FD_SET (sockfd, &wset);

  struct timeval tv;
  tv.tv_sec = target->timeout_ms / 1000;
  tv.tv_usec = (target->timeout_ms % 1000) * 1000;

  int sel = select (sockfd + 1, NULL, &wset, NULL, &tv);

  if (sel <= 0) {
    close (sockfd);
    target->is_open = false;
    return -1;
  }

  int err = 0;
  socklen_t len = sizeof (err);
  getsockopt (sockfd, SOL_SOCKET, SO_ERROR, &err, &len);
  if (err != 0) {
    char msg[64];
    snprintf (msg, sizeof (msg), "Port %d refused: %s", target->port, strerror (err));
    sslog (true, COL_YLW, "SKIP", msg);
    close (sockfd);
    target->is_open = false;
    return -1;
  }

  fcntl (sockfd, F_SETFL, flags);

  timeout.tv_sec = target->timeout_ms / 1000;
  timeout.tv_usec = (target->timeout_ms % 1000) * 1000;
  setsockopt (sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof (timeout));
  setsockopt (sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof (timeout));

  target->is_open = true;
  sslog (true, COL_GRN, "OPEN", "Socket spawned on port %d", target->port);
  return sockfd;
}

void usage (void)
{
  printf (COL_CYAN "\n Welcome to the CameradarC!\n" COL_DEF);
  printf ("\n Usage:\n");
  printf ("\n       -t --target <IP>\n");
  printf ("\n       -p --port <PORT>, you can type an any port that needs to scan for RTSP\n");
  printf ("\n       -b --brute with this you can do bruteforce, reading the logins and passwords text file in brute dir\n");
  printf ("\n       -v --verbose this is a verbose, adding more logs called 'trash'\n"); /* Trash vs garbage❤❤❤ */
  printf ("\n       -n --nmap this thing uses nmap for discovery, can takes more time\n");
  printf ("\n       --nmap-xml <FILE> this thing uses nmap for discovery, can takes more time + uses an exisiting nmap XML\n");
  printf ("\n       --nmap-fast Fast nmap mode, scanning only 100 top ports\n");
  printf ("\n       --export-json <FILE> this thing exports a result into JSON\n");
  printf ("\n       --include-amb this thing add argument that include a 'open|filtered' port from nmap XML\n");
  printf ("\n Github: https://github.com/gnom2949/cameradarC\n");
  printf ("\n Credits: https://github.com/Ullaakut/cameradar\n");
  printf ("\nThis is a free software under GNU GPLv3, see more: https://www.gnu.org/licenses/gpl-3.0.html\n");
  exit (1);
}

int main (int argc, char *argv[])
{
  pthread_t           anim_tid;
  radarType           target = {0};
  atomic_store        (&globA.active, true);
  target.timeout_ms = 1000;
  pthread_create      (&anim_tid, NULL, scanim, &globA);
  int                 opt, optIndex = 0, portSt = 0, portEnd = 0;
  int                 bruteF = 0;
  
  static struct option ion[] = {
    {"target", required_argument,      0, 't'},
    {"port", required_argument,        0, 'p'},
    {"brute", no_argument,             0, 'b'},
    {"verbose", no_argument,           0, 'v'},
    {"nmap", no_argument,              0, 'n'},
    {"nmap-xml", required_argument,    0, 1007},
    {"fast", no_argument,              0, 1008},
    {"export-json", required_argument, 0, 1000},
    {"include-amb", no_argument,       0, 1006},
    {"help", no_argument,              0, 'h'},
    {0, 0, 0, 0}
  };
   
  while ((opt = getopt_long (argc, argv, "t:p:bhvn", ion, &optIndex)) != -1) {
    switch (opt) {
      case 't':
        target.ipAddr = inet_addr (optarg);
        break;
      case 'p':
        if (strchr (optarg, '-')) {
          sscanf (optarg, "%d-%d", &portSt, &portEnd);
          snprintf (port_range_string, sizeof (port_range_string), "%d-%d", portSt, portEnd);
        } else {
          portSt = portEnd = atoi (optarg);
          snprintf (port_range_string, sizeof (port_range_string), "%d", portSt);
        }
        break;
      case 'b':
        bruteF = 1;
        break;
      case 'v':
        crc_verbose_mode = true;
        break;
      case 'n':
        use_nmap = true;
        break;
      case 1008:
        nmap_fast = true;
        break;
      case 1007:
        nmap_xml_file = optarg;
        break;
      case 1000:
        crc_export_json = optarg;
      break;
      case 1006:
        ambiguous_include = true;
        sslog (false, COL_YLW, "INFO", "Including open|filtered port (less reliable)");
        break;
      case 'h':
      default:
        usage();
        return 1;
    }
  }

  if (target.ipAddr == INADDR_NONE || portSt == 0) {
    usage();
    return 1;
  }

  bool                use_nmap_mode = (use_nmap || nmap_xml_file != NULL);
  int                 totalPorts = portEnd - portSt + 1;
  ResultCtx           result_ctx = {0};
  NmRes               nmap_res = {0};
  result_init         (&result_ctx, totalPorts);
  char ipStr[INET_ADDRSTRLEN];
  
  if (use_nmap_mode) {
    const char *xml_path = nmap_xml_file;
    bool need_cleanup = false;

    if (!xml_path) {
      int fd = mkstemps (temp_xml, 4); // 4 is a length of '.xml' extension
      if (fd < 0) {
        sslog (false, COL_RED, "ERROR", "Cannot create temporary XML file");
        return 1;
      }
      close (fd);
      xml_path = temp_xml;
      need_cleanup = true;

      if (!ran_nmap (ipStr, port_range_string, xml_path, nmap_fast)) {
        if (need_cleanup) unlink (xml_path);
          return 1;
      }
    }

    nmap_parser_init (&nmap_res);
    if (!parse_www_xml (xml_path, &nmap_res, ambiguous_include)) {
      sslog(false, COL_YLW, "WARN", "No open ports found in nmap XML");
      if (need_cleanup) unlink(xml_path);
      nmap_parser_free(&nmap_res);
      return 0;
    }

    sslog (false, COL_GRN, "INFO", "Found %d open ports via nmap", nmap_res.count);
    result_init (&result_ctx, nmap_res.count);

    pthread_t threads[nmap_res.count];
    int threadCount = 0;

    for (int i = 0; i < nmap_res.count; i++) {
      radarType *threadData = malloc(sizeof(radarType));
      if (!threadData) continue;

      memcpy(threadData, &target, sizeof(radarType));
      threadData->ipAddr = nmap_res.ipAddr;
      threadData->port = nmap_res.ports[i].port;
      threadData->doBrute = bruteF;
      threadData->result_ctx = &result_ctx;

      if (pthread_create(&threads[threadCount], NULL, threadScan, threadData) != 0) {
        free(threadData);
          continue;
      }
      threadCount++;

      if (threadCount % 20 == 0) usleep(100000);
    }

    for (int i = 0; i < threadCount; i++) {
      pthread_join(threads[i], NULL);
    }

    if (need_cleanup) {
      unlink (xml_path);
      nmap_parser_free (&nmap_res);
    }
  } else {
    pthread_t *threads = calloc (totalPorts, sizeof (pthread_t));

    if (!threads) {
      fprintf (stderr, COL_RED "[FAILURE] Memory Allocation failed!\n" COL_DEF);
      return 1;
    }
    
    int threadCount = 0;

    for (int p = portSt; p <= portEnd; p++) {
      radarType* threadData = malloc (sizeof (radarType));
      if (!threadData) continue;

      memcpy (threadData, &target, sizeof (radarType));
      threadData->port = (uint16_t)p;
      threadData->doBrute = bruteF;
      threadData->result_ctx = &result_ctx;

      pthread_create (&threads[threadCount], NULL, threadScan, threadData);
      threadCount++;

      if (threadCount % 50 == 0) usleep (50000);
    }

    for (int i = 0; i < threadCount; i++)
    {
          pthread_join (threads[i], NULL);
    }

    atomic_store (&globA.active, false);
    pthread_join (anim_tid, NULL);

    struct in_addr addr = {.s_addr = target.ipAddr};
    inet_ntop (AF_INET, &addr, ipStr, sizeof (ipStr));

    result_print_summary (&result_ctx, ipStr);\

    if (crc_export_json) {
      export_result_json (&result_ctx, ipStr, crc_export_json);
    }
  }
  
   atomic_store(&globA.active, false);
    pthread_join(anim_tid, NULL);

    struct in_addr addr = {.s_addr = target.ipAddr};
    inet_ntop(AF_INET, &addr, ipStr, sizeof(ipStr));

    result_print_summary(&result_ctx, ipStr);

    if (crc_export_json) {
        export_result_json(&result_ctx, ipStr, crc_export_json);
    }

    result_free(&result_ctx);
    return 0;
}
