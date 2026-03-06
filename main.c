/* main.c
 * The main of Cameradar on C
 * No license
 */

#include "cam.h"

static size_t WrMemCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    if (!contents || !userp) return 0;
    struct MemBuf *mem = userp;
    if (nmemb != 0 && size > SIZE_MAX / nmemb) return 0;

    size_t realsize = size * nmemb;

    if (mem->size > SIZE_MAX - realsize - 1) return 0;
    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (!ptr) return 0;

    mem->memory = ptr;

    memcpy(mem->memory + mem->size, contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = '\0';

    return realsize;
}

void bsfEncode (const char* input, char* output)
{
  const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  int i = 0, j = 0;
  int len = strlen (input);
  unsigned char tmp[3];
  
  while (len--) {
    tmp[i++] = *(input++);
    if (i == 3) {
      output[j++] = table[tmp[0] >> 2];
      output[j++] = table[((tmp[0] & 0x03) << 4) | (tmp[1] >> 4)];
      output[j++] = table[((tmp[1] & 0x0f) << 2) | (tmp[2] >> 6)];
      output[j++] = table[tmp[2] & 0x03f];
      i = 0;
    }
  }
  
  if (i) {
    output[j++] = table[tmp[0] >> 2];
    if (i == 1) {
      output[j++] = table[(tmp[0]  & 0x03) << 4];
      output[j++] = '=';    
    } else {
      output[j++] = table[((tmp[0] & 0x03) << 4) | (tmp[1] >> 4)];
      output[j++] = table[(tmp[1] & 0x0f) << 2];
    }
    output[j++] = '=';
  }
  output[j] = '\0';
}

bool bruteforce (radarType* target)
{
  pthread_t anim_tid;
  atomic_store (&globA.active, true);
  FILE *fLog = fopen ("brute/logins.txt", "r");
  FILE *fPass = fopen ("brute/passwords.txt", "r");
  pthread_create (&anim_tid, NULL, scanim, &globA);
  
  if (!fLog || !fPass) {
    fprintf (stderr, COL_RED "\n[ERROR] Keywords not found in brute dir!!\n" COL_DEF);
    if (fLog) fclose (fLog); if (fPass) fclose (fPass);
    return false;
  }
  
  char login[128], pass[128];
  char rawAu[128], bsfAu[256];
  char req[1024], resp[1024];
  char *ip = inet_ntoa (*(struct in_addr*)&target->ipAddr);
  
  for (int p = 0; p < 5; p++) {
    rewind (fLog);
    while (fgets (login, sizeof (login), fLog)) {
      login[strcspn (login, "\r\n")] = 0;
      
      rewind (fPass);
      while (fgets (pass, sizeof (pass), fPass)) {
        pass[strcspn (pass, "\r\n")] = 0;
        
        int fd = spawnSock (target);
        if (fd < 0) usleep (500000); continue;
        
        // prepare a header in base64
        snprintf (rawAu, sizeof (rawAu), "%s:%s", login, pass);
        bsfEncode (rawAu, bsfAu);
        
        // describe
        snprintf (req, sizeof (req),
                  "DESCRIBE rtsp://%s:%d%s RTSP/1.0\r\n"
                  "CSeq: 1\r\n"
                  "Authorization: Basic %s\r\n"
                  "User-Agent: SatWatcher/1.0\r\n\r\n",
                  ip, target->port, rtspPath[p], bsfAu);
        
        send (fd, req, strnlen (req, sizeof req), 0);
        
        memset (resp, 0, sizeof (resp));
        int received = recv (fd, resp, sizeof(resp) - 1, 0);
        close (fd);
        
        if (received > 0) {
          if (strstr (resp, "RTSP/1.0 200")) {
            printf (COL_GRN "\n[SUCCESS] %s:%d%s -> %s:%s\n" COL_DEF, ip, target->port, rtspPath[p], login, pass);
            FILE *res = fopen ("found.txt", "a");
            fprintf (res, "rtsp://%s:%s@%s:%d%s\n", login, pass, ip, target->port, rtspPath[p]);
            fclose (res);
            
            fclose (fLog); fclose (fPass);
            return true;
          }
        }
        printf (globA.msg, 256, COL_BLU "\r[INFO] Brute %s:%s on %s, please wait." COL_DEF, login, pass, rtspPath[p]);
        fflush (stdout);
        
        usleep (100000);
      }
    }
  } 
  atomic_store (&globA.active, false);
  pthread_join (anim_tid, NULL);
  fclose(fLog);
  fclose(fPass);
  return false;
}

int spawnSock (radarType* target)
{
  int sockfd;
  struct sockaddr_in addr;
  struct timeval timeout;
  
  sockfd = socket (AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) return -1;
  
  timeout.tv_sec = target->timeout_ms / 1000;
  timeout.tv_usec = (target->timeout_ms % 1000) * 1000;
  
  setsockopt (sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof (timeout));
  setsockopt (sockfd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof (timeout));
  
  addr.sin_family = AF_INET;
  addr.sin_port = htons (target->port);
  addr.sin_addr.s_addr = target->ipAddr;
  
  if (connect (sockfd, (struct sockaddr*)&addr, sizeof (addr)) < 0) {
    close (sockfd);
    target->is_open = false;
    return -1;
  }
  
  target->is_open = true;
  printf (COL_GRN "\n[SUCC]Socket spawned\n" COL_DEF);
  return sockfd;
}

bool check4Cam (int sockfd, radarType* target) 
{
  char buf[1024];
  char req[512];
  char ipStr[INET_ADDRSTRLEN];
  strncpy (ipStr, inet_ntoa (*(struct in_addr*)&target->ipAddr), INET_ADDRSTRLEN);
  
  for (int i = 0; i < (sizeof (rtspPath)/sizeof(char*)); i++) {
    snprintf (req, sizeof (req),
              "DESCRIBE rtsp://%s:%d%s RTSP/1.0\r\n"
              "CSeq: 1\r\n"
              "User-Agent: SatWatcher/1.0\r\n"
              "Accept: application/sdp\r\n\r\n",          
              ipStr, target->port, rtspPath[i]);
    
    send (sockfd, req, strlen (req), 0);
    memset (buf, 0, sizeof (buf));
    ssize_t received = recv (sockfd, buf, sizeof (buf) - 1, 0);
    
    if (received > 0) {
      
      if (strstr (buf, "RTSP/1.0") != NULL) {
        
        if (strstr (buf, "200 OK") != NULL) {
          printf (COL_GRN "\n[SUCCESS] Found opened stream: rtsp://%s:%d%s\n" COL_DEF, ipStr, target->port, rtspPath[i]);
          snprintf (target->service, sizeof (target->service), "RTSP OPEN");
          return true;  
        }
        
        if (strstr (buf, "401") != NULL || strstr (buf, "Unathorized") != NULL) {
          printf (COL_YLW "\n[WARNING] Path Found: %s, needed login!\n" COL_DEF, rtspPath[i]);
          snprintf (target->service, sizeof (target->service), "RTSP AUTH REQUIRED!", rtspPath[i]);
          return true;
        }                                     
      }
    }
  }
  return false;
}

void* scanim (void* arg)
{
  aConf* cfg = (aConf*)arg;
  const char* frames[] = {"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"};
  int i = 0;
  while (atomic_load (&cfg->active)) {
    printf ("\r\33[2K" COL_PRPL "[%s] %s" COL_DEF, frames[i++ % 10], cfg->msg);
    fflush (stdout);
    usleep (80000);
  }
  return NULL;
}

void usage (void)
{
  printf (COL_CYAN "\n Welcome to the CameradarC!\n" COL_DEF);
  printf ("\n Usage:\n");
  printf ("\n       -t value(ip)\n");
  printf ("\n       -p value, you can type an any port that needs to scan for RTSP\n");
  printf ("\n       -b with this you can do bruteforce, reading the logins and passwords text file in brute dir\n");
  printf ("\n Github: https://github.com/gnom2949/cameradarC\n");
  printf ("\n Credits: https://github.com/Ullaakut/cameradar\n");
  printf ("\nThis is a free software under GNU GPLv3, see more: https://www.gnu.org/licenses/gpl-3.0.html\n");
  exit (1);
}

void* threadScan(void* arg) {
    radarType* data = (radarType*)arg;
    
    int fd = spawnSock(data);
    if (fd >= 0) {
        printf(COL_GRN "\n[INFO] Port %d is OPEN\n" COL_DEF, data->port);
        
        if (check4Cam (fd, data)) {
            if (data->doBrute) {
                bruteforce(data);
            }
        }
        close(fd);
    }
    
    free(data);
    return NULL;
}


int main (int argc, char *argv[])
{
  pthread_t anim_tid;
  radarType target = {0};
  atomic_store (&globA.active, true);
  target.timeout_ms = 1000;
  pthread_create (&anim_tid, NULL, scanim, &globA);
  
  static struct option ion[] = {
    {"target", required_argument, 0, 't'},
    {"port", required_argument, 0, 'p'},
    {"brute", no_argument, 0, 'b'},
    {"help", no_argument, 0, 'h'},
    {0, 0, 0, 0}
  };
  
  int opt, optIndex = 0, portSt = 0, portEnd = 0;
  int bruteF = 0;
   
  while ((opt = getopt_long (argc, argv, "t:p:bh", ion, &optIndex)) != -1) {
    switch (opt) {
      case 't':
        target.ipAddr = inet_addr (optarg);
        break;
      case 'p':
        if (strchr (optarg, '-')) {
          sscanf (optarg, "%d-%d", &portSt, &portEnd);
        } else {
          portSt = portEnd = atoi (optarg);
        }
        break;
      case 'b':
        bruteF = 1;
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
  
  printf (globA.msg, 256,COL_CYAN "\n[INFO] Scanning target: %s\n" COL_DEF, inet_ntoa (*(struct in_addr*)&target.ipAddr));
  
  pthread_t threads[portEnd - portSt + 1];
  int threadCount = 0;
  
  for (int p = portSt; p <= portEnd; p++) {
    // creating a copy for every thread
    radarType* threadData = (radarType*)malloc(sizeof(radarType));
    if (!threadData) {  
      perror(COL_BR_RED "Failed to allocate memory" COL_DEF);
      continue;
    }
    memcpy (threadData, &target, sizeof (radarType));
    threadData->port = (uint16_t)p;
    
    if (pthread_create (&threads[threadCount++], NULL, threadScan, threadData) != 0) {
      perror ("Failed to create thread");
      free(threadData); 
      continue;
    }
                                            
    usleep (1000); 
  }
  
  if (bruteF) {
    bruteforce (&target);
  }
  
  for (int i = 0; i < threadCount; i++) {
    pthread_join (threads[i], NULL);
  }
  
  printf (COL_GRN "\nScan Complete\n" COL_DEF);
  return 0;
}
