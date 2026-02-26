/* main.c
 * The main of Cameradar on C
 * No license
 */

#include "cam.h"

bool loadCensysKey (censysAuth* auth, radarType* target)
{
  FILE *f = fopen ("censys.api", "r");
  if (!f) {
    fprintf (stderr, COL_RED "\n[ERROR] File censys.api not found\n" COL_DEF);
    return false;
  }
  char token[128];
  if (fscanf (f, "%127s", token) != 1) {
    fclose (f); return false;
  }
  fclose (f);
  
  CURL *curl = curl_easy_init ();
  if (curl) {
    char url[256];
    char auth_header[256];
    struct in_addr ipStruct;
    ipStruct.s_addr = target->ipAddr;
    
    snprintf (url, sizeof (url), "https://api.platform.censys.io/%s", inet_ntoa (ipStruct));
    snprintf (auth_header, sizeof (auth_header), "Authorization: Bearer %s", token);
    
    struct curl_slist *headers = NULL;
    headers = curl_slist_append (headers, "Accept: application/vnd.censys.api.v3.host.v1+json");
    headers = curl_slist_append (headers, auth_header);
    
    curl_easy_setopt (curl, CURLOPT_URL, url);
    curl_easy_setopt (curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt (curl, CURLOPT_TIMEOUT, 10L);
    
    printf (COL_CYAN "[INFO] Do a query to the censys api for %s\n" COL_DEF, inet_ntoa (ipStruct));
    
    CURLcode res = curl_easy_perform (curl);
    if (res != CURLE_OK) {
      fprintf (stderr, COL_RED "[ERROR] Curl output: %s\n" COL_DEF, curl_easy_strerror (res));
    }
              
    curl_slist_free_all (headers);
    curl_easy_cleanup (curl);
  }
}

bool bruteforce (radarType* target)
{
  FILE *fLog = fopen ("brute/logins.txt", "r");
  FILE *fPass = fopen ("brute/passwords.txt", "r");
  
  if (!fLog || !fPass) {
    fprintf (stderr, COL_RED "\n[ERROR] Keywords not found in brute dir!!\n" COL_DEF);
    return false;
  }
  
  char login[256], pass[256]; 
  while (fgets(login, sizeof(login), fLog)) {
        login[strcspn(login, "\n")] = 0; 
        
        rewind(fPass); 
          while (fgets(pass, sizeof(pass), fPass)) {
            pass[strcspn(pass, "\n")] = 0;

            int fd = spawnSock(target);
            if (fd < 0) continue;

            char request[512];
            snprintf(request, sizeof(request),
                     "DESCRIBE rtsp://%s:%s@%s:%d/ RTSP/1.0\r\n"
                     "CSeq: 1\r\n\r\n", 
                     login, pass, inet_ntoa(*(struct in_addr*)&target->ipAddr), target->port);

            send(fd, request, strlen(request), 0);
            char response[1024];
            int received = recv(fd, response, sizeof(response)-1, 0);
            close(fd);

            if (received > 0) {
                response[received] = '\0';  
                if (strstr(response, "RTSP/1.0 200 OK")) {
                    printf(COL_GRN "[SUCCESS] Found: %s:%s\n" COL_DEF, login, pass);
                    fclose(fLog); fclose(fPass);
                    return true;
                }
            }
            printf("\r[BRUTE] Trying %s:%s...  ", login, pass);
            fflush(stdout);
        }
    }
    
    fclose(fLog); fclose(fPass);
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
  return sockfd;
}

bool check4Cam (int sockfd, radarType* target)
{
  char buf[1024];
  char req[256];
  
  snprintf (req, sizeof (req),
            "DESCRIBE rtsp://%s:%d/ RTSP/1.0\r\n"
            "CSeq: 1\r\n\r\n",  
            inet_ntoa (*(struct in_addr*)&target->ipAddr), target->port);
  
  if (send(sockfd, req, strnlen (req, sizeof (req)), 0) < 0) {  
       return false;
  }
  
  ssize_t received = recv (sockfd, buf, sizeof (buf) - 1, 0); 
  if (received > 0) {
    buf[received] = '\0';
    
    if (strstr (buf, "RTSP/1.0") != NULL) {
      char *server_head = strstr (buf, "Server:");
      if (server_head) {
        snprintf (target->service, sizeof (target->service), "RTSP (%.20s)", server_head + 8);        
      } else {
        snprintf (target->service, sizeof (target->service), "RTSP"); 
      }
      return true;
    }
  }
  return false;
}

void scanim (void)
{
  const char* erp[] = {"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"};
  int frameof = 0;
  int num_frames = 10;
  
  for (int i = 0; i < 40; i++) { 
    printf ("\rScanning... %s", erp[frameof]);
    
    fflush (stdout);
    frameof = (frameof + 1) % num_frames;
    
    usleep (100000);
  }
  printf("\n");
}

void usage (void)
{
  printf (COL_CYAN "\n Welcome to the CameradarC!\n" COL_DEF);
  printf ("\n Usage:\n");
  printf ("\n       -t value(ip)\n");
  printf ("\n       -p value, you can type an any port that needs to scan for RTSP\n");
  printf ("\n       -b with this you can do bruteforce, reading the logins and passwords text file in brute dir\n");
  printf ("\n       -aV with this you can do query to censys, needs token from censys and put is to censys.api file\n");
  printf ("\n Github: https://github.com/gnom2949/cameradarC\n");
  printf ("\n Credits: https://github.com/Ullaakut/cameradar\n");
  printf ("\nThis is a free software under GNU GPLv3, see more: https://www.gnu.org/licenses/gpl-3.0.html\n");
  exit (1);
}

void* threadScan (void* arg)
{
  // copying memory to avoid TOCTOU (race condition)
  radarType* data = (radarType*)arg;
  
  int s = spawnSock (data);
  if (s >= 0) {
    printf (COL_GRN "\n[INFO] Port %d is OPEN\n" COL_DEF, data->port);  
    
    if (check4Cam (s, data)) {
      printf (COL_CYAN "\n[INFO] RTSP CAMERA FOUND\n" COL_DEF);
    }
    close (s);
  }
  
  free (data);
  return NULL;
}

int main (int argc, char *argv[])
{
  radarType target = {0};
  censysAuth auth = {0};
  target.timeout_ms = 1000;
  
  static struct option ion[] = {
    {"target", required_argument, 0, 't'},
    {"port", required_argument, 0, 'p'},
    {"brute", no_argument, 0, 'b'},
    {"all", no_argument, 0, 'a'},
    {"vulnerability", no_argument, 0, 'V'},
    {"help", no_argument, 0, 'h'},
    {0, 0, 0, 0}
  };
  
  int opt, optIndex = 0, portSt = 0, portEnd = 0;
  int bruteF = 0, allF = 0, vulnF = 0;
   
  while ((opt = getopt_long (argc, argv, "t:p:", ion, &optIndex)) != -1) {
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
        if (bruteforce (&target)) {
          printf (COL_CYAN "\n[INFO] Starting brute force\n" COL_DEF);
          scanim ();
          if (!bruteforce (&target)) {
            fprintf (stderr, COL_RED "\n[FAILURE] No valid credentials found!\n" COL_DEF);
            exit (1);
          }
        }
        break;
      case 'h':
        usage();
        return 0;
        break;
      case 'a':
        allF = 1;
        break;
      default:
        usage();
        return 1;
    }
  }
  
  if (target.ipAddr == INADDR_NONE || portSt == 0) { 
    usage();
    return 1;
  }
  
  printf (COL_CYAN "\n[INFO] Scanning target: %s\n" COL_DEF, inet_ntoa (*(struct in_addr*)&target.ipAddr));
  scanim ();
  
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
  
  for (int i = 0; i < threadCount; i++) {
    pthread_join (threads[i], NULL);
  }
  
  printf (COL_GRN "\nScan Complete\n" COL_DEF);
  return 0;
}
