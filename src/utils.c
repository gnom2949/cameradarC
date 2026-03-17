/* utils.c
 * Utils for Cameradar on C
 * SPDX-License-Identifier: GNU General Public License v3
 */
#include "cam.h"

aConf           globA = {.msg = "Initializing...", .active = true, .pause = false};
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
bool            crc_verbose_mode = false;
const char *crc_export_json = NULL;

void result_init (ResultCtx *ctx, int cap)
{
  // ctx->results = calloc (cap, sizeof (ScanResult)); this is a garbage. First allocation
  ctx->count = 0;
  ctx->cap = cap;
  ctx->results = MemoryAllocate (cap * sizeof (ScanResult)); // second.
  if (!ctx->results) {
    sslog (false, COL_RED, "ERROR", "Memory allocation failed!");
    return;
  }
  pthread_mutex_init (&ctx->mutex, NULL);
}

void result_add (ResultCtx  *ctx, ScanResult *res)
{
  pthread_mutex_lock (&ctx->mutex);
  if (ctx->count < ctx->cap) {
    ctx->results[ctx->count++] = *res;
  }
  pthread_mutex_unlock (&ctx->mutex);
}

void result_print_summary (ResultCtx  *ctx, const char *ip)
{
  pthread_mutex_lock (&ctx->mutex);

  int open_count = 0;
  int cum_count = 0;

  printf ("\n" COL_CYAN "\n==== Scan Summary for %s ====" COL_DEF "\n", ip);

  for (int i = 0; i < ctx->count; i++) {
    ScanResult *r = &ctx->results[i];
    if (r->is_open) {
      open_count++;
      if (r->is_camera) {
        cum_count++;
        if (r->needs_auth) {
          printf (COL_YLW "[AUTH] Port %d: %s%s (Login required)" COL_DEF "\n", r->port, ip, r->path);
        } else {
          printf (COL_GRN "[CAM] Port %d: %s%s (OPEN, no auth)" COL_DEF "\n", r->port, ip, r->path);
        }
      } else {
          printf (COL_BLU "[OPEN] Port %d: %s" COL_DEF "\n", r->port, r->service);
      }
    }
  }

  if (open_count == 0) {
    printf (COL_RED "\n[INFO] No open ports found in scanned range." COL_DEF "\n");
  } else if (cum_count == 0) {
    printf (COL_YLW "\n[INFO] %d open port(s), but no RTSP cameras detected." COL_DEF "\n", open_count);
  } else {
    printf (COL_GRN "\n[SUCCESS] Found %d camera(s) on %d open port" COL_DEF "\n", cum_count, open_count);
  }

  pthread_mutex_unlock (&ctx->mutex);
}

void result_free (ResultCtx *ctx)
{
  pthread_mutex_lock (&ctx->mutex);
  cleanbit (ctx->results);
  ctx->results = NULL;
  ctx->count = 0;
  ctx->cap = 0;
  pthread_mutex_unlock (&ctx->mutex);
  pthread_mutex_destroy (&ctx->mutex);
}

const char* const rtspPath[] = {
  "/live/ch0", "/live/ch1", // Hikvision or Generic
  "/cam/realmonitor?channel=1&subtype=0", //Dahua
  "/Streaming/Channels/101", // ONVIF
  "/mpeg4", "/h264", // Chinese cameras
  "/ipcam/stream.asf", // Specific vendors
  "/videoMain", // XMeye
  "/" // root
};
const size_t rtspPcount = sizeof (rtspPath) / sizeof (rtspPath[0]);

void sslog /* No streSS */(bool verbose_only, const char* color, const char* label, const char* format, ...)
{
  if (verbose_only && !crc_verbose_mode) return;

  pthread_mutex_lock (&log_mutex);
  printf ("\033%s[%s] " COL_DEF, color, label);

  va_list args;
  va_start (args, format);
  vprintf (format, args);
  va_end (args);

  printf ("\n");
  fflush (stdout);

  pthread_mutex_unlock (&log_mutex);
}

static size_t WrMemCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    if (!contents || !userp) return 0;
    struct MemBuf *mem = userp;
    if (nmemb != 0 && size > SIZE_MAX / nmemb) return 0;

    size_t realsize = size * nmemb;

    if (mem->size > SIZE_MAX - realsize - 1) return 0;
    char *ptr = MemoryReAllocate (mem->memory, mem->size + realsize + 1);
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
      output[j++] = table[tmp[2] & 0x3f];
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

bool export_result_json (ResultCtx  *ctx,
                         const char *ip,
                         const char *filename)
{
  if (!ctx || !filename) return false;

  FILE *f = fopen (filename, "w");

  if (!f) {
    sslog (false, COL_RED, "ERROR", "Cannot open %s for writing", filename);
    return false;
  }

  pthread_mutex_lock (&ctx->mutex);

  fprintf (f, "{\n");
  fprintf (f, " \"target\": \"%s\", \n", ip);
  fprintf (f, " \"timestamp\": %ld, \n", (long)time (NULL));
  fprintf (f, " \"result\": [\n");

  for (int i = 0; i < ctx->count; i++) {
    ScanResult *r = &ctx->results[i];
    if (!r->is_open) continue;

    fprintf(f, "    {\n");
        fprintf(f, "      \"port\": %d,\n", r->port);
        fprintf(f, "      \"service\": \"%s\",\n", r->service);
        fprintf(f, "      \"is_camera\": %s,\n", r->is_camera ? "true" : "false");
        fprintf(f, "      \"needs_auth\": %s,\n", r->needs_auth ? "true" : "false");
        fprintf(f, "      \"path\": \"%s\"\n", r->path);
        fprintf(f, "    }%s\n", (i < ctx->count - 1) ? "," : "");
  }

  fprintf (f, " ]\n");
  fprintf (f, "}\n");

  pthread_mutex_unlock (&ctx->mutex);
  fclose (f);

  sslog (false, COL_GRN, "EXPORT", "Result saved to %s", filename);
  return true;
}

bool bruteforce (radarType* target)
{
  pthread_t anim_tid;
  atomic_store (&globA.active, true);
  FILE *fLog = fopen ("brute/logins.txt", "r");
  FILE *fPass = fopen ("brute/passwords.txt", "r");
  pthread_create (&anim_tid, NULL, scanim, &globA);

  if (!fLog) {
    sslog (false, COL_RED, "ERROR", "Cannot open brute/logins.txt");
    atomic_store(&globA.active, false);
    pthread_join(anim_tid, NULL);
    fclose (fLog);
    return false;
  } else if (!fPass) {
    sslog (false, COL_RED, "ERROR", "Cannot open brute/passwords.txt");
    atomic_store(&globA.active, false);
    pthread_join(anim_tid, NULL);
    fclose (fPass);
    return false;
  }

  fseek (fLog, 0, SEEK_END);
  long log_s = ftell(fLog);
  fseek (fLog, 0, SEEK_SET);

  fseek (fPass, 0, SEEK_END);
  long pass_s = ftell(fPass);
  fseek (fPass, 0, SEEK_SET);

  if (log_s == 0) {
    sslog (false, COL_RED, "ERROR", "brute/logins.txt are empty!");
    fclose (fLog);
    fclose (fPass);
    atomic_store (&globA.active, false);
    pthread_join (anim_tid, NULL);
    return false;
  } else if (pass_s == 0) {
    sslog (false, COL_RED, "ERROR", "brute/passwords.txt are empty!");
    fclose (fLog);
    fclose (fPass);
    atomic_store (&globA.active, false);
    pthread_join (anim_tid, NULL);
    return false;
  }

  sslog (true, COL_CYAN, "INFO", "Loaded %ld bytes from logins.txt, %ld bytes from passwords.");

  char login[128], pass[128];
  char rawAu[256], bsfAu[512];
  char req[1024], resp[1024];

  struct in_addr addr = {.s_addr = target->ipAddr};
  char ip[INET_ADDRSTRLEN];
  inet_ntop (AF_INET, &addr, ip, sizeof (ip));

  int attemp = 0;

  for (int p = 0; p < 5; p++) {
    rewind (fLog);
    while (fgets (login, sizeof (login), fLog)) {
      login[strcspn (login, "\r\n")] = 0;
      if (strlen (login) == 0) continue;

      rewind (fPass);
      while (fgets (pass, sizeof (pass), fPass)) {
        pass[strcspn (pass, "\r\n")] = 0;
        if (strlen (pass) == 0) continue;

        attemp++;

        int fd = spawnSock (target);
        if (fd < 0) {
          usleep (500000);
          continue;
        }
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
        sslog (true, COL_BLU, "BRUTE", "Trying %s:%s on %s", login, pass, rtspPath[p]);

        send (fd, req, strnlen (req, sizeof req), 0);

        memset (resp, 0, sizeof (resp));
        int received = recv (fd, resp, sizeof(resp) - 1, 0);
        close (fd);

        if (received > 0 && strstr (resp, "RTSP/1.0 200")) {
          sslog (false, COL_GRN, "SUCCESS", "%s:%d%s -> %s:%s\n", ip, target->port, rtspPath[p], login, pass);
          FILE *res = fopen ("found.txt", "a");
          if (res) {
            fprintf (res, "rtsp://%s:%s@%s:%d%s\n", login, pass, ip, target->port, rtspPath[p]);
            fclose (res);
          }
          fclose (fLog);
          fclose (fPass);
          atomic_store (&globA.active, false);
          pthread_join (anim_tid, NULL);
          return true;
        }
        snprintf (globA.msg, 256, COL_BLU "\r[INFO] Brute Attemp #%d | %s:%s on %s, please wait." COL_DEF, attemp, login, pass, rtspPath[p]);
        fflush (stdout);

        usleep (100000);
      }
    }
  }
  sslog (false, COL_YLW, "INFO", "Bruteforce completed: %d attempts, no valid credentials found", attemp);

  atomic_store (&globA.active, false);
  pthread_join (anim_tid, NULL);
  fclose(fLog);
  fclose(fPass);
  return false;
}

bool check4Cam (int         sockfd,
                radarType  *target,
                ScanResult *out_result)
{
  char buf[1024];
  char req[512];
  char ipStr[INET_ADDRSTRLEN];

  struct in_addr addr = {.s_addr = target->ipAddr};
  inet_ntop (AF_INET, &addr, ipStr, sizeof (ipStr));

  for (size_t i = 0; i < rtspPcount; i++) {
    snprintf (req, sizeof (req),
              "DESCRIBE rtsp://%s:%d%s RTSP/1.0\r\n"
              "CSeq: 1\r\n"
              "User-Agent: SatWatcher/1.0\r\n"
              "Accept: application/sdp\r\n\r\n",
              ipStr, target->port, rtspPath[i]);

    send (sockfd, req, strlen (req), 0);
    memset (buf, 0, sizeof (buf));
    ssize_t received = recv (sockfd, buf, sizeof (buf) - 1, 0);

    if (received > 0 && strstr (buf, "RTSP/1.0")) {

      if (out_result) {
        out_result->port = target->port;
        out_result->is_open = true;
        out_result->is_camera = true;
        strncpy (out_result->path, rtspPath[i], sizeof (out_result->path) - 1);
      }

      if (strstr (buf, "200 OK")) {
        sslog (false, COL_GRN, "SUCCESS", "Found RTSP stream: %s:%d%s", ipStr, target->port, rtspPath[i]);
        if (out_result) {
          out_result->needs_auth = false;
          snprintf (out_result->service, sizeof (out_result->service), "RTSP OPEN");
        }

        return true;
      }

      if (strstr (buf, "401") || strstr (buf, "Unauthorized")) {

        if (out_result) {
          out_result->needs_auth = true;
          snprintf (out_result->service, sizeof (out_result->service), "RTSP AUTH");
        }

        return true;
      }
    }
  }

  if (out_result) {
    out_result->port = target->port;
    out_result->is_open = true;
    out_result->is_camera = false;
    snprintf (out_result->service, sizeof (out_result->service), "Unknown service");
  }
  return false;
}

void* scanim (void* arg)
{
  aConf* cfg = (aConf*)arg;
  const char* frames[] = {"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"};
  int i = 0;

  while (atomic_load (&cfg->active)) {
    if (atomic_load (&cfg->pause)) {
      usleep (1000000);
      continue;
    }

    printf ("\r\33[2K" COL_PRPL "[%s] %s" COL_DEF, frames[i++ % 10], cfg->msg);
    fflush (stdout);
    usleep (80000);
  }
  return NULL;
}

void* threadScan(void* arg) /* fuck threads */
{
    if (!arg) return NULL;

    radarType* data = (radarType*)arg;

    ScanResult res = {0};
    res.port = data->port;

    int fd = spawnSock(data);
    if (fd < 0) {
      res.is_open = false;
      if (data->result_ctx) result_add (data->result_ctx, &res);
      //cleanbit (data); trash, it calls a fuckin double-free
      return NULL;
    }

    res.is_open = true;

    if (check4Cam (fd, data, &res)) {
        // i doesn't write a log because it already written in check4Cam
      if (data->doBrute && res.needs_auth) {
        bruteforce (data);
      }
    }

    if (data->result_ctx) {
      result_add (data->result_ctx, &res);
    }

    close (fd);
    cleanbit (data);
    return NULL;
}

int check4File (const char *path)
{
  if (access (path, F_OK) != 0) {
    sslog (false, COL_RED, "ERROR", "File %s does not exist", path);
    return 1;
  }

  FILE *file = fopen (path, "r");
  if (!file) return 1;

  fseek (file, 0, SEEK_END);
  long size = ftell (file);
  fclose (file);

  if (size <= 0) {
    return 2;
  }

  sslog (true, COL_GRN, "SYSTEM", "Valid File Found: %s", path);
  return 0;
}

bool ran_nmap (const char *target_ip, const char *port_range, const char *xml_output, bool fast_mode)
{
  sslog (true, COL_YLW, "DEBUG", "ran_nmap called: ");
  sslog (true, COL_YLW, "DEBUG", " target_ip = '%s', len=%zu, ptr=%p", target_ip ? target_ip : "null", target_ip ? strlen (target_ip) : 0, (void*)target_ip);
  if (!target_ip || !xml_output) {
    sslog (false, COL_RED, "ERROR", "Invalid arguments for nmap scan.");
    return false;
  } else if (strlen (target_ip) == 0) {
    sslog (false, COL_RED, "ERROR", "target ip is NULL or Empty");
    return false;
  } else if (!xml_output) {
    sslog (false, COL_RED, "ERROR", "xml output is NULL!");
    return false;
  }

  if (check4File ("/usr/bin/nmap") != 0) {
    sslog (false, COL_RED, "ERROR", "Nmap not found in PATH. Did you install the dependencies?");
    return false;
  }

  const char *scan_type = crc_nmap_connect ? "-sT" : "-sS";
  const char *timing = crc_nmap_connect ? "T2" : "T3";

  char cmd[1024];

  if (fast_mode) {
    snprintf (cmd, sizeof (cmd),
              "nmap %s -%s --top-ports 100 -oX %s %s 2>/dev/null", scan_type, timing, xml_output, target_ip);
  } else if (port_range && strlen (port_range) > 0) {
    snprintf (cmd, sizeof (cmd),
              "nmap %s -sV -%s -p %s -oX %s %s 2>/dev/null", scan_type,  timing, port_range, xml_output, target_ip);
  } else {
    snprintf(cmd, sizeof(cmd),
                 "nmap %s -sV -%s -oX %s %s 2>/dev/null", scan_type, timing, xml_output, target_ip);
  }

  sslog (true, COL_BLU, "NMAP", "Running: %s, UID:%d", cmd, getuid());

  int ran = system (cmd);

  if (ran != 0) {
    sslog (false, COL_RED, "ERROR", "nmap failed with code %d", WEXITSTATUS (ran));
    return false;
  }

  if (check4File (xml_output) != 0) {
    sslog (false, COL_RED, "FAILURE", "Nmap XML not created: %s", xml_output);
    return false;
  } else if (check4File (xml_output) == 2) {
    sslog (false, COL_RED, "FAILURE", "Nmap XML empty or invalid: %s", xml_output);
    return false;
  }

  sslog (true, COL_GRN, "SYSTEM", "Scan completed, XML to %s", xml_output);
  return true;
}

bool check4Right (bool use_syn_scan)
{
  return use_syn_scan && (getuid() != 0);
}

bool restart_with_sudo (int argc, char *argv[])
{
  sslog (false, COL_YLW, "PRIV", "Root privileges required for nmap (-sS)");

  char **sudo_argv = MemoryAllocate ((argc + 3) * sizeof (char *));
  if (!sudo_argv) {
    sslog (false, COL_BR_RED, "ERROR", "Memory allocation failed");
    return false;
  }

  sudo_argv[0] = "sudo";
  sudo_argv[1] = "-E"; // saves enviroment

  for (int i = 0; i < argc; i++) {
    sudo_argv[i + 2] = argv[i];
  }
  sudo_argv[argc + 2] = NULL;

  char ePath[1024];
  ssize_t len = readlink ("/proc/self/exe", ePath, sizeof (ePath) - 1);
  if (len == 1) {
    //fallback
    sslog (true, COL_YLW, "WARNING", "Cannot resolve exe path, using argv[0]");
    execvp ("sudo", sudo_argv);
  } else {
    ePath[len] = '\0';
    execvp ("sudo", sudo_argv);
  }
  sslog(false, COL_RED, "ERROR", "Failed to exec sudo: %s", strerror(errno));
  cleanbit (sudo_argv);
  return false;
}

char* input_prompt (const char *prompt,
                    aConf      *cfg,
                    char       *buf,
                    size_t      bufsize)
{
  atomic_store(&cfg->pause, true);

    printf("\r\33[2K%s", prompt);
    fflush(stdout);

    char *result = fgets(buf, bufsize, stdin);

    atomic_store(&cfg->pause, false);

    printf("\n");
    fflush(stdout);

    return result;
}
