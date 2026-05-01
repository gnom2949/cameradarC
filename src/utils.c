/* utils.c
 * Utils for Cameradar on C
 * SPDX-License-Identifier: GNU General Public License v3
 */
#include "cam.h"
#include "version.h"
#include "config.h"
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
  if (!ctx || !ctx->results)
  {
    fprintf (stderr, "\033[41;1mCRITICAL\033[0m: ctx or results is NULL!!!!");
    return;
  }
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

    pthread_mutex_lock (&log_mutex);
    printf ("\r\33[2K" COL_PRPL "[%s] %s" COL_DEF, frames[i++ % 10], cfg->msg);
    fflush (stdout);
    pthread_mutex_unlock (&log_mutex);
    usleep (80000);
  }
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

void usage (void)
{
  printf (COL_CYAN "\n Welcome to the CameradarC %s!\n" COL_DEF, PROJECT_VERSION);
  printf ("\n Usage:\n");
  printf ("\n       -t --target <IP>\n");
  printf ("\n       -p --port <PORT>, you can type an any port that needs to scan for RTSP\n");
  printf ("\n       -b --brute with this you can do bruteforce, reading the logins and passwords text file in brute dir\n");
  printf ("\n       -V --verbose this is a verbose, adding more logs called 'trash'\n"); /* Trash vs garbage❤❤❤ */
  printf ("\n       -n --nmap this thing uses nmap for discovery, can takes more time\n");
  printf ("\n       -v --version this argument just show the build tag and version\n");
  printf ("\n       --nmap-xml <FILE> this thing uses nmap for discovery, can takes more time + uses an exisiting nmap XML\n");
  printf ("\n       --nmap-fast Fast nmap mode, scanning only 100 top ports\n");
  printf ("\n       --export-json <FILE> this thing exports a result into JSON\n");
  printf ("\n       --include-amb this thing add argument that include a 'open|filtered' port from nmap XML\n");
  printf ("\n Github: https://github.com/gnom2949/cameradarC\n");
  printf ("\n Credits: https://github.com/Ullaakut/cameradar\n");
  printf ("\nThis is a free software under GNU GPLv3, see more: https://www.gnu.org/licenses/gpl-3.0.html\n");
  exit (1);
}
