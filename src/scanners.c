/* scannerS.c
 * The Scan functions for Cameradar on C
 * SPDX-License-Identifier: GNU General Public License v3
 */

#include "cam.h"

void* threadScan(void* arg) /* fuck threads */
{
    if (!arg) return NULL;

    radarType* data = (radarType*)arg;

    ScanResult res = {};
    res.port = data->port;

    int fd = spawnSock(data);
    if (fd < 0)
    {
      res.port = data->port;
      res.is_open = false;
      if (data->result_ctx) result_add (data->result_ctx, &res);
      cleanbit (data);
      return NULL;
    }

    res.port = data->port;
    res.is_open = true;

    if (check4Cam (fd, data, &res))
    {
      if (data->doBrute && res.needs_auth)
      {
        bruteforce (data, data->logins, data->passwords);
      }
    }

    if (data->result_ctx)
    {
      result_add (data->result_ctx, &res);
    }

    close (fd);
    cleanbit (data);
    return NULL;
}

