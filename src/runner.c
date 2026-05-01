/* runner.c
 * The functions that executes for Cameradar on C
 * SPDX-License-Identifier: GNU General Public License v3
 */

#include "cam.h"

bool ran_nmap (const char *target_ip, const char *port_range, const char *xml_output, bool fast_mode)
{
  if (!target_ip || !xml_output) {
    sslog (false, COL_RED, "ERROR", "Invalid arguments for nmap scan.");
    return false;
  }

  if (strlen (target_ip) == 0) {
    sslog (false, COL_RED, "ERROR", "target ip is NULL or Empty");
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

