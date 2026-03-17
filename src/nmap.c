#include "cam.h"
#include <libxml2/libxml/parser.h>
#include <libxml2/libxml/tree.h>

void nmap_parser_init (NmRes *res)
{
  size_t total = 1000 * sizeof (PInfo);
  res->ports = MemoryAllocate (total);
  if (res->ports) {
    memset (res->ports, 0, total);
  }
  res->count = 0;
  res->cap = 1000;
}

void nmap_parser_add (NmRes      *res,
                      uint16_t    port,
                      PState      state,
                      const char *service,
                      const char *version)
{
    if (res->count >= res->cap) {
      res->cap *= 2;
      res->ports = MemoryReAllocate (res->ports, res->cap * sizeof (PInfo));
    }
    PInfo *p = &res->ports[res->count++];
    p->port = port;
    p->state = state;
    strncpy (p->service, service ? service : "unknown", sizeof (p->service) - 1);
    strncpy (p->version, version ? version : "", sizeof (p->version) - 1);
}

PState parse_port_state (const char *state_string)
{
  if (!state_string) {
    return PORT_FILTER;
  } else if (strcmp (state_string, "open") == 0) {
    return PORT_OPEN;
  } else if (strcmp (state_string, "closed") == 0) {
    return PORT_CLOSE;
  } else if (strcmp (state_string, "filtered") == 0) {
    return PORT_FILTER;
  } else if (strcmp (state_string, "open|filtered") == 0) {
    return PORT_OPEN_FILTER;
  } else {
    sslog (false, COL_RED, "ERROR", "Cannot define target state!");
    return -1;
  }
  return PORT_FILTER;
}

bool parse_www_xml (const char *xml_file, NmRes *res, bool ambiguous_include)
{
    xmlDocPtr doc = xmlReadFile (xml_file, NULL, XML_PARSE_NOBLANKS);
    if (!doc) {
      sslog (false, COL_RED, "ERROR", "Failed to parse XML: %s", xml_file);
      xmlFreeDoc (doc);
      return false;
    }

    xmlNodePtr root = xmlDocGetRootElement (doc);
    if (!root || xmlStrcmp (root->name, (const xmlChar*)"nmaprun")) {
      xmlFreeDoc (doc);
      return false;
    }

    for (xmlNodePtr host = root->children; host; host = host->next) {
      if (host->type != XML_ELEMENT_NODE || xmlStrcmp (host->name, (const xmlChar*)"host")) continue;

      bool host_up = false;
      for (xmlNodePtr status = host->children; status; status = status->next) {
        if (status->type == XML_ELEMENT_NODE && xmlStrcmp (status->name, (const xmlChar*)"status") == 0) {
          xmlChar *state = xmlGetProp (status, (const xmlChar*)"state");
          if (state && xmlStrcmp (state, (const xmlChar*)"up") == 0) host_up = true;
          if (state) xmlFree (state);
        }
      }
      if (!host_up) continue;

      for (xmlNodePtr addr = host->children; addr; addr = addr->next) {
        if (addr->type == XML_ELEMENT_NODE && xmlStrcmp(addr->name, (const xmlChar*)"address") == 0) {
          xmlChar *ip = xmlGetProp(addr, (const xmlChar*)"addr");
          if (ip) {
            strncpy(res->ipStr, (char*)ip, sizeof(res->ipStr) - 1);
            res->ipAddr = inet_addr((char*)ip);
            xmlFree(ip);
          }
        }
      }

      for (xmlNodePtr ports = host->children; ports; ports = ports->next) {
        if (ports->type != XML_ELEMENT_NODE || xmlStrcmp(ports->name, (const xmlChar*)"ports")) continue;

          for (xmlNodePtr port = ports->children; port; port = port->next) {
            if (port->type != XML_ELEMENT_NODE || xmlStrcmp(port->name, (const xmlChar*)"port")) continue;

              xmlChar *portid = xmlGetProp(port, (const xmlChar*)"portid");
              xmlChar *proto = xmlGetProp(port, (const xmlChar*)"protocol");

              if (!portid || !proto || xmlStrcmp(proto, (const xmlChar*)"tcp")) {
                  if (portid) xmlFree(portid);
                  if (proto) xmlFree(proto);
                  continue;
              }

              PState state = PORT_FILTER;
              char service[64] = "unknown";
              char version[128] = "";

              for (xmlNodePtr child = port->children; child; child = child->next) {
                if (child->type != XML_ELEMENT_NODE) continue;

                  if (xmlStrcmp(child->name, (const xmlChar*)"state") == 0) {
                    xmlChar *s = xmlGetProp(child, (const xmlChar*)"state");
                      if (s) {
                        state = parse_port_state((char*)s);
                        xmlFree(s);
                      }
                  }

        if (xmlStrcmp(child->name, (const xmlChar*)"service") == 0) {
            xmlChar *svc = xmlGetProp(child, (const xmlChar*)"name");
            xmlChar *ver = xmlGetProp(child, (const xmlChar*)"version");
            if (svc) {
            strncpy(service, (char*)svc, sizeof(service) - 1);
            xmlFree(svc);
          } else if (ver) {
            strncpy(version, (char*)ver, sizeof(version) - 1);
            xmlFree(ver);
          }
        }
      }

      if (state == PORT_OPEN || (state == PORT_OPEN_FILTER && ambiguous_include)) {
        nmap_parser_add (res, atoi ((char*)portid), state, service, version);
        sslog (true, COL_BLU, "PORT", "Found: %s:%d [%s] %s %s", res->ipStr, res->ports[res->count-1].port,
               state == PORT_OPEN ? "OPEN" : "OPEN|FILTERED", service, version);
      }

      xmlFree (portid);
      xmlFree (proto);
    }
    for (xmlNodePtr extra = ports->children; extra; extra = extra->next) {
      if (extra->type != XML_ELEMENT_NODE || xmlStrcmp (extra->name, (const xmlChar*)"extraports")) continue;

      xmlChar *state_string = xmlGetProp (extra, (const xmlChar*)"state");
      xmlChar *count_string = xmlGetProp (extra, (const xmlChar*)"count");
      xmlChar *port_list = xmlGetProp (extra, (const xmlChar*)"ports");

      if (state_string && count_string && port_list) {
        PState state = parse_port_state ((char*)state_string);
          int count = atoi ((char*)count_string);

          if ((state == PORT_OPEN || (state == PORT_OPEN_FILTER && ambiguous_include)) && port_list) {
            // parse a list of ports
            char *portscpy = strdup ((char*)port_list);
            char *token = strtok (portscpy, ",");

            while (token) {
              char *dash = strchr (token, '-');
              if (dash) {
                int start = atoi (token);
                int end = atoi (dash + 1);
                for (int p = start; p <= end; p++) {
                  nmap_parser_add (res, p, state, "unknown", "");
                }
              } else { // single port
                nmap_parser_add (res, atoi (token), state, "unknown", "");
              }
              token = strtok (NULL, ",");
            }
            cleanbit (portscpy);

            sslog (true, COL_YLW, "XML", "Added %d ports from extraports [%s]", count, state_string);
          }
        }
        if (state_string) {
          xmlFree (state_string);
        } else if (count_string) {
          xmlFree (count_string);
        } else if (port_list) {
          xmlFree (port_list);
        }

      }
    }
  }

  xmlFreeDoc (doc);
  return res->count > 0;
}

void nmap_parser_free (NmRes *res)
{
  cleanbit (res->ports);
  res->ports = NULL;
  res->count = 0;
}
