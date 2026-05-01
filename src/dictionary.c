/* dictionary.c
 * Dictionary word list of passwords and logins loader for Cameradar on C.
 * SPDX-License-Identifier: GNU General Public License v3
 */

#include "cam.h"

Dictionary *load_passlist (ustring path)
{
  /* File setup */
  FILE *pass = fopen (path, "r");
  if (!pass) {
    sslog (false, COL_RED, "ERROR", "Cannot open password list located at '%s'!", path);
    return null;
  }

  /* check file */
  fseek (pass, 0, SEEK_END);
  long pass_long = ftell (pass);
  rewind (pass);

  if (pass_long == 0) {
    sslog (false, COL_RED, "ERROR", "'%s' is empty!", pass);
    fclose (pass);
    return null;
  }

  /* prints if verbose flag setted */
  sslog (true, COL_CYAN, "INFO", "%ld bytes from password list.", pass_long);

  int ln_count = 0;
  char buf[256];

  while (fgets (buf, sizeof (buf), pass))
  {
    buf[strcspn (buf, "\r\n")] = 0;
    if (strnlen (buf, sizeof (buf)) > 0) {
     ln_count++;
    }
  }

  rewind (pass);

  Dictionary *dict = MemoryAllocate (sizeof (Dictionary));
  dict->count = ln_count;
  dict->lines = MemoryAllocate (sizeof (char *) * ln_count);

  int cur_ln = 0;

  while (fgets (buf, sizeof (buf), pass))
  {
    buf[strcspn (buf, "\r\n")] = 0;

    int len = strnlen (buf, sizeof (buf));
    if (len == 0) continue; // skip empty strings

    dict->lines[cur_ln] = MemoryAllocate (len + 1);

    for (int i = 0; i < len; i++)
    {
      dict->lines[cur_ln][i] = buf[i];
    }
    dict->lines[cur_ln][len] = '\0';

    cur_ln++;
  }

  sslog (true, COL_CYAN, "INFO", "Loaded %d passwords from '%s'.", dict->count, path);

  fclose (pass);

  return dict;
}

Dictionary *load_loginlist (ustring path)
{
  /* File setup */
  FILE *login = fopen (path, "r");
  if (!login) {
    sslog (false, COL_RED, "ERROR", "Cannot open logins list located at '%s'!", path);
    return null;
  }

  /* check file */
  fseek (login, 0, SEEK_END);
  long log_long = ftell (login);
  rewind (login);

  if (log_long == 0) {
    sslog (false, COL_RED, "ERROR", "'%s' is empty!", path);
    fclose (login);
    return null;
  }

  /* prints if verbose flag setted */
  sslog (true, COL_CYAN, "INFO", "%ld bytes from login list.", log_long);

  int ln_count = 0;
  char buf[256];

  while (fgets (buf, sizeof (buf), login))
  {
    buf[strcspn (buf, "\r\n")] = 0;
    if (strnlen (buf, sizeof (buf)) > 0) {
     ln_count++;
    }
  }

  rewind (login);

  Dictionary *dict = MemoryAllocate (sizeof (Dictionary));
  dict->count = ln_count;
  dict->lines = MemoryAllocate (sizeof (char *) * ln_count);

  int cur_ln = 0;

  while (fgets (buf, sizeof (buf), login))
  {
    buf[strcspn (buf, "\r\n")] = 0;

    int len = strnlen (buf, sizeof (buf));
    if (len == 0) continue; // skip empty strings

    dict->lines[cur_ln] = MemoryAllocate (len + 1);

    for (int i = 0; i < len; i++)
    {
      dict->lines[cur_ln][i] = buf[i];
    }
    dict->lines[cur_ln][len] = '\0';

    cur_ln++;
  }

  sslog (true, COL_CYAN, "INFO", "Loaded %d passwords from '%s'.", dict->count, path);

  fclose (login);

  return dict;
}

void list_free (Dictionary *dict)
{
  if (!dict) return;

  if (dict->lines)
  {
    for (int j = 0; j < dict->count; j++)
    {
      if (dict->lines[j]) cleanbit (dict->lines[j]);
    }
    cleanbit (dict->lines);
  }

  cleanbit (dict);
}
