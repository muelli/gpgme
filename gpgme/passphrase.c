/* passphrase.c -  passphrase functions
   Copyright (C) 2000 Werner Koch (dd9jn)
   Copyright (C) 2001, 2002 g10 Code GmbH
 
   This file is part of GPGME.
 
   GPGME is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
 
   GPGME is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.
 
   You should have received a copy of the GNU General Public License
   along with GPGME; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

#if HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "util.h"
#include "context.h"
#include "ops.h"


struct passphrase_result_s
{
  int no_passphrase;
  void *last_pw_handle;
  char *userid_hint;
  char *passphrase_info;
  int bad_passphrase;
};


void
_gpgme_release_passphrase_result (PassphraseResult result)
{
  if (!result)
    return;
  free (result->passphrase_info);
  free (result->userid_hint);
  free (result);
}


GpgmeError
_gpgme_passphrase_status_handler (GpgmeCtx ctx, GpgmeStatusCode code, char *args)
{
  test_and_allocate_result (ctx, passphrase);

  switch (code)
    {
    case GPGME_STATUS_USERID_HINT:
      free (ctx->result.passphrase->userid_hint);
      if (!(ctx->result.passphrase->userid_hint = strdup (args)))
	return mk_error (Out_Of_Core);
      break;

    case GPGME_STATUS_BAD_PASSPHRASE:
      ctx->result.passphrase->bad_passphrase++;
      ctx->result.passphrase->no_passphrase = 0;
      break;

    case GPGME_STATUS_GOOD_PASSPHRASE:
      ctx->result.passphrase->bad_passphrase = 0;
      ctx->result.passphrase->no_passphrase = 0;
      break;

    case GPGME_STATUS_NEED_PASSPHRASE:
    case GPGME_STATUS_NEED_PASSPHRASE_SYM:
      free (ctx->result.passphrase->passphrase_info);
      ctx->result.passphrase->passphrase_info = strdup (args);
      if (!ctx->result.passphrase->passphrase_info)
	return mk_error (Out_Of_Core);
      break;

    case GPGME_STATUS_MISSING_PASSPHRASE:
      DEBUG0 ("missing passphrase - stop\n");;
      ctx->result.passphrase->no_passphrase = 1;
      break;

    case GPGME_STATUS_EOF:
      if (ctx->result.passphrase->no_passphrase
	  || ctx->result.passphrase->bad_passphrase)
	return mk_error (No_Passphrase);
      break;

    default:
      /* Ignore all other codes.  */
      break;
    }
  return 0;
}


GpgmeError
_gpgme_passphrase_command_handler (void *opaque, GpgmeStatusCode code,
				   const char *key, const char **result)
{
  GpgmeCtx ctx = opaque;

  if (!ctx->result.passphrase)
    {
      ctx->result.passphrase = calloc (1, sizeof *ctx->result.passphrase);
      if (!ctx->result.passphrase)
	return mk_error (Out_Of_Core);
    }

  if (!code)
    {
      /* We have been called for cleanup.  */
      if (ctx->passphrase_cb)
	{ 
	  /* Fixme: Take the key in account.  */
	  ctx->passphrase_cb (ctx->passphrase_cb_value, NULL, 
			      &ctx->result.passphrase->last_pw_handle);
        }
      *result = NULL;
      return 0;
    }

  if (!key || !ctx->passphrase_cb)
    {
      *result = NULL;
      return 0;
    }
    
  if (code == GPGME_STATUS_GET_HIDDEN && !strcmp (key, "passphrase.enter"))
    {
      const char *userid_hint = ctx->result.passphrase->userid_hint;
      const char *passphrase_info = ctx->result.passphrase->passphrase_info;
      int bad_passphrase = ctx->result.passphrase->bad_passphrase;
      char *buf;

      ctx->result.passphrase->bad_passphrase = 0;
      if (!userid_hint)
	userid_hint = "[User ID hint missing]";
      if (!passphrase_info)
	passphrase_info = "[passphrase info missing]";
      buf = malloc (20 + strlen (userid_hint)
			+ strlen (passphrase_info) + 3);
      if (!buf)
	return mk_error (Out_Of_Core);
      sprintf (buf, "%s\n%s\n%s",
	       bad_passphrase ? "TRY_AGAIN":"ENTER",
	       userid_hint, passphrase_info);

      *result = ctx->passphrase_cb (ctx->passphrase_cb_value, buf,
				    &ctx->result.passphrase->last_pw_handle);
      free (buf);
      return 0;
    }

  *result = NULL;
  return 0;
}


GpgmeError
_gpgme_passphrase_start (GpgmeCtx ctx)
{
  GpgmeError err = 0;

  if (ctx->passphrase_cb)
    err = _gpgme_engine_set_command_handler (ctx->engine,
					     _gpgme_passphrase_command_handler,
					     ctx, NULL);
  return err;
}