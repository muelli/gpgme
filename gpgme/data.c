/* data.c - An abstraction for data objects.
   Copyright (C) 2002 g10 Code GmbH

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
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307 USA.  */

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "data.h"
#include "util.h"
#include "ops.h"
#include "io.h"


GpgmeError
_gpgme_data_new (GpgmeData *r_dh, struct gpgme_data_cbs *cbs)
{
  GpgmeData dh;

  if (!r_dh)
    return mk_error (Invalid_Value);

  *r_dh = NULL;
  dh = calloc (1, sizeof (*dh));
  if (!dh)
    return mk_error (Out_Of_Core);

  dh->cbs = cbs;

  *r_dh = dh;
  return 0;
}


void
_gpgme_data_release (GpgmeData dh)
{
  if (dh)
    free (dh);
}


/* Read up to SIZE bytes into buffer BUFFER from the data object with
   the handle DH.  Return the number of characters read, 0 on EOF and
   -1 on error.  If an error occurs, errno is set.  */
ssize_t
gpgme_data_read (GpgmeData dh, void *buffer, size_t size)
{
  if (!dh)
    {
      errno = EINVAL;
      return -1;
    }
  if (!dh->cbs->read)
    {
      errno = EOPNOTSUPP;
      return -1;
    }
  return (*dh->cbs->read) (dh, buffer, size);
}


/* Write up to SIZE bytes from buffer BUFFER to the data object with
   the handle DH.  Return the number of characters written, or -1 on
   error.  If an error occurs, errno is set.  */
ssize_t
gpgme_data_write (GpgmeData dh, const void *buffer, size_t size)
{
  if (!dh)
    {
      errno = EINVAL;
      return -1;
    }
  if (!dh->cbs->write)
    {
      errno = EOPNOTSUPP;
      return -1;
    }
  return (*dh->cbs->write) (dh, buffer, size);
}


/* Set the current position from where the next read or write starts
   in the data object with the handle DH to OFFSET, relativ to
   WHENCE.  */
off_t
gpgme_data_seek (GpgmeData dh, off_t offset, int whence)
{
  if (!dh)
    {
      errno = EINVAL;
      return -1;
    }
  if (!dh->cbs->read)
    {
      errno = EOPNOTSUPP;
      return -1;
    }
  return (*dh->cbs->seek) (dh, offset, whence);
}


/* Release the data object with the handle DH.  */
void
gpgme_data_release (GpgmeData dh)
{
  if (!dh)
    return;

  if (dh->cbs->release)
    (*dh->cbs->release) (dh);
  _gpgme_data_release (dh);
}


/* Get the current encoding meta information for the data object with
   handle DH.  */
GpgmeDataEncoding
gpgme_data_get_encoding (GpgmeData dh)
{
  return dh ? dh->encoding : GPGME_DATA_ENCODING_NONE;
}


/* Set the encoding meta information for the data object with handle
   DH to ENC.  */
GpgmeError
gpgme_data_set_encoding (GpgmeData dh, GpgmeDataEncoding enc)
{
  if (!dh)
    return mk_error (Invalid_Value);
  if (enc < 0 || enc > GPGME_DATA_ENCODING_ARMOR)
    return GPGME_Invalid_Value;
  dh->encoding = enc;
  return 0;
}


/* Functions to support the wait interface.  */

GpgmeError
_gpgme_data_inbound_handler (void *opaque, int fd)
{
  GpgmeData dh = (GpgmeData) opaque;
  char buffer[BUFFER_SIZE];
  ssize_t buflen;

  assert (dh);

  buflen = read (fd, buffer, BUFFER_SIZE);
  if (buflen < 0)
    return mk_error (File_Error);
  if (buflen == 0)
    {
      _gpgme_io_close (fd);
      return 0;
    }

  return _gpgme_data_append (dh, buffer, buflen);
}


GpgmeError
_gpgme_data_outbound_handler (void *opaque, int fd)
{
  GpgmeData dh = (GpgmeData) opaque;
  ssize_t nwritten;

  assert (dh);

  if (!dh->pending_len)
    {
      ssize_t amt = gpgme_data_read (dh, dh->pending, BUFFER_SIZE);
      if (amt < 0)
	return mk_error (File_Error);
      if (amt == 0)
	{
	  _gpgme_io_close (fd);
	  return 0;
	}
      dh->pending_len = amt;
    }

  nwritten = _gpgme_io_write (fd, dh->pending, dh->pending_len);
  if (nwritten == -1 && errno == EAGAIN )
    return 0;

  if (nwritten <= 0)
    return mk_error (File_Error);

  if (nwritten < dh->pending_len)
    memmove (dh->pending, dh->pending + nwritten, dh->pending_len - nwritten);
  dh->pending_len -= nwritten;
  return 0;
}