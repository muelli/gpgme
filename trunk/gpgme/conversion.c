/* conversion.c - String conversion helper functions.
   Copyright (C) 2000 Werner Koch (dd9jn)
   Copyright (C) 2001, 2002, 2003 g10 Code GmbH
 
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

#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>
#include <stdlib.h>

#include "gpgme.h"
#include "util.h"


/* Convert two hexadecimal digits from STR to the value they
   represent.  Returns -1 if one of the characters is not a
   hexadecimal digit.  */
int
_gpgme_hextobyte (const unsigned char *str)
{
  int val = 0;
  int i;

#define NROFHEXDIGITS 2
  for (i = 0; i < NROFHEXDIGITS; i++)
    {
      if (*str >= '0' && *str <= '9')
	val += *str - '0';
      else if (*str >= 'A' && *str <= 'F')
	val += 10 + *str - 'A';
      else if (*str >= 'a' && *str <= 'f')
	val += 10 + *str - 'a';
      else
	return -1;
      if (i < NROFHEXDIGITS - 1)
	val *= 16;
      str++;
    }
  return val;
}


/* Decode the C formatted string SRC and store the result in the
   buffer *DESTP which is LEN bytes long.  If LEN is zero, then a
   large enough buffer is allocated with malloc and *DESTP is set to
   the result.  Currently, LEN is only used to specify if allocation
   is desired or not, the caller is expected to make sure that *DESTP
   is large enough if LEN is not zero.  */
GpgmeError
_gpgme_decode_c_string (const char *src, char **destp, int len)
{
  char *dest;

  /* Set up the destination buffer.  */
  if (len)
    {
      if (len < strlen (src) + 1)
	return GPGME_General_Error;

      dest = *destp;
    }
  else
    {
      /* The converted string will never be larger than the original
	 string.  */
      dest = malloc (strlen (src) + 1);
      if (!dest)
	return GPGME_Out_Of_Core;

      *destp = dest;
    }

  /* Convert the string.  */
  while (*src)
    {
      if (*src != '\\')
	{
	  *(dest++) = *(src++);
	  continue;
	}

      switch (src[1])
	{
#define DECODE_ONE(match,result)	\
	case match:			\
	  src += 2;			\
	  *(dest++) = result;		\
	  break;

	  DECODE_ONE ('\'', '\'');
	  DECODE_ONE ('\"', '\"');
	  DECODE_ONE ('\?', '\?');
	  DECODE_ONE ('\\', '\\');
	  DECODE_ONE ('a', '\a');
	  DECODE_ONE ('b', '\b');
	  DECODE_ONE ('f', '\f');
	  DECODE_ONE ('n', '\n');
	  DECODE_ONE ('r', '\r');
	  DECODE_ONE ('t', '\t');
	  DECODE_ONE ('v', '\v');

	case 'x':
	  {
	    int val = _gpgme_hextobyte (&src[2]);

	    if (val == -1)
	      {
		/* Should not happen.  */
		*(dest++) = *(src++);
		*(dest++) = *(src++);
		if (*src)
		  *(dest++) = *(src++);
		if (*src)
		  *(dest++) = *(src++);
	      }
	    else
	      {
		if (!val)
		  {
		    /* A binary zero is not representable in a C
		       string.  */
		    *(dest++) = '\\';
		    *(dest++) = '0'; 
		  }
		else 
		  *((unsigned char *) dest++) = val;
		src += 4;
	      }
	  }

	default:
	  {
	    /* Should not happen.  */
	    *(dest++) = *(src++);
	    *(dest++) = *(src++);
	  }
        } 
    }
  *(dest++) = 0;

  return 0;
}


GpgmeError
_gpgme_data_append (GpgmeData dh, const char *buffer, size_t length)
{
  if (!dh || !buffer)
    return GPGME_Invalid_Value;

  do
    {
      ssize_t amt = gpgme_data_write (dh, buffer, length);
      if (amt == 0 || (amt < 0 && errno != EINTR))
	return GPGME_File_Error;
      buffer += amt;
      length -= amt;
    }
  while (length > 0);

  return 0;
}


GpgmeError
_gpgme_data_append_string (GpgmeData dh, const char *str)
{
  if (!str)
    return 0;

  return _gpgme_data_append (dh, str, strlen (str));
}


GpgmeError
_gpgme_data_append_for_xml (GpgmeData dh, const char *buffer, size_t len)
{
  const char *text, *str;
  size_t count;
  int err = 0;

  if (!dh || !buffer)
    return GPGME_Invalid_Value;

  do
    {
      text = NULL;
      str = buffer;
      for (count = len; count && !text; str++, count--)
        {
          if (*str == '<')
            text = "&lt;";
          else if (*str == '>')
            text = "&gt;";  /* Not sure whether this is really needed.  */
          else if (*str == '&')
            text = "&amp;";
          else if (!*str)
            text = "&#00;";
        }
      if (text)
        {
          str--;
          count++;
        }
      if (str != buffer)
        err = _gpgme_data_append (dh, buffer, str - buffer);
      if (!err && text)
        {
          err = _gpgme_data_append_string (dh, text);
          str++;
          count--;
        }
      buffer = str;
      len = count;
    }
  while (!err && len);
  return err;
}


/* Append a string to DATA and convert it so that the result will be
   valid XML.  */
GpgmeError
_gpgme_data_append_string_for_xml (GpgmeData dh, const char *str)
{
  return _gpgme_data_append_for_xml (dh, str, strlen (str));
}


/* Append a string with percent style (%XX) escape characters as
   XML.  */
GpgmeError
_gpgme_data_append_percentstring_for_xml (GpgmeData dh, const char *str)
{
  const unsigned char *src;
  unsigned char *buf, *dst;
  int val;
  GpgmeError err;

  buf = malloc (strlen (str));
  dst = buf;
  for (src = str; *src; src++)
    {
      if (*src == '%' && (val = _gpgme_hextobyte (src + 1)) != -1)
        {
          *dst++ = val;
          src += 2;
        }
      else
        *dst++ = *src;
    }

  err = _gpgme_data_append_for_xml (dh, buf, dst - buf);
  free (buf);
  return err;
}