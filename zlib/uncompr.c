/* uncompr.c -- decompress a memory buffer
 * Copyright (C) 1995-2003 Jean-loup Gailly.
 * For conditions of distribution and use, see copyright notice in zlib.h
 */

 /* @(#) $Id: uncompr.c 3308 2006-06-23 15:19:29Z oleg $ */

#define ZLIB_INTERNAL
#include "zlib.h"

#pragma warning (disable : 4702)

/* ===========================================================================
	 Decompresses the source buffer into the destination buffer.  sourceLen is
   the byte length of the source buffer. Upon entry, destLen is the total
   size of the destination buffer, which must be large enough to hold the
   entire uncompressed data. (The size of the uncompressed data must have
   been saved previously by the compressor and transmitted to the decompressor
   by some mechanism outside the scope of this compression library.)
   Upon exit, destLen is the actual size of the compressed buffer.
	 This function can be used to decompress a whole file at once if the
   input file is mmap'ed.

	 uncompress returns Z_OK if success, Z_MEM_ERROR if there was not
   enough memory, Z_BUF_ERROR if there was not enough room in the output
   buffer, or Z_DATA_ERROR if the input data was corrupted.
*/
int ZEXPORT uncompress(dest, destLen, source, sourceLen)
Bytef *dest;
uLongf *destLen;
const Bytef *source;
uLong sourceLen;
{
	z_stream stream;
	int err;
	uLongf dstlen = *destLen;

	*destLen = 0;

	stream.next_in = (Bytef*)source;
	stream.avail_in = (uInt)sourceLen;
	/* Check for source > 64K on 16-bit machine: */
	if ((uLong)stream.avail_in != sourceLen)
		return Z_BUF_ERROR;

	stream.next_out = dest;
	stream.avail_out = (uInt)dstlen;
	if ((uLong)stream.avail_out != dstlen)
		return Z_BUF_ERROR;

	stream.zalloc = (alloc_func)0;
	stream.zfree = (free_func)0;

	err = inflateInit(&stream);
	if (err != Z_OK)
		return err;

	err = inflate(&stream, Z_FINISH);
	*destLen = stream.total_out;

	if (err != Z_STREAM_END) {
		inflateEnd(&stream);
		if (err == Z_NEED_DICT || (err == Z_BUF_ERROR && stream.avail_in == 0))
			return Z_DATA_ERROR;
		return err;
	}

	err = inflateEnd(&stream);
	return err;
}

int ZEXPORT uncompress1(Bytef *dst, uLongf *dstlen,
	const Bytef *src, uLong srclen)
{
	z_stream stream = { 0 };
	int err, extra_chunks;
	uInt dstlen1 = (uInt)*dstlen;

	if ((uLong)dstlen1 != (uLong)*dstlen) {
		*dstlen = 0;
		return Z_BUF_ERROR;
	}
	*dstlen = 0;

	stream.next_in = (Bytef *)src;
	stream.avail_in = (uInt)srclen;
	if ((uLong)stream.avail_in != (uLong)srclen)
		return Z_BUF_ERROR;

	err = inflateInit(&stream);
	if (err != Z_OK)
		return err;

	extra_chunks = 0;
	do {
		stream.next_out = dst;
		stream.avail_out = dstlen1;
		err = inflate(&stream, Z_FINISH);
		if (err == Z_STREAM_END)
			break;
		if (err == Z_NEED_DICT || (err == Z_BUF_ERROR && stream.avail_in == 0))
			err = Z_DATA_ERROR;
		if (err != Z_BUF_ERROR) {
			inflateEnd(&stream);
			return err;
		}
		extra_chunks += 1;
	} while (stream.avail_out == 0);

	*dstlen = stream.total_out;

	err = inflateEnd(&stream);
	if (err != Z_OK)
		return err;

	return extra_chunks ? Z_BUF_ERROR : Z_OK;
}