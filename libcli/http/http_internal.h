/*
   Unix SMB/CIFS implementation.

   HTTP library

   Copyright (C) 2014 Samuel Cabrero <samuelcabrero@kernevil.me>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _HTTP_INTERNAL_H_
#define _HTTP_INTERNAL_H_

enum http_parser_state {
	HTTP_READING_FIRSTLINE,
	HTTP_READING_HEADERS,
	HTTP_READING_BODY,
	HTTP_READING_TRAILER,
	HTTP_READING_DONE,
	HTTP_READING_CHUNK_SIZE,
	HTTP_READING_CHUNK,
	HTTP_READING_CHUNK_TERM,
	HTTP_READING_FINAL_CHUNK_TERM,
};

enum http_read_status {
	HTTP_ALL_DATA_READ,
	HTTP_MORE_DATA_EXPECTED,
	HTTP_DATA_CORRUPTED,
	HTTP_REQUEST_CANCELED,
	HTTP_DATA_TOO_LONG,
};

struct http_conn {
	struct tevent_queue *send_queue;
	struct {
		struct tstream_context *raw;
		struct tstream_context *tls;
		struct tstream_context *active;
	} tstreams;
};

#endif /* _HTTP_INTERNAL_H_ */
