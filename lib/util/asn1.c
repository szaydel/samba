/*
   Unix SMB/CIFS implementation.
   simple ASN1 routines
   Copyright (C) Andrew Tridgell 2001

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

#include "replace.h"
#include "system/locale.h"
#include "lib/util/asn1.h"
#include "lib/util/debug.h"
#include "lib/util/samba_util.h"
#include "lib/util/smb_strtox.h"

struct nesting {
	off_t start;
	size_t taglen; /* for parsing */
	struct nesting *next;
};


struct asn1_data {
	uint8_t *data;
	size_t length;
	off_t ofs;
	struct nesting *nesting;
	bool has_error;
	unsigned depth;
	unsigned max_depth;
};

/* allocate an asn1 structure */
struct asn1_data *asn1_init(TALLOC_CTX *mem_ctx, unsigned max_depth)
{
	struct asn1_data *ret = talloc_zero(mem_ctx, struct asn1_data);
	if (ret == NULL) {
		DBG_ERR("asn1_init failed! out of memory\n");
		return ret;
	}
	ret->max_depth = max_depth;
	return ret;
}

/* free an asn1 structure */
void asn1_free(struct asn1_data *data)
{
	talloc_free(data);
}

bool asn1_has_error(const struct asn1_data *data)
{
	return data->has_error;
}

void asn1_set_error(struct asn1_data *data)
{
	data->has_error = true;
}

bool asn1_has_nesting(const struct asn1_data *data)
{
	return data->nesting != NULL;
}

off_t asn1_current_ofs(const struct asn1_data *data)
{
	return data->ofs;
}

/* write to the ASN1 buffer, advancing the buffer pointer */
bool asn1_write(struct asn1_data *data, const void *p, int len)
{
	if (data->has_error) return false;

	if ((len < 0) || (data->ofs + (size_t)len < data->ofs)) {
		data->has_error = true;
		return false;
	}

	if (data->length < data->ofs+len) {
		uint8_t *newp;
		newp = talloc_realloc(data, data->data, uint8_t, data->ofs+len);
		if (!newp) {
			data->has_error = true;
			return false;
		}
		data->data = newp;
		data->length = data->ofs+len;
	}
	if (len > 0) {
		memcpy(data->data + data->ofs, p, len);
		data->ofs += len;
	}
	return true;
}

/* useful fn for writing a uint8_t */
bool asn1_write_uint8(struct asn1_data *data, uint8_t v)
{
	return asn1_write(data, &v, 1);
}

/* push a tag onto the asn1 data buffer. Used for nested structures */
bool asn1_push_tag(struct asn1_data *data, uint8_t tag)
{
	struct nesting *nesting;

	if (!asn1_write_uint8(data, tag)) {
		return false;
	}
	nesting = talloc(data, struct nesting);
	if (!nesting) {
		data->has_error = true;
		return false;
	}

	nesting->start = data->ofs;
	nesting->next = data->nesting;
	data->nesting = nesting;
	return asn1_write_uint8(data, 0xff);
}

/* pop a tag */
bool asn1_pop_tag(struct asn1_data *data)
{
	struct nesting *nesting;
	size_t len;

	if (data->has_error) {
		return false;
	}

	nesting = data->nesting;

	if (!nesting) {
		data->has_error = true;
		return false;
	}
	len = data->ofs - (nesting->start+1);
	/* yes, this is ugly. We don't know in advance how many bytes the length
	   of a tag will take, so we assumed 1 byte. If we were wrong then we
	   need to correct our mistake */
	if (len > 0xFFFFFF) {
		data->data[nesting->start] = 0x84;
		if (!asn1_write_uint8(data, 0)) return false;
		if (!asn1_write_uint8(data, 0)) return false;
		if (!asn1_write_uint8(data, 0)) return false;
		if (!asn1_write_uint8(data, 0)) return false;
		memmove(data->data+nesting->start+5, data->data+nesting->start+1, len);
		data->data[nesting->start+1] = (len>>24) & 0xFF;
		data->data[nesting->start+2] = (len>>16) & 0xFF;
		data->data[nesting->start+3] = (len>>8) & 0xFF;
		data->data[nesting->start+4] = len&0xff;
	} else if (len > 0xFFFF) {
		data->data[nesting->start] = 0x83;
		if (!asn1_write_uint8(data, 0)) return false;
		if (!asn1_write_uint8(data, 0)) return false;
		if (!asn1_write_uint8(data, 0)) return false;
		memmove(data->data+nesting->start+4, data->data+nesting->start+1, len);
		data->data[nesting->start+1] = (len>>16) & 0xFF;
		data->data[nesting->start+2] = (len>>8) & 0xFF;
		data->data[nesting->start+3] = len&0xff;
	} else if (len > 255) {
		data->data[nesting->start] = 0x82;
		if (!asn1_write_uint8(data, 0)) return false;
		if (!asn1_write_uint8(data, 0)) return false;
		memmove(data->data+nesting->start+3, data->data+nesting->start+1, len);
		data->data[nesting->start+1] = len>>8;
		data->data[nesting->start+2] = len&0xff;
	} else if (len > 127) {
		data->data[nesting->start] = 0x81;
		if (!asn1_write_uint8(data, 0)) return false;
		memmove(data->data+nesting->start+2, data->data+nesting->start+1, len);
		data->data[nesting->start+1] = len;
	} else {
		data->data[nesting->start] = len;
	}

	data->nesting = nesting->next;
	talloc_free(nesting);
	return true;
}

/* "i" is the one's complement representation, as is the normal result of an
 * implicit signed->unsigned conversion */

static bool push_int_bigendian(struct asn1_data *data, unsigned int i, bool negative)
{
	uint8_t lowest = i & 0xFF;

	i = i >> 8;
	if (i != 0)
		if (!push_int_bigendian(data, i, negative))
			return false;

	if (data->nesting->start+1 == data->ofs) {

		/* We did not write anything yet, looking at the highest
		 * valued byte */

		if (negative) {
			/* Don't write leading 0xff's */
			if (lowest == 0xFF)
				return true;

			if ((lowest & 0x80) == 0) {
				/* The only exception for a leading 0xff is if
				 * the highest bit is 0, which would indicate
				 * a positive value */
				if (!asn1_write_uint8(data, 0xff))
					return false;
			}
		} else {
			if (lowest & 0x80) {
				/* The highest bit of a positive integer is 1,
				 * this would indicate a negative number. Push
				 * a 0 to indicate a positive one */
				if (!asn1_write_uint8(data, 0))
					return false;
			}
		}
	}

	return asn1_write_uint8(data, lowest);
}

/* write an Integer without the tag framing. Needed for example for the LDAP
 * Abandon Operation */

bool asn1_write_implicit_Integer(struct asn1_data *data, int i)
{
	if (data->has_error) {
		return false;
	}

	if (i == -1) {
		/* -1 is special as it consists of all-0xff bytes. In
                    push_int_bigendian this is the only case that is not
                    properly handled, as all 0xff bytes would be handled as
                    leading ones to be ignored. */
		return asn1_write_uint8(data, 0xff);
	} else {
		return push_int_bigendian(data, i, i<0);
	}
}


/* write an integer */
bool asn1_write_Integer(struct asn1_data *data, int i)
{
	if (!asn1_push_tag(data, ASN1_INTEGER)) return false;
	if (!asn1_write_implicit_Integer(data, i)) return false;
	return asn1_pop_tag(data);
}

/* write a BIT STRING */
bool asn1_write_BitString(struct asn1_data *data, const void *p, size_t length, uint8_t padding)
{
	if (!asn1_push_tag(data, ASN1_BIT_STRING)) return false;
	if (!asn1_write_uint8(data, padding)) return false;
	if (!asn1_write(data, p, length)) return false;
	return asn1_pop_tag(data);
}

bool ber_write_OID_String(TALLOC_CTX *mem_ctx, DATA_BLOB *blob, const char *OID)
{
	unsigned long int v, v2;
	const char *p = (const char *)OID;
	char *newp;
	int i;
	int error = 0;

	if (!isdigit(*p)) return false;
	v = smb_strtoul(p, &newp, 10, &error, SMB_STR_STANDARD);
	if (newp[0] != '.' || error != 0) {
		return false;
	}
	p = newp + 1;

	if (!isdigit(*p)) return false;
	v2 = smb_strtoul(p, &newp, 10, &error, SMB_STR_STANDARD);
	if (newp[0] != '.' || error != 0) {
		return false;
	}
	p = newp + 1;

	/*the ber representation can't use more space than the string one */
	*blob = data_blob_talloc(mem_ctx, NULL, strlen(OID));
	if (!blob->data) return false;

	blob->data[0] = 40*v + v2;

	i = 1;
	while (*p) {
		if (!isdigit(*p)) return false;
		v = smb_strtoul(p, &newp, 10, &error, SMB_STR_STANDARD);
		if (newp[0] == '.' || error != 0) {
			p = newp + 1;
			if (!*p) {
				/* empty last component */
				data_blob_free(blob);
				return false;
			}
		} else if (newp[0] == '\0') {
			p = newp;
		} else {
			data_blob_free(blob);
			return false;
		}
		if (v >= (1<<28)) blob->data[i++] = (0x80 | ((v>>28)&0x7f));
		if (v >= (1<<21)) blob->data[i++] = (0x80 | ((v>>21)&0x7f));
		if (v >= (1<<14)) blob->data[i++] = (0x80 | ((v>>14)&0x7f));
		if (v >= (1<<7)) blob->data[i++] = (0x80 | ((v>>7)&0x7f));
		blob->data[i++] = (v&0x7f);
	}

	blob->length = i;

	return true;
}

/**
 * Serialize partial OID string.
 * Partial OIDs are in the form:
 *   1:2.5.6:0x81
 *   1:2.5.6:0x8182
 */
bool ber_write_partial_OID_String(TALLOC_CTX *mem_ctx, DATA_BLOB *blob, const char *partial_oid)
{
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	char *oid = talloc_strdup(tmp_ctx, partial_oid);
	char *p;

	/* truncate partial part so ber_write_OID_String() works */
	p = strchr(oid, ':');
	if (p) {
		*p = '\0';
		p++;
	}

	if (!ber_write_OID_String(mem_ctx, blob, oid)) {
		talloc_free(tmp_ctx);
		return false;
	}

	/* Add partially encoded sub-identifier */
	if (p) {
		DATA_BLOB tmp_blob = strhex_to_data_blob(tmp_ctx, p);
		if (!data_blob_append(mem_ctx, blob, tmp_blob.data,
				      tmp_blob.length)) {
			talloc_free(tmp_ctx);
			return false;
		}
	}

	talloc_free(tmp_ctx);

	return true;
}

/* write an object ID to a ASN1 buffer */
bool asn1_write_OID(struct asn1_data *data, const char *OID)
{
	DATA_BLOB blob;

	if (!asn1_push_tag(data, ASN1_OID)) return false;

	if (!ber_write_OID_String(NULL, &blob, OID)) {
		data->has_error = true;
		return false;
	}

	if (!asn1_write(data, blob.data, blob.length)) {
		data_blob_free(&blob);
		data->has_error = true;
		return false;
	}
	data_blob_free(&blob);
	return asn1_pop_tag(data);
}

/* write an octet string */
bool asn1_write_OctetString(struct asn1_data *data, const void *p, size_t length)
{
	if (!asn1_push_tag(data, ASN1_OCTET_STRING)) return false;
	if (!asn1_write(data, p, length)) return false;
	return asn1_pop_tag(data);
}

/* write a LDAP string */
bool asn1_write_LDAPString(struct asn1_data *data, const char *s)
{
	return asn1_write(data, s, strlen(s));
}

/* write a LDAP string from a DATA_BLOB */
bool asn1_write_DATA_BLOB_LDAPString(struct asn1_data *data, const DATA_BLOB *s)
{
	return asn1_write(data, s->data, s->length);
}

/* write a general string */
bool asn1_write_GeneralString(struct asn1_data *data, const char *s)
{
	if (!asn1_push_tag(data, ASN1_GENERAL_STRING)) return false;
	if (!asn1_write_LDAPString(data, s)) return false;
	return asn1_pop_tag(data);
}

bool asn1_write_ContextSimple(struct asn1_data *data, uint8_t num, DATA_BLOB *blob)
{
	if (!asn1_push_tag(data, ASN1_CONTEXT_SIMPLE(num))) return false;
	if (!asn1_write(data, blob->data, blob->length)) return false;
	return asn1_pop_tag(data);
}

/* write a BOOLEAN */
bool asn1_write_BOOLEAN(struct asn1_data *data, bool v)
{
	if (!asn1_push_tag(data, ASN1_BOOLEAN)) return false;
	if (!asn1_write_uint8(data, v ? 0xFF : 0)) return false;
	return asn1_pop_tag(data);
}

bool asn1_read_BOOLEAN(struct asn1_data *data, bool *v)
{
	uint8_t tmp = 0;
	if (!asn1_start_tag(data, ASN1_BOOLEAN)) return false;
	*v = false;
	if (!asn1_read_uint8(data, &tmp)) return false;
	if (tmp == 0xFF) {
		*v = true;
	}
	return asn1_end_tag(data);
}

/* write a BOOLEAN in a simple context */
bool asn1_write_BOOLEAN_context(struct asn1_data *data, bool v, int context)
{
	if (!asn1_push_tag(data, ASN1_CONTEXT_SIMPLE(context))) return false;
	if (!asn1_write_uint8(data, v ? 0xFF : 0)) return false;
	return asn1_pop_tag(data);
}

bool asn1_read_BOOLEAN_context(struct asn1_data *data, bool *v, int context)
{
	uint8_t tmp = 0;
	if (!asn1_start_tag(data, ASN1_CONTEXT_SIMPLE(context))) return false;
	*v = false;
	if (!asn1_read_uint8(data, &tmp)) return false;
	if (tmp == 0xFF) {
		*v = true;
	}
	return asn1_end_tag(data);
}

/* check a BOOLEAN */
bool asn1_check_BOOLEAN(struct asn1_data *data, bool v)
{
	uint8_t b = 0;

	if (!asn1_read_uint8(data, &b)) return false;
	if (b != ASN1_BOOLEAN) {
		data->has_error = true;
		return false;
	}
	if (!asn1_read_uint8(data, &b)) return false;
	if (b != v) {
		data->has_error = true;
		return false;
	}
	return !data->has_error;
}


/* load a struct asn1_data structure with a lump of data, ready to be parsed */
bool asn1_load(struct asn1_data *data, DATA_BLOB blob)
{
	/*
	 * Save the maximum depth
	 */
	unsigned max_depth = data->max_depth;

	ZERO_STRUCTP(data);
	data->data = (uint8_t *)talloc_memdup(data, blob.data, blob.length);
	if (!data->data) {
		data->has_error = true;
		return false;
	}
	data->length = blob.length;
	data->max_depth = max_depth;
	return true;
}

/* Peek into an ASN1 buffer, not advancing the pointer */
bool asn1_peek(struct asn1_data *data, void *p, int len)
{
	if (data->has_error)
		return false;

	if (len < 0 || data->ofs + len < data->ofs || data->ofs + len < len)
		return false;

	if (data->ofs + len > data->length) {
		/* we need to mark the buffer as consumed, so the caller knows
		   this was an out of data error, and not a decode error */
		data->ofs = data->length;
		return false;
	}

	memcpy(p, data->data + data->ofs, len);
	return true;
}

/* read from a ASN1 buffer, advancing the buffer pointer */
bool asn1_read(struct asn1_data *data, void *p, int len)
{
	if (!asn1_peek(data, p, len)) {
		data->has_error = true;
		return false;
	}

	data->ofs += len;
	return true;
}

/* read a uint8_t from a ASN1 buffer */
bool asn1_read_uint8(struct asn1_data *data, uint8_t *v)
{
	return asn1_read(data, v, 1);
}

bool asn1_peek_uint8(struct asn1_data *data, uint8_t *v)
{
	return asn1_peek(data, v, 1);
}

bool asn1_peek_tag(struct asn1_data *data, uint8_t tag)
{
	uint8_t b;

	if (asn1_tag_remaining(data) <= 0) {
		return false;
	}

	if (!asn1_peek_uint8(data, &b))
		return false;

	return (b == tag);
}

/*
 * just get the needed size the tag would consume
 */
static bool asn1_peek_tag_needed_size(struct asn1_data *data, uint8_t tag,
				      size_t *size)
{
	off_t start_ofs = data->ofs;
	uint8_t b;
	size_t taglen = 0;

	if (data->has_error) {
		return false;
	}

	if (!asn1_read_uint8(data, &b)) {
		data->ofs = start_ofs;
		data->has_error = false;
		return false;
	}

	if (b != tag) {
		data->ofs = start_ofs;
		data->has_error = false;
		return false;
	}

	if (!asn1_read_uint8(data, &b)) {
		data->ofs = start_ofs;
		data->has_error = false;
		return false;
	}

	if (b & 0x80) {
		int n = b & 0x7f;
		if (!asn1_read_uint8(data, &b)) {
			data->ofs = start_ofs;
			data->has_error = false;
			return false;
		}
		if (n > 4) {
			/*
			 * We should not allow more than 4 bytes
			 * for the encoding of the tag length.
			 *
			 * Otherwise we'd overflow the taglen
			 * variable on 32 bit systems.
			 */
			data->ofs = start_ofs;
			data->has_error = false;
			return false;
		}
		taglen = b;
		while (n > 1) {
			size_t tmp_taglen;

			if (!asn1_read_uint8(data, &b)) {
				data->ofs = start_ofs;
				data->has_error = false;
				return false;
			}

			tmp_taglen = (taglen << 8) | b;

			if ((tmp_taglen >> 8) != taglen) {
				/* overflow */
				data->ofs = start_ofs;
				data->has_error = false;
				return false;
			}
			taglen = tmp_taglen;

			n--;
		}
	} else {
		taglen = b;
	}

	*size = (data->ofs - start_ofs) + taglen;

	data->ofs = start_ofs;
	data->has_error = false;
	return true;
}

/* start reading a nested asn1 structure */
bool asn1_start_tag(struct asn1_data *data, uint8_t tag)
{
	uint8_t b;
	struct nesting *nesting;

	/*
	 * Check the depth of the parse tree and prevent it from growing
	 * too large.
	 */
	data->depth++;
	if (data->depth > data->max_depth) {
		data->has_error = true;
		return false;
	}

	if (!asn1_read_uint8(data, &b))
		return false;

	if (b != tag) {
		data->has_error = true;
		return false;
	}
	nesting = talloc(data, struct nesting);
	if (!nesting) {
		data->has_error = true;
		return false;
	}

	if (!asn1_read_uint8(data, &b)) {
		return false;
	}

	if (b & 0x80) {
		int n = b & 0x7f;
		if (!asn1_read_uint8(data, &b))
			return false;
		nesting->taglen = b;
		while (n > 1) {
			size_t taglen;

			if (!asn1_read_uint8(data, &b))
				return false;

			taglen = (nesting->taglen << 8) | b;

			if ((taglen >> 8) != nesting->taglen) {
				/* overflow */
				data->has_error = true;
				return false;
			}
			nesting->taglen = taglen;

			n--;
		}
	} else {
		nesting->taglen = b;
	}
	nesting->start = data->ofs;
	nesting->next = data->nesting;
	data->nesting = nesting;
	if (asn1_tag_remaining(data) == -1) {
		return false;
	}
	return !data->has_error;
}

/* stop reading a tag */
bool asn1_end_tag(struct asn1_data *data)
{
	struct nesting *nesting;

	if (data->depth == 0) {
		smb_panic("Unbalanced ASN.1 Tag nesting");
	}
	data->depth--;
	/* make sure we read it all */
	if (asn1_tag_remaining(data) != 0) {
		data->has_error = true;
		return false;
	}

	nesting = data->nesting;

	if (!nesting) {
		data->has_error = true;
		return false;
	}

	data->nesting = nesting->next;
	talloc_free(nesting);
	return true;
}

/* work out how many bytes are left in this nested tag */
int asn1_tag_remaining(struct asn1_data *data)
{
	int remaining;
	if (data->has_error) {
		return -1;
	}

	if (!data->nesting) {
		data->has_error = true;
		return -1;
	}
	remaining = data->nesting->taglen - (data->ofs - data->nesting->start);
	if (remaining > (data->length - data->ofs)) {
		data->has_error = true;
		return -1;
	}
	if (remaining < 0) {
		data->has_error = true;
		return -1;
	}
	return remaining;
}

/**
 * Internal implementation for reading binary OIDs
 * Reading is done as far in the buffer as valid OID
 * till buffer ends or not valid sub-identifier is found.
 */
static bool _ber_read_OID_String_impl(TALLOC_CTX *mem_ctx, DATA_BLOB blob,
				      char **OID, size_t *bytes_eaten)
{
	size_t i;
	uint8_t *b;
	unsigned int v;
	char *tmp_oid = NULL;

	if (blob.length < 2) return false;

	b = blob.data;

	tmp_oid = talloc_asprintf(mem_ctx, "%u.%u", b[0]/40, b[0]%40);

	if (bytes_eaten != NULL) {
		*bytes_eaten = 0;
	}

	for(i = 1, v = 0; i < blob.length; i++) {
		v = (v<<7) | (b[i]&0x7f);
		if ( ! (b[i] & 0x80)) {
			talloc_asprintf_addbuf(&tmp_oid, ".%u",  v);
			v = 0;
			if (bytes_eaten)
				*bytes_eaten = i+1;
		}
	}

	if (tmp_oid == NULL) {
		goto nomem;
	}

	*OID = tmp_oid;
	return true;

nomem:
	return false;
}

/* read an object ID from a data blob */
bool ber_read_OID_String(TALLOC_CTX *mem_ctx, DATA_BLOB blob, char **OID)
{
	size_t bytes_eaten;

	if (!_ber_read_OID_String_impl(mem_ctx, blob, OID, &bytes_eaten))
		return false;

	return (bytes_eaten == blob.length);
}

/**
 * Deserialize partial OID string.
 * Partial OIDs are in the form:
 *   1:2.5.6:0x81
 *   1:2.5.6:0x8182
 */
bool ber_read_partial_OID_String(TALLOC_CTX *mem_ctx, DATA_BLOB blob,
				 char **partial_oid)
{
	size_t bytes_left;
	size_t bytes_eaten;
	char *identifier = NULL;
	char *tmp_oid = NULL;

	if (!_ber_read_OID_String_impl(mem_ctx, blob, &tmp_oid, &bytes_eaten))
		return false;

	if (bytes_eaten < blob.length) {
		bytes_left = blob.length - bytes_eaten;
		identifier = hex_encode_talloc(mem_ctx, &blob.data[bytes_eaten], bytes_left);
		if (!identifier)	goto nomem;

		*partial_oid = talloc_asprintf_append_buffer(tmp_oid, ":0x%s", identifier);
		if (!*partial_oid)	goto nomem;
		TALLOC_FREE(identifier);
	} else {
		*partial_oid = tmp_oid;
	}

	return true;

nomem:
	TALLOC_FREE(identifier);
	TALLOC_FREE(tmp_oid);
	return false;
}

/* read an object ID from a ASN1 buffer */
bool asn1_read_OID(struct asn1_data *data, TALLOC_CTX *mem_ctx, char **OID)
{
	DATA_BLOB blob;
	int len;

	if (!asn1_start_tag(data, ASN1_OID)) return false;

	len = asn1_tag_remaining(data);
	if (len < 0) {
		data->has_error = true;
		return false;
	}

	blob = data_blob(NULL, len);
	if (!blob.data) {
		data->has_error = true;
		return false;
	}

	if (!asn1_read(data, blob.data, len)) return false;
	if (!asn1_end_tag(data)) {
		data_blob_free(&blob);
		return false;
	}

	if (!ber_read_OID_String(mem_ctx, blob, OID)) {
		data->has_error = true;
		data_blob_free(&blob);
		return false;
	}

	data_blob_free(&blob);
	return true;
}

/* check that the next object ID is correct */
bool asn1_check_OID(struct asn1_data *data, const char *OID)
{
	char *id;

	if (!asn1_read_OID(data, data, &id)) return false;

	if (strcmp(id, OID) != 0) {
		talloc_free(id);
		data->has_error = true;
		return false;
	}
	talloc_free(id);
	return true;
}

/* read a LDAPString from a ASN1 buffer */
bool asn1_read_LDAPString(struct asn1_data *data, TALLOC_CTX *mem_ctx, char **s)
{
	int len;
	len = asn1_tag_remaining(data);
	if (len < 0) {
		data->has_error = true;
		return false;
	}
	*s = talloc_array(mem_ctx, char, len+1);
	if (! *s) {
		data->has_error = true;
		return false;
	}
	(*s)[len] = 0;
	return asn1_read(data, *s, len);
}


/* read a GeneralString from a ASN1 buffer */
bool asn1_read_GeneralString(struct asn1_data *data, TALLOC_CTX *mem_ctx, char **s)
{
	if (!asn1_start_tag(data, ASN1_GENERAL_STRING)) return false;
	if (!asn1_read_LDAPString(data, mem_ctx, s)) return false;
	return asn1_end_tag(data);
}


/* read a octet string blob */
bool asn1_read_OctetString(struct asn1_data *data, TALLOC_CTX *mem_ctx, DATA_BLOB *blob)
{
	int len;
	ZERO_STRUCTP(blob);
	if (!asn1_start_tag(data, ASN1_OCTET_STRING)) return false;
	len = asn1_tag_remaining(data);
	if (len < 0) {
		data->has_error = true;
		return false;
	}
	*blob = data_blob_talloc(mem_ctx, NULL, len+1);
	if (!blob->data || blob->length < len) {
		data->has_error = true;
		return false;
	}
	if (!asn1_read(data, blob->data, len)) goto err;
	if (!asn1_end_tag(data)) goto err;
	blob->length--;
	blob->data[len] = 0;
	return true;

  err:

	data_blob_free(blob);
	*blob = data_blob_null;
	return false;
}

bool asn1_read_ContextSimple(struct asn1_data *data, TALLOC_CTX *mem_ctx, uint8_t num,
			     DATA_BLOB *blob)
{
	int len;
	ZERO_STRUCTP(blob);
	if (!asn1_start_tag(data, ASN1_CONTEXT_SIMPLE(num))) return false;
	len = asn1_tag_remaining(data);
	if (len < 0) {
		data->has_error = true;
		return false;
	}
	*blob = data_blob_talloc(mem_ctx, NULL, len + 1);
	if ((len != 0) && (!blob->data)) {
		data->has_error = true;
		return false;
	}
	if (!asn1_read(data, blob->data, len)) return false;
	blob->length--;
	blob->data[len] = 0;
	return asn1_end_tag(data);
}

/* read an integer without tag*/
bool asn1_read_implicit_Integer(struct asn1_data *data, int *i)
{
	uint8_t b;
	uint32_t x = 0;
	bool first_byte = true;

	*i = 0;

	while (!data->has_error && asn1_tag_remaining(data)>0) {
		if (!asn1_read_uint8(data, &b)) return false;
		if (first_byte) {
			if (b & 0x80) {
				/* Number is negative. */
				x = (uint32_t)-1;
			}
			first_byte = false;
		}
		x = (x << 8) + b;
	}
	*i = (int)x;

	return !data->has_error;
}

/* read an integer */
bool asn1_read_Integer(struct asn1_data *data, int *i)
{
	*i = 0;

	if (!asn1_start_tag(data, ASN1_INTEGER)) return false;
	if (!asn1_read_implicit_Integer(data, i)) return false;
	return asn1_end_tag(data);
}

/* read a BIT STRING */
bool asn1_read_BitString(struct asn1_data *data, TALLOC_CTX *mem_ctx, DATA_BLOB *blob, uint8_t *padding)
{
	int len;
	ZERO_STRUCTP(blob);
	if (!asn1_start_tag(data, ASN1_BIT_STRING)) return false;
	len = asn1_tag_remaining(data);
	if (len < 0) {
		data->has_error = true;
		return false;
	}
	if (!asn1_read_uint8(data, padding)) return false;

	*blob = data_blob_talloc(mem_ctx, NULL, len+1);
	if (!blob->data || blob->length < len) {
		data->has_error = true;
		return false;
	}
	if (asn1_read(data, blob->data, len - 1)) {
		blob->length--;
		blob->data[len] = 0;
		asn1_end_tag(data);
	}

	if (data->has_error) {
		data_blob_free(blob);
		*blob = data_blob_null;
		*padding = 0;
		return false;
	}
	return true;
}

/* read a non-negative enumerated value */
bool asn1_read_enumerated(struct asn1_data *data, int *v)
{
	unsigned int val_will_wrap = (0xFFU << ((sizeof(int)*8)-8));
	*v = 0;

	if (!asn1_start_tag(data, ASN1_ENUMERATED)) return false;
	while (!data->has_error && asn1_tag_remaining(data)>0) {
		uint8_t b;
		if (!asn1_read_uint8(data, &b)) {
			return false;
		}
		if (*v & val_will_wrap) {
			/*
			 * There is something already in
			 * the top byte of the int. If we
			 * shift left by 8 it's going to
			 * wrap. Prevent this.
			 */
			data->has_error = true;
			return false;
		}
		/*
		 * To please/fool the Undefined Behaviour Sanitizer we cast to
		 * unsigned for the left shift.
		 */
		*v = ((unsigned int)*v << 8) + b;
		if (*v < 0) {
			/* ASN1_ENUMERATED can't be -ve. */
			data->has_error = true;
			return false;
		}
	}
	return asn1_end_tag(data);
}

/* write an enumerated value to the stream */
bool asn1_write_enumerated(struct asn1_data *data, uint8_t v)
{
	if (!asn1_push_tag(data, ASN1_ENUMERATED)) return false;
	if (!asn1_write_uint8(data, v)) return false;
	return asn1_pop_tag(data);
}

/*
  Get us the data just written without copying
*/
bool asn1_blob(const struct asn1_data *asn1, DATA_BLOB *blob)
{
	if (asn1->has_error) {
		return false;
	}
	if (asn1->nesting != NULL) {
		return false;
	}
	blob->data = asn1->data;
	blob->length = asn1->length;
	return true;
}

bool asn1_extract_blob(struct asn1_data *asn1, TALLOC_CTX *mem_ctx,
		       DATA_BLOB *pblob)
{
	DATA_BLOB blob;

	if (!asn1_blob(asn1, &blob)) {
		return false;
	}

	*pblob = (DATA_BLOB) { .length = blob.length };
	pblob->data = talloc_move(mem_ctx, &blob.data);

	/*
	 * Stop access from here on
	 */
	asn1->has_error = true;

	return true;
}

/*
  Fill in an asn1 struct without making a copy
*/
void asn1_load_nocopy(struct asn1_data *data, uint8_t *buf, size_t len)
{
	/*
	 * Save max_depth
	 */
	unsigned max_depth = data->max_depth;
	ZERO_STRUCTP(data);
	data->data = buf;
	data->length = len;
	data->max_depth = max_depth;
}

int asn1_peek_full_tag(DATA_BLOB blob, uint8_t tag, size_t *packet_size)
{
	struct asn1_data asn1;
	size_t size;
	bool ok;

	ZERO_STRUCT(asn1);
	asn1.data = blob.data;
	asn1.length = blob.length;

	ok = asn1_peek_tag_needed_size(&asn1, tag, &size);
	if (!ok) {
		return EMSGSIZE;
	}

	if (size > blob.length) {
		*packet_size = size;
		return EAGAIN;
	}

	*packet_size = size;
	return 0;
}

/*
 * Get the length of the ASN.1 data
 */
size_t asn1_get_length(const struct asn1_data *asn1) {
	return asn1->length;
}
