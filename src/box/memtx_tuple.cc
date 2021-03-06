/*
 * Copyright 2010-2016, Tarantool AUTHORS, please see AUTHORS file.
 *
 * Redistribution and use in source and binary forms, with or
 * without modification, are permitted provided that the following
 * conditions are met:
 *
 * 1. Redistributions of source code must retain the above
 *    copyright notice, this list of conditions and the
 *    following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials
 *    provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * AUTHORS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "memtx_tuple.h"
#include "tuple.h"
#include "small/small.h"
#include "box.h"

struct memtx_tuple {
	/*
	 * sic: the header of the tuple is used
	 * to store a free list pointer in smfree_delayed.
	 * Please don't change it without understanding
	 * how smfree_delayed and snapshotting COW works.
	 */
	/** Snapshot generation version. */
	uint32_t version;
	struct tuple base;
};

/** Common quota for memtx tuples and indexes */
extern struct quota memtx_quota;
/** Memtx tuple allocator */
extern struct small_alloc memtx_alloc;
/** Memtx tuple slab arena */
extern struct slab_arena memtx_arena;

struct tuple_format_vtab memtx_tuple_format_vtab = {
	memtx_tuple_new,
	memtx_tuple_delete,
};

struct tuple *
memtx_tuple_new(struct tuple_format *format, const char *data, const char *end)
{
	assert(mp_typeof(*data) == MP_ARRAY);
	size_t tuple_len = end - data;
	size_t total =
		sizeof(struct memtx_tuple) + tuple_len + format->field_map_size;
	ERROR_INJECT(ERRINJ_TUPLE_ALLOC,
		     do { diag_set(OutOfMemory, (unsigned) total,
				   "slab allocator", "memtx_tuple"); return NULL; }
		     while(false); );
	struct memtx_tuple *memtx_tuple =
		(struct memtx_tuple *) smalloc(&memtx_alloc, total);
	/**
	 * Use a nothrow version and throw an exception here,
	 * to throw an instance of ClientError. Apart from being
	 * more nice to the user, ClientErrors are ignored in
	 * panic_on_wal_error=false mode, allowing us to start
	 * with lower arena than necessary in the circumstances
	 * of disaster recovery.
	 */
	if (memtx_tuple == NULL) {
		if (total > memtx_alloc.objsize_max) {
			diag_set(ClientError, ER_SLAB_ALLOC_MAX,
				 (unsigned) total);
			error_log(diag_last_error(diag_get()));
		} else {
			diag_set(OutOfMemory, (unsigned) total,
				 "slab allocator", "memtx_tuple");
		}
		return NULL;
	}
	struct tuple *tuple = &memtx_tuple->base;
	tuple->refs = 0;
	memtx_tuple->version = snapshot_version;
	tuple->bsize = tuple_len;
	tuple->format_id = tuple_format_id(format);
	tuple_format_ref(format, 1);
	/*
	 * Data offset is calculated from the begin of the struct
	 * tuple base, not from memtx_tuple, because the struct
	 * tuple is not the first field of the memtx_tuple.
	 */
	tuple->data_offset = sizeof(struct tuple) + format->field_map_size;
	char *raw = (char *) tuple + tuple->data_offset;
	uint32_t *field_map = (uint32_t *) raw;
	memcpy(raw, data, tuple_len);
	if (tuple_init_field_map(format, field_map, raw)) {
		memtx_tuple_delete(format, tuple);
		return NULL;
	}
	say_debug("%s(%zu) = %p", __func__, tuple_len, memtx_tuple);
	return tuple;
}

void
memtx_tuple_delete(struct tuple_format *format, struct tuple *tuple)
{
	say_debug("%s(%p)", __func__, tuple);
	assert(tuple->refs == 0);
	size_t total = sizeof(struct memtx_tuple) + tuple->bsize +
		       format->field_map_size;
	tuple_format_ref(format, -1);
	struct memtx_tuple *memtx_tuple =
		container_of(tuple, struct memtx_tuple, base);
	if (!memtx_alloc.is_delayed_free_mode ||
	    memtx_tuple->version == snapshot_version)
		smfree(&memtx_alloc, memtx_tuple, total);
	else
		smfree_delayed(&memtx_alloc, memtx_tuple, total);
}
