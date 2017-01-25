#ifndef INCLUDES_TARANTOOL_BOX_VY_STMT_H
#define INCLUDES_TARANTOOL_BOX_VY_STMT_H
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

#include <trivia/util.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <msgpuck.h>

#include "tuple.h"
#include "tuple_compare.h"
#include "iproto_constants.h"

#if defined(__cplusplus)
extern "C" {
#endif /* defined(__cplusplus) */

struct xrow_header;
struct region;
struct tuple_format;
struct iovec;

/**
 * There are two groups of statements:
 *
 *  - SELECT, DELETE and REPLACE in secondary indexes are "key"
 *    statements.
 *  - UPSERT and REPLACE in a primary index are "tuple"
 *    statements.
 *
 * Statements structure:
 *                                  data_offset
 *                                      ^
 * +------------------------------------+
 * |      1 - 8 byte  4 bytes                 MessagePack data
 * |     . - - - - - + - - -+ - -+ - - -+--------------+- - - - - - .
 *tuple: | type data | offN | .. | off1 | fields array | operations |
 *       . - - - - - + -+ - + - -+ -+ - +--------------+- - - - - - .
 *                      |     ...   |       ^     ^
 *                      |           +-------+     |
 *                      +-------------------------+
 * 'Type data' contains 1 byte for 'n_upserts' field, if the
 * statement has UPSERT type.
 * n_upserts is number of UPSERT statements for the same key
 * preceding this statement. Used to trigger upsert squashing in
 * the background. @sa vy_range_set_upsert().
 *
 * Also 'type data' can contain 8 bytes
 * for column mask of UPDATE operation (@sa vy_can_skip_update()).
 *
 * Offsets are stored only for indexed fields in primary index
 * tuples. (For format @sa tuple_format.h)
 * Field 'operations' is used to store operations of UPSERT
 * statements.
 */
struct vy_stmt {
	struct tuple base;
	int64_t lsn;
	/* IPROTO_SELECT/REPLACE/UPSERT/DELETE */
	enum iproto_type type:4;
	/**
	 * Set if the statement contains only key fields without
	 * offsets. That is such statement can be used in
	 * comparators as key.
	 */
	bool is_key_compatible:1;
	/**
	 * Set if the statement is DELETE or REPLACE statement
	 * created during the UPDATE or UPSERT of a space with
	 * secondary indexes.
	 */
	bool has_column_mask:1;
	/**
	 * Type specific data, offsets array concatenated with
	 * MessagePack fields array.
	 * char raw[0];
	 */
};

/**
 * Initialize struct vy_stmt.
 * @param stmt              Vinyl statement to initialize.
 * @param format            Format of the statement.
 * @param bsize             Size of the variable part of the
 *                          statement. It includes size of
 *                          MessagePack tuple data and, for
 *                          upserts, MessagePack array of
 *                          operations.
 * @param type              Statement type.
 * @param lsn               Statement LSN.
 * @param is_key_compatible True if the statement contains only
 *                          indexed fields and hasn't offsets
 *                          table.
 * @param has_column_mask   True if the statement has 8 byte
 *                          column mask right after last struct
 *                          field and before offsets table.
 */
void
vy_stmt_create(struct tuple *stmt, const struct tuple_format *format,
	       uint32_t bsize, enum iproto_type type, int64_t lsn,
	       bool is_key_compatible, bool has_column_mask);

/** Get LSN of the vinyl statement. */
static inline int64_t
vy_stmt_lsn(const struct tuple *stmt)
{
	return ((const struct vy_stmt *) stmt)->lsn;
}

/** Set LSN of the vinyl statement. */
static inline void
vy_stmt_set_lsn(struct tuple *stmt, int64_t lsn)
{
	((struct vy_stmt *) stmt)->lsn = lsn;
}

/** Get type of the vinyl statement. */
static inline enum iproto_type
vy_stmt_type(const struct tuple *stmt)
{
	return ((const struct vy_stmt *) stmt)->type;
}

/** Set type of the vinyl statement. */
static inline void
vy_stmt_set_type(struct tuple *stmt, enum iproto_type type)
{
	((struct vy_stmt *) stmt)->type = type;
}

/** Get upserts count of the vinyl statement. */
static inline uint8_t
vy_stmt_n_upserts(const struct tuple *stmt)
{
	assert(vy_stmt_type(stmt) == IPROTO_UPSERT);
	return *((const uint8_t *) stmt + sizeof(struct vy_stmt));
}

/** Set upserts count of the vinyl statement. */
static inline void
vy_stmt_set_n_upserts(struct tuple *stmt, uint8_t n)
{
	assert(vy_stmt_type(stmt) == IPROTO_UPSERT);
	*((uint8_t *) stmt + sizeof(struct vy_stmt)) = n;
}

/** Return true, if the statement can be treated as key. */
static inline bool
vy_stmt_key_compatible(const struct tuple *stmt)
{
	return ((const struct vy_stmt *) stmt)->is_key_compatible;
}

/**
 * Return true if the statement is part of an UPDATE operation.
 */
static inline bool
vy_stmt_has_column_mask(const struct tuple *stmt)
{
	return ((const struct vy_stmt *) stmt)->has_column_mask;
}

/**
 * Set column mask for the statement, that is part of an UPDATE
 * statement.
 */
static inline void
vy_stmt_set_column_mask(struct tuple *stmt, uint64_t mask)
{
	assert(vy_stmt_has_column_mask(stmt));
	*((uint64_t *) ((char *) stmt + sizeof(struct vy_stmt))) = mask;
}

/**
 * Get column mask of the statement that is part of an UPDATE
 * statement.
 */
static inline uint64_t
vy_stmt_column_mask(const struct tuple *stmt)
{
	assert(vy_stmt_has_column_mask(stmt));
	return *((const uint64_t *) ((const char *) stmt +
				     sizeof(struct vy_stmt)));
}

/** Return MessagePack array with key fields of the statement. */
static inline const char *
vy_stmt_cast_to_key(const struct tuple *stmt)
{
	assert(vy_stmt_key_compatible(stmt));
	return tuple_data(stmt);
}

/** Create a tuple in the vinyl engine format. @sa tuple_new(). */
struct tuple *
vy_tuple_new(struct tuple_format *format, const char *data, const char *end);

/**
 * Free the tuple of a vinyl space.
 * @pre tuple->refs  == 0
 */
void
vy_tuple_delete(struct tuple_format *format, struct tuple *tuple);

/**
 * Duplicate statememnt.
 *
 * @param stmt statement
 * @return new statement of the same type with the same data.
 */
struct tuple *
vy_stmt_dup(const struct tuple *stmt);

/**
 * Specialized comparators are faster than general-purpose comparators.
 * For example, vy_stmt_compare - slowest comparator because it in worst case
 * checks all combinations of key and tuple types, but
 * vy_key_compare - fastest comparator, because it shouldn't check statement
 * types.
 */

/**
 * Compare key statements by their raw data.
 * @param key_a Left operand of comparison.
 * @param key_b Right operand of comparison.
 * @param key_def Definition of the format of both statements.
 *
 * @retval 0   if key_a == key_b
 * @retval > 0 if key_a > key_b
 * @retval < 0 if key_a < key_b
 */
static inline int
vy_key_compare_raw(const char *key_a, const char *key_b,
		   const struct key_def *key_def)
{
	uint32_t part_count_a = mp_decode_array(&key_a);
	uint32_t part_count_b = mp_decode_array(&key_b);
	return tuple_compare_key_raw(key_a, part_count_a, key_b, part_count_b,
				     key_def);
}

/** @sa vy_key_compare_raw. */
static inline int
vy_key_compare(const struct tuple *a, const struct tuple *b,
	       const struct key_def *key_def)
{
	assert(vy_stmt_key_compatible(a) && vy_stmt_key_compatible(b));
	return vy_key_compare_raw(vy_stmt_cast_to_key(a),
				  vy_stmt_cast_to_key(b), key_def);
}

/**
 * Compare statements by their raw data.
 * @param a       Left operand of comparison.
 * @param b       Right operand of comparison.
 * @param key_def Key definition of the both statements.
 *
 * @retval 0   if a == b
 * @retval > 0 if a > b
 * @retval < 0 if a < b
 */
static inline int
vy_tuple_compare(const struct tuple *a, const struct tuple *b,
		 const struct key_def *key_def)
{
	assert(!vy_stmt_key_compatible(a) && !vy_stmt_key_compatible(b));
	return tuple_compare_default(a, b, key_def);
}

/*
 * Compare a tuple statement with a key statement using their raw data.
 * @param tuple_stmt the raw data of a tuple statement
 * @param key raw data of a key statement
 *
 * @retval > 0  tuple > key.
 * @retval == 0 tuple == key in all fields
 * @retval == 0 tuple is prefix of key
 * @retval == 0 key is a prefix of tuple
 * @retval < 0  tuple < key.
 */
static inline int
vy_tuple_compare_with_key(const struct tuple *tuple, const struct tuple *key,
			  const struct key_def *key_def)
{
	assert(!vy_stmt_key_compatible(tuple) && vy_stmt_key_compatible(key));
	const char *key_mp = vy_stmt_cast_to_key(key);
	uint32_t part_count = mp_decode_array(&key_mp);
	return tuple_compare_with_key_default(tuple, key_mp, part_count,
					      key_def);
}

/** @sa vy_stmt_compare_raw. */
static inline int
vy_stmt_compare(const struct tuple *a, const struct tuple *b,
		const struct key_def *key_def)
{
	bool a_is_tuple = !vy_stmt_key_compatible(a);
	bool b_is_tuple = !vy_stmt_key_compatible(b);
	if (a_is_tuple && b_is_tuple) {
		return vy_tuple_compare(a, b, key_def);
	} else if (a_is_tuple && !b_is_tuple) {
		return vy_tuple_compare_with_key(a, b, key_def);
	} else if (!a_is_tuple && b_is_tuple) {
		return -vy_tuple_compare_with_key(b, a, key_def);
	} else {
		assert(!a_is_tuple && !b_is_tuple);
		return vy_key_compare(a, b, key_def);
	}
}

/** @sa vy_stmt_compare_with_raw_key. */
static inline int
vy_stmt_compare_with_key(const struct tuple *stmt, const struct tuple *key,
			 const struct key_def *key_def)
{
	assert(vy_stmt_key_compatible(key));
	if (! vy_stmt_key_compatible(stmt))
		return vy_tuple_compare_with_key(stmt, key, key_def);
	return vy_key_compare(stmt, key, key_def);
}

/**
 * Create the SELECT statement from raw MessagePack data.
 * @param format     Format of an index.
 * @param key        MessagePack data that contain an array of
 *                   fields WITHOUT the array header.
 * @param part_count Count of the key fields that will be saved as
 *                   result.
 *
 * @retval NULL     Memory allocation error.
 * @retval not NULL Success.
 */
struct tuple *
vy_stmt_new_select(struct tuple_format *format, const char *key,
		   uint32_t part_count);

/**
 * Create the REPLACE statement from raw MessagePack data.
 * @param tuple_begin     MessagePack data that contain an array
 *                        of fields WITH the array header.
 * @param tuple_end       End of the array that begins from
 *                        \a tuple_begin.
 * @param format          Format of a tuple for offsets generating.
 * @param part_count      Part count from key definition.
 * @param has_column_mask True if the statement has 8 byte column
 *                        mask right after last struct field and
 *                        before offsets table.
 * @retval NULL     Memory allocation error.
 * @retval not NULL Success.
 */
struct tuple *
vy_stmt_new_replace(const char *tuple_begin, const char *tuple_end,
		    struct tuple_format *format, uint32_t part_count,
		    bool has_column_mask);

/**
 * Create the UPSERT statement from raw MessagePack data.
 * @param tuple_begin MessagePack data that contain an array of fields WITH the
 *                    array header.
 * @param tuple_end End of the array that begins from @param tuple_begin.
 * @param format Format of a tuple for offsets generating.
 * @param part_count Part count from key definition.
 * @param operations Vector of update operations.
 * @param ops_cnt Length of the update operations vector.
 *
 * @retval NULL     Memory allocation error.
 * @retval not NULL Success.
 */
struct tuple *
vy_stmt_new_upsert(const char *tuple_begin, const char *tuple_end,
		   struct tuple_format *format, uint32_t part_count,
		   struct iovec *operations, uint32_t ops_cnt);

/**
 * Create REPLACE statement from UPSERT statement.
 *
 * @param upsert upsert statement.
 * @retval not NULL Success.
 * @retval     NULL Memory error.
 */
struct tuple *
vy_stmt_replace_from_upsert(const struct tuple *upsert);

/**
 * Extract MessagePack data from the REPLACE/UPSERT statement.
 * @param stmt An UPSERT or REPLACE statement.
 * @param[out] p_size Size of the MessagePack array in bytes.
 *
 * @return MessagePack array of tuple fields.
 */
static inline const char *
vy_upsert_data_range(const struct tuple *tuple, uint32_t *p_size)
{
	assert(vy_stmt_type(tuple) == IPROTO_UPSERT);
	const char *mp = tuple_data(tuple);
	assert(mp_typeof(*mp) == MP_ARRAY);
	const char *mp_end = mp;
	mp_next(&mp_end);
	assert(mp < mp_end);
	*p_size = mp_end - mp;
	return mp;
}

/**
 * Extract the operations array from the UPSERT statement.
 * @param stmt An UPSERT statement.
 * @param mp_size Out parameter for size of the returned array.
 *
 * @retval Pointer on MessagePack array of update operations.
 */
static inline const char *
vy_stmt_upsert_ops(const struct tuple *tuple, uint32_t *mp_size)
{
	assert(vy_stmt_type(tuple) == IPROTO_UPSERT);
	const char *mp = tuple_data(tuple);
	mp_next(&mp);
	*mp_size = tuple_data(tuple) + tuple->bsize - mp;
	return mp;
}

/**
 * Extract the key compatible statement from raw data.
 * @param stmt    Raw data of struct vy_stmt.
 * @param key_def Key definition.
 * @param gc      Region for temporary allocations. Automatically
 *                shrinked to the original size.
 * @param type    Type of the new statement.
 *
 * @retval not NULL Success.
 * @retval NULL Memory allocation error.
 */
struct tuple *
vy_stmt_extract_key(const struct tuple *stmt, const struct key_def *key_def,
		    struct region *gc, enum iproto_type type);

/**
 * Extract the new statement with all indexed fields of the
 * specified statement. Such statements contains offsets table and
 * is not key compatible.
 * @sa vy_update(), vy_upsert().
 * @param format          Format of the statement.
 * @param tuple           Vinyl statement to extract the full key.
 * @param type            Type of the new statement.
 * @param has_column_mask True if the statement has 8 byte column
 *                        mask right after last struct field and
 *                        before offsets table.
 * @retval not NULL Success.
 * @retval     NULL Memory error.
 */
struct tuple *
vy_stmt_extract_full_key(struct tuple_format *format, const struct tuple *tuple,
			 enum iproto_type type, bool has_column_mask);

/**
 * Create the key_compatible statement from MessagePack array.
 * @param format  Format of an index.
 * @param key     MessagePack array of key fields.
 * @param key_def Definition of the key.
 * @param type    Type of the result statement.
 *
 * @retval not NULL Success.
 * @retval     NULL Memory error.
 */
struct tuple *
vy_key_from_msgpack(struct tuple_format *format, const char *key,
		    enum iproto_type type);

/**
 * Encode vy_stmt as xrow_header
 *
 * @retval 0 if OK
 * @retval -1 if error
 */
int
vy_stmt_encode(const struct tuple *value, const struct key_def *key_def,
	       struct xrow_header *xrow);

/**
 * Reconstruct vinyl tuple info and data from xrow
 *
 * @retval stmt on success
 * @retval NULL on error
 */
struct tuple *
vy_stmt_decode(struct xrow_header *xrow, struct tuple_format *format,
	       uint32_t part_count);

/**
 * Format a key into string.
 * Example: [1, 2, "string"]
 * \sa mp_snprint()
 */
int
vy_key_snprint(char *buf, int size, const char *key);

/**
 * Format a statement into string.
 * Example: REPLACE([1, 2, "string"], lsn=48)
 */
int
vy_stmt_snprint(char *buf, int size, const struct tuple *stmt);

/*
* Format a key into string using a static buffer.
* Useful for gdb and say_debug().
* \sa vy_key_snprint()
*/
const char *
vy_key_str(const char *key);

/*
* Format a statement into string using a static buffer.
* Useful for gdb and say_debug().
* \sa vy_stmt_snprint()
*/
const char *
vy_stmt_str(const struct tuple *stmt);

#if defined(__cplusplus)
} /* extern "C" */
#endif /* defined(__cplusplus) */

#endif /* INCLUDES_TARANTOOL_BOX_VY_STMT_H */
