#ifndef TARANTOOL_RECOVERY_H_INCLUDED
#define TARANTOOL_RECOVERY_H_INCLUDED
/*
 * Copyright 2010-2015, Tarantool AUTHORS, please see AUTHORS file.
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
 * THIS SOFTWARE IS PROVIDED BY <COPYRIGHT HOLDER> ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * <COPYRIGHT HOLDER> OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include "trivia/util.h"
#include "third_party/tarantool_ev.h"
#include "xlog.h"
#include "vclock.h"
#include "tt_uuid.h"
#include "wal.h"

#if defined(__cplusplus)
extern "C" {
#endif /* defined(__cplusplus) */

struct recovery;
extern struct recovery *recovery;

struct xrow_header;
typedef void (apply_row_f)(struct recovery *, void *,
			   struct xrow_header *packet);

struct recovery {
	struct vclock vclock;
	/** The WAL we're currently reading/writing from/to. */
	struct xlog *current_wal;
	struct xdir wal_dir;
	/**
	 * This is used in local hot standby or replication
	 * relay mode: look for changes in the wal_dir and apply them
	 * locally or send to the replica.
	 */
	struct fiber *watcher;
	/**
	 * apply_row is a module callback invoked during initial
	 * recovery and when reading rows from the master.
	 */
	apply_row_f *apply_row;
	void *apply_row_param;
	uint32_t server_id;
};

struct recovery *
recovery_new(const char *wal_dirname, bool panic_on_wal_error,
	     apply_row_f apply_row, void *apply_row_param);

void
recovery_delete(struct recovery *r);

/* to be called at exit */
void
recovery_exit(struct recovery *r);

void
recovery_bootstrap(struct recovery *r);

void
recover_xlog(struct recovery *r, struct xlog *l);

void
recovery_follow_local(struct recovery *r, const char *name,
		      ev_tstamp wal_dir_rescan_delay);

void
recovery_stop_local(struct recovery *r);

void
recovery_finalize(struct recovery *r, enum wal_mode mode,
		  int64_t rows_per_wal);

void
recovery_fill_lsn(struct recovery *r, struct xrow_header *row);

void
recovery_apply_row(struct recovery *r, struct xrow_header *packet);

/**
 * The write ahead log doesn't store the last checkpoint:
 * it is represented by the last valid snapshot of memtx engine.
 * This is legacy from the time the entire box was single-engine.
 *
 * @param[out] vclock vclock of the last checkpoint
 * @retval         signature of the last checkpoint, or -1
 *                 in case of fresh boot
 *
 * The function may throw XlogError exception.
 * It is implemented in memtx_engine.cc
 */
int
recovery_last_checkpoint(struct vclock *vclock);

#if defined(__cplusplus)
} /* extern "C" */
#endif /* defined(__cplusplus) */

#endif /* TARANTOOL_RECOVERY_H_INCLUDED */
