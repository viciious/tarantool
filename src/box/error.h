#ifndef TARANTOOL_BOX_ERROR_H_INCLUDED
#define TARANTOOL_BOX_ERROR_H_INCLUDED
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
#include "errcode.h"
#include "exception.h"

extern const struct type type_ClientError;
class ClientError: public Exception {
public:
	virtual void raise()
	{
		throw this;
	}

	virtual void log() const;

	int
	errcode() const
	{
		return m_errcode;
	}

	ClientError(const char *file, unsigned line, uint32_t errcode, ...);
	/* A special constructor for lbox_raise */
	ClientError(const char *file, unsigned line, const char *msg,
		    uint32_t errcode);

	static uint32_t get_errcode(const Exception *e);
private:
	/* client errno code */
	int m_errcode;
};

class LoggedError: public ClientError {
public:
	template <typename ... Args>
	LoggedError(const char *file, unsigned line, uint32_t errcode, Args ... args)
		: ClientError(file, line, errcode, args...)
	{
		/* TODO: actually calls ClientError::log */
		log();
	}
};

class IllegalParams: public LoggedError {
public:
	template <typename ... Args>
	IllegalParams(const char *file, unsigned line, const char *format,
		      Args ... args)
		:LoggedError(file, line, ER_ILLEGAL_PARAMS,
			     format, args...) {}
};

class ErrorInjection: public LoggedError {
public:
	ErrorInjection(const char *file, unsigned line, const char *msg);
};

/** \cond public */
struct box_error;
typedef struct box_error box_error_t;

/**
 * Return error type, e.g. "ClientError", "SocketError", etc.
 */
API_EXPORT const char *
box_error_type(const box_error_t *error);

/*
 * Return IPROTO error code
 */
API_EXPORT uint32_t
box_error_code(const box_error_t *error);

/*
 * Return error message
 */
API_EXPORT const char *
box_error_message(const box_error_t *error);

/**
 * Return last error
 */
API_EXPORT const box_error_t *
box_error_last(void);

/*
 * Clear last error
 */
API_EXPORT void
box_error_clear(void);

/*
 * Set last error
 * \param code IPROTO error code
 */
API_EXPORT int
box_error_raise(uint32_t code, const char *fmt, ...);
/** \endcond public */

#endif /* TARANTOOL_BOX_ERROR_H_INCLUDED */