/*
   Unix SMB/CIFS implementation.

   generalised event loop handling

   Copyright (C) Andrew Tridgell 2005
   Copyright (C) Stefan Metzmacher 2005-2009
   Copyright (C) Volker Lendecke 2008

     ** NOTE! The following LGPL license applies to the tevent
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __TEVENT_H__
#define __TEVENT_H__

#include <stdint.h>
#include <talloc.h>
#include <sys/time.h>
#include <sys/types.h>
#include <stdbool.h>

/* for old gcc releases that don't have the feature test macro __has_attribute */
#ifndef __has_attribute
#define __has_attribute(x) 0
#endif

#ifdef TEVENT_DEPRECATED
#ifndef _DEPRECATED_
#if __has_attribute(deprecated) || (__GNUC__ >= 3)
#define _DEPRECATED_ __attribute__ ((deprecated))
#else
#define _DEPRECATED_
#endif
#endif
#endif

struct tevent_context;
struct tevent_ops;
struct tevent_fd;
struct tevent_timer;
struct tevent_immediate;
struct tevent_signal;
struct tevent_thread_proxy;
struct tevent_threaded_context;

/**
 * @defgroup tevent The tevent API
 *
 * The tevent low-level API
 *
 * This API provides the public interface to manage events in the tevent
 * mainloop. Functions are provided for managing low-level events such
 * as timer events, fd events and signal handling.
 *
 * @{
 */

/* event handler types */
/**
 * Called when a file descriptor monitored by tevent has
 * data to be read or written on it.
 */
typedef void (*tevent_fd_handler_t)(struct tevent_context *ev,
				    struct tevent_fd *fde,
				    uint16_t flags,
				    void *private_data);

/**
 * Called when tevent is ceasing the monitoring of a file descriptor.
 */
typedef void (*tevent_fd_close_fn_t)(struct tevent_context *ev,
				     struct tevent_fd *fde,
				     int fd,
				     void *private_data);

/**
 * Called when a tevent timer has fired.
 */
typedef void (*tevent_timer_handler_t)(struct tevent_context *ev,
				       struct tevent_timer *te,
				       struct timeval current_time,
				       void *private_data);

/**
 * Called when a tevent immediate event is invoked.
 */
typedef void (*tevent_immediate_handler_t)(struct tevent_context *ctx,
					   struct tevent_immediate *im,
					   void *private_data);

/**
 * Called after tevent detects the specified signal.
 */
typedef void (*tevent_signal_handler_t)(struct tevent_context *ev,
					struct tevent_signal *se,
					int signum,
					int count,
					void *siginfo,
					void *private_data);

/**
 * @brief Create a event_context structure.
 *
 * This must be the first events call, and all subsequent calls pass this
 * event_context as the first element. Event handlers also receive this as
 * their first argument.
 *
 * @param[in]  mem_ctx  The memory context to use.
 *
 * @return              An allocated tevent context, NULL on error.
 *
 * @see tevent_context_init()
 */
struct tevent_context *tevent_context_init(TALLOC_CTX *mem_ctx);

/**
 * @brief Create a event_context structure and select a specific backend.
 *
 * This must be the first events call, and all subsequent calls pass this
 * event_context as the first element. Event handlers also receive this as
 * their first argument.
 *
 * @param[in]  mem_ctx  The memory context to use.
 *
 * @param[in]  name     The name of the backend to use.
 *
 * @return              An allocated tevent context, NULL on error.
 */
struct tevent_context *tevent_context_init_byname(TALLOC_CTX *mem_ctx, const char *name);

/**
 * @brief Create a custom event context
 *
 * @param[in]  mem_ctx  The memory context to use.
 * @param[in]  ops      The function pointer table of the backend.
 * @param[in]  additional_data  The additional/private data to this instance
 *
 * @return              An allocated tevent context, NULL on error.
 *
 */
struct tevent_context *tevent_context_init_ops(TALLOC_CTX *mem_ctx,
					       const struct tevent_ops *ops,
					       void *additional_data);

/**
 * @brief List available backends.
 *
 * @param[in]  mem_ctx  The memory context to use.
 *
 * @return              A string vector with a terminating NULL element, NULL
 *                      on error.
 */
const char **tevent_backend_list(TALLOC_CTX *mem_ctx);

/**
 * @brief Set the default tevent backend.
 *
 * @param[in]  backend  The name of the backend to set.
 */
void tevent_set_default_backend(const char *backend);

/**
 * @brief Set the default time to wait without tevent_timers pending
 *
 * Setting the wait timeout to 0 means polling behaviour, e.g.
 * tevent_loop_once will return -1/errno=EAGAIN, when all
 * currently available events were processes.
 *
 * Setting it to UINT32_MAX makes tevent_loop_once wait forever.
 * The default is 30 seconds.
 *
 * @param[in]  ev       The tevent context to set this on
 *
 * @param[in]  secs     The number of seconds to wait without timers
 *
 * @return     secs     The previous wait_timeout value
 */
uint32_t tevent_context_set_wait_timeout(struct tevent_context *ev,
					 uint32_t secs);

#ifdef DOXYGEN
/**
 * @brief Add a file descriptor based event.
 *
 * @param[in]  ev       The event context to work on.
 *
 * @param[in]  mem_ctx  The talloc memory context to use.
 *
 * @param[in]  fd       The file descriptor to base the event on.
 *
 * @param[in]  flags    #TEVENT_FD_READ, #TEVENT_FD_WRITE or #TEVENT_FD_ERROR.
 *
 * @param[in]  handler  The callback handler for the event.
 *
 * @param[in]  private_data  The private data passed to the callback handler.
 *
 * @return              The file descriptor based event, NULL on error.
 *
 * @note To cancel the monitoring of a file descriptor, call talloc_free()
 * on the object returned by this function.
 *
 * @note The caller should avoid closing the file descriptor before
 * calling talloc_free()! Otherwise the behaviour is undefined which
 * might result in crashes. See https://bugzilla.samba.org/show_bug.cgi?id=11141
 * for an example.
 */
struct tevent_fd *tevent_add_fd(struct tevent_context *ev,
				TALLOC_CTX *mem_ctx,
				int fd,
				uint16_t flags,
				tevent_fd_handler_t handler,
				void *private_data);
#else
struct tevent_fd *_tevent_add_fd(struct tevent_context *ev,
				 TALLOC_CTX *mem_ctx,
				 int fd,
				 uint16_t flags,
				 tevent_fd_handler_t handler,
				 void *private_data,
				 const char *handler_name,
				 const char *location);
#define tevent_add_fd(ev, mem_ctx, fd, flags, handler, private_data) \
	_tevent_add_fd(ev, mem_ctx, fd, flags, handler, private_data, \
		       #handler, __location__)
#endif

/**
 * @brief Associate a custom tag with the event.
 *
 * This tag can be then retrieved with tevent_fd_get_tag()
 *
 * @param[in]  fde  The file descriptor event.
 *
 * @param[in]  tag  Custom tag.
 */
void tevent_fd_set_tag(struct tevent_fd *fde, uint64_t tag);

/**
 * @brief Get custom event tag.
 */
uint64_t tevent_fd_get_tag(const struct tevent_fd *fde);

#ifdef DOXYGEN
/**
 * @brief Add a timed event
 *
 * @param[in]  ev       The event context to work on.
 *
 * @param[in]  mem_ctx  The talloc memory context to use.
 *
 * @param[in]  next_event  Timeval specifying the absolute time to fire this
 * event. This is not an offset.
 *
 * @param[in]  handler  The callback handler for the event.
 *
 * @param[in]  private_data  The private data passed to the callback handler.
 *
 * @return The newly-created timer event, or NULL on error.
 *
 * @note To cancel a timer event before it fires, call talloc_free() on the
 * event returned from this function. This event is automatically
 * talloc_free()-ed after its event handler files, if it hasn't been freed yet.
 *
 * @note Unlike some mainloops, tevent timers are one-time events. To set up
 * a recurring event, it is necessary to call tevent_add_timer() again during
 * the handler processing.
 *
 * @note Due to the internal mainloop processing, a timer set to run
 * immediately will do so after any other pending timers fire, but before
 * any further file descriptor or signal handling events fire. Callers should
 * not rely on this behavior!
 */
struct tevent_timer *tevent_add_timer(struct tevent_context *ev,
                                      TALLOC_CTX *mem_ctx,
                                      struct timeval next_event,
                                      tevent_timer_handler_t handler,
                                      void *private_data);
#else
struct tevent_timer *_tevent_add_timer(struct tevent_context *ev,
				       TALLOC_CTX *mem_ctx,
				       struct timeval next_event,
				       tevent_timer_handler_t handler,
				       void *private_data,
				       const char *handler_name,
				       const char *location);
#define tevent_add_timer(ev, mem_ctx, next_event, handler, private_data) \
	_tevent_add_timer(ev, mem_ctx, next_event, handler, private_data, \
			  #handler, __location__)
#endif

/**
 * @brief Set the time a tevent_timer fires
 *
 * @param[in]  te       The timer event to reset
 *
 * @param[in]  next_event  Timeval specifying the absolute time to fire this
 * event. This is not an offset.
 */
void tevent_update_timer(struct tevent_timer *te, struct timeval next_event);

/**
 * @brief Associate a custom tag with the event.
 *
 * This tag can be then retrieved with tevent_timer_get_tag()
 *
 * @param[in]  te   The timer event.
 *
 * @param[in]  tag  Custom tag.
 */
void tevent_timer_set_tag(struct tevent_timer *te, uint64_t tag);

/**
 * @brief Get custom event tag.
 */
uint64_t tevent_timer_get_tag(const struct tevent_timer *te);

#ifdef DOXYGEN
/**
 * Initialize an immediate event object
 *
 * This object can be used to trigger an event to occur immediately after
 * returning from the current event (before any other event occurs)
 *
 * @param[in] mem_ctx  The talloc memory context to use as the parent
 *
 * @return An empty tevent_immediate object. Use tevent_schedule_immediate
 * to populate and use it.
 *
 * @note Available as of tevent 0.9.8
 */
struct tevent_immediate *tevent_create_immediate(TALLOC_CTX *mem_ctx);
#else
struct tevent_immediate *_tevent_create_immediate(TALLOC_CTX *mem_ctx,
						  const char *location);
#define tevent_create_immediate(mem_ctx) \
	_tevent_create_immediate(mem_ctx, __location__)
#endif

#ifdef DOXYGEN

/**
 * Schedule an event for immediate execution. This event will occur
 * immediately after returning from the current event (before any other
 * event occurs)
 *
 * @param[in] im       The tevent_immediate object to populate and use
 * @param[in] ctx      The tevent_context to run this event
 * @param[in] handler  The event handler to run when this event fires
 * @param[in] private_data  Data to pass to the event handler
 *
 * @note To cancel an immediate handler, call talloc_free() on the event returned
 * from tevent_create_immediate() or call tevent_reset_immediate() to
 * keep the structure alive for later usage.
 *
 * @see tevent_create_immediate, tevent_reset_immediate
 */
void tevent_schedule_immediate(struct tevent_immediate *im,
                struct tevent_context *ctx,
                tevent_immediate_handler_t handler,
                void *private_data);
#else
void _tevent_schedule_immediate(struct tevent_immediate *im,
				struct tevent_context *ctx,
				tevent_immediate_handler_t handler,
				void *private_data,
				const char *handler_name,
				const char *location);
#define tevent_schedule_immediate(im, ctx, handler, private_data) \
	_tevent_schedule_immediate(im, ctx, handler, private_data, \
				   #handler, __location__);
#endif

/**
 * Reset an event for immediate execution.
 *
 * Undo the effect of tevent_schedule_immediate().
 *
 * @param[in] im The tevent_immediate object to clear the handler
 *
 * @see tevent_schedule_immediate.
 */
void tevent_reset_immediate(struct tevent_immediate *im);

/**
 * @brief Associate a custom tag with the event.
 *
 * This tag can be then retrieved with tevent_immediate_get_tag()
 *
 * @param[in]  im   The immediate event.
 *
 * @param[in]  tag  Custom tag.
 */
void tevent_immediate_set_tag(struct tevent_immediate *im, uint64_t tag);

/**
 * @brief Get custom event tag.
 */
uint64_t tevent_immediate_get_tag(const struct tevent_immediate *fde);

#ifdef DOXYGEN
/**
 * @brief Add a tevent signal handler
 *
 * tevent_add_signal() creates a new event for handling a signal the next
 * time through the mainloop. It implements a very simple traditional signal
 * handler whose only purpose is to add the handler event into the mainloop.
 *
 * @param[in]  ev       The event context to work on.
 *
 * @param[in]  mem_ctx  The talloc memory context to use.
 *
 * @param[in]  signum   The signal to trap
 *
 * @param[in]  handler  The callback handler for the signal.
 *
 * @param[in]  sa_flags sigaction flags for this signal handler.
 *
 * @param[in]  private_data  The private data passed to the callback handler.
 *
 * @return The newly-created signal handler event, or NULL on error.
 *
 * @note To cancel a signal handler, call talloc_free() on the event returned
 * from this function.
 *
 * @see tevent_num_signals, tevent_sa_info_queue_count
 */
struct tevent_signal *tevent_add_signal(struct tevent_context *ev,
                     TALLOC_CTX *mem_ctx,
                     int signum,
                     int sa_flags,
                     tevent_signal_handler_t handler,
                     void *private_data);
#else
struct tevent_signal *_tevent_add_signal(struct tevent_context *ev,
					 TALLOC_CTX *mem_ctx,
					 int signum,
					 int sa_flags,
					 tevent_signal_handler_t handler,
					 void *private_data,
					 const char *handler_name,
					 const char *location);
#define tevent_add_signal(ev, mem_ctx, signum, sa_flags, handler, private_data) \
	_tevent_add_signal(ev, mem_ctx, signum, sa_flags, handler, private_data, \
			   #handler, __location__)
#endif

/**
 * @brief Associate a custom tag with the event.
 *
 * This tag can be then retrieved with tevent_signal_get_tag()
 *
 * @param[in]  fde  The signal event.
 *
 * @param[in]  tag  Custom tag.
 */
void tevent_signal_set_tag(struct tevent_signal *se, uint64_t tag);

/**
 * @brief Get custom event tag.
 */
uint64_t tevent_signal_get_tag(const struct tevent_signal *se);

/**
 * @brief the number of supported signals
 *
 * This returns value of the configure time TEVENT_NUM_SIGNALS constant.
 *
 * The 'signum' argument of tevent_add_signal() must be less than
 * TEVENT_NUM_SIGNALS.
 *
 * @see tevent_add_signal
 */
size_t tevent_num_signals(void);

/**
 * @brief the number of pending realtime signals
 *
 * This returns value of TEVENT_SA_INFO_QUEUE_COUNT.
 *
 * The tevent internals remember the last TEVENT_SA_INFO_QUEUE_COUNT
 * siginfo_t structures for SA_SIGINFO signals. If the system generates
 * more some signals get lost.
 *
 * @see tevent_add_signal
 */
size_t tevent_sa_info_queue_count(void);

#ifdef DOXYGEN
/**
 * @brief Pass a single time through the mainloop
 *
 * This will process any appropriate signal, immediate, fd and timer events
 *
 * @param[in]  ev The event context to process
 *
 * @return Zero on success, nonzero if an internal error occurred
 */
int tevent_loop_once(struct tevent_context *ev);
#else
int _tevent_loop_once(struct tevent_context *ev, const char *location);
#define tevent_loop_once(ev) \
	_tevent_loop_once(ev, __location__)
#endif

#ifdef DOXYGEN
/**
 * @brief Run the mainloop
 *
 * The mainloop will run until there are no events remaining to be processed
 *
 * @param[in]  ev The event context to process
 *
 * @return Zero if all events have been processed. Nonzero if an internal
 * error occurred.
 */
int tevent_loop_wait(struct tevent_context *ev);
#else
int _tevent_loop_wait(struct tevent_context *ev, const char *location);
#define tevent_loop_wait(ev) \
	_tevent_loop_wait(ev, __location__)
#endif


/**
 * Assign a function to run when a tevent_fd is freed
 *
 * This function is a destructor for the tevent_fd. It does not automatically
 * close the file descriptor. If this is the desired behavior, then it must be
 * performed by the close_fn.
 *
 * @param[in] fde       File descriptor event on which to set the destructor
 * @param[in] close_fn  Destructor to execute when fde is freed
 *
 * @note That the close_fn() on tevent_fd is *NOT* wrapped on contexts
 * created by tevent_context_wrapper_create()!
 *
 * @see tevent_fd_set_close_fn
 * @see tevent_context_wrapper_create
 */
void tevent_fd_set_close_fn(struct tevent_fd *fde,
			    tevent_fd_close_fn_t close_fn);

/**
 * Automatically close the file descriptor when the tevent_fd is freed
 *
 * This function calls close(fd) internally.
 *
 * @param[in] fde  File descriptor event to auto-close
 *
 * @see tevent_fd_set_close_fn
 */
void tevent_fd_set_auto_close(struct tevent_fd *fde);

/**
 * Return the flags set on this file descriptor event
 *
 * @param[in] fde  File descriptor event to query
 *
 * @return The flags set on the event. See #TEVENT_FD_READ,
 * #TEVENT_FD_WRITE and #TEVENT_FD_ERROR
 */
uint16_t tevent_fd_get_flags(struct tevent_fd *fde);

/**
 * Set flags on a file descriptor event
 *
 * @param[in] fde    File descriptor event to set
 * @param[in] flags  Flags to set on the event. See #TEVENT_FD_READ,
 * #TEVENT_FD_WRITE and #TEVENT_FD_ERROR
 */
void tevent_fd_set_flags(struct tevent_fd *fde, uint16_t flags);

/**
 * Query whether tevent supports signal handling
 *
 * @param[in] ev  An initialized tevent context
 *
 * @return True if this platform and tevent context support signal handling
 */
bool tevent_signal_support(struct tevent_context *ev);

void tevent_set_abort_fn(void (*abort_fn)(const char *reason));

/* bits for file descriptor event flags */

/**
 * Monitor a file descriptor for data to be read and errors
 *
 * Note: we map this from/to POLLIN, POLLHUP, POLLERR and
 * where available POLLRDHUP
 */
#define TEVENT_FD_READ 1
/**
 * Monitor a file descriptor for writeability
 *
 * Note: we map this from/to POLLOUT
 */
#define TEVENT_FD_WRITE 2
/**
 * Monitor a file descriptor for errors
 *
 * Note: we map this from/to POLLHUP, POLLERR and
 * where available POLLRDHUP
 */
#define TEVENT_FD_ERROR 4

/**
 * Convenience function for declaring a tevent_fd writable
 */
#define TEVENT_FD_WRITEABLE(fde) \
	tevent_fd_set_flags(fde, tevent_fd_get_flags(fde) | TEVENT_FD_WRITE)

/**
 * Convenience function for declaring a tevent_fd readable
 */
#define TEVENT_FD_READABLE(fde) \
	tevent_fd_set_flags(fde, tevent_fd_get_flags(fde) | TEVENT_FD_READ)

/**
 * Convenience function for declaring a tevent_fd waiting for errors
 */
#define TEVENT_FD_WANTERROR(fde) \
	tevent_fd_set_flags(fde, tevent_fd_get_flags(fde) | TEVENT_FD_ERROR)

/**
 * Convenience function for declaring a tevent_fd non-writable
 */
#define TEVENT_FD_NOT_WRITEABLE(fde) \
	tevent_fd_set_flags(fde, tevent_fd_get_flags(fde) & ~TEVENT_FD_WRITE)

/**
 * Convenience function for declaring a tevent_fd non-readable
 */
#define TEVENT_FD_NOT_READABLE(fde) \
	tevent_fd_set_flags(fde, tevent_fd_get_flags(fde) & ~TEVENT_FD_READ)

/**
 * Convenience function for declaring a tevent_fd not waiting for errors
 */
#define TEVENT_FD_NOT_WANTERROR(fde) \
	tevent_fd_set_flags(fde, tevent_fd_get_flags(fde) & ~TEVENT_FD_ERROR)

/**
 * Debug level of tevent
 */
enum tevent_debug_level {
	TEVENT_DEBUG_FATAL,
	TEVENT_DEBUG_ERROR,
	TEVENT_DEBUG_WARNING,
	TEVENT_DEBUG_TRACE
};

/**
 * @brief The tevent debug callbac.
 *
 * @param[in]  context  The memory context to use.
 *
 * @param[in]  level    The debug level.
 *
 * @param[in]  fmt      The format string.
 *
 * @param[in]  ap       The arguments for the format string.
 */
typedef void (*tevent_debug_fn)(void *context,
				enum tevent_debug_level level,
				const char *fmt,
				va_list ap) PRINTF_ATTRIBUTE(3,0);

/**
 * Set destination for tevent debug messages
 *
 * As of version 0.15.0 the invocation of
 * the debug function for individual messages
 * is limited by the current max_debug_level,
 * which means TEVENT_DEBUG_TRACE messages
 * are not passed by default:
 *
 * - tevent_set_debug() with debug == NULL implies
 *   tevent_set_max_debug_level(ev, TEVENT_DEBUG_FATAL).
 *
 * - tevent_set_debug() with debug != NULL implies
 *   tevent_set_max_debug_level(ev, TEVENT_DEBUG_WARNING).
 *
 * @param[in] ev        Event context to debug
 * @param[in] debug     Function to handle output printing
 * @param[in] context   The context to pass to the debug function.
 *
 * @return Always returns 0 as of version 0.9.8
 *
 * @note Default is to emit no debug messages
 *
 * @see tevent_set_max_debug_level()
 */
int tevent_set_debug(struct tevent_context *ev,
		     tevent_debug_fn debug,
		     void *context);

/**
 * Set maximum debug level for tevent debug messages
 *
 * @param[in] ev         Event context to debug
 * @param[in] max_level  Function to handle output printing
 *
 * @return The former max level is returned.
 *
 * @see tevent_set_debug()
 *
 * @note Available as of tevent 0.15.0
 */
enum tevent_debug_level
tevent_set_max_debug_level(struct tevent_context *ev,
			   enum tevent_debug_level max_level);

/**
 * Designate stderr for debug message output
 *
 * @param[in] ev     Event context to debug
 *
 * @note This function will only output TEVENT_DEBUG_FATAL, TEVENT_DEBUG_ERROR
 * and TEVENT_DEBUG_WARNING messages. For TEVENT_DEBUG_TRACE, please define a
 * function for tevent_set_debug()
 */
int tevent_set_debug_stderr(struct tevent_context *ev);

enum tevent_trace_point {
	/**
	 * Corresponds to a trace point just before waiting
	 */
	TEVENT_TRACE_BEFORE_WAIT,
	/**
	 * Corresponds to a trace point just after waiting
	 */
	TEVENT_TRACE_AFTER_WAIT,
#define TEVENT_HAS_LOOP_ONCE_TRACE_POINTS 1
	/**
	 * Corresponds to a trace point just before calling
	 * the loop_once() backend function.
	 */
	TEVENT_TRACE_BEFORE_LOOP_ONCE,
	/**
	 * Corresponds to a trace point right after the
	 * loop_once() backend function has returned.
	 */
	TEVENT_TRACE_AFTER_LOOP_ONCE,
};

typedef void (*tevent_trace_callback_t)(enum tevent_trace_point,
					void *private_data);

/**
 * Register a callback to be called at certain trace points
 *
 * @param[in] ev             Event context
 * @param[in] cb             Trace callback
 * @param[in] private_data   Data to be passed to callback
 *
 * @note The callback will be called at trace points defined by
 * tevent_trace_point.  Call with NULL to reset.
 */
void tevent_set_trace_callback(struct tevent_context *ev,
			       tevent_trace_callback_t cb,
			       void *private_data);

/**
 * Retrieve the current trace callback
 *
 * @param[in] ev             Event context
 * @param[out] cb            Registered trace callback
 * @param[out] private_data  Registered data to be passed to callback
 *
 * @note This can be used to allow one component that wants to
 * register a callback to respect the callback that another component
 * has already registered.
 */
void tevent_get_trace_callback(struct tevent_context *ev,
			       tevent_trace_callback_t *cb,
			       void *private_data);

enum tevent_event_trace_point {
	/**
	 * Corresponds to a trace point just before the event is added.
	 */
	TEVENT_EVENT_TRACE_ATTACH,

	/**
	 * Corresponds to a trace point just before the event is removed.
	 */
	TEVENT_EVENT_TRACE_DETACH,

	/**
	 * Corresponds to a trace point just before the event handler is called.
	 */
	TEVENT_EVENT_TRACE_BEFORE_HANDLER,
};

typedef void (*tevent_trace_fd_callback_t)(struct tevent_fd *fde,
					   enum tevent_event_trace_point,
					   void *private_data);

typedef void (*tevent_trace_signal_callback_t)(struct tevent_signal *se,
					       enum tevent_event_trace_point,
					       void *private_data);

typedef void (*tevent_trace_timer_callback_t)(struct tevent_timer *te,
					      enum tevent_event_trace_point,
					      void *private_data);

typedef void (*tevent_trace_immediate_callback_t)(struct tevent_immediate *im,
						  enum tevent_event_trace_point,
						  void *private_data);

/**
 * Register a callback to be called at certain trace points of fd event.
 *
 * @param[in] ev             Event context
 * @param[in] cb             Trace callback
 * @param[in] private_data   Data to be passed to callback
 *
 * @note The callback will be called at trace points defined by
 * tevent_event_trace_point. Call with NULL to reset.
 */
void tevent_set_trace_fd_callback(struct tevent_context *ev,
				  tevent_trace_fd_callback_t cb,
				  void *private_data);

/**
 * Retrieve the current trace callback of file descriptor event.
 *
 * @param[in] ev             Event context
 * @param[out] cb            Registered trace callback
 * @param[out] p_private_data  Registered data to be passed to callback
 *
 * @note This can be used to allow one component that wants to
 * register a callback to respect the callback that another component
 * has already registered.
 */
void tevent_get_trace_fd_callback(struct tevent_context *ev,
				  tevent_trace_fd_callback_t *cb,
				  void *p_private_data);

/**
 * Register a callback to be called at certain trace points of signal event.
 *
 * @param[in] ev             Event context
 * @param[in] cb             Trace callback
 * @param[in] private_data   Data to be passed to callback
 *
 * @note The callback will be called at trace points defined by
 * tevent_event_trace_point. Call with NULL to reset.
 */
void tevent_set_trace_signal_callback(struct tevent_context *ev,
				      tevent_trace_signal_callback_t cb,
				      void *private_data);

/**
 * Retrieve the current trace callback of signal event.
 *
 * @param[in] ev             Event context
 * @param[out] cb            Registered trace callback
 * @param[out] p_private_data  Registered data to be passed to callback
 *
 * @note This can be used to allow one component that wants to
 * register a callback to respect the callback that another component
 * has already registered.
 */
void tevent_get_trace_signal_callback(struct tevent_context *ev,
				      tevent_trace_signal_callback_t *cb,
				      void *p_private_data);

/**
 * Register a callback to be called at certain trace points of timer event.
 *
 * @param[in] ev             Event context
 * @param[in] cb             Trace callback
 * @param[in] private_data   Data to be passed to callback
 *
 * @note The callback will be called at trace points defined by
 * tevent_event_trace_point. Call with NULL to reset.
 */
void tevent_set_trace_timer_callback(struct tevent_context *ev,
				     tevent_trace_timer_callback_t cb,
				     void *private_data);

/**
 * Retrieve the current trace callback of timer event.
 *
 * @param[in] ev             Event context
 * @param[out] cb            Registered trace callback
 * @param[out] p_private_data  Registered data to be passed to callback
 *
 * @note This can be used to allow one component that wants to
 * register a callback to respect the callback that another component
 * has already registered.
 */
void tevent_get_trace_timer_callback(struct tevent_context *ev,
				     tevent_trace_timer_callback_t *cb,
				     void *p_private_data);

/**
 * Register a callback to be called at certain trace points of immediate event.
 *
 * @param[in] ev             Event context
 * @param[in] cb             Trace callback
 * @param[in] private_data   Data to be passed to callback
 *
 * @note The callback will be called at trace points defined by
 * tevent_event_trace_point. Call with NULL to reset.
 */
void tevent_set_trace_immediate_callback(struct tevent_context *ev,
					 tevent_trace_immediate_callback_t cb,
					 void *private_data);

/**
 * Retrieve the current trace callback of immediate event.
 *
 * @param[in] ev             Event context
 * @param[out] cb            Registered trace callback
 * @param[out] p_private_data  Registered data to be passed to callback
 *
 * @note This can be used to allow one component that wants to
 * register a callback to respect the callback that another component
 * has already registered.
 */
void tevent_get_trace_immediate_callback(struct tevent_context *ev,
					 tevent_trace_immediate_callback_t *cb,
					 void *p_private_data);

/**
 * @}
 */

/**
 * @defgroup tevent_request The tevent request functions.
 * @ingroup tevent
 *
 * A tevent_req represents an asynchronous computation.
 *
 * The tevent_req group of API calls is the recommended way of
 * programming async computations within tevent. In particular the
 * file descriptor (tevent_add_fd) and timer (tevent_add_timed) events
 * are considered too low-level to be used in larger computations. To
 * read and write from and to sockets, Samba provides two calls on top
 * of tevent_add_fd: tstream_read_packet_send/recv and tstream_writev_send/recv.
 * These requests are much easier to compose than the low-level event
 * handlers called from tevent_add_fd.
 *
 * A lot of the simplicity tevent_req has brought to the notoriously
 * hairy async programming came via a set of conventions that every
 * async computation programmed should follow. One central piece of
 * these conventions is the naming of routines and variables.
 *
 * Every async computation needs a name (sensibly called "computation"
 * down from here). From this name quite a few naming conventions are
 * derived.
 *
 * Every computation that requires local state needs a
 * @code
 * struct computation_state {
 *     int local_var;
 * };
 * @endcode
 * Even if no local variables are required, such a state struct should
 * be created containing a dummy variable. Quite a few helper
 * functions and macros (for example tevent_req_create()) assume such
 * a state struct.
 *
 * An async computation is started by a computation_send
 * function. When it is finished, its result can be received by a
 * computation_recv function. For an example how to set up an async
 * computation, see the code example in the documentation for
 * tevent_req_create() and tevent_req_post(). The prototypes for _send
 * and _recv functions should follow some conventions:
 *
 * @code
 * struct tevent_req *computation_send(TALLOC_CTX *mem_ctx,
 *                                     struct tevent_context *ev,
 *                                     ... further args);
 * int computation_recv(struct tevent_req *req, ... further output args);
 * @endcode
 *
 * The "int" result of computation_recv() depends on the result the
 * sync version of the function would have, "int" is just an example
 * here.
 *
 * Another important piece of the conventions is that the program flow
 * is interrupted as little as possible. Because a blocking
 * sub-computation requires that the flow needs to continue in a
 * separate function that is the logical sequel of some computation,
 * it should lexically follow sending off the blocking
 * sub-computation. Setting the callback function via
 * tevent_req_set_callback() requires referencing a function lexically
 * below the call to tevent_req_set_callback(), forward declarations
 * are required. A lot of the async computations thus begin with a
 * sequence of declarations such as
 *
 * @code
 * static void computation_step1_done(struct tevent_req *subreq);
 * static void computation_step2_done(struct tevent_req *subreq);
 * static void computation_step3_done(struct tevent_req *subreq);
 * @endcode
 *
 * It really helps readability a lot to do these forward declarations,
 * because the lexically sequential program flow makes the async
 * computations almost as clear to read as a normal, sync program
 * flow.
 *
 * It is up to the user of the async computation to talloc_free it
 * after it has finished. If an async computation should be aborted,
 * the tevent_req structure can be talloc_free'ed. After it has
 * finished, it should talloc_free'ed by the API user.
 *
 * tevent_req variable naming conventions:
 *
 * The name of the variable pointing to the tevent_req structure
 * returned by a _send() function SHOULD be named differently between
 * implementation and caller.
 *
 * From the point of view of the implementation (of the _send() and
 * _recv() functions) the variable returned by tevent_req_create() is
 * always called @em req.
 *
 * While the caller of the _send() function should use @em subreq to
 * hold the result.
 *
 * @see tevent_req_create()
 * @see tevent_req_fn()
 *
 * @{
 */

/**
 * An async request moves from TEVENT_REQ_INIT to
 * TEVENT_REQ_IN_PROGRESS. All other states are valid after a request
 * has finished.
 */
enum tevent_req_state {
	/**
	 * We are creating the request
	 */
	TEVENT_REQ_INIT,
	/**
	 * We are waiting the request to complete
	 */
	TEVENT_REQ_IN_PROGRESS,
	/**
	 * The request is finished successfully
	 */
	TEVENT_REQ_DONE,
	/**
	 * A user error has occurred. The user error has been
	 * indicated by tevent_req_error(), it can be retrieved via
	 * tevent_req_is_error().
	 */
	TEVENT_REQ_USER_ERROR,
	/**
	 * Request timed out after the timeout set by tevent_req_set_endtime.
	 */
	TEVENT_REQ_TIMED_OUT,
	/**
	 * An internal allocation has failed, or tevent_req_nomem has
	 * been given a NULL pointer as the first argument.
	 */
	TEVENT_REQ_NO_MEMORY,
	/**
	 * The request has been received by the caller. No further
	 * action is valid.
	 */
	TEVENT_REQ_RECEIVED
};

/**
 * @brief An async request
 */
struct tevent_req;

/**
 * @brief A tevent request callback function.
 *
 * @param[in]  subreq      The tevent async request which executed this callback.
 */
typedef void (*tevent_req_fn)(struct tevent_req *subreq);

/**
 * @brief Set an async request callback.
 *
 * See the documentation of tevent_req_post() for an example how this
 * is supposed to be used.
 *
 * @param[in]  req      The async request to set the callback.
 *
 * @param[in]  fn       The callback function to set.
 *
 * @param[in]  pvt      A pointer to private data to pass to the async request
 *                      callback.
 */
void tevent_req_set_callback(struct tevent_req *req, tevent_req_fn fn, void *pvt);
void _tevent_req_set_callback(struct tevent_req *req,
			      tevent_req_fn fn,
			      const char *fn_name,
			      void *pvt);

#define tevent_req_set_callback(req, fn, pvt) \
	_tevent_req_set_callback(req, fn, #fn, pvt)

#ifdef DOXYGEN
/**
 * @brief Get the private data cast to the given type for a callback from
 *        a tevent request structure.
 *
 * @code
 * static void computation_done(struct tevent_req *subreq) {
 *     struct tevent_req *req = tevent_req_callback_data(subreq, struct tevent_req);
 *     struct computation_state *state = tevent_req_data(req, struct computation_state);
 *     .... more things, eventually maybe call tevent_req_done(req);
 * }
 * @endcode
 *
 * @param[in]  req      The structure to get the callback data from.
 *
 * @param[in]  type     The type of the private callback data to get.
 *
 * @return              The type casted private data set NULL if not set.
 */
void *tevent_req_callback_data(struct tevent_req *req, #type);
#else
void *_tevent_req_callback_data(struct tevent_req *req);
#define tevent_req_callback_data(_req, _type) \
	talloc_get_type_abort(_tevent_req_callback_data(_req), _type)
#endif

#ifdef DOXYGEN
/**
 * @brief Get the private data for a callback from a tevent request structure.
 *
 * @param[in]  req      The structure to get the callback data from.
 *
 * @return              The private data or NULL if not set.
 */
void *tevent_req_callback_data_void(struct tevent_req *req);
#else
#define tevent_req_callback_data_void(_req) \
	_tevent_req_callback_data(_req)
#endif

#ifdef DOXYGEN
/**
 * @brief Get the private data from a tevent request structure.
 *
 * When the tevent_req has been created by tevent_req_create, the
 * result of tevent_req_data() is the state variable created by
 * tevent_req_create() as a child of the req.
 *
 * @param[in]  req      The structure to get the private data from.
 *
 * @param[in]  type	The type of the private data
 *
 * @return              The private data or NULL if not set.
 */
void *tevent_req_data(struct tevent_req *req, #type);
#else
void *_tevent_req_data(struct tevent_req *req);
#define tevent_req_data(_req, _type) \
	talloc_get_type_abort(_tevent_req_data(_req), _type)
#endif

/**
 * @brief The print function which can be set for a tevent async request.
 *
 * @param[in]  req      The tevent async request.
 *
 * @param[in]  ctx      A talloc memory context which can be uses to allocate
 *                      memory.
 *
 * @return              An allocated string buffer to print.
 *
 * Example:
 * @code
 *   static char *my_print(struct tevent_req *req, TALLOC_CTX *mem_ctx)
 *   {
 *     struct my_data *data = tevent_req_data(req, struct my_data);
 *     char *result;
 *
 *     result = tevent_req_default_print(mem_ctx, req);
 *     if (result == NULL) {
 *       return NULL;
 *     }
 *
 *     return talloc_asprintf_append_buffer(result, "foo=%d, bar=%d",
 *       data->foo, data->bar);
 *   }
 * @endcode
 */
typedef char *(*tevent_req_print_fn)(struct tevent_req *req, TALLOC_CTX *ctx);

/**
 * @brief This function sets a print function for the given request.
 *
 * This function can be used to setup a print function for the given request.
 * This will be triggered if the tevent_req_print() function was
 * called on the given request.
 *
 * @param[in]  req      The request to use.
 *
 * @param[in]  fn       A pointer to the print function
 *
 * @note This function should only be used for debugging.
 */
void tevent_req_set_print_fn(struct tevent_req *req, tevent_req_print_fn fn);

/**
 * @brief The default print function for creating debug messages.
 *
 * The function should not be used by users of the async API,
 * but custom print function can use it and append custom text
 * to the string.
 *
 * @param[in]  req      The request to be printed.
 *
 * @param[in]  mem_ctx  The memory context for the result.
 *
 * @return              Text representation of request.
 *
 */
char *tevent_req_default_print(struct tevent_req *req, TALLOC_CTX *mem_ctx);

/**
 * @brief Print an tevent_req structure in debug messages.
 *
 * This function should be used by callers of the async API.
 *
 * @param[in]  mem_ctx  The memory context for the result.
 *
 * @param[in] req       The request to be printed.
 *
 * @return              Text representation of request.
 */
char *tevent_req_print(TALLOC_CTX *mem_ctx, struct tevent_req *req);

/**
 * @brief A typedef for a cancel function for a tevent request.
 *
 * @param[in]  req      The tevent request calling this function.
 *
 * @return              True if the request could be canceled, false if not.
 */
typedef bool (*tevent_req_cancel_fn)(struct tevent_req *req);

/**
 * @brief This function sets a cancel function for the given tevent request.
 *
 * This function can be used to setup a cancel function for the given request.
 * This will be triggered if the tevent_req_cancel() function was
 * called on the given request.
 *
 * @param[in]  req      The request to use.
 *
 * @param[in]  fn       A pointer to the cancel function.
 */
void tevent_req_set_cancel_fn(struct tevent_req *req, tevent_req_cancel_fn fn);
void _tevent_req_set_cancel_fn(struct tevent_req *req,
			       tevent_req_cancel_fn fn,
			       const char *fn_name);
#define tevent_req_set_cancel_fn(req, fn) \
	_tevent_req_set_cancel_fn(req, fn, #fn)

#ifdef DOXYGEN
/**
 * @brief Try to cancel the given tevent request.
 *
 * This function can be used to cancel the given request.
 *
 * It is only possible to cancel a request when the implementation
 * has registered a cancel function via the tevent_req_set_cancel_fn().
 *
 * @param[in]  req      The request to use.
 *
 * @return              This function returns true if the request is
 *                      cancelable, otherwise false is returned.
 *
 * @note Even if the function returns true, the caller need to wait
 *       for the function to complete normally.
 *       Only the _recv() function of the given request indicates
 *       if the request was really canceled.
 */
bool tevent_req_cancel(struct tevent_req *req);
#else
bool _tevent_req_cancel(struct tevent_req *req, const char *location);
#define tevent_req_cancel(req) \
	_tevent_req_cancel(req, __location__)
#endif

/**
 * @brief A typedef for a cleanup function for a tevent request.
 *
 * @param[in]  req       The tevent request calling this function.
 *
 * @param[in]  req_state The current tevent_req_state.
 *
 */
typedef void (*tevent_req_cleanup_fn)(struct tevent_req *req,
				      enum tevent_req_state req_state);

/**
 * @brief This function sets a cleanup function for the given tevent request.
 *
 * This function can be used to setup a cleanup function for the given request.
 * This will be triggered when the tevent_req_done() or tevent_req_error()
 * function was called, before notifying the callers callback function,
 * and also before scheduling the deferred trigger.
 *
 * This might be useful if more than one tevent_req belong together
 * and need to finish both requests at the same time.
 *
 * The cleanup function is able to call tevent_req_done() or tevent_req_error()
 * recursively, the cleanup function is only triggered the first time.
 *
 * The cleanup function is also called by tevent_req_received()
 * (possibly triggered from tevent_req_destructor()) before destroying
 * the private data of the tevent_req.
 *
 * @param[in]  req      The request to use.
 *
 * @param[in]  fn       A pointer to the cancel function.
 */
void tevent_req_set_cleanup_fn(struct tevent_req *req, tevent_req_cleanup_fn fn);
void _tevent_req_set_cleanup_fn(struct tevent_req *req,
				tevent_req_cleanup_fn fn,
				const char *fn_name);
#define tevent_req_set_cleanup_fn(req, fn) \
	_tevent_req_set_cleanup_fn(req, fn, #fn)

#ifdef DOXYGEN
/**
 * @brief Create an async tevent request.
 *
 * The new async request will be initialized in state TEVENT_REQ_IN_PROGRESS.
 *
 * @code
 * struct tevent_req *req;
 * struct computation_state *state;
 * req = tevent_req_create(mem_ctx, &state, struct computation_state);
 * @endcode
 *
 * Tevent_req_create() allocates and zeros the state variable as a talloc
 * child of its result. The state variable should be used as the talloc
 * parent for all temporary variables that are allocated during the async
 * computation. This way, when the user of the async computation frees
 * the request, the state as a talloc child will be free'd along with
 * all the temporary variables hanging off the state.
 *
 * @param[in] mem_ctx   The memory context for the result.
 * @param[in] pstate    Pointer to the private request state.
 * @param[in] type      The name of the request.
 *
 * @return              A new async request. NULL on error.
 */
struct tevent_req *tevent_req_create(TALLOC_CTX *mem_ctx,
				     void **pstate, #type);
#else
struct tevent_req *_tevent_req_create(TALLOC_CTX *mem_ctx,
				      void *pstate,
				      size_t state_size,
				      const char *type,
				      const char *location);

struct tevent_req *__tevent_req_create(TALLOC_CTX *mem_ctx,
				       void *pstate,
				       size_t state_size,
				       const char *type,
				       const char *func,
				       const char *location);

#define tevent_req_create(_mem_ctx, _pstate, _type) \
	__tevent_req_create((_mem_ctx),             \
			    (_pstate),              \
			    sizeof(_type),          \
			    #_type,                 \
			    __func__,               \
			    __location__)
#endif

/**
 * @brief Set a timeout for an async request. On failure, "req" is already
 *        set to state TEVENT_REQ_NO_MEMORY.
 *
 * @param[in]  req      The request to set the timeout for.
 *
 * @param[in]  ev       The event context to use for the timer.
 *
 * @param[in]  endtime  The endtime of the request.
 *
 * @return              True if succeeded, false if not.
 */
bool tevent_req_set_endtime(struct tevent_req *req,
			    struct tevent_context *ev,
			    struct timeval endtime);

/**
 * @brief Reset the timer set by tevent_req_set_endtime.
 *
 * @param[in]  req      The request to reset the timeout for
 */
void tevent_req_reset_endtime(struct tevent_req *req);

#ifdef DOXYGEN
/**
 * @brief Call the notify callback of the given tevent request manually.
 *
 * @param[in]  req      The tevent request to call the notify function from.
 *
 * @see tevent_req_set_callback()
 */
void tevent_req_notify_callback(struct tevent_req *req);
#else
void _tevent_req_notify_callback(struct tevent_req *req, const char *location);
#define tevent_req_notify_callback(req)		\
	_tevent_req_notify_callback(req, __location__)
#endif

#ifdef DOXYGEN
/**
 * @brief An async request has successfully finished.
 *
 * This function is to be used by implementors of async requests. When a
 * request is successfully finished, this function calls the user's completion
 * function.
 *
 * @param[in]  req       The finished request.
 */
void tevent_req_done(struct tevent_req *req);
#else
void _tevent_req_done(struct tevent_req *req,
		      const char *location);
#define tevent_req_done(req) \
	_tevent_req_done(req, __location__)
#endif

#ifdef DOXYGEN
/**
 * @brief An async request has seen an error.
 *
 * This function is to be used by implementors of async requests. When a
 * request can not successfully completed, the implementation should call this
 * function with the appropriate status code.
 *
 * If error is 0 the function returns false and does nothing more.
 *
 * @param[in]  req      The request with an error.
 *
 * @param[in]  error    The error code.
 *
 * @return              On success true is returned, false if error is 0.
 *
 * @code
 * int error = first_function();
 * if (tevent_req_error(req, error)) {
 *      return;
 * }
 *
 * error = second_function();
 * if (tevent_req_error(req, error)) {
 *      return;
 * }
 *
 * tevent_req_done(req);
 * return;
 * @endcode
 */
bool tevent_req_error(struct tevent_req *req,
		      uint64_t error);
#else
bool _tevent_req_error(struct tevent_req *req,
		       uint64_t error,
		       const char *location);
#define tevent_req_error(req, error) \
	_tevent_req_error(req, error, __location__)
#endif

#ifdef DOXYGEN
/**
 * @brief Helper function for nomem check.
 *
 * Convenience helper to easily check alloc failure within a callback
 * implementing the next step of an async request.
 *
 * @param[in]  p        The pointer to be checked.
 *
 * @param[in]  req      The request being processed.
 *
 * @code
 * p = talloc(mem_ctx, bla);
 * if (tevent_req_nomem(p, req)) {
 *      return;
 * }
 * @endcode
 */
bool tevent_req_nomem(const void *p,
		      struct tevent_req *req);
#else
bool _tevent_req_nomem(const void *p,
		       struct tevent_req *req,
		       const char *location);
#define tevent_req_nomem(p, req) \
	_tevent_req_nomem(p, req, __location__)
#endif

#ifdef DOXYGEN
/**
 * @brief Indicate out of memory to a request
 *
 * @param[in]  req      The request being processed.
 */
void tevent_req_oom(struct tevent_req *req);
#else
void _tevent_req_oom(struct tevent_req *req,
		     const char *location);
#define tevent_req_oom(req) \
	_tevent_req_oom(req, __location__)
#endif

/**
 * @brief Finish a request before the caller had a chance to set the callback.
 *
 * An implementation of an async request might find that it can either finish
 * the request without waiting for an external event, or it can not even start
 * the engine. To present the illusion of a callback to the user of the API,
 * the implementation can call this helper function which triggers an
 * immediate event. This way the caller can use the same calling
 * conventions, independent of whether the request was actually deferred.
 *
 * @code
 * struct tevent_req *computation_send(TALLOC_CTX *mem_ctx,
 *                                     struct tevent_context *ev)
 * {
 *     struct tevent_req *req, *subreq;
 *     struct computation_state *state;
 *     req = tevent_req_create(mem_ctx, &state, struct computation_state);
 *     if (req == NULL) {
 *         return NULL;
 *     }
 *     subreq = subcomputation_send(state, ev);
 *     if (tevent_req_nomem(subreq, req)) {
 *         return tevent_req_post(req, ev);
 *     }
 *     tevent_req_set_callback(subreq, computation_done, req);
 *     return req;
 * }
 * @endcode
 *
 * @param[in]  req      The finished request.
 *
 * @param[in]  ev       The tevent_context for the immediate event.
 *
 * @return              The given request will be returned.
 */
struct tevent_req *tevent_req_post(struct tevent_req *req,
				   struct tevent_context *ev);

/**
 * @brief Finish multiple requests within one function
 *
 * Normally tevent_req_notify_callback() and all wrappers
 * (e.g. tevent_req_done() and tevent_req_error())
 * need to be the last thing an event handler should call.
 * This is because the callback is likely to destroy the
 * context of the current function.
 *
 * If a function wants to notify more than one caller,
 * it is dangerous if it just triggers multiple callbacks
 * in a row. With tevent_req_defer_callback() it is possible
 * to set an event context that will be used to defer the callback
 * via an immediate event (similar to tevent_req_post()).
 *
 * @code
 * struct complete_state {
 *       struct tevent_context *ev;
 *
 *       struct tevent_req **reqs;
 * };
 *
 * void complete(struct complete_state *state)
 * {
 *       size_t i, c = talloc_array_length(state->reqs);
 *
 *       for (i=0; i < c; i++) {
 *            tevent_req_defer_callback(state->reqs[i], state->ev);
 *            tevent_req_done(state->reqs[i]);
 *       }
 * }
 * @endcode
 *
 * @param[in]  req      The finished request.
 *
 * @param[in]  ev       The tevent_context for the immediate event.
 *
 * @return              The given request will be returned.
 */
void tevent_req_defer_callback(struct tevent_req *req,
			       struct tevent_context *ev);

/**
 * @brief Check if the given request is still in progress.
 *
 * It is typically used by sync wrapper functions.
 *
 * @param[in]  req      The request to poll.
 *
 * @return              The boolean form of "is in progress".
 */
bool tevent_req_is_in_progress(struct tevent_req *req);

/**
 * @brief Actively poll for the given request to finish.
 *
 * This function is typically used by sync wrapper functions.
 *
 * @param[in]  req      The request to poll.
 *
 * @param[in]  ev       The tevent_context to be used.
 *
 * @return              On success true is returned. If a critical error has
 *                      happened in the tevent loop layer false is returned.
 *                      This is not the return value of the given request!
 *
 * @note This should only be used if the given tevent context was created by the
 * caller, to avoid event loop nesting.
 *
 * @code
 * req = tstream_writev_queue_send(mem_ctx,
 *                                 ev_ctx,
 *                                 tstream,
 *                                 send_queue,
 *                                 iov, 2);
 * ok = tevent_req_poll(req, tctx->ev);
 * rc = tstream_writev_queue_recv(req, &sys_errno);
 * TALLOC_FREE(req);
 * @endcode
 */
bool tevent_req_poll(struct tevent_req *req,
		     struct tevent_context *ev);

/**
 * @brief Get the tevent request state and the actual error set by
 * tevent_req_error.
 *
 * @code
 * int computation_recv(struct tevent_req *req, uint64_t *perr)
 * {
 *     enum tevent_req_state state;
 *     uint64_t err;
 *     if (tevent_req_is_error(req, &state, &err)) {
 *         *perr = err;
 *         return -1;
 *     }
 *     return 0;
 * }
 * @endcode
 *
 * @param[in]  req      The tevent request to get the error from.
 *
 * @param[out] state    A pointer to store the tevent request error state.
 *
 * @param[out] error    A pointer to store the error set by tevent_req_error().
 *
 * @return              True if the function could set error and state, false
 *                      otherwise.
 *
 * @see tevent_req_error()
 */
bool tevent_req_is_error(struct tevent_req *req,
			 enum tevent_req_state *state,
			 uint64_t *error);

/**
 * @brief Use as the last action of a _recv() function.
 *
 * This function destroys the attached private data.
 *
 * @param[in]  req      The finished request.
 */
void tevent_req_received(struct tevent_req *req);

/**
 * @brief Mark a tevent_req for profiling
 *
 * This will turn on profiling for this tevent_req an all subreqs that
 * are directly started as helper requests off this
 * tevent_req. subreqs are chained by walking up the talloc_parent
 * hierarchy at a subreq's tevent_req_create. This means to get the
 * profiling chain right the subreq that needs to be profiled as part
 * of this tevent_req's profile must be a talloc child of the requests
 * state variable.
 *
 * @param[in] req The request to do tracing for
 *
 * @return        False if the profile could not be activated
 */
bool tevent_req_set_profile(struct tevent_req *req);

struct tevent_req_profile;

/**
 * @brief Get a request's profile for inspection
 *
 * @param[in] req The request to get the profile from
 *
 * @return        The request's profile
 */
const struct tevent_req_profile *tevent_req_get_profile(
	struct tevent_req *req);

/**
 * @brief Move the profile out of a request
 *
 * This function detaches the request's profile from the request, so
 * that the profile can outlive the request in a _recv function.
 *
 * @param[in] req     The request to move the profile out of
 * @param[in] mem_ctx The new talloc context for the profile
 *
 * @return            The moved profile
 */

struct tevent_req_profile *tevent_req_move_profile(struct tevent_req *req,
						   TALLOC_CTX *mem_ctx);

/**
 * @brief Get a profile description
 *
 * @param[in] profile  The profile to be queried
 * @param[in] req_name The name of the request (state's name)
 *
 * "req_name" after this call is still in talloc-posession of "profile"
 */
void tevent_req_profile_get_name(const struct tevent_req_profile *profile,
				 const char **req_name);

/**
 * @brief Get a profile's start event data
 *
 * @param[in] profile        The profile to be queried
 * @param[in] start_location The location where this event started
 * @param[in] start_time     The time this event started
 *
 * "start_location" after this call is still in talloc-posession of "profile"
 */
void tevent_req_profile_get_start(const struct tevent_req_profile *profile,
				  const char **start_location,
				  struct timeval *start_time);

/**
 * @brief Get a profile's stop event data
 *
 * @param[in] profile        The profile to be queried
 * @param[in] stop_location  The location where this event stopped
 * @param[in] stop_time      The time this event stopped
 *
 * "stop_location" after this call is still in talloc-posession of "profile"
 */
void tevent_req_profile_get_stop(const struct tevent_req_profile *profile,
				 const char **stop_location,
				 struct timeval *stop_time);

/**
 * @brief Get a profile's result data
 *
 * @param[in] pid        The process where this profile was taken
 * @param[in] state      The status the profile's tevent_req finished with
 * @param[in] user_error The user error of the profile's tevent_req
 */
void tevent_req_profile_get_status(const struct tevent_req_profile *profile,
				   pid_t *pid,
				   enum tevent_req_state *state,
				   uint64_t *user_error);

/**
 * @brief Retrieve the first subreq's profile from a profile
 *
 * @param[in] profile The profile to query
 *
 * @return The first tevent subreq's profile
 */
const struct tevent_req_profile *tevent_req_profile_get_subprofiles(
	const struct tevent_req_profile *profile);

/**
 * @brief Walk the chain of subreqs
 *
 * @param[in] profile The subreq's profile to walk
 *
 * @return The next subprofile in the list
 */
const struct tevent_req_profile *tevent_req_profile_next(
	const struct tevent_req_profile *profile);

/**
 * @brief Create a fresh tevent_req_profile
 *
 * @param[in] mem_ctx The talloc context to hang the fresh struct off
 *
 * @return The fresh struct
 */
struct tevent_req_profile *tevent_req_profile_create(TALLOC_CTX *mem_ctx);

/**
 * @brief Set a profile's name
 *
 * @param[in] profile The profile to set the name for
 * @param[in] name    The new name for the profile
 *
 * @return True if the internal talloc_strdup succeeded
 */
bool tevent_req_profile_set_name(struct tevent_req_profile *profile,
				 const char *name);

/**
 * @brief Set a profile's start event
 *
 * @param[in] profile        The profile to set the start data for
 * @param[in] start_location The new start location
 * @param[in] start_time     The new start time
 *
 * @return True if the internal talloc_strdup succeeded
 */
bool tevent_req_profile_set_start(struct tevent_req_profile *profile,
				  const char *start_location,
				  struct timeval start_time);

/**
 * @brief Set a profile's stop event
 *
 * @param[in] profile        The profile to set the stop data for
 * @param[in] stop_location  The new stop location
 * @param[in] stop_time      The new stop time
 *
 * @return True if the internal talloc_strdup succeeded
 */
bool tevent_req_profile_set_stop(struct tevent_req_profile *profile,
				 const char *stop_location,
				 struct timeval stop_time);

/**
 * @brief Set a profile's exit status
 *
 * @param[in] profile    The profile to set the exit status for
 * @param[in] pid        The process where this profile was taken
 * @param[in] state      The status the profile's tevent_req finished with
 * @param[in] user_error The user error of the profile's tevent_req
 */
void tevent_req_profile_set_status(struct tevent_req_profile *profile,
				   pid_t pid,
				   enum tevent_req_state state,
				   uint64_t user_error);

/**
 * @brief Add a subprofile to a profile
 *
 * @param[in] parent_profile The profile to be modified
 * @param[in] sub_profile The subreqs profile profile to be added
 *
 * "subreq" is talloc_move'ed into "parent_profile", so the talloc
 * ownership of "sub_profile" changes
 */

void tevent_req_profile_append_sub(struct tevent_req_profile *parent_profile,
				   struct tevent_req_profile **sub_profile);

/**
 * @brief Create a tevent subrequest at a given time.
 *
 * The idea is that always the same syntax for tevent requests.
 *
 * @param[in]  mem_ctx  The talloc memory context to use.
 *
 * @param[in]  ev       The event handle to setup the request.
 *
 * @param[in]  wakeup_time The time to wakeup and execute the request.
 *
 * @return              The new subrequest, NULL on error.
 *
 * Example:
 * @code
 *   static void my_callback_wakeup_done(tevent_req *subreq)
 *   {
 *     struct tevent_req *req = tevent_req_callback_data(subreq,
 *                              struct tevent_req);
 *     bool ok;
 *
 *     ok = tevent_wakeup_recv(subreq);
 *     TALLOC_FREE(subreq);
 *     if (!ok) {
 *         tevent_req_error(req, -1);
 *         return;
 *     }
 *     ...
 *   }
 * @endcode
 *
 * @code
 *   subreq = tevent_wakeup_send(mem_ctx, ev, wakeup_time);
 *   if (tevent_req_nomem(subreq, req)) {
 *     return false;
 *   }
 *   tevent_set_callback(subreq, my_callback_wakeup_done, req);
 * @endcode
 *
 * @see tevent_wakeup_recv()
 */
struct tevent_req *tevent_wakeup_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct timeval wakeup_time);

/**
 * @brief Check if the wakeup has been correctly executed.
 *
 * This function needs to be called in the callback function set after calling
 * tevent_wakeup_send().
 *
 * @param[in]  req      The tevent request to check.
 *
 * @return              True on success, false otherwise.
 *
 * @see tevent_wakeup_recv()
 */
bool tevent_wakeup_recv(struct tevent_req *req);

/* @} */

/**
 * @defgroup tevent_helpers The tevent helper functions
 * @ingroup tevent
 *
 * @todo description
 *
 * @{
 */

/**
 * @brief Compare two timeval values.
 *
 * @param[in]  tv1      The first timeval value to compare.
 *
 * @param[in]  tv2      The second timeval value to compare.
 *
 * @return              0 if they are equal.
 *                      1 if the first time is greater than the second.
 *                      -1 if the first time is smaller than the second.
 */
int tevent_timeval_compare(const struct timeval *tv1,
			   const struct timeval *tv2);

/**
 * @brief Get a zero timeval value.
 *
 * @return              A zero timeval value.
 */
struct timeval tevent_timeval_zero(void);

/**
 * @brief Get a timeval value for the current time.
 *
 * @return              A timeval value with the current time.
 */
struct timeval tevent_timeval_current(void);

/**
 * @brief Get a timeval structure with the given values.
 *
 * @param[in]  secs     The seconds to set.
 *
 * @param[in]  usecs    The microseconds to set.
 *
 * @return              A timeval structure with the given values.
 */
struct timeval tevent_timeval_set(uint32_t secs, uint32_t usecs);

/**
 * @brief Get the difference between two timeval values.
 *
 * @param[in]  tv1      The first timeval.
 *
 * @param[in]  tv2      The second timeval.
 *
 * @return              A timeval structure with the difference between the
 *                      first and the second value.
 */
struct timeval tevent_timeval_until(const struct timeval *tv1,
				    const struct timeval *tv2);

/**
 * @brief Check if a given timeval structure is zero.
 *
 * @param[in]  tv       The timeval to check if it is zero.
 *
 * @return              True if it is zero, false otherwise.
 */
bool tevent_timeval_is_zero(const struct timeval *tv);

/**
 * @brief Add the given amount of time to a timeval structure.
 *
 * @param[in]  tv        The timeval structure to add the time.
 *
 * @param[in]  secs      The seconds to add to the timeval.
 *
 * @param[in]  usecs     The microseconds to add to the timeval.
 *
 * @return               The timeval structure with the new time.
 */
struct timeval tevent_timeval_add(const struct timeval *tv, uint32_t secs,
				  uint32_t usecs);

/**
 * @brief Get a timeval in the future with a specified offset from now.
 *
 * @param[in]  secs     The seconds of the offset from now.
 *
 * @param[in]  usecs    The microseconds of the offset from now.
 *
 * @return              A timeval with the given offset in the future.
 */
struct timeval tevent_timeval_current_ofs(uint32_t secs, uint32_t usecs);

/**
 *
 * @brief A cached version of getpid()
 *
 * We use getpid() in a lot a performance critical situations
 * in order to check if caches are still valid in the current process.
 *
 * Calling getpid() always add the cost of an additional syscall!
 *
 * When tevent is build with pthread support, we already make use
 * of pthread_atfork(), so it's trivial to use it maintain a cache for getpid().
 *
 * @return              The pid of the current process.
 */
pid_t tevent_cached_getpid(void);

/* @} */


/**
 * @defgroup tevent_thread_call_depth The tevent call depth tracking functions
 * @ingroup tevent
 *
 *
 * The call depth tracking consists of two parts.
 *
 * Part 1 - storing the depth inside each tevent request.
 *
 * Each instance of 'struct tevent_req' internally stores the value of the
 * current depth. If a new subrequest is created via tevent_req_create(), the
 * newly created subrequest gets the value from the parent incremented by 1.
 *
 * Part 2 - updating external variable with the call depth of the currently
 * processed tevent request.
 *
 * The intended use of call depth is for the trace indentation.  This is done
 * by registering the address of an external size_t variable via
 * tevent_thread_call_depth_activate(). And the tracing code just reads it's
 * value.
 *
 * The updates happen during:
 *
 * tevent_req_create()
 * - external variable is set to the value of the newly created request (i.e.
 *   value of the parent incremented by 1)
 *
 * tevent_req_notify_callback()
 * - external variable is set to the value of the parent tevent request, which
 *   is just about to be processed
 *
 * tevent_queue_immediate_trigger()
 * - external variable is set to the value of the request coming from the queue
 *
 *
 * While 'Part 1' maintains the call depth value inside each teven request
 * precisely, the value of the external variable depends on the call flow and
 * can be changed after return from a function call, so it no longer matches
 * the value of the request being processed in the current function.
 *
 * @code
 * struct tevent_req *foo_send(TALLOC_CTX *mem_ctx, struct tevent_context *ev)
 * {
 *     struct tevent_req *req, *subreq;
 *     struct foo_state *state;
 *
 *     // External variable has value 'X', which is the value in parent code
 *     // It is ok, since tracing starts often only after tevent_req_create()
 *     req = tevent_req_create(mem_ctx, &state, struct foo_state);
 *
 *     // External variable has now value 'X + 1'
 *     D_DEBUG("foo_send(): the external variable has the expected value\n");
 *
 *     subreq = bar_send(state, ev, ...);
 *     tevent_req_set_callback(subreq, foo_done, req);
 *
 *     // External variable has value 'X + 1 + n', where n > 0 and n is the
 *     // depth reached in bar_send().
 *     // We want to reset it via tevent_thread_call_depth_reset_from_req(),
 *     // since we want the following D_DEBUG() to have the right trace
 *     //indentation.
 *
 *     tevent_thread_call_depth_reset_from_req(req);
 *     // External variable has again value 'X + 1' taken from req.
 *     D_DEBUG("foo_send(): the external variable has the expected value\n");
 *     return req;
 * }
 *
 * static void foo_done(struct tevent_req *subreq)
 * {
 *     struct tevent_req *req =
 *         tevent_req_callback_data(subreq,
 *         struct tevent_req);
 *     struct foo_state *state =
 *         tevent_req_data(req,
 *         struct foo_state);
 *
 *     // external variable has value 'X + 1'
 *
 *     D_DEBUG("foo_done(): the external variable has the expected value\n");
 *     status = bar_recv(subreq, state, ...)
 *     tevent_req_done(req);
 * }
 *
 * NTSTATUS foo_recv(struct tevent_req *req)
 * {
 *     struct foo_state *state = tevent_req_data( req, struct foo_state);
 *
 *     // external variable has value 'X' (not 'X + 1')
 *     // which is ok, if we consider _recv() to be an access function
 *     // called from the parent context
 *
 *     D_DEBUG("foo_recv(): external variable has the value from parent\n");
 *     return NT_STATUS_OK;
 * }
 * @endcode
 *
 * Interface has 3 parts:
 *
 * Part 1: activation/deactivation
 *
 * void tevent_thread_call_depth_set_callback(f, private_data)
 * Register a callback that can track 'call depth' and 'request flow'
 * NULL as a function callback means deactivation.
 *
 * Part 2: Mark the request (and its subrequests) to be tracked
 *
 * tevent_thread_call_depth_start(struct tevent_req *req)
 *
 * By default, all newly created requests have call depth set to 0.
 * tevent_thread_call_depth_start() should be called shortly after
 * tevent_req_create(). It sets the call depth to 1.
 * Subrequest will have call depth 2 and so on.
 *
 * Part 3: reset the external variable using value from tevent request
 *
 * tevent_thread_call_depth_reset_from_req(struct tevent_req *req)
 *
 * If the call depth is used for trace indentation, it might be useful to
 * reset the external variable to the call depth of currently processed tevent
 * request, since the ext. variable can be changed after return from a function
 * call that has created subrequests.
 *
 * THREADING
 *
 * The state is thread specific, i.e. each thread can activate it and register
 * its own external variable.
 *
 * @{
 */

enum tevent_thread_call_depth_cmd {
	TEVENT_CALL_FLOW_REQ_RESET,
	TEVENT_CALL_FLOW_REQ_CREATE,
	TEVENT_CALL_FLOW_REQ_CANCEL,
	TEVENT_CALL_FLOW_REQ_CLEANUP,
	TEVENT_CALL_FLOW_REQ_NOTIFY_CB,
	TEVENT_CALL_FLOW_REQ_QUEUE_ENTER,
	TEVENT_CALL_FLOW_REQ_QUEUE_TRIGGER,
	TEVENT_CALL_FLOW_REQ_QUEUE_LEAVE,
};

typedef void (*tevent_call_depth_callback_t)(
	void *private_data,
	enum tevent_thread_call_depth_cmd cmd,
	struct tevent_req *req,
	size_t depth,
	const char *fname);

struct tevent_thread_call_depth_state {
	tevent_call_depth_callback_t cb;
	void *cb_private;
};

extern __thread struct tevent_thread_call_depth_state
	tevent_thread_call_depth_state_g;

/**
 * Register callback function for request/subrequest call depth / flow tracking.
 *
 * @param[in]  f  External call depth and flow handling function
 */
void tevent_thread_call_depth_set_callback(tevent_call_depth_callback_t f,
					   void *private_data);

#ifdef TEVENT_DEPRECATED

void tevent_thread_call_depth_activate(size_t *ptr) _DEPRECATED_;
void tevent_thread_call_depth_deactivate(void) _DEPRECATED_;
void tevent_thread_call_depth_start(struct tevent_req *req) _DEPRECATED_;

#endif

/**
 * Reset the external call depth to the call depth of the request.
 *
 * @param[in]  req   Request from which the call depth is reset.
 * variable.
 */
void tevent_thread_call_depth_reset_from_req(struct tevent_req *req);

void _tevent_thread_call_depth_reset_from_req(struct tevent_req *req,
					      const char *fname);

#define tevent_thread_call_depth_reset_from_req(req) \
	_tevent_thread_call_depth_reset_from_req(req, __func__)

/* @} */


/**
 * @defgroup tevent_queue The tevent queue functions
 * @ingroup tevent
 *
 * A tevent_queue is used to queue up async requests that must be
 * serialized. For example writing buffers into a socket must be
 * serialized. Writing a large lump of data into a socket can require
 * multiple write(2) or send(2) system calls. If more than one async
 * request is outstanding to write large buffers into a socket, every
 * request must individually be completed before the next one begins,
 * even if multiple syscalls are required.
 *
 * Take a look at @ref tevent_queue_tutorial for more details.
 * @{
 */

struct tevent_queue;
struct tevent_queue_entry;

/**
 * @brief Associate a custom tag with the queue entry.
 *
 * This tag can be then retrieved with tevent_queue_entry_get_tag()
 *
 * @param[in]  qe   The queue entry.
 *
 * @param[in]  tag  Custom tag.
 */
void tevent_queue_entry_set_tag(struct tevent_queue_entry *qe, uint64_t tag);

/**
 * @brief Get custom queue entry tag.
 */
uint64_t tevent_queue_entry_get_tag(const struct tevent_queue_entry *qe);

typedef void (*tevent_trace_queue_callback_t)(struct tevent_queue_entry *qe,
					      enum tevent_event_trace_point,
					      void *private_data);

/**
 * Register a callback to be called at certain trace points of queue.
 *
 * @param[in] ev             Event context
 * @param[in] cb             Trace callback
 * @param[in] private_data   Data to be passed to callback
 *
 * @note The callback will be called at trace points defined by
 * tevent_event_trace_point. Call with NULL to reset.
 */
void tevent_set_trace_queue_callback(struct tevent_context *ev,
				     tevent_trace_queue_callback_t cb,
				     void *private_data);

/**
 * Retrieve the current trace callback of queue.
 *
 * @param[in] ev             Event context
 * @param[out] cb            Registered trace callback
 * @param[out] p_private_data  Registered data to be passed to callback
 *
 * @note This can be used to allow one component that wants to
 * register a callback to respect the callback that another component
 * has already registered.
 */
void tevent_get_trace_queue_callback(struct tevent_context *ev,
				     tevent_trace_queue_callback_t *cb,
				     void *p_private_data);

#ifdef DOXYGEN
/**
 * @brief Create and start a tevent queue.
 *
 * @param[in]  mem_ctx  The talloc memory context to allocate the queue.
 *
 * @param[in]  name     The name to use to identify the queue.
 *
 * @return              An allocated tevent queue on success, NULL on error.
 *
 * @see tevent_queue_start()
 * @see tevent_queue_stop()
 */
struct tevent_queue *tevent_queue_create(TALLOC_CTX *mem_ctx,
					 const char *name);
#else
struct tevent_queue *_tevent_queue_create(TALLOC_CTX *mem_ctx,
					  const char *name,
					  const char *location);

#define tevent_queue_create(_mem_ctx, _name) \
	_tevent_queue_create((_mem_ctx), (_name), __location__)
#endif

/**
 * @brief A callback trigger function run by the queue.
 *
 * @param[in]  req      The tevent request the trigger function is executed on.
 *
 * @param[in]  private_data The private data pointer specified by
 *                          tevent_queue_add().
 *
 * @see tevent_queue_add()
 * @see tevent_queue_add_entry()
 * @see tevent_queue_add_optimize_empty()
 */
typedef void (*tevent_queue_trigger_fn_t)(struct tevent_req *req,
					  void *private_data);

/**
 * @brief Add a tevent request to the queue.
 *
 * @param[in]  queue    The queue to add the request.
 *
 * @param[in]  ev       The event handle to use for the request.
 *
 * @param[in]  req      The tevent request to add to the queue.
 *
 * @param[in]  trigger  The function triggered by the queue when the request
 *                      is called. Since tevent 0.9.14 it's possible to
 *                      pass NULL, in order to just add a "blocker" to the
 *                      queue.
 *
 * @param[in]  private_data The private data passed to the trigger function.
 *
 * @return              True if the request has been successfully added, false
 *                      otherwise.
 */
bool tevent_queue_add(struct tevent_queue *queue,
		      struct tevent_context *ev,
		      struct tevent_req *req,
		      tevent_queue_trigger_fn_t trigger,
		      void *private_data);

bool _tevent_queue_add(struct tevent_queue *queue,
		      struct tevent_context *ev,
		      struct tevent_req *req,
		      tevent_queue_trigger_fn_t trigger,
		      const char* trigger_name,
		      void *private_data);

#define tevent_queue_add(queue, ev, req, trigger, private_data) \
     _tevent_queue_add(queue, ev, req, trigger, #trigger, private_data)

/**
 * @brief Add a tevent request to the queue.
 *
 * The request can be removed from the queue by calling talloc_free()
 * (or a similar function) on the returned queue entry. This
 * is the only difference to tevent_queue_add().
 *
 * @param[in]  queue    The queue to add the request.
 *
 * @param[in]  ev       The event handle to use for the request.
 *
 * @param[in]  req      The tevent request to add to the queue.
 *
 * @param[in]  trigger  The function triggered by the queue when the request
 *                      is called. Since tevent 0.9.14 it's possible to
 *                      pass NULL, in order to just add a "blocker" to the
 *                      queue.
 *
 * @param[in]  private_data The private data passed to the trigger function.
 *
 * @return              a pointer to the tevent_queue_entry if the request
 *                      has been successfully added, NULL otherwise.
 *
 * @see tevent_queue_add()
 * @see tevent_queue_add_optimize_empty()
 */
struct tevent_queue_entry *tevent_queue_add_entry(
					struct tevent_queue *queue,
					struct tevent_context *ev,
					struct tevent_req *req,
					tevent_queue_trigger_fn_t trigger,
					void *private_data);

struct tevent_queue_entry *_tevent_queue_add_entry(
					struct tevent_queue *queue,
					struct tevent_context *ev,
					struct tevent_req *req,
					tevent_queue_trigger_fn_t trigger,
					const char* trigger_name,
					void *private_data);

#define tevent_queue_add_entry(queue, ev, req, trigger, private_data) \
	_tevent_queue_add_entry(queue, ev, req, trigger, #trigger, private_data);

/**
 * @brief Add a tevent request to the queue using a possible optimization.
 *
 * This tries to optimize for the empty queue case and may calls
 * the trigger function directly. This is the only difference compared
 * to tevent_queue_add_entry().
 *
 * The caller needs to be prepared that the trigger function has
 * already called tevent_req_notify_callback(), tevent_req_error(),
 * tevent_req_done() or a similar function.
 *
 * The trigger function has no chance to see the returned
 * queue_entry in the optimized case.
 *
 * The request can be removed from the queue by calling talloc_free()
 * (or a similar function) on the returned queue entry.
 *
 * @param[in]  queue    The queue to add the request.
 *
 * @param[in]  ev       The event handle to use for the request.
 *
 * @param[in]  req      The tevent request to add to the queue.
 *
 * @param[in]  trigger  The function triggered by the queue when the request
 *                      is called. Since tevent 0.9.14 it's possible to
 *                      pass NULL, in order to just add a "blocker" to the
 *                      queue.
 *
 * @param[in]  private_data The private data passed to the trigger function.
 *
 * @return              a pointer to the tevent_queue_entry if the request
 *                      has been successfully added, NULL otherwise.
 *
 * @see tevent_queue_add()
 * @see tevent_queue_add_entry()
 */
struct tevent_queue_entry *tevent_queue_add_optimize_empty(
					struct tevent_queue *queue,
					struct tevent_context *ev,
					struct tevent_req *req,
					tevent_queue_trigger_fn_t trigger,
					void *private_data);

struct tevent_queue_entry *_tevent_queue_add_optimize_empty(
					struct tevent_queue *queue,
					struct tevent_context *ev,
					struct tevent_req *req,
					tevent_queue_trigger_fn_t trigger,
					const char* trigger_name,
					void *private_data);

#define tevent_queue_add_optimize_empty(queue, ev, req, trigger, private_data) \
	_tevent_queue_add_optimize_empty(queue, ev, req, trigger, #trigger, private_data)

/**
 * @brief Untrigger an already triggered queue entry.
 *
 * If a trigger function detects that it needs to remain
 * in the queue, it needs to call tevent_queue_stop()
 * followed by tevent_queue_entry_untrigger().
 *
 * @note In order to call tevent_queue_entry_untrigger()
 * the queue must be already stopped and the given queue_entry
 * must be the first one in the queue! Otherwise it calls abort().
 *
 * @note You can't use this together with tevent_queue_add_optimize_empty()
 * because the trigger function doesn't have access to the queue entry
 * in the case of an empty queue.
 *
 * @param[in]  queue_entry The queue entry to rearm.
 *
 * @see tevent_queue_add_entry()
 * @see tevent_queue_stop()
 */
void tevent_queue_entry_untrigger(struct tevent_queue_entry *entry);

/**
 * @brief Start a tevent queue.
 *
 * The queue is started by default.
 *
 * @param[in]  queue    The queue to start.
 */
void tevent_queue_start(struct tevent_queue *queue);

/**
 * @brief Stop a tevent queue.
 *
 * The queue is started by default.
 *
 * @param[in]  queue    The queue to stop.
 */
void tevent_queue_stop(struct tevent_queue *queue);

/**
 * @brief Get the length of the queue.
 *
 * @param[in]  queue    The queue to get the length from.
 *
 * @return              The number of elements.
 */
size_t tevent_queue_length(struct tevent_queue *queue);

/**
 * @brief Is the tevent queue running.
 *
 * The queue is started by default.
 *
 * @param[in]  queue    The queue.
 *
 * @return              Whether the queue is running or not..
 */
bool tevent_queue_running(struct tevent_queue *queue);

/**
 * @brief Create a tevent subrequest that waits in a tevent_queue
 *
 * The idea is that always the same syntax for tevent requests.
 *
 * @param[in]  mem_ctx  The talloc memory context to use.
 *
 * @param[in]  ev       The event handle to setup the request.
 *
 * @param[in]  queue    The queue to wait in.
 *
 * @return              The new subrequest, NULL on error.
 *
 * @see tevent_queue_wait_recv()
 */
struct tevent_req *tevent_queue_wait_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct tevent_queue *queue);

/**
 * @brief Check if we no longer need to wait in the queue.
 *
 * This function needs to be called in the callback function set after calling
 * tevent_queue_wait_send().
 *
 * @param[in]  req      The tevent request to check.
 *
 * @return              True on success, false otherwise.
 *
 * @see tevent_queue_wait_send()
 */
bool tevent_queue_wait_recv(struct tevent_req *req);

typedef int (*tevent_nesting_hook)(struct tevent_context *ev,
				   void *private_data,
				   uint32_t level,
				   bool begin,
				   void *stack_ptr,
				   const char *location);

/**
 * @brief Create a tevent_thread_proxy for message passing between threads.
 *
 * The tevent_context must have been allocated on the NULL
 * talloc context, and talloc_disable_null_tracking() must
 * have been called.
 *
 * @param[in]  dest_ev_ctx      The tevent_context to receive events.
 *
 * @return              An allocated tevent_thread_proxy, NULL on error.
 *                      If tevent was compiled without PTHREAD support
 *                      NULL is always returned and errno set to ENOSYS.
 *
 * @see tevent_thread_proxy_schedule()
 */
struct tevent_thread_proxy *tevent_thread_proxy_create(
                struct tevent_context *dest_ev_ctx);

/**
 * @brief Schedule an immediate event on an event context from another thread.
 *
 * Causes dest_ev_ctx, being run by another thread, to receive an
 * immediate event calling the handler with the *pp_private parameter.
 *
 * *pp_im must be a pointer to an immediate event talloced on a context owned
 * by the calling thread, or the NULL context. Ownership will
 * be transferred to the tevent_thread_proxy and *pp_im will be returned as NULL.
 *
 * *pp_private_data must be a talloced area of memory with no destructors.
 * Ownership of this memory will be transferred to the tevent library and
 * *pp_private_data will be set to NULL on successful completion of
 * the call. Set pp_private to NULL if no parameter transfer
 * needed (a pure callback). This is an asynchronous request, caller
 * does not wait for callback to be completed before returning.
 *
 * @param[in]  tp               The tevent_thread_proxy to use.
 *
 * @param[in]  pp_im            Pointer to immediate event pointer.
 *
 * @param[in]  handler          The function that will be called.
 *
 * @param[in]  pp_private_data  The talloced memory to transfer.
 *
 * @see tevent_thread_proxy_create()
 */
void tevent_thread_proxy_schedule(struct tevent_thread_proxy *tp,
				  struct tevent_immediate **pp_im,
				  tevent_immediate_handler_t handler,
				  void *pp_private_data);

/*
 * @brief Create a context for threaded activation of immediates
 *
 * A tevent_treaded_context provides a link into an event
 * context. Using tevent_threaded_schedule_immediate, it is possible
 * to activate an immediate event from within a thread.
 *
 * It is the duty of the caller of tevent_threaded_context_create() to
 * keep the event context around longer than any
 * tevent_threaded_context. tevent will abort if ev is talloc_free'ed
 * with an active tevent_threaded_context.
 *
 * If tevent is build without pthread support, this always returns
 * NULL with errno=ENOSYS.
 *
 * @param[in]  mem_ctx  The talloc memory context to use.
 * @param[in]  ev       The event context to link this to.
 * @return              The threaded context, or NULL with errno set.
 *
 * @see tevent_threaded_schedule_immediate()
 *
 * @note Available as of tevent 0.9.30
 */
struct tevent_threaded_context *tevent_threaded_context_create(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev);

#ifdef DOXYGEN
/*
 * @brief Activate an immediate from a thread
 *
 * Activate an immediate from within a thread.
 *
 * This routine does not watch out for talloc hierarchies. This means
 * that it is highly recommended to create the tevent_immediate in the
 * thread owning tctx, allocate a threaded job description for the
 * thread, hand over both pointers to a helper thread and not touch it
 * in the main thread at all anymore.
 *
 * tevent_threaded_schedule_immediate is intended as a job completion
 * indicator for simple threaded helpers.
 *
 * Please be aware that tevent_threaded_schedule_immediate is very
 * picky about its arguments: An immediate may not already be
 * activated and the handler must exist. With
 * tevent_threaded_schedule_immediate memory ownership is transferred
 * to the main thread holding the tevent context behind tctx, the
 * helper thread can't access it anymore.
 *
 * @param[in]  tctx     The threaded context to go through
 * @param[in]  im       The immediate event to activate
 * @param[in]  handler  The immediate handler to call in the main thread
 * @param[in]  private_data Pointer for the immediate handler
 *
 * @see tevent_threaded_context_create()
 *
 * @note Available as of tevent 0.9.30
 */
void tevent_threaded_schedule_immediate(struct tevent_threaded_context *tctx,
					struct tevent_immediate *im,
					tevent_immediate_handler_t handler,
					void *private_data);
#else
void _tevent_threaded_schedule_immediate(struct tevent_threaded_context *tctx,
					 struct tevent_immediate *im,
					 tevent_immediate_handler_t handler,
					 void *private_data,
					 const char *handler_name,
					 const char *location);
#define tevent_threaded_schedule_immediate(tctx, im, handler, private_data) \
	_tevent_threaded_schedule_immediate(tctx, im, handler, private_data, \
				   #handler, __location__);
#endif

#ifdef TEVENT_DEPRECATED
void tevent_loop_allow_nesting(struct tevent_context *ev) _DEPRECATED_;
void tevent_loop_set_nesting_hook(struct tevent_context *ev,
				  tevent_nesting_hook hook,
				  void *private_data) _DEPRECATED_;
int _tevent_loop_until(struct tevent_context *ev,
		       bool (*finished)(void *private_data),
		       void *private_data,
		       const char *location) _DEPRECATED_;
#define tevent_loop_until(ev, finished, private_data) \
	_tevent_loop_until(ev, finished, private_data, __location__)
#endif

int tevent_re_initialise(struct tevent_context *ev);

/* @} */

/**
 * @defgroup tevent_ops The tevent operation functions
 * @ingroup tevent
 *
 * The following structure and registration functions are exclusively
 * needed for people writing and plugging a different event engine.
 * There is nothing useful for normal tevent user in here.
 * @{
 */

struct tevent_ops {
	/* context init */
	int (*context_init)(struct tevent_context *ev);

	/* fd_event functions */
	struct tevent_fd *(*add_fd)(struct tevent_context *ev,
				    TALLOC_CTX *mem_ctx,
				    int fd, uint16_t flags,
				    tevent_fd_handler_t handler,
				    void *private_data,
				    const char *handler_name,
				    const char *location);
	void (*set_fd_close_fn)(struct tevent_fd *fde,
				tevent_fd_close_fn_t close_fn);
	uint16_t (*get_fd_flags)(struct tevent_fd *fde);
	void (*set_fd_flags)(struct tevent_fd *fde, uint16_t flags);

	/* timed_event functions */
	struct tevent_timer *(*add_timer)(struct tevent_context *ev,
					  TALLOC_CTX *mem_ctx,
					  struct timeval next_event,
					  tevent_timer_handler_t handler,
					  void *private_data,
					  const char *handler_name,
					  const char *location);

	/* immediate event functions */
	void (*schedule_immediate)(struct tevent_immediate *im,
				   struct tevent_context *ev,
				   tevent_immediate_handler_t handler,
				   void *private_data,
				   const char *handler_name,
				   const char *location);

	/* signal functions */
	struct tevent_signal *(*add_signal)(struct tevent_context *ev,
					    TALLOC_CTX *mem_ctx,
					    int signum, int sa_flags,
					    tevent_signal_handler_t handler,
					    void *private_data,
					    const char *handler_name,
					    const char *location);

	/* loop functions */
	int (*loop_once)(struct tevent_context *ev, const char *location);
	int (*loop_wait)(struct tevent_context *ev, const char *location);
};

bool tevent_register_backend(const char *name, const struct tevent_ops *ops);
const struct tevent_ops *tevent_find_ops_byname(const char *name);

/* @} */

#ifdef TEVENT_DEPRECATED
/**
 * @defgroup tevent_wrapper_ops The tevent wrapper operation functions
 * @ingroup tevent
 *
 * The following structure and registration functions are exclusively
 * needed for people writing wrapper functions for event handlers
 * e.g. wrappers can be used for debugging/profiling or impersonation.
 *
 * There is nothing useful for normal tevent user in here.
 *
 * @note That the close_fn() on tevent_fd is *NOT* wrapped!
 *
 * @see tevent_context_wrapper_create
 * @see tevent_fd_set_auto_close
 * @{
 */

struct tevent_wrapper_ops {
	const char *name;

	bool (*before_use)(struct tevent_context *wrap_ev,
			   void *private_state,
			   struct tevent_context *main_ev,
			   const char *location);
	void (*after_use)(struct tevent_context *wrap_ev,
			  void *private_state,
			  struct tevent_context *main_ev,
			  const char *location);

	void (*before_fd_handler)(struct tevent_context *wrap_ev,
				  void *private_state,
				  struct tevent_context *main_ev,
				  struct tevent_fd *fde,
				  uint16_t flags,
				  const char *handler_name,
				  const char *location);
	void (*after_fd_handler)(struct tevent_context *wrap_ev,
				 void *private_state,
				 struct tevent_context *main_ev,
				 struct tevent_fd *fde,
				 uint16_t flags,
				 const char *handler_name,
				 const char *location);

	void (*before_timer_handler)(struct tevent_context *wrap_ev,
				     void *private_state,
				     struct tevent_context *main_ev,
				     struct tevent_timer *te,
				     struct timeval requested_time,
				     struct timeval trigger_time,
				     const char *handler_name,
				     const char *location);
	void (*after_timer_handler)(struct tevent_context *wrap_ev,
				    void *private_state,
				    struct tevent_context *main_ev,
				    struct tevent_timer *te,
				    struct timeval requested_time,
				    struct timeval trigger_time,
				    const char *handler_name,
				    const char *location);

	void (*before_immediate_handler)(struct tevent_context *wrap_ev,
					 void *private_state,
					 struct tevent_context *main_ev,
					 struct tevent_immediate *im,
					 const char *handler_name,
					 const char *location);
	void (*after_immediate_handler)(struct tevent_context *wrap_ev,
					void *private_state,
					struct tevent_context *main_ev,
					struct tevent_immediate *im,
					const char *handler_name,
					const char *location);

	void (*before_signal_handler)(struct tevent_context *wrap_ev,
				      void *private_state,
				      struct tevent_context *main_ev,
				      struct tevent_signal *se,
				      int signum,
				      int count,
				      void *siginfo,
				      const char *handler_name,
				      const char *location);
	void (*after_signal_handler)(struct tevent_context *wrap_ev,
				     void *private_state,
				     struct tevent_context *main_ev,
				     struct tevent_signal *se,
				     int signum,
				     int count,
				     void *siginfo,
				     const char *handler_name,
				     const char *location);
};

#ifdef DOXYGEN
/**
 * @brief Create a wrapper tevent_context.
 *
 * @param[in]  main_ev        The main event context to work on.
 *
 * @param[in]  mem_ctx        The talloc memory context to use.
 *
 * @param[in]  ops            The tevent_wrapper_ops function table.
 *
 * @param[out] private_state  The private state use by the wrapper functions.
 *
 * @param[in]  private_type   The talloc type of the private_state.
 *
 * @return                    The wrapper event context, NULL on error.
 *
 * @note Available as of tevent 0.9.37
 * @note Deprecated as of tevent 0.9.38
 */
struct tevent_context *tevent_context_wrapper_create(struct tevent_context *main_ev,
						TALLOC_CTX *mem_ctx,
						const struct tevent_wrapper_ops *ops,
						void **private_state,
						const char *private_type);
#else
struct tevent_context *_tevent_context_wrapper_create(struct tevent_context *main_ev,
						TALLOC_CTX *mem_ctx,
						const struct tevent_wrapper_ops *ops,
						void *pstate,
						size_t psize,
						const char *type,
						const char *location) _DEPRECATED_;
#define tevent_context_wrapper_create(main_ev, mem_ctx, ops, state, type) \
	_tevent_context_wrapper_create(main_ev, mem_ctx, ops, \
				       state, sizeof(type), #type, __location__)
#endif

/**
 * @brief Check if the event context is a wrapper event context.
 *
 * @param[in]  ev       The event context to work on.
 *
 * @return              Is a wrapper (true), otherwise (false).
 *
 * @see tevent_context_wrapper_create()
 *
 * @note Available as of tevent 0.9.37
 * @note Deprecated as of tevent 0.9.38
 */
bool tevent_context_is_wrapper(struct tevent_context *ev) _DEPRECATED_;

#ifdef DOXYGEN
/**
 * @brief Prepare the environment of a (wrapper) event context.
 *
 * A caller might call this before passing a wrapper event context
 * to a tevent_req based *_send() function.
 *
 * The wrapper event context might do something like impersonation.
 *
 * tevent_context_push_use() must always be used in combination
 * with tevent_context_pop_use().
 *
 * There is a global stack of currently active/busy wrapper event contexts.
 * Each wrapper can only appear once on that global stack!
 * The stack size is limited to 32 elements, which should be enough
 * for all useful scenarios.
 *
 * In addition to an explicit tevent_context_push_use() also
 * the invocation of an immediate, timer or fd handler implicitly
 * pushes the wrapper on the stack.
 *
 * Therefore there are some strict constraints for the usage of
 * tevent_context_push_use():
 * - It must not be called from within an event handler
 *   that already acts on the wrapper.
 * - tevent_context_pop_use() must be called before
 *   leaving the code block that called tevent_context_push_use().
 * - The caller is responsible ensure the correct stack ordering
 * - Any violation of these constraints results in calling
 *   the abort handler of the given tevent context.
 *
 * Calling tevent_context_push_use() on a raw event context
 * still consumes an element on the stack, but it's otherwise
 * a no-op.
 *
 * If tevent_context_push_use() returns false, it means
 * that the wrapper's before_use() hook returned this failure,
 * in that case you must not call tevent_context_pop_use() as
 * the wrapper is not pushed onto the stack.
 *
 * @param[in]  ev       The event context to work on.
 *
 * @return              Success (true) or failure (false).
 *
 * @note This is only needed if wrapper event contexts are in use.
 *
 * @see tevent_context_pop_use
 *
 * @note Available as of tevent 0.9.37
 * @note Deprecated as of tevent 0.9.38
 */
bool tevent_context_push_use(struct tevent_context *ev);
#else
bool _tevent_context_push_use(struct tevent_context *ev,
				const char *location) _DEPRECATED_;
#define tevent_context_push_use(ev) \
	_tevent_context_push_use(ev, __location__)
#endif

#ifdef DOXYGEN
/**
 * @brief Release the environment of a (wrapper) event context.
 *
 * The wrapper event context might undo something like impersonation.
 *
 * This must be called after a successful tevent_context_push_use().
 * Any ordering violation results in calling
 * the abort handler of the given tevent context.
 *
 * This basically calls the wrapper's after_use() hook.
 *
 * @param[in]  ev       The event context to work on.
 *
 * @note This is only needed if wrapper event contexts are in use.
 *
 * @see tevent_context_push_use
 *
 * @note Available as of tevent 0.9.37
 * @note Deprecated as of tevent 0.9.38
 */
void tevent_context_pop_use(struct tevent_context *ev);
#else
void _tevent_context_pop_use(struct tevent_context *ev,
			       const char *location) _DEPRECATED_;
#define tevent_context_pop_use(ev) \
	_tevent_context_pop_use(ev, __location__)
#endif

/**
 * @brief Check is the two context pointers belong to the same low level loop
 *
 * With the introduction of wrapper contexts it's not trivial
 * to check if two context pointers belong to the same low level
 * event loop. Some code may need to know this in order
 * to make some caching decisions.
 *
 * @param[in]  ev1       The first event context.
 * @param[in]  ev2       The second event context.
 *
 * @return true if both contexts belong to the same (still existing) context
 * loop, false otherwise.
 *
 * @see tevent_context_wrapper_create
 *
 * @note Available as of tevent 0.9.37
 * @note Deprecated as of tevent 0.9.38
 */
bool tevent_context_same_loop(struct tevent_context *ev1,
			      struct tevent_context *ev2) _DEPRECATED_;

/* @} */
#endif /* TEVENT_DEPRECATED */

/**
 * @defgroup tevent_compat The tevent compatibility functions
 * @ingroup tevent
 *
 * The following definitions are useful only for compatibility with the
 * implementation originally developed within the samba4 code and will be
 * soon removed. Please NEVER use in new code.
 *
 * @todo Ignore it?
 *
 * @{
 */

#ifdef TEVENT_COMPAT_DEFINES

#define event_context	tevent_context
#define event_ops	tevent_ops
#define fd_event	tevent_fd
#define timed_event	tevent_timer
#define signal_event	tevent_signal

#define event_fd_handler_t	tevent_fd_handler_t
#define event_timed_handler_t	tevent_timer_handler_t
#define event_signal_handler_t	tevent_signal_handler_t

#define event_context_init(mem_ctx) \
	tevent_context_init(mem_ctx)

#define event_context_init_byname(mem_ctx, name) \
	tevent_context_init_byname(mem_ctx, name)

#define event_backend_list(mem_ctx) \
	tevent_backend_list(mem_ctx)

#define event_set_default_backend(backend) \
	tevent_set_default_backend(backend)

#define event_add_fd(ev, mem_ctx, fd, flags, handler, private_data) \
	tevent_add_fd(ev, mem_ctx, fd, flags, handler, private_data)

#define event_add_timed(ev, mem_ctx, next_event, handler, private_data) \
	tevent_add_timer(ev, mem_ctx, next_event, handler, private_data)

#define event_add_signal(ev, mem_ctx, signum, sa_flags, handler, private_data) \
	tevent_add_signal(ev, mem_ctx, signum, sa_flags, handler, private_data)

#define event_loop_once(ev) \
	tevent_loop_once(ev)

#define event_loop_wait(ev) \
	tevent_loop_wait(ev)

#define event_get_fd_flags(fde) \
	tevent_fd_get_flags(fde)

#define event_set_fd_flags(fde, flags) \
	tevent_fd_set_flags(fde, flags)

#define EVENT_FD_READ		TEVENT_FD_READ
#define EVENT_FD_WRITE		TEVENT_FD_WRITE

#define EVENT_FD_WRITEABLE(fde) \
	TEVENT_FD_WRITEABLE(fde)

#define EVENT_FD_READABLE(fde) \
	TEVENT_FD_READABLE(fde)

#define EVENT_FD_NOT_WRITEABLE(fde) \
	TEVENT_FD_NOT_WRITEABLE(fde)

#define EVENT_FD_NOT_READABLE(fde) \
	TEVENT_FD_NOT_READABLE(fde)

#define ev_debug_level		tevent_debug_level

#define EV_DEBUG_FATAL		TEVENT_DEBUG_FATAL
#define EV_DEBUG_ERROR		TEVENT_DEBUG_ERROR
#define EV_DEBUG_WARNING	TEVENT_DEBUG_WARNING
#define EV_DEBUG_TRACE		TEVENT_DEBUG_TRACE

#define ev_set_debug(ev, debug, context) \
	tevent_set_debug(ev, debug, context)

#define ev_set_debug_stderr(_ev) tevent_set_debug_stderr(ev)

#endif /* TEVENT_COMPAT_DEFINES */

/* @} */

#endif /* __TEVENT_H__ */
