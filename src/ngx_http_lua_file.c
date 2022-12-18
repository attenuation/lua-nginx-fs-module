#include "ngx_http_lua_common.h"
#include "ngx_http_lua_util.h"
#include "ngx_http_lua_file.h"

static ngx_int_t
ngx_http_lua_file_read(ngx_http_lua_ffi_file_t *file, ngx_http_lua_file_ctx_t *ctx);
static ngx_int_t
ngx_http_lua_file_write(ngx_http_lua_ffi_file_t *file, ngx_http_lua_file_ctx_t *ctx);
static ngx_int_t
ngx_http_lua_file_flush(ngx_http_lua_ffi_file_t *file, ngx_http_lua_file_ctx_t *ctx);
static ngx_int_t
ngx_http_lua_file_close(ngx_http_lua_ffi_file_t *file, ngx_http_lua_file_ctx_t *ctx);

#define NGX_HTTP_LUA_FILE_READ_MODE              (1 << 0)
#define NGX_HTTP_LUA_FILE_WRITE_MODE             (1 << 1)
#define NGX_HTTP_LUA_FILE_APPEND_MODE            (1 << 2)
#define NGX_HTTP_LUA_FILE_CREATE_MODE            (1 << 3)


enum {
    FILE_ERR_CLOSED = 1,
    FILE_ERR_SYSCALL,
    FILE_ERR_NOMEM,
    FILE_ERR_TIMEOUT,
    FILE_ERR_ADD_READ_EV,
    FILE_ERR_ADD_WRITE_EV,
    FILE_ERR_ABORTED,
};


enum {
    FILE_READ_ALL = 0,
    FILE_READ_BYTES,
    FILE_READ_LINE,
    FILE_READ_ANY,
};

#if (NGX_THREADS)

typedef struct {
    ngx_fd_t       fd;
    ngx_uint_t     write;   /* unsigned  write:1; */

    u_char        *buf;
    size_t         size;
    ngx_chain_t   *chain;
    off_t          offset;

    size_t         nbytes;
    ngx_err_t      err;
} ngx_http_lua_thread_file_ctx_t;

static ngx_int_t
ngx_http_lua_file_resume(ngx_http_request_t *r)
{
    int                              nret;
    lua_State                       *vm;
    ngx_int_t                        rc;
    ngx_uint_t                       nreqs;
    ngx_connection_t                *c;
    ngx_http_lua_ctx_t              *ctx;
    ngx_http_lua_file_ctx_t         *file_ctx;
    ngx_http_lua_ffi_file_t         *file;

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ctx->resume_handler = ngx_http_lua_wev_handler;
    ctx->cur_co_ctx->cleanup = NULL;

    file = ctx->cur_co_ctx->data;
    file_ctx = file->ctx;
    nret = file_ctx->retval_handler(file, ctx->cur_co_ctx->co);
    if (nret == NGX_AGAIN) {
        return NGX_DONE;
    }

    c = r->connection;
    vm = ngx_http_lua_get_lua_vm(r, ctx);
    nreqs = c->requests;

    rc = ngx_http_lua_run_thread(vm, r, ctx, nret);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua run thread returned %d", rc);

    if (rc == NGX_AGAIN) {
        return ngx_http_lua_run_posted_threads(c, vm, r, ctx, nreqs);
    }

    if (rc == NGX_DONE) {
        ngx_http_lua_finalize_request(r, NGX_DONE);
        return ngx_http_lua_run_posted_threads(c, vm, r, ctx, nreqs);
    }

    /* rc == NGX_ERROR || rc >= NGX_OK */

    if (ctx->entered_content_phase) {
        ngx_http_lua_finalize_request(r, rc);
        return NGX_DONE;
    }

    return rc;
}


static void
ngx_http_lua_file_resume_helper(ngx_event_t *ev,
    ngx_http_lua_co_ctx_t *wait_co_ctx)
{
    ngx_connection_t                *c;
    ngx_http_request_t              *r;
    ngx_http_lua_ctx_t              *ctx;
    ngx_http_lua_file_ctx_t         *file_ctx;
    ngx_http_lua_ffi_file_t         *file;


    r = ngx_http_lua_get_req(wait_co_ctx->co);
    c = r->connection;

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
    ngx_http_lua_assert(ctx != NULL);

    ctx->cur_co_ctx = wait_co_ctx;

    if (ctx->entered_content_phase) {
        (void) ngx_http_lua_file_resume(r);

    } else {
        ctx->resume_handler = ngx_http_lua_file_resume;
        ngx_http_core_run_phases(r);
    }

    ngx_http_run_posted_requests(c);
}

static int
ngx_http_lua_file_read_retval(ngx_http_lua_ffi_file_t *file, lua_State *L)
{
    int                              rc;
    ngx_msec_t                       timeout;
    ngx_event_t                     *rev;
    ngx_http_lua_file_ctx_t         *file_ctx;

    file_ctx = file->ctx;

    rc = ngx_http_lua_file_read(file, file_ctx);
    if (rc != NGX_AGAIN) {
        return 0;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "lua file read yielding ctx:%p",file_ctx);

    return NGX_AGAIN;
}

static int
ngx_http_lua_file_write_retval(ngx_http_lua_ffi_file_t *file, lua_State *L)
{
    int                              rc;
    ngx_msec_t                       timeout;
    ngx_event_t                     *rev;
    ngx_http_lua_file_ctx_t         *file_ctx;

    file_ctx = file->ctx;

    rc = ngx_http_lua_file_write(file, file_ctx);
    if (rc != NGX_AGAIN) {
        return 0;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "lua file read yielding ctx:%p",file_ctx);

    return NGX_AGAIN;
}

static int
ngx_http_lua_file_flush_retval(ngx_http_lua_ffi_file_t *file, lua_State *L)
{
    int                              rc;
    ngx_msec_t                       timeout;
    ngx_event_t                     *rev;
    ngx_http_lua_file_ctx_t         *file_ctx;

    file_ctx = file->ctx;

    rc = ngx_http_lua_file_flush(file, file_ctx);
    if (rc != NGX_AGAIN) {
        return 0;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "lua file read yielding ctx:%p",file_ctx);

    return NGX_AGAIN;
}


static int
ngx_http_lua_file_close_retval(ngx_http_lua_ffi_file_t *file, lua_State *L)
{
    int                              rc;
    ngx_msec_t                       timeout;
    ngx_event_t                     *rev;
    ngx_http_lua_file_ctx_t         *file_ctx;

    file_ctx = file->ctx;

    rc = ngx_http_lua_file_close(file, file_ctx);
    if (rc != NGX_AGAIN) {
        return 0;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "lua file read yielding ctx:%p",file_ctx);

    return NGX_AGAIN;
}


static void
ngx_http_lua_file_thread_event_handler(ngx_event_t *ev)
{
    ngx_connection_t    *c;
    ngx_http_request_t  *r;
    ngx_http_lua_co_ctx_t           *wait_co_ctx;
    ngx_http_lua_file_ctx_t         *file_ctx;
    ngx_http_lua_ffi_file_t         *file;


    file_ctx = ev->data;
    if (file_ctx->abort) {
        ngx_close_file(file_ctx->file.fd);
        ngx_destroy_pool(file_ctx->pool);
        file->ctx = NULL;
        return;
    }

    wait_co_ctx = file_ctx->wait_co_ctx;
    ngx_http_lua_file_resume_helper(ev, wait_co_ctx);

    // ngx_http_set_log_request(c->log, r);

    // ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
    //                "http file cache thread: \"%V?%V\"", &r->uri, &r->args);


    // r->write_event_handler(r);

    // ngx_http_run_posted_requests(c);
}


static ngx_int_t
ngx_http_lua_file_thread_handler(ngx_thread_task_t *task, ngx_http_lua_file_ctx_t *ctx)
{
    ngx_str_t                  name;
    ngx_thread_pool_t         *tp;
    ngx_http_request_t        *r;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_file_t *file;

    file = &ctx->file;
    r = file->thread_ctx;

    task->event.data = ctx;
    task->event.handler = ngx_http_lua_file_thread_event_handler;

    if (ngx_thread_task_post(ctx->thread_pool, task) != NGX_OK) {
        return NGX_ERROR;
    }

    // r->main->blocked++;
    // r->aio = 1;

    return NGX_OK;
}

static void
ngx_http_lua_file_put_data(ngx_http_lua_ffi_file_t *file, ngx_http_lua_file_ctx_t *file_ctx,
     u_char **buf, size_t *buf_size)
{
    size_t                   size = 0;
    size_t                   chunk_size;
    size_t                   nbufs;
    u_char                  *p;
    ngx_buf_t               *b;
    ngx_chain_t             *cl;
    ngx_chain_t            **ll;

    nbufs = 0;
    ll = NULL;

    for (cl = file_ctx->bufs_in; cl; cl = cl->next) {
        b = cl->buf;
        chunk_size = b->last - b->pos;

        if (cl->next) {
            ll = &cl->next;
        }

        size += chunk_size;

        nbufs++;
    }

    if (*buf_size < size) {
        *buf = NULL;
        *buf_size = size;

        return;
    }

    *buf_size = size;

    p = *buf;
    for (cl = file_ctx->bufs_in; cl; cl = cl->next) {
        b = cl->buf;
        chunk_size = b->last - b->pos;
        p = ngx_cpymem(p, b->pos, chunk_size);
    }

    if (nbufs > 1 && ll) {
        *ll = file_ctx->free_bufs;
        file_ctx->free_bufs = file_ctx->bufs_in;
        file_ctx->bufs_in = file_ctx->buf_in;
    }

    if (file_ctx->buffer.pos == file_ctx->buffer.last) {
        file_ctx->buffer.pos = file_ctx->buffer.start;
        file_ctx->buffer.last = file_ctx->buffer.start;
    }

    if (file_ctx->bufs_in) {
        file_ctx->buf_in->buf->last = file_ctx->buffer.pos;
        file_ctx->buf_in->buf->pos = file_ctx->buffer.pos;
    }
}

static ngx_int_t
ngx_http_lua_file_add_input_buffer(ngx_http_lua_ffi_file_t *file, ngx_http_lua_file_ctx_t *file_ctx)
{
    ngx_chain_t             *cl;

    cl = ngx_http_lua_chain_get_free_buf(ngx_cycle->log, file_ctx->pool,
                                         &file_ctx->free_bufs,
                                         file->buffer_size);

    if (cl == NULL) {
        file_ctx->file_err_type = FILE_ERR_NOMEM;
        return NGX_ERROR;
    }

    file_ctx->buf_in->next = cl;
    file_ctx->buf_in = cl;
    file_ctx->buffer = *cl->buf;

    return NGX_OK;
}


static ngx_int_t
ngx_http_lua_file_read_all(void *data, ssize_t bytes)
{
    ngx_http_lua_file_ctx_t      *file_ctx = data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0, "lua file read all");
    return ngx_http_lua_read_all(&file_ctx->buffer, file_ctx->buf_in, bytes,
                                 ngx_cycle->log);
}


static ngx_int_t
ngx_http_lua_file_read_bytes(void *data, ssize_t bytes)
{
    ngx_int_t                          rc;
    ngx_http_lua_file_ctx_t            *file_ctx = data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "lua file read bytes %z", bytes);

    rc = ngx_http_lua_read_bytes(&file_ctx->buffer, file_ctx->buf_in,
                                 &file_ctx->rest, bytes, ngx_cycle->log);
    if (rc == NGX_ERROR) {
        file_ctx->file_err_type = FILE_ERR_CLOSED;
        return NGX_ERROR;
    }

    return rc;
}


static ngx_int_t
ngx_http_lua_file_read_line(void *data, ssize_t bytes)
{
    ngx_int_t                          rc;
    ngx_http_lua_file_ctx_t            *file_ctx = data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "lua file read line");
    rc = ngx_http_lua_read_line(&file_ctx->buffer, file_ctx->buf_in, bytes,
                                ngx_cycle->log);
    if (rc == NGX_ERROR) {
        file_ctx->file_err_type = FILE_ERR_CLOSED;
        return NGX_ERROR;
    }

    return rc;
}


static ngx_int_t
ngx_http_lua_file_read_any(void *data, ssize_t bytes)
{
    ngx_int_t                          rc;
    ngx_http_lua_file_ctx_t            *file_ctx = data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0, "lua file read any");
    rc = ngx_http_lua_read_any(&file_ctx->buffer, file_ctx->buf_in,
                               &file_ctx->rest, bytes, ngx_cycle->log);
    if (rc == NGX_ERROR) {
        file_ctx->file_err_type = FILE_ERR_CLOSED;
        return NGX_ERROR;
    }

    return rc;
}


static void
ngx_http_lua_thread_file_read_handler(void *data, ngx_log_t *log)
{
    ngx_http_lua_thread_file_ctx_t *ctx = data;

    ssize_t  n;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, log, 0, "thread read handler");

    n = pread(ctx->fd, ctx->buf, ctx->size, ctx->offset);

    if (n == -1) {
        ctx->err = ngx_errno;

    } else {
        ctx->nbytes = n;
        ctx->err = 0;
    }

#if 0
    ngx_time_update();
#endif

    ngx_log_debug4(NGX_LOG_DEBUG_CORE, log, 0,
                   "pread: %z (err: %d) of %uz @%O",
                   n, ctx->err, ctx->size, ctx->offset);
}


ssize_t
ngx_http_lua_thread_file_read(ngx_http_lua_file_ctx_t *file_ctx, u_char *buf, size_t size, off_t offset,
    ngx_pool_t *pool)
{
    ngx_thread_task_t      *task;
    ngx_http_lua_thread_file_ctx_t  *ctx;
    ngx_file_t *file;

    file = &file_ctx->file;

    ngx_log_debug4(NGX_LOG_DEBUG_CORE, file->log, 0,
                   "thread read: %d, %p, %uz, %O",
                   file->fd, buf, size, offset);

    task = file->thread_task;

    if (task == NULL) {
        task = ngx_thread_task_alloc(pool, sizeof(ngx_http_lua_thread_file_ctx_t));
        if (task == NULL) {
            return NGX_ERROR;
        }

        file->thread_task = task;
    }

    ctx = task->ctx;

    if (task->event.complete) {
        task->event.complete = 0;

        if (ctx->write) {
            ngx_log_error(NGX_LOG_ALERT, file->log, 0,
                          "invalid thread call, read instead of write");
            return NGX_ERROR;
        }

        if (ctx->err) {
            ngx_log_error(NGX_LOG_CRIT, file->log, ctx->err,
                          "pread() \"%s\" failed", file->name.data);
            return NGX_ERROR;
        }

        return ctx->nbytes;
    }

    task->handler = ngx_http_lua_thread_file_read_handler;

    ctx->write = 0;

    ctx->fd = file->fd;
    ctx->buf = buf;
    ctx->size = size;
    ctx->offset = offset;

    if (file->thread_handler(task, file_ctx) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_AGAIN;
}

static ngx_int_t
ngx_http_lua_file_read(ngx_http_lua_ffi_file_t *file, ngx_http_lua_file_ctx_t *ctx)
{
    int                                 rc;
    int                                 read;
    size_t                              size;
    ssize_t                             n;
    ngx_buf_t                          *b;
    ngx_event_t                        *rev;
    ngx_connection_t                   *c;

    c = ctx->r->connection;
    rev = c->read;
    b = &ctx->buffer;

    for ( ;; ) {
        size = b->last - b->pos;
        if (size || ctx->eof) {
            rc = ctx->input_filter(ctx->input_filter_ctx, size);
            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

            if (rc == NGX_OK) {
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                               "lua file read done pipe:%p", ctx);
                ctx->read_waiting = 0;
                return NGX_OK;
            }

            if (ctx->eof) {
                return NGX_OK;
            }

            /* rc == NGX_AGAIN */
            continue;
        }

        size = b->end - b->last;
        if (size == 0) {
            rc = ngx_http_lua_file_add_input_buffer(file, ctx);
            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

            b = &ctx->buffer;
            size = (size_t) (b->end - b->last);
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                       "lua file try to read data %uz ctx:%p",
                       size, ctx);

        ctx->file.thread_task = ctx->thread_task;
        ctx->retval_handler = ngx_http_lua_file_read_retval;
        ctx->file.thread_handler = ngx_http_lua_file_thread_handler;
        ctx->file.thread_ctx = ctx->r;
        n = ngx_http_lua_thread_file_read(ctx, b->last, (size_t) size,
                                ctx->file.offset, ctx->pool);
        ctx->thread_task = ctx->file.thread_task;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                       "lua file read data returned %z ctx:%p", n, ctx);

        if (n == NGX_AGAIN) {
            break;
        }

        if (n == 0) {
            ctx->eof = 1;
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                           "lua file closed ctx:%p", ctx);
            continue;
        }

        if (n == NGX_ERROR) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, ngx_errno,
                           "lua file read data error ctx:%p", ctx);

            ctx->file_err_type = FILE_ERR_SYSCALL;
            ctx->file_errno = ngx_errno;
            return NGX_ERROR;
        }

        b->last += n;
        ctx->file.offset += n;
    }

    return NGX_AGAIN;
}


static ngx_chain_t *
ngx_http_lua_thread_file_chain_to_iovec(ngx_iovec_t *vec, ngx_chain_t *cl)
{
    size_t         total, size;
    u_char        *prev;
    ngx_uint_t     n;
    struct iovec  *iov;

    iov = NULL;
    prev = NULL;
    total = 0;
    n = 0;

    for ( /* void */ ; cl; cl = cl->next) {

        if (ngx_buf_special(cl->buf)) {
            continue;
        }

        size = cl->buf->last - cl->buf->pos;

        if (prev == cl->buf->pos) {
            iov->iov_len += size;

        } else {
            if (n == vec->nalloc) {
                break;
            }

            iov = &vec->iovs[n++];

            iov->iov_base = (void *) cl->buf->pos;
            iov->iov_len = size;
        }

        prev = cl->buf->pos + size;
        total += size;
    }

    vec->count = n;
    vec->size = total;

    return cl;
}



static void
ngx_http_lua_thread_file_write_handler(void *data, ngx_log_t *log)
{
    ngx_http_lua_thread_file_ctx_t *ctx = data;

#if (NGX_HAVE_PWRITEV)

    off_t          offset;
    ssize_t        n;
    ngx_err_t      err;
    ngx_chain_t   *cl;
    ngx_iovec_t    vec;
    struct iovec   iovs[NGX_IOVS_PREALLOCATE];

    vec.iovs = iovs;
    vec.nalloc = NGX_IOVS_PREALLOCATE;

    cl = ctx->chain;
    offset = ctx->offset;

    ctx->nbytes = 0;
    ctx->err = 0;

    do {
        /* create the iovec and coalesce the neighbouring bufs */
        cl = ngx_http_lua_thread_file_chain_to_iovec(&vec, cl);

eintr:

        n = pwritev(ctx->fd, iovs, vec.count, offset);

        if (n == -1) {
            err = ngx_errno;

            if (err == NGX_EINTR) {
                ngx_log_debug0(NGX_LOG_DEBUG_CORE, log, err,
                               "pwritev() was interrupted");
                goto eintr;
            }

            ctx->err = err;
            return;
        }

        if ((size_t) n != vec.size) {
            ctx->nbytes = 0;
            return;
        }

        ctx->nbytes += n;
        offset += n;
    } while (cl);

#else

    ctx->err = NGX_ENOSYS;
    return;

#endif
}


ssize_t
ngx_http_lua_thread_file_write(ngx_http_lua_file_ctx_t *file_ctx, ngx_chain_t *cl, off_t offset,
    ngx_pool_t *pool)
{
    ngx_thread_task_t      *task;
    ngx_http_lua_thread_file_ctx_t  *ctx;
    ngx_file_t *file;

    file = &file_ctx->file;
    ngx_log_debug3(NGX_LOG_DEBUG_CORE, file->log, 0,
                   "thread write chain: %d, %p, %O",
                   file->fd, cl, offset);

    task = file->thread_task;

    if (task == NULL) {
        task = ngx_thread_task_alloc(pool,
                                     sizeof(ngx_http_lua_thread_file_ctx_t));
        if (task == NULL) {
            return NGX_ERROR;
        }

        file->thread_task = task;
    }

    ctx = task->ctx;

    if (task->event.complete) {
        task->event.complete = 0;

        if (!ctx->write) {
            ngx_log_error(NGX_LOG_ALERT, file->log, 0,
                          "invalid thread call, write instead of read");
            return NGX_ERROR;
        }

        if (ctx->err || ctx->nbytes == 0) {
            ngx_log_error(NGX_LOG_CRIT, file->log, ctx->err,
                          "pwritev() \"%s\" failed", file->name.data);
            return NGX_ERROR;
        }

        file->offset += ctx->nbytes;
        return ctx->nbytes;
    }

    task->handler = ngx_http_lua_thread_file_write_handler;

    ctx->write = 1;

    ctx->fd = file->fd;
    ctx->chain = cl;
    ctx->offset = offset;

    if (file->thread_handler(task, file_ctx) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_AGAIN;
}


static ngx_int_t
ngx_http_lua_file_write(ngx_http_lua_ffi_file_t *file, ngx_http_lua_file_ctx_t *ctx)
{
    int                                 rc;
    int                                 read;
    size_t                              size;
    ssize_t                             n;
    ngx_buf_t                          *b;
    ngx_event_t                        *rev;
    ngx_connection_t                   *c;

    c = ctx->r->connection;
    rev = c->read;
    b = &ctx->buffer;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                    "lua file try to write data %uz ctx:%p",
                    size, ctx);

    ctx->file.thread_task = ctx->thread_task;
    ctx->retval_handler = ngx_http_lua_file_write_retval;
    ctx->file.thread_handler = ngx_http_lua_file_thread_handler;
    ctx->file.thread_ctx = ctx->r;
    n = ngx_http_lua_thread_file_write(ctx, ctx->buf_in,
                            ctx->file.offset, ctx->pool);
    ctx->thread_task = ctx->file.thread_task;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                    "lua file write data returned %z ctx:%p", n, ctx);

    if (n >= 0) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                        "lua file write sucess ctx:%p", ctx);
        ctx->write_waiting = 0;
        return NGX_OK;
    }

    if (n == NGX_ERROR) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, ngx_errno,
                        "lua file read data error ctx:%p", ctx);

        ctx->file_err_type = FILE_ERR_SYSCALL;
        ctx->file_errno = ngx_errno;
        return NGX_ERROR;
    }
    
    return NGX_AGAIN;
}

static void
ngx_http_lua_thread_file_flush_handler(void *data, ngx_log_t *log)
{
    ngx_http_lua_thread_file_ctx_t *ctx = data;
    if(fsync(ctx->fd) < 0) {
        ctx->err = ngx_errno;
    }
}


ssize_t
ngx_http_lua_thread_file_flush(ngx_http_lua_file_ctx_t *file_ctx, ngx_pool_t *pool)
{
    ngx_thread_task_t      *task;
    ngx_http_lua_thread_file_ctx_t  *ctx;

    ngx_file_t *file;

    file = &file_ctx->file;

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, file->log, 0, "thread flush file: %d", file->fd);

    task = file->thread_task;

    if (task == NULL) {
        task = ngx_thread_task_alloc(pool,
                                     sizeof(ngx_http_lua_thread_file_ctx_t));
        if (task == NULL) {
            return NGX_ERROR;
        }

        file->thread_task = task;
    }

    ctx = task->ctx;

    if (task->event.complete) {
        task->event.complete = 0;

        return NGX_OK;
    }

    task->handler = ngx_http_lua_thread_file_flush_handler;

    ctx->fd = file->fd;

    if (file->thread_handler(task, file_ctx) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_AGAIN;
}


static ngx_int_t
ngx_http_lua_file_flush(ngx_http_lua_ffi_file_t *file, ngx_http_lua_file_ctx_t *ctx)
{
    int                                 rc;
    int                                 read;
    size_t                              size;
    ssize_t                             n;
    ngx_buf_t                          *b;
    ngx_event_t                        *rev;
    ngx_connection_t                   *c;

    c = ctx->r->connection;
    rev = c->read;
    b = &ctx->buffer;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                    "lua file try to write data %uz ctx:%p",
                    size, ctx);

    ctx->file.thread_task = ctx->thread_task;
    ctx->retval_handler = ngx_http_lua_file_flush_retval;
    ctx->file.thread_handler = ngx_http_lua_file_thread_handler;
    ctx->file.thread_ctx = ctx->r;
    n = ngx_http_lua_thread_file_flush(ctx, ctx->pool);
    ctx->thread_task = ctx->file.thread_task;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                    "lua file flush data returned %z ctx:%p", n, ctx);

    if (n >= 0) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                        "lua file flush sucess ctx:%p", ctx);
        ctx->flush_waiting = 0;
        return NGX_OK;
    }

    if (n == NGX_ERROR) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, ngx_errno,
                        "lua file read data error ctx:%p", ctx);
        ctx->flush_waiting = 0;
        ctx->file_err_type = FILE_ERR_SYSCALL;
        ctx->file_errno = ngx_errno;
        return NGX_ERROR;
    }
    
    return NGX_AGAIN;
}

static void
ngx_http_lua_file_cleanup(void *data)
{
    ngx_http_lua_co_ctx_t          *wait_co_ctx = data;
    ngx_http_lua_file_ctx_t        *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "lua pipe proc write cleanup");

    ctx = wait_co_ctx->data;
    if (ctx->read_waiting || ctx->write_waiting || ctx->flush_waiting) {
        ctx->abort = 1;
    }

    wait_co_ctx->cleanup = NULL;
}


void
ngx_http_lua_ffi_file_destroy(ngx_http_lua_ffi_file_t *file)
{
    ngx_http_lua_file_ctx_t     *ctx;

    ctx = file->ctx;
    if (ctx == NULL) {
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "lua file destroy");

    if (ctx->abort) {
        return;
    }

    ngx_close_file(ctx->file.fd);
    ngx_destroy_pool(ctx->pool);
    file->ctx = NULL;
    return;
}


int
ngx_http_lua_ffi_file_parse_flags(const u_char *string)
{
    if (strcmp(string, "r")   == 0) return O_RDONLY;
#ifdef O_SYNC
    if (strcmp(string, "rs")  == 0 ||
        strcmp(string, "sr")  == 0) return O_RDONLY | O_SYNC;
#endif
    if (strcmp(string, "r+")  == 0) return O_RDWR;
#ifdef O_SYNC
    if (strcmp(string, "rs+") == 0 ||
        strcmp(string, "sr+") == 0) return O_RDWR   | O_SYNC;
#endif
    if (strcmp(string, "w")   == 0) return O_TRUNC  | O_CREAT | O_WRONLY;
    if (strcmp(string, "wx")  == 0 ||
        strcmp(string, "xw")  == 0) return O_TRUNC  | O_CREAT | O_WRONLY | O_EXCL;
    if (strcmp(string, "w+")  == 0) return O_TRUNC  | O_CREAT | O_RDWR;
    if (strcmp(string, "wx+") == 0 ||
        strcmp(string, "xw+") == 0) return O_TRUNC  | O_CREAT | O_RDWR   | O_EXCL;
    if (strcmp(string, "a")   == 0) return O_APPEND | O_CREAT | O_WRONLY;
    if (strcmp(string, "ax")  == 0 ||
        strcmp(string, "xa")  == 0) return O_APPEND | O_CREAT | O_WRONLY | O_EXCL;
    if (strcmp(string, "a+")  == 0) return O_APPEND | O_CREAT | O_RDWR;
    if (strcmp(string, "ax+") == 0 ||
        strcmp(string, "xa+") == 0) return O_APPEND | O_CREAT | O_RDWR   | O_EXCL;
    
    return NGX_ERROR;
}


int
ngx_http_lua_ffi_file_open(ngx_http_request_t *r, ngx_http_lua_ffi_file_t *file,
    const u_char *filename, const u_char *flags, int mode, const u_char *thread_pool_name, size_t buffer_size, u_char *errbuf, size_t *errbuf_size)
{
    ngx_err_t   err;
    ngx_int_t   create;
    off_t       offset;
    u_char      errstr[NGX_MAX_ERROR_STR];
    u_char      *p;
    ssize_t                         pool_size;
    ngx_pool_t                     *pool;
    ngx_http_lua_file_ctx_t *ctx;
    ngx_http_cleanup_t             *cln;
    int file_flags;

    if (filename == NULL) {
        *errbuf_size = ngx_snprintf(errbuf, *errbuf_size, "empty filename")
                       - errbuf;
        return NGX_ERROR;
    }

    if (file == NULL) {
        *errbuf_size = ngx_snprintf(errbuf, *errbuf_size, "empty file ctx")
                       - errbuf;
        return NGX_ERROR;
    }

    file_flags = ngx_http_lua_ffi_file_parse_flags(flags);
    if (file_flags == NGX_ERROR) {
        *errbuf_size = ngx_snprintf(errbuf, *errbuf_size, "flags error")
                       - errbuf;
        return NGX_ERROR;
    }

    pool_size = ngx_align(NGX_MIN_POOL_SIZE + buffer_size * 2,
                          NGX_POOL_ALIGNMENT);
    file->buffer_size = buffer_size;
    pool = ngx_create_pool(pool_size, ngx_cycle->log);
    
    if (pool == NULL) {
        *errbuf_size = ngx_snprintf(errbuf, *errbuf_size, "no memory")
                       - errbuf;
        goto free_pool;
    }

    file->ctx = ngx_pcalloc(pool, sizeof(ngx_http_lua_file_ctx_t));
    if (file->ctx == NULL) {
        *errbuf_size = ngx_snprintf(errbuf, *errbuf_size, "no memory")
                       - errbuf;
        goto free_pool;
    }

    ctx = file->ctx;
    ctx->pool = pool;

    ctx->file.name.data = ngx_pcalloc(pool, ngx_strlen(filename));
    if (ctx->file.name.data == NULL) {
        *errbuf_size = ngx_snprintf(errbuf, *errbuf_size, "no memory")
                       - errbuf;
        goto free_pool;
    }
    ctx->file.name.len = ngx_strlen(filename);

    ngx_memcpy(ctx->file.name.data, filename, ngx_strlen(filename));

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "file_name: %V file: %s", &ctx->file.name, filename);

    file->thread_pool.data = ngx_pcalloc(pool, ngx_strlen(thread_pool_name));
    if (file->thread_pool.data == NULL) {
        *errbuf_size = ngx_snprintf(errbuf, *errbuf_size, "no memory")
                       - errbuf;
        goto free_pool;
    }
    file->thread_pool.len = ngx_strlen(thread_pool_name);
    ngx_memcpy(file->thread_pool.data, thread_pool_name, ngx_strlen(thread_pool_name));


        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "thread_pool: %V", &file->thread_pool);
    ctx->thread_pool = ngx_thread_pool_get((ngx_cycle_t *) ngx_cycle,
                                      &file->thread_pool);
    if (ctx->thread_pool == NULL) {
        *errbuf_size = ngx_snprintf(errbuf, *errbuf_size, "no threadpool")
                       - errbuf;
        goto free_pool;
    }

    ctx->flags = file_flags;
    ctx->file.fd = ngx_open_file(filename, file_flags, 0, mode);
    if (ctx->file.fd == NGX_INVALID_FILE) {
        err = ngx_errno;

        ngx_memzero(errstr, NGX_MAX_ERROR_STR);
        p = ngx_strerror(err, errstr, sizeof(errstr));
        ngx_strlow(errstr, errstr, p - errstr);

        if (ngx_strlen(errstr) < *errbuf_size) {
            *errbuf_size = ngx_strlen(errstr);
        }

        ngx_memcpy(errbuf, errstr, *errbuf_size);
        
        goto free_pool;
    }

    // if (mode & NGX_HTTP_LUA_FILE_APPEND_MODE) {
    //     offset = lseek(ctx->file.fd, 0, SEEK_END);
    //     if (offset < 0) {
    //         err = ngx_errno;

    //         p = ngx_strerror(err, errstr, sizeof(errstr));
    //         ngx_strlow(errstr, errstr, p - errstr);

    //         *errbuf_size = ngx_snprintf(errbuf, *errbuf_size, p)
    //                         - errbuf;
    //         goto free_pool;
    //     }

    //     ctx->file.offset = offset;
    // }

    if (ngx_fd_info(ctx->file.fd, &ctx->file.info) == NGX_FILE_ERROR) {
        *errbuf_size = ngx_snprintf(errbuf, *errbuf_size, ngx_fd_info_n "%s failed", filename)
                        - errbuf;
        goto free_pool;
    }

    ctx->file.log = r->connection->log;
    ctx->r = r;

    cln = ngx_http_lua_cleanup_add(r, 0);

    if (cln == NULL) {
        *errbuf_size = ngx_snprintf(errbuf, *errbuf_size, "no memory")
                        - errbuf;
        goto free_pool;
    }

    cln->handler = (ngx_http_cleanup_pt) ngx_http_lua_ffi_file_destroy;
    cln->data = file;


    return NGX_OK;

free_pool:
    ngx_destroy_pool(pool);
    return NGX_ERROR;
}

static void
ngx_http_lua_file_put_error(ngx_http_lua_file_ctx_t *file_ctx, u_char *errbuf,
    size_t *errbuf_size)
{
    switch (file_ctx->file_err_type) {

    case FILE_ERR_CLOSED:
        *errbuf_size = ngx_snprintf(errbuf, *errbuf_size, "closed") - errbuf;
        break;

    case FILE_ERR_SYSCALL:
        *errbuf_size = ngx_snprintf(errbuf, *errbuf_size, "%s",
                                    strerror(file_ctx->file_errno))
                       - errbuf;
        break;

    case FILE_ERR_NOMEM:
        *errbuf_size = ngx_snprintf(errbuf, *errbuf_size, "no memory")
                       - errbuf;
        break;

    case FILE_ERR_TIMEOUT:
        *errbuf_size = ngx_snprintf(errbuf, *errbuf_size, "timeout")
                       - errbuf;
        break;

    case FILE_ERR_ADD_READ_EV:
        *errbuf_size = ngx_snprintf(errbuf, *errbuf_size,
                                    "failed to add read event")
                       - errbuf;
        break;

    case FILE_ERR_ADD_WRITE_EV:
        *errbuf_size = ngx_snprintf(errbuf, *errbuf_size,
                                    "failed to add write event")
                       - errbuf;
        break;

    case FILE_ERR_ABORTED:
        *errbuf_size = ngx_snprintf(errbuf, *errbuf_size, "aborted") - errbuf;
        break;

    default:
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "unexpected err type: %d", file_ctx->file_err_type);
        ngx_http_lua_assert(NULL);
    }
}

static ngx_int_t
ngx_http_lua_file_get_lua_ctx(ngx_http_request_t *r,
    ngx_http_lua_ctx_t **ctx, u_char *errbuf, size_t *errbuf_size)
{
    int                                 rc;

    *ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
    if (*ctx == NULL) {
        return NGX_HTTP_LUA_FFI_NO_REQ_CTX;
    }

    rc = ngx_http_lua_ffi_check_context(*ctx, NGX_HTTP_LUA_CONTEXT_YIELDABLE,
                                        errbuf, errbuf_size);
    if (rc != NGX_OK) {
        return NGX_HTTP_LUA_FFI_BAD_CONTEXT;
    }

    return NGX_OK;
}

int
ngx_http_lua_ffi_file_read(ngx_http_request_t *r,  ngx_http_lua_ffi_file_t *file,
    size_t length, int mode, u_char **buf, size_t *buf_size, u_char *errbuf,
    size_t *errbuf_size)
{
    ngx_err_t   err;
    off_t       _offset;
    u_char      errstr[NGX_MAX_ERROR_STR];
    u_char      *p;
    ssize_t     n;
    ngx_http_lua_file_ctx_t *ctx;
    ngx_http_lua_co_ctx_t              *wait_co_ctx;
    ngx_http_lua_ctx_t                 *lctx;
    ngx_event_t                        *rev;
    ngx_connection_t                   *c;
    ngx_int_t                           rc;

    rc = ngx_http_lua_file_get_lua_ctx(r, &lctx, errbuf, errbuf_size);
    if (rc != NGX_OK) {
        return rc;
    }

    if (file == NULL) {
        *errbuf_size = ngx_snprintf(errbuf, *errbuf_size, "empty file ctx")
                       - errbuf;
        return NGX_ERROR;
    }

    ctx = file->ctx;

    if (ctx == NULL) {
        *errbuf_size = ngx_snprintf(errbuf, *errbuf_size, "empty ctx")
                       - errbuf;
        return NGX_ERROR;
    }

    if (ctx->read_waiting) {
        *errbuf_size = ngx_snprintf(errbuf, *errbuf_size, "read waiting")
                       - errbuf;
        return NGX_ERROR;
    }

    if (ctx->write_waiting) {
        *errbuf_size = ngx_snprintf(errbuf, *errbuf_size, "write waiting")
                       - errbuf;
        return NGX_ERROR;
    }

    if (ctx->flush_waiting) {
        *errbuf_size = ngx_snprintf(errbuf, *errbuf_size, "flush waiting")
                       - errbuf;
        return NGX_ERROR;
    }

    if (ctx->closing) {
        *errbuf_size = ngx_snprintf(errbuf, *errbuf_size, "closing")
                       - errbuf;
        return NGX_ERROR;
    }

    // if (!(ctx->flags | ))
    // if (!(ctx->file.info.st_mode & NGX_HTTP_LUA_FILE_READ_MODE)) {
    //     *errbuf_size = ngx_snprintf(errbuf, *errbuf_size, "operation not permitted")
    //                    - errbuf;
    //     return NGX_ERROR;
    // }

    ctx->input_filter_ctx = ctx;

    switch (mode) {

    case FILE_READ_ALL:
        ctx->input_filter = ngx_http_lua_file_read_all;
        break;

    case FILE_READ_BYTES:
        ctx->input_filter = ngx_http_lua_file_read_bytes;
        break;

    case FILE_READ_LINE:
        ctx->input_filter = ngx_http_lua_file_read_line;
        break;

    case FILE_READ_ANY:
        ctx->input_filter = ngx_http_lua_file_read_any;
        break;

    default:
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "unexpected read mode: %d", mode);
        *errbuf_size = ngx_snprintf(errbuf, *errbuf_size,  "unexpected read mode: %d", mode)
                       - errbuf;
        return NGX_ERROR;
    }

    ctx->rest = length;

    if (ctx->bufs_in == NULL) {
        ctx->bufs_in =
            ngx_http_lua_chain_get_free_buf(ngx_cycle->log, ctx->pool,
                                            &ctx->free_bufs,
                                            file->buffer_size);

        if (ctx->bufs_in == NULL) {
            ctx->file_err_type = FILE_ERR_NOMEM;
            goto error;
        }

        ctx->buf_in = ctx->bufs_in;
        ctx->buffer = *ctx->buf_in->buf;
    }

    rc = ngx_http_lua_file_read(file, ctx);
    if (rc == NGX_ERROR) {
        goto error;
    }

    if (rc == NGX_OK) {
        ngx_http_lua_file_put_data(file, ctx, buf, buf_size);
        return NGX_OK;
    }

    /* rc == NGX_AGAIN */
    wait_co_ctx = lctx->cur_co_ctx;
    ctx->wait_co_ctx = wait_co_ctx;

    // c->data = wait_co_ctx;
    
    // rev->handler = ngx_http_lua_file_resume_handler;
    wait_co_ctx->data = file;
    wait_co_ctx->cleanup = ngx_http_lua_file_cleanup;
    
    // if (ngx_handle_read_event(rev, 0) != NGX_OK) {
    //     pipe_ctx->err_type = FILE_ERR_ADD_READ_EV;
    //     goto error;
    // }
    ctx->read_waiting = 1;
    return NGX_AGAIN;

error:
    if (ctx->bufs_in) {
        ngx_http_lua_file_put_data(file, ctx, buf, buf_size);
        ngx_http_lua_file_put_error(ctx, errbuf, errbuf_size);
        return NGX_DECLINED;
    }

    ngx_http_lua_file_put_error(ctx, errbuf, errbuf_size);

    return NGX_ERROR;

}


int
ngx_http_lua_ffi_file_get_read_result(ngx_http_request_t *r,
    ngx_http_lua_ffi_file_t *file, u_char **buf,
    size_t *buf_size, u_char *errbuf, size_t *errbuf_size)
{
    ngx_http_lua_file_ctx_t *ctx;

    // ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
    //                "lua pipe get read result process:%p pid:%P", proc,
    //                proc->_pid);

    ctx = file->ctx;
    if (!ctx->file_err_type) {
        ngx_http_lua_file_put_data(file, ctx, buf, buf_size);
        return NGX_OK;
    }

    if (ctx->bufs_in) {
        ngx_http_lua_file_put_data(file, ctx, buf, buf_size);
        ngx_http_lua_file_put_error(ctx, errbuf, errbuf_size);
        return NGX_DECLINED;
    }

    ngx_http_lua_file_put_error(ctx, errbuf, errbuf_size);

    return NGX_ERROR;
}



int
ngx_http_lua_ffi_file_write(ngx_http_request_t *r,  ngx_http_lua_ffi_file_t *file,
    const u_char *data, size_t len, u_char *errbuf,
    size_t *errbuf_size)
{
    int         rc;
    ngx_err_t   err;
    off_t       _offset;
    u_char      errstr[NGX_MAX_ERROR_STR];
    u_char      *p;
    ssize_t     n;
    ngx_http_lua_file_ctx_t *ctx;
    ngx_http_lua_ctx_t                 *lctx;
    ngx_http_lua_co_ctx_t              *wait_co_ctx;
    ngx_event_t                        *rev;
    ngx_connection_t                   *c;
    ngx_buf_t                          *b;
    ngx_chain_t                        *cl;


    rc = ngx_http_lua_file_get_lua_ctx(r, &lctx, errbuf, errbuf_size);
    if (rc != NGX_OK) {
        return rc;
    }

    if (file == NULL) {
        *errbuf_size = ngx_snprintf(errbuf, *errbuf_size, "empty file ctx")
                       - errbuf;
        return NGX_ERROR;
    }

    ctx = file->ctx;

    if (ctx == NULL) {
        *errbuf_size = ngx_snprintf(errbuf, *errbuf_size, "empty ctx")
                       - errbuf;
        return NGX_ERROR;
    }

    if (ctx->read_waiting) {
        *errbuf_size = ngx_snprintf(errbuf, *errbuf_size, "read waiting")
                       - errbuf;
        return NGX_ERROR;
    }

    if (ctx->write_waiting) {
        *errbuf_size = ngx_snprintf(errbuf, *errbuf_size, "write waiting")
                       - errbuf;
        return NGX_ERROR;
    }

    if (ctx->flush_waiting) {
        *errbuf_size = ngx_snprintf(errbuf, *errbuf_size, "flush waiting")
                       - errbuf;
        return NGX_ERROR;
    }

    if (ctx->closing) {
        *errbuf_size = ngx_snprintf(errbuf, *errbuf_size, "closing")
                       - errbuf;
        return NGX_ERROR;
    }

    // if (!(ctx->file.info.st_mode & NGX_HTTP_LUA_FILE_WRITE_MODE)) {
    //     *errbuf_size = ngx_snprintf(errbuf, *errbuf_size, "operation not permitted")
    //                    - errbuf;
    //     return NGX_ERROR;
    // }

    ctx->rest = len;

    cl = ngx_http_lua_chain_get_free_buf(ngx_cycle->log, ctx->pool,
                                         &ctx->free_bufs, len);
    if (cl == NULL) {
        ctx->file_err_type = FILE_ERR_NOMEM;
        goto error;
    }

    ctx->buf_in = cl;
    b = ctx->buf_in->buf;
    b->last = ngx_copy(b->last, data, len);

    rc = ngx_http_lua_file_write(file, ctx);
    if (rc == NGX_ERROR) {
        goto error;
    }

    if (rc == NGX_OK) {
        return len;
    }

    ctx->write_waiting = 1;

    /* rc == NGX_AGAIN */
    wait_co_ctx = lctx->cur_co_ctx;
    ctx->wait_co_ctx = wait_co_ctx;

    // c->data = wait_co_ctx;
    
    // rev->handler = ngx_http_lua_file_resume_handler;
    wait_co_ctx->data = file;
    wait_co_ctx->cleanup = ngx_http_lua_file_cleanup;
    
    // if (ngx_handle_read_event(rev, 0) != NGX_OK) {
    //     pipe_ctx->err_type = FILE_ERR_ADD_READ_EV;
    //     goto error;
    // }

    return NGX_AGAIN;

error:
    ngx_http_lua_file_put_error(ctx, errbuf, errbuf_size);

    return NGX_ERROR;
}


int
ngx_http_lua_ffi_file_get_write_result(ngx_http_request_t *r,
    ngx_http_lua_ffi_file_t *file, u_char *errbuf, size_t *errbuf_size)
{
    ngx_http_lua_file_ctx_t *ctx;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua file get write result process:%p ", file);

    ctx = file->ctx;
    if (ctx->file_err_type) {
        ngx_http_lua_file_put_error(ctx, errbuf, errbuf_size);
        return NGX_ERROR;
    }

    return ctx->rest;
}


int
ngx_http_lua_ffi_file_seek(ngx_http_request_t *r,  ngx_http_lua_ffi_file_t *file,
    size_t offset, int whence, u_char *errbuf,
    size_t *errbuf_size)
{
    ngx_err_t   err;
    off_t       _offset;
    u_char      errstr[NGX_MAX_ERROR_STR];
    u_char      *p;
    ngx_http_lua_file_ctx_t *ctx;

    if (file == NULL) {
        *errbuf_size = ngx_snprintf(errbuf, *errbuf_size, "empty ctx")
                       - errbuf;
        return NGX_ERROR;
    }

    ctx = file->ctx;

    if (ctx->read_waiting) {
        *errbuf_size = ngx_snprintf(errbuf, *errbuf_size, "read waiting")
                       - errbuf;
        return NGX_ERROR;
    }

    if (ctx->write_waiting) {
        *errbuf_size = ngx_snprintf(errbuf, *errbuf_size, "write waiting")
                       - errbuf;
        return NGX_ERROR;
    }

    if (ctx->flush_waiting) {
        *errbuf_size = ngx_snprintf(errbuf, *errbuf_size, "flush waiting")
                       - errbuf;
        return NGX_ERROR;
    }

    if (ctx->closing) {
        *errbuf_size = ngx_snprintf(errbuf, *errbuf_size, "closing")
                       - errbuf;
        return NGX_ERROR;
    }

    _offset = lseek(ctx->file.fd, offset, whence);
    if (offset < 0) {
        err = ngx_errno;

        p = ngx_strerror(err, errstr, sizeof(errstr));
        ngx_strlow(errstr, errstr, p - errstr);

        *errbuf_size = ngx_snprintf(errbuf, *errbuf_size, p)
                        - errbuf;
        return NGX_ERROR;
    }

    ctx->file.offset = _offset;

    return NGX_OK;
}


int
ngx_http_lua_ffi_file_flush(ngx_http_request_t *r,  ngx_http_lua_ffi_file_t *file,
    u_char *errbuf, size_t *errbuf_size)
{
    ngx_err_t   err;
    off_t       _offset;
    u_char      errstr[NGX_MAX_ERROR_STR];
    u_char      *p;
    ngx_http_lua_file_ctx_t *ctx;
    ngx_http_lua_ctx_t       *lctx;
    ngx_http_lua_co_ctx_t    *wait_co_ctx;
    ngx_int_t                  rc;

    rc = ngx_http_lua_file_get_lua_ctx(r, &lctx, errbuf, errbuf_size);
    if (rc != NGX_OK) {
        return rc;
    }


    if (file == NULL) {
        *errbuf_size = ngx_snprintf(errbuf, *errbuf_size, "empty ctx")
                       - errbuf;
        return NGX_ERROR;
    }

    ctx = file->ctx;

    if (ctx->read_waiting) {
        *errbuf_size = ngx_snprintf(errbuf, *errbuf_size, "read waiting")
                       - errbuf;
        return NGX_ERROR;
    }

    if (ctx->write_waiting) {
        *errbuf_size = ngx_snprintf(errbuf, *errbuf_size, "write waiting")
                       - errbuf;
        return NGX_ERROR;
    }

    if (ctx->flush_waiting) {
        *errbuf_size = ngx_snprintf(errbuf, *errbuf_size, "flush waiting")
                       - errbuf;
        return NGX_ERROR;
    }

    if (ctx->closing) {
        *errbuf_size = ngx_snprintf(errbuf, *errbuf_size, "closing")
                       - errbuf;
        return NGX_ERROR;
    }

    rc = ngx_http_lua_file_flush(file, ctx);
    if (rc == NGX_ERROR) {
        goto error;
    }

    if (rc == NGX_OK) {
        return NGX_OK;
    }

    ctx->flush_waiting = 1;

    /* rc == NGX_AGAIN */
    wait_co_ctx = lctx->cur_co_ctx;
    ctx->wait_co_ctx = wait_co_ctx;

    // c->data = wait_co_ctx;
    
    // rev->handler = ngx_http_lua_file_resume_handler;
    wait_co_ctx->data = file;
    wait_co_ctx->cleanup = ngx_http_lua_file_cleanup;
    
    // if (ngx_handle_read_event(rev, 0) != NGX_OK) {
    //     pipe_ctx->err_type = FILE_ERR_ADD_READ_EV;
    //     goto error;
    // }

    return NGX_AGAIN;

error:
    ngx_http_lua_file_put_error(ctx, errbuf, errbuf_size);

    return NGX_ERROR;
}


int
ngx_http_lua_ffi_file_get_flush_result(ngx_http_request_t *r,
    ngx_http_lua_ffi_file_t *file, u_char *errbuf, size_t *errbuf_size)
{
    ngx_http_lua_file_ctx_t *ctx;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua file get write result process:%p ", file);

    ctx = file->ctx;
    if (ctx->file_err_type) {
        ngx_http_lua_file_put_error(ctx, errbuf, errbuf_size);
        return NGX_ERROR;
    }

    return NGX_OK;
}


int
ngx_http_lua_ffi_file_close(ngx_http_request_t *r,  ngx_http_lua_ffi_file_t *file,
    u_char *errbuf, size_t *errbuf_size)
{
    ngx_err_t   err;
    off_t       _offset;
    u_char      errstr[NGX_MAX_ERROR_STR];
    u_char      *p;
    ngx_http_lua_file_ctx_t *ctx;

    if (file == NULL) {
        *errbuf_size = ngx_snprintf(errbuf, *errbuf_size, "empty ctx")
                       - errbuf;
        return NGX_ERROR;
    }

    ctx = file->ctx;
    
    if (ctx->file.fd != NGX_INVALID_FILE && ngx_close_file(ctx->file.fd) < 0) {
        err = ngx_errno;

        p = ngx_strerror(err, errstr, sizeof(errstr));
        ngx_strlow(errstr, errstr, p - errstr);

        *errbuf_size = ngx_snprintf(errbuf, *errbuf_size, p)
                        - errbuf;
        return NGX_ERROR;
    }

    return NGX_OK;
}

#endif