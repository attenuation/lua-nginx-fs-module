#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <lauxlib.h>
#include <ngx_http_lua_api.h>
#include <ngx_http_lua_common.h>
#include <ngx_http_lua_util.h>
#include <ngx_http_lua_output.h>


typedef struct ngx_http_lua_ffi_file_s ngx_http_lua_ffi_file_t;
typedef struct ngx_http_lua_file_ctx_s ngx_http_lua_file_ctx_t;

typedef ngx_int_t (*ngx_http_lua_file_input_filter)(void *data, ssize_t bytes);
typedef ngx_int_t (*ngx_http_lua_file_retval_handler)(ngx_http_lua_ffi_file_t *file, lua_State *L);

struct ngx_http_lua_file_ctx_s {
    ngx_file_t              file;
    ngx_pool_t             *pool;
    ngx_chain_t            *free_bufs;

    unsigned                read_waiting:1;
    unsigned                write_waiting:1;
    unsigned                flush_waiting:1;
    unsigned                seeking:1;
    unsigned                closing:1;
    unsigned                closed:1;
    unsigned                eof:1;

    unsigned                            timeout:1;
    unsigned                            abort:1;
    

    ngx_http_cleanup_pt                *cleanup;
    ngx_http_request_t                 *r;

    ngx_thread_task_t           *thread_task;

    size_t                  read_buffer_size;
    size_t                  write_buffer_size;
    ngx_chain_t            *bufs_in;
    ngx_chain_t            *buf_in;
    ngx_buf_t               buffer;

    ngx_err_t                           file_errno;
    unsigned                            file_err_type:16;

    ngx_http_lua_file_input_filter      input_filter;
    void                               *input_filter_ctx;
    ngx_http_lua_file_retval_handler    retval_handler;
    size_t                              rest;
    ngx_thread_pool_t                  *thread_pool;
    ngx_http_lua_co_ctx_t              *wait_co_ctx;
    int                                 flags;
};

struct ngx_http_lua_ffi_file_s {
    size_t                  buffer_size;
    ngx_http_lua_file_ctx_t *ctx;
    ngx_str_t               thread_pool;
};