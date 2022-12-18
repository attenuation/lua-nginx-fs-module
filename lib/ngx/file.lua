-- Copyright (C) by OpenResty Inc.


local base = require "resty.core.base"
base.allows_subsystem("http")


require "resty.core.phase"  -- for ngx.get_phase

local assert = assert
local error = error
local ipairs = ipairs
local tonumber = tonumber
local tostring = tostring
local type = type
local str_find = string.find
local table_concat = table.concat
local ffi = require "ffi"
local bit  = require "bit"
local C = ffi.C
local ffi_new = ffi.new
local ffi_str = ffi.string
local ngx_phase = ngx.get_phase
local get_string_buf = base.get_string_buf
local get_size_ptr = base.get_size_ptr
local get_request = base.get_request
local FFI_AGAIN = base.FFI_AGAIN
local FFI_BAD_CONTEXT = base.FFI_BAD_CONTEXT
local FFI_DECLINED = base.FFI_DECLINED
local FFI_ERROR = base.FFI_ERROR
local FFI_NO_REQ_CTX = base.FFI_NO_REQ_CTX
local FFI_OK = base.FFI_OK
local co_yield = coroutine._yield


ffi.cdef[[
typedef int                         ngx_pid_t;
typedef uintptr_t                   ngx_msec_t;
typedef unsigned char               u_char;

typedef struct ngx_http_lua_file_ctx_s ngx_http_lua_file_ctx_t;                                                                                                                                                                                                                                                         
                                                                                                                                                                                                                                                                                                                        
typedef struct {                                                                                                                                                                                                                                                                                                        
    size_t                  buffer_size;                                                                                                                                                                                                                                                                                
    ngx_http_lua_file_ctx_t *ctx;                                                                                                                                                                                                                                                                                       
    ngx_str_t               thread_pool;                                                                                                                                                                                                                                                                                
} ngx_http_lua_ffi_file_t;  

int ngx_http_lua_ffi_file_open(ngx_http_request_t *r, ngx_http_lua_ffi_file_t *file,
    const u_char *filename, const u_char *flags, int mode ,const u_char *thread_pool_name, size_t buffer_size, u_char *errbuf, size_t *errbuf_size);

int ngx_http_lua_ffi_file_read(ngx_http_request_t *r,  ngx_http_lua_ffi_file_t *file,
    size_t length, int mode, u_char **buf, size_t *buf_size, u_char *errbuf,
    size_t *errbuf_size);

int ngx_http_lua_ffi_file_get_read_result(ngx_http_request_t *r,
    ngx_http_lua_ffi_file_t *file, u_char **buf,
    size_t *buf_size, u_char *errbuf, size_t *errbuf_size);

int ngx_http_lua_ffi_file_write(ngx_http_request_t *r,  ngx_http_lua_ffi_file_t *file,
        const u_char *data, size_t len, u_char *errbuf,
        size_t *errbuf_size);

int ngx_http_lua_ffi_file_get_write_result(ngx_http_request_t *r,
            ngx_http_lua_ffi_file_t *file, u_char *errbuf, size_t *errbuf_size);

int ngx_http_lua_ffi_file_seek(ngx_http_request_t *r,  ngx_http_lua_ffi_file_t *file,
                size_t offset, int whence, u_char *errbuf,
                size_t *errbuf_size);

int ngx_http_lua_ffi_file_flush(ngx_http_request_t *r,  ngx_http_lua_ffi_file_t *file,
                    u_char *errbuf, size_t *errbuf_size);
int ngx_http_lua_ffi_file_get_flush_result(ngx_http_request_t *r,
                ngx_http_lua_ffi_file_t *file, u_char *errbuf, size_t *errbuf_size);

int ngx_http_lua_ffi_file_seek(ngx_http_request_t *r,  ngx_http_lua_ffi_file_t *file,
                    size_t offset, int whence, u_char *errbuf,
                    size_t *errbuf_size);

int ngx_http_lua_ffi_file_close(ngx_http_request_t *r,  ngx_http_lua_ffi_file_t *file,
                        u_char *errbuf, size_t *errbuf_size);
void ngx_http_lua_ffi_file_destroy(ngx_http_lua_ffi_file_t *file);
]]


if not pcall(function() return C.ngx_http_lua_ffi_file_open end) then
    error("pipe API is not supported due to either a platform issue " ..
          "or lack of the NGX_THREAD support", 2)
end


local _M = { version = base.version }


local ERR_BUF_SIZE = 256
local VALUE_BUF_SIZE = 512
local FILE_READ_ALL   = 0
local FILE_READ_BYTES = 1
local FILE_READ_LINE  = 2
local FILE_READ_ANY   = 3


local function check_file_instance(file)
    if type(file) ~= "cdata" then
        error("not a file instance", 3)
    end
end


local file_read
do
    local value_buf = ffi_new("char[?]", VALUE_BUF_SIZE)
    local buf = ffi_new("char *[1]")
    local buf_size = ffi_new("size_t[1]")

    function file_read(file, reader_type, len)
        check_file_instance(file)

        local r = get_request()
        if not r then
            error("no request found")
        end

        buf[0] = value_buf
        buf_size[0] = VALUE_BUF_SIZE
        local errbuf = get_string_buf(ERR_BUF_SIZE)
        local errbuf_size = get_size_ptr()
        errbuf_size[0] = ERR_BUF_SIZE
        local rc = C.ngx_http_lua_ffi_file_read(r, file, len,
                                                     reader_type, buf,
                                                     buf_size, errbuf,
                                                     errbuf_size)
        if rc == FFI_NO_REQ_CTX then
            error("no request ctx found")
        end

        if rc == FFI_BAD_CONTEXT then
            error(ffi_str(errbuf, errbuf_size[0]), 2)
        end

        while true do
            if rc == FFI_ERROR then
                return nil, ffi_str(errbuf, errbuf_size[0])
            end

            if rc == FFI_OK then
                local p = buf[0]
                if p ~= value_buf then
                    p = ffi_new("char[?]", buf_size[0])
                    buf[0] = p
                    C.ngx_http_lua_ffi_file_get_read_result(r, file,
                                                            buf, buf_size,
                                                            errbuf, errbuf_size)
                    assert(p == buf[0])
                end

                return ffi_str(p, buf_size[0])
            end

            if rc == FFI_DECLINED then
                local err = ffi_str(errbuf, errbuf_size[0])

                local p = buf[0]
                if p ~= value_buf then
                    p = ffi_new("char[?]", buf_size[0])
                    buf[0] = p
                    C.ngx_http_lua_ffi_file_get_read_result(r, file,
                                                            buf, buf_size,
                                                            errbuf, errbuf_size)
                    assert(p == buf[0])
                end

                local partial = ffi_str(p, buf_size[0])
                return nil, err, partial
            end

            assert(rc == FFI_AGAIN)

            co_yield()

            buf[0] = value_buf
            buf_size[0] = VALUE_BUF_SIZE
            errbuf = get_string_buf(ERR_BUF_SIZE)
            errbuf_size = get_size_ptr()
            errbuf_size[0] = ERR_BUF_SIZE
            rc = C.ngx_http_lua_ffi_file_get_read_result(r, file,
                buf, buf_size,
                errbuf, errbuf_size)
        end
    end

end


local function file_write(file, data)
    check_file_instance(file)

    local r = get_request()
    if not r then
        error("no request found", 2)
    end

    local data_type = type(data)
    if data_type ~= "string" then
        if data_type == "table" then
            data = table_concat(data, "")

        elseif data_type == "number" then
            data = tostring(data)

        else
            error("bad data arg: string, number, or table expected, got "
                  .. data_type, 2)
        end
    end

    local errbuf = get_string_buf(ERR_BUF_SIZE)
    local errbuf_size = get_size_ptr()
    errbuf_size[0] = ERR_BUF_SIZE
    local rc = C.ngx_http_lua_ffi_file_write(r, file, data, #data, errbuf,
                                                  errbuf_size)
    if rc == FFI_NO_REQ_CTX then
        error("no request ctx found", 2)
    end

    if rc == FFI_BAD_CONTEXT then
        error(ffi_str(errbuf, errbuf_size[0]), 2)
    end

    while true do
        if rc == FFI_ERROR then
            return nil, ffi_str(errbuf, errbuf_size[0])
        end

        if rc >= 0 then
            -- rc holds the bytes sent
            return tonumber(rc)
        end

        assert(rc == FFI_AGAIN)

        co_yield()

        errbuf = get_string_buf(ERR_BUF_SIZE)
        errbuf_size = get_size_ptr()
        errbuf_size[0] = ERR_BUF_SIZE
        rc = C.ngx_http_lua_ffi_file_get_write_result(r, file, errbuf,
                                                      errbuf_size)
    end
end

local function file_flush(file)
    check_file_instance(file)

    local r = get_request()
    if not r then
        error("no request found", 2)
    end

    local errbuf = get_string_buf(ERR_BUF_SIZE)
    local errbuf_size = get_size_ptr()
    errbuf_size[0] = ERR_BUF_SIZE
    local rc = C.ngx_http_lua_ffi_file_flush(r, file, errbuf,
                                                  errbuf_size)
    if rc == FFI_NO_REQ_CTX then
        error("no request ctx found", 2)
    end

    if rc == FFI_BAD_CONTEXT then
        error(ffi_str(errbuf, errbuf_size[0]), 2)
    end

    while true do
        if rc == FFI_ERROR then
            return nil, ffi_str(errbuf, errbuf_size[0])
        end

        if rc >= 0 then
            -- rc holds the bytes sent
            return tonumber(rc)
        end

        assert(rc == FFI_AGAIN)

        co_yield()

        errbuf = get_string_buf(ERR_BUF_SIZE)
        errbuf_size = get_size_ptr()
        errbuf_size[0] = ERR_BUF_SIZE
        rc = C.ngx_http_lua_ffi_file_get_flush_result(r, file, errbuf,
                                                      errbuf_size)
    end
end


local function file_seek(file, offset, whence)
    check_file_instance(file)

    if type(offset) ~= "number" then
        error("bad offset arg: number expected, got " .. tostring(offset), 2)
    end

    local errbuf = get_string_buf(ERR_BUF_SIZE)
    local errbuf_size = get_size_ptr()
    errbuf_size[0] = ERR_BUF_SIZE

    local rc = C.ngx_http_lua_ffi_file_seek(r, file, offset, whence,
                                            errbuf, errbuf_size)
    if rc == FFI_ERROR then
        return nil, ffi_str(errbuf, errbuf_size[0])
    end

    return true
end

local function file_close(file)
    check_file_instance(file)

    local errbuf = get_string_buf(ERR_BUF_SIZE)
    local errbuf_size = get_size_ptr()
    errbuf_size[0] = ERR_BUF_SIZE

    local rc = C.ngx_http_lua_ffi_file_close(r, file, errbuf, errbuf_size)
    if rc == FFI_ERROR then
        return nil, ffi_str(errbuf, errbuf_size[0])
    end

    return true
end


local mt = {
    __gc = C.ngx_http_lua_ffi_file_destroy,

    __index = {
        read_all = function (file)
            local data, err, partial = file_read(file, FILE_READ_ALL, 0)
            return data, err, partial
        end,

        read_bytes = function (file, len)
            if len <= 0 then
                if len < 0 then
                    error("bad len argument", 2)
                end

                return ""
            end
            local data, err, partial = file_read(file, FILE_READ_BYTES, len)
            return data, err, partial
        end,

        read_line = function (file)
            local data, err, partial = file_read(file, FILE_READ_LINE, 0)
            return data, err, partial
        end,

        read_any = function (file, max)
            if type(max) ~= "number" then
                max = tonumber(max)
            end

            if not max or max <= 0 then
                error("bad max argument", 2)
            end

            local data, err, partial = file_read(file, FILE_READ_ANY, max)
            return data, err, partial
        end,

        write = file_write,
        seek = file_seek,
        flush = file_flush,
        close = file_close,
    }
}
local File = ffi.metatype("ngx_http_lua_ffi_file_t", mt)


local file_open
do

    function file_open(filename, thread_pool_name, flags, mode)
        if ngx_phase() == "init" then
            error("API disabled in the current context", 2)
        end

        if type(filename) ~= "string" then
            error("bad filename argument", 2)
        end

        if type(flags) ~= "string" then
            error("bad flags argument", 2)
        end

        if type(thread_pool_name) ~= "string" then
            error("bad thread_pool_name argument", 2)
        end

        if type(mode) ~= "number" then
            error("bad mode argument", 2)
        end

        local buffer_size = 4096

        local errbuf = get_string_buf(ERR_BUF_SIZE)
        local errbuf_size = get_size_ptr()
        local r = get_request()
        local file = File()
        errbuf_size[0] = ERR_BUF_SIZE

        local rc = C.ngx_http_lua_ffi_file_open(r, file, filename, flags, mode, thread_pool_name, buffer_size, errbuf, errbuf_size)
        if rc == FFI_ERROR then
            return nil, ffi_str(errbuf, errbuf_size[0])
        end
        
        return file
    end
end  -- do


_M.open = file_open


return _M
