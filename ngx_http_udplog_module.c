
/*
 * Copyright (C) Valery Kholodkov
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define NGX_UDPLOG_FACILITY_LOCAL7      23
#define NGX_UDPLOG_SEVERITY_INFO        6

typedef struct ngx_http_log_op_s  ngx_http_log_op_t;

typedef u_char *(*ngx_http_log_op_run_pt) (ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op);

typedef size_t (*ngx_http_log_op_getlen_pt) (ngx_http_request_t *r,
    uintptr_t data);


struct ngx_http_log_op_s {
    size_t                      len;
    ngx_http_log_op_getlen_pt   getlen;
    ngx_http_log_op_run_pt      run;
    uintptr_t                   data;
};

typedef struct {
    ngx_str_t                   name;
    ngx_array_t                *flushes;
    ngx_array_t                *ops;        /* array of ngx_http_log_op_t */
} ngx_http_log_fmt_t;

typedef struct {
    ngx_array_t                 formats;    /* array of ngx_http_log_fmt_t */
    ngx_uint_t                  combined_used; /* unsigned  combined_used:1 */
} ngx_http_log_main_conf_t;

typedef struct {
    ngx_str_t                   name;
    ngx_uint_t                  number;
} ngx_udplog_facility_t;

typedef ngx_udplog_facility_t ngx_udplog_severity_t;

typedef struct {
    ngx_addr_t                 peer_addr;
    ngx_udp_connection_t      *udp_connection;
} ngx_udp_endpoint_t;

typedef struct {
    ngx_udp_endpoint_t       *endpoint;
    ngx_http_log_fmt_t       *format;
    ngx_uint_t                facility;
    ngx_uint_t                severity;
} ngx_http_udplog_t;

typedef struct {
    ngx_array_t                *endpoints;
} ngx_http_udplog_main_conf_t;

typedef struct {
    ngx_array_t                *logs;       /* array of ngx_http_udplog_t */
    unsigned                    enabled;
} ngx_http_udplog_conf_t;

ngx_int_t ngx_udp_connect(ngx_udp_connection_t *uc);

static void ngx_udplogger_cleanup(void *data);
static ngx_int_t ngx_http_udplogger_send(ngx_udp_endpoint_t *l, u_char *buf, size_t len);

static void *ngx_http_udplog_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_udplog_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_udplog_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);

static char *ngx_http_udplog_set_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_udplog_init(ngx_conf_t *cf);


static ngx_command_t  ngx_http_udplog_commands[] = {

    { ngx_string("access_udplog"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                        |NGX_HTTP_LMT_CONF|NGX_CONF_TAKE123,
      ngx_http_udplog_set_log,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_udplog_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_udplog_init,                  /* postconfiguration */

    ngx_http_udplog_create_main_conf,      /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_udplog_create_loc_conf,       /* create location configration */
    ngx_http_udplog_merge_loc_conf         /* merge location configration */
};

extern ngx_module_t  ngx_http_log_module;

ngx_module_t  ngx_http_udplog_module = {
    NGX_MODULE_V1,
    &ngx_http_udplog_module_ctx,           /* module context */
    ngx_http_udplog_commands,              /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_udplog_facility_t ngx_udplog_facilities[] = {
    { ngx_string("kern"),       0 },
    { ngx_string("user"),       1 },
    { ngx_string("mail"),       2 },
    { ngx_string("daemon"),     3 },
    { ngx_string("auth"),       4 },
    { ngx_string("intern"),     5 },
    { ngx_string("lpr"),        6 },
    { ngx_string("news"),       7 },
    { ngx_string("uucp"),       8 },
    { ngx_string("clock"),      9 },
    { ngx_string("authpriv"),  10 },
    { ngx_string("ftp"),       11 },
    { ngx_string("ntp"),       12 },
    { ngx_string("audit"),     13 },
    { ngx_string("alert"),     14 },
    { ngx_string("cron"),      15 },
    { ngx_string("local0"),    16 },
    { ngx_string("local1"),    17 },
    { ngx_string("local2"),    18 },
    { ngx_string("local3"),    19 },
    { ngx_string("local4"),    20 },
    { ngx_string("local5"),    21 },
    { ngx_string("local6"),    22 },
    { ngx_string("local7"),    23 },

    { ngx_null_string, 0 }
};

static ngx_udplog_severity_t ngx_udplog_severity[] = {
    { ngx_string("emerg"),      0 },
    { ngx_string("alert"),      1 },
    { ngx_string("crit"),       2 },
    { ngx_string("err"),        3 },
    { ngx_string("warning"),    4 },
    { ngx_string("notice"),     5 },
    { ngx_string("info"),       6 },
    { ngx_string("debug"),      7 },

    { ngx_null_string, 0 }
};

static char *months[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

ngx_int_t
ngx_http_udplog_handler(ngx_http_request_t *r)
{
    u_char                   *line, *p;
    size_t                    len;
    ngx_uint_t                i, l, pri;
    ngx_http_udplog_t        *log;
    ngx_http_log_op_t        *op;
    ngx_http_udplog_conf_t   *ulcf;
    time_t                    time;
    ngx_tm_t                  tm;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http udplog handler");

    ulcf = ngx_http_get_module_loc_conf(r, ngx_http_udplog_module);

    if (!ulcf->enabled) {
        return NGX_OK;
    }

    time = ngx_time();
    ngx_gmtime(time, &tm);

    log = ulcf->logs->elts;
    for (l = 0; l < ulcf->logs->nelts; l++) {
        pri = log[l].facility * 8 + log[l].severity;

        if(pri > 255) {
            pri = NGX_UDPLOG_FACILITY_LOCAL7 * 8 + NGX_UDPLOG_SEVERITY_INFO;
        }

        ngx_http_script_flush_no_cacheable_variables(r, log[l].format->flushes);

        len = 0;
        op = log[l].format->ops->elts;
        for (i = 0; i < log[l].format->ops->nelts; i++) {
            if (op[i].len == 0) {
                len += op[i].getlen(r, op[i].data);

            } else {
                len += op[i].len;
            }
        }

        len += sizeof("<255>") - 1 + sizeof("Jan 31 00:00:00") - 1 + 1 + ngx_cycle->hostname.len + 1;

        line = ngx_pnalloc(r->pool, len);
        if (line == NULL) {
            return NGX_ERROR;
        }

        /*
         * BSD syslog message header (see RFC 3164)
         */
        p = ngx_sprintf(line, "<%ui>%s %2d %02d:%02d:%02d %V ", pri, months[tm.ngx_tm_mon - 1], tm.ngx_tm_mday,
            tm.ngx_tm_hour, tm.ngx_tm_min, tm.ngx_tm_sec, &ngx_cycle->hostname);

        for (i = 0; i < log[l].format->ops->nelts; i++) {
            p = op[i].run(r, p, &op[i]);
        }

        ngx_http_udplogger_send(log[l].endpoint, line, p - line);
    }

    return NGX_OK;
}

static ngx_int_t ngx_udplog_init_endpoint(ngx_conf_t *cf, ngx_udp_endpoint_t *endpoint) {
    ngx_pool_cleanup_t    *cln;
    ngx_udp_connection_t  *uc;

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if(cln == NULL) {
        return NGX_ERROR;
    }

    cln->handler = ngx_udplogger_cleanup;
    cln->data = endpoint;

    uc = ngx_calloc(sizeof(ngx_udp_connection_t), cf->log);
    if (uc == NULL) {
        return NGX_ERROR;
    }

    endpoint->udp_connection = uc;

    uc->sockaddr = endpoint->peer_addr.sockaddr;
    uc->socklen = endpoint->peer_addr.socklen;
    uc->server = endpoint->peer_addr.name;
    uc->log = &cf->cycle->new_log;

    return NGX_OK;
}

static void
ngx_udplogger_cleanup(void *data)
{
    ngx_udp_endpoint_t  *e = data;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "cleanup udplogger");

    if(e->udp_connection) {
        if(e->udp_connection->connection) {
            ngx_close_connection(e->udp_connection->connection);
        }

        ngx_free(e->udp_connection);
    }
}

static void ngx_http_udplogger_dummy_handler(ngx_event_t *ev)
{
}

static ngx_int_t
ngx_http_udplogger_send(ngx_udp_endpoint_t *l, u_char *buf, size_t len)
{
    ssize_t                n;
    ngx_udp_connection_t  *uc;

    uc = l->udp_connection;

    if (uc->connection == NULL) {
        if(ngx_udp_connect(uc) != NGX_OK) {
            return NGX_ERROR;
        }

        uc->connection->data = l;
        uc->connection->read->handler = ngx_http_udplogger_dummy_handler;
        uc->connection->read->resolver = 0;
    }

    n = ngx_send(uc->connection, buf, len);

    if (n == -1) {
        return NGX_ERROR;
    }

    if ((size_t) n != (size_t) len) {
        ngx_log_error(NGX_LOG_CRIT, uc->log, 0, "send() incomplete");
        return NGX_ERROR;
    }

    return NGX_OK;
}

static void *
ngx_http_udplog_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_udplog_main_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_udplog_main_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    return conf;
}

static void *
ngx_http_udplog_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_udplog_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_udplog_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    return conf;
}

static char *
ngx_http_udplog_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_udplog_conf_t *prev = parent;
    ngx_http_udplog_conf_t *conf = child;

    ngx_http_udplog_t         *log;
    ngx_http_log_fmt_t        *fmt;
    ngx_http_log_main_conf_t  *lmcf;

    if(conf->logs || !conf->enabled) {
        return NGX_CONF_OK;
    }

    conf->logs = prev->logs;
    conf->enabled = prev->enabled;

    if(conf->logs || !conf->enabled) {
        return NGX_CONF_OK;
    }

    conf->logs = ngx_array_create(cf->pool, 2, sizeof(ngx_http_udplog_t));
    if(conf->logs == NULL) {
        return NGX_CONF_ERROR;
    }

    log = ngx_array_push(conf->logs);
    if(log == NULL) {
        return NGX_CONF_ERROR;
    }

    lmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_log_module);
    fmt = lmcf->formats.elts;

    /* the default "combined" format */
    log->format = &fmt[0];
    lmcf->combined_used = 1;

    return NGX_CONF_OK;
}

static ngx_udp_endpoint_t *
ngx_http_udplog_add_endpoint(ngx_conf_t *cf, ngx_addr_t *peer_addr)
{
    ngx_http_udplog_main_conf_t    *umcf;
    ngx_udp_endpoint_t             *endpoint;

    umcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_udplog_module);

    if(umcf->endpoints == NULL) {
        umcf->endpoints = ngx_array_create(cf->pool, 2, sizeof(ngx_udp_endpoint_t));
        if (umcf->endpoints == NULL) {
            return NULL;
        }
    }

    endpoint = ngx_array_push(umcf->endpoints);
    if (endpoint == NULL) {
        return NULL;
    }

    endpoint->peer_addr = *peer_addr;

    return endpoint;
}

static ngx_int_t
ngx_http_udplog_set_facility_and_severity(ngx_http_udplog_t *log, ngx_str_t *value)
{
    return NGX_OK;
}

static char *
ngx_http_udplog_set_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_udplog_conf_t      *ulcf = conf;

    ngx_uint_t                   i;
    ngx_str_t                   *value, name;
    ngx_http_udplog_t           *log;
    ngx_http_log_fmt_t          *fmt;
    ngx_http_log_main_conf_t    *lmcf;
    ngx_url_t                    u;

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {
        return NGX_CONF_OK;
    }

    if (ulcf->logs == NULL) {
        ulcf->logs = ngx_array_create(cf->pool, 2, sizeof(ngx_http_udplog_t));
        if (ulcf->logs == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    lmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_log_module);

    if(lmcf == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "udplog module requires log module to be compiled in");
        return NGX_CONF_ERROR;
    }

    log = ngx_array_push(ulcf->logs);
    if (log == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(log, sizeof(ngx_http_udplog_t));

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.host = value[1];
    u.port = 514;

    if(ngx_inet_resolve_host(cf->pool, &u) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V: %s", &u.host, u.err);
        return NGX_CONF_ERROR;
    }

    log->endpoint = ngx_http_udplog_add_endpoint(cf, &u.addrs[0]);

    if(log->endpoint == NULL) {
        return NGX_CONF_ERROR;
    }

    if (cf->args->nelts >= 3) {
        name = value[2];

        if (ngx_strcmp(name.data, "combined") == 0) {
            lmcf->combined_used = 1;
        }
    } else {
        name.len = sizeof("combined") - 1;
        name.data = (u_char *) "combined";
        lmcf->combined_used = 1;
    }

    fmt = lmcf->formats.elts;
    for (i = 0; i < lmcf->formats.nelts; i++) {
        if (fmt[i].name.len == name.len
            && ngx_strcasecmp(fmt[i].name.data, name.data) == 0)
        {
            log->format = &fmt[i];
            ulcf->enabled = 1;
            goto facility;
        }
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "unknown log format \"%V\"", &name);
    return NGX_CONF_ERROR;

facility:
    log->facility = NGX_UDPLOG_FACILITY_LOCAL7;
    log->severity = NGX_UDPLOG_SEVERITY_INFO;

    if(cf->args->nelts == 4) {
        if(ngx_http_udplog_set_facility_and_severity(log, &value[3]) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_udplog_init(ngx_conf_t *cf)
{
    ngx_int_t                     rc;
    ngx_uint_t                    i;
    ngx_http_core_main_conf_t    *cmcf;
    ngx_http_udplog_main_conf_t  *umcf;
    ngx_http_handler_pt          *h;
    ngx_udp_endpoint_t           *e;

    umcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_udplog_module);

    if(umcf->endpoints != NULL) {
        e = umcf->endpoints->elts;
        for(i = 0;i < umcf->endpoints->nelts;i++) {
            rc = ngx_udplog_init_endpoint(cf, e + i);

            if(rc != NGX_OK) {
                return NGX_ERROR;
            }
        }

        cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

        h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
        if (h == NULL) {
            return NGX_ERROR;
        }

        *h = ngx_http_udplog_handler;
    }

    return NGX_OK;
}
