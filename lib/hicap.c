#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <sys/select.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>

#include "hicap.h" // this includes broker headers and also dummypthread.h

// undo changes made by dummypthread.h, which is included automatically during compilation of the broker only
#undef pthread_create
#undef pthread_join
#undef pthread_cancel
#undef pthread_mutex_init
#undef pthread_mutex_destroy
#undef pthread_mutex_lock
#undef pthread_mutex_unlock
// and include real pthread headers
#include <pthread.h>                // needed for locking

#include <nsutils/base64.h>         // needed for BASE-64 encoding of mqtt payload
#include <jansson.h>                // needed for JSON encoding of collected metadata
#include <uv.h>                     // needed for sending collected metadata over TCP to logstash (elastic search stack) or netcat
#include <openssl/ssl.h>            // needed for decoding SSL client certificate

#include "mqtt3_protocol.h"

static pthread_mutex_t _hicap_mutex = PTHREAD_MUTEX_INITIALIZER;

static char*                _hostStr;
static char*                _portStr;
static struct addrinfo      _hints;
static uv_getaddrinfo_t     _resolver;
static uv_tcp_t             _uvSock;
static uv_connect_t         _uvConn;
static bool                 _isInitialized = false;
static bool                 _isResolveStarted = false;
static bool                 _isConnected = false;
static bool                 _hasStarted = false;

static void _hicap_capture_startup();

static void _uv_on_connect_cb( __attribute__((unused)) uv_connect_t *conn, int uvErr ) {
    if( uvErr == 0 ) {
        _isConnected = true;
        HICAP_LOG_DEBUG("_uv_on_connect_cb() connect successfull");
        if(!_hasStarted) {
            _hasStarted = true;
            _hicap_capture_startup();
        }
    } else {
        _isConnected = false;
        _isResolveStarted = false;
        HICAP_LOG_ERR( "_uv_on_connect_cb() connect failed: %s: %s", uv_err_name(uvErr), uv_strerror(uvErr) );
    }
}

static void _uv_on_resolved_cb( __attribute__((unused)) uv_getaddrinfo_t *resolver, int uvErr, struct addrinfo *res ) {
    if( uvErr < 0 ) {
        HICAP_LOG_ERR( "_uv_on_resolved_cb() failed for host '%s' port '%s': %s: %s", _hostStr, _portStr, uv_err_name(uvErr), uv_strerror(uvErr) );
        _isConnected = false;
        _isResolveStarted = false;
    } else {
        char addr[17] = {'\0'};
        uv_ip4_name((struct sockaddr_in*) res->ai_addr, addr, 16);
        HICAP_LOG_NOTICE( "_uv_on_resolved_cb() resolved IP '%s' for host '%s' port '%s'", addr, _hostStr, _portStr );
        memset(&_uvConn, 0, sizeof(_uvConn));
        uvErr = uv_tcp_init(uv_default_loop(), &_uvSock);
        if( uvErr == 0 ) {
            uvErr = uv_tcp_connect(&_uvConn, &_uvSock, (const struct sockaddr*)(res->ai_addr), _uv_on_connect_cb);
            uv_freeaddrinfo(res);
            if( uvErr != 0 ) { // }&& uvErr != uv_translate_sys_error(EISCONN) ) {
                HICAP_LOG_ERR( "uv_tcp_connect() failed for host '%s' port '%s': %s: %s", _hostStr, _portStr, uv_err_name(uvErr), uv_strerror(uvErr) );
                _isConnected = false;
                _isResolveStarted = false;
            }
        } else {
            HICAP_LOG_ERR( "uv_tcp_init() failed: %s: %s", uv_err_name(uvErr), uv_strerror(uvErr) );
            _isConnected = false;
            _isResolveStarted = false;
        }
    }
}

/**
 * Only called, if _isInitialized is already true.
 */
static bool _hicap_auto_reconnect_unlocked() {
    if( _isConnected ) {
        return true;
    } else if( _isResolveStarted == false ) {
        int uvErr;
        _isResolveStarted = true;
        HICAP_LOG_NOTICE( "_hicap_auto_reconnect_unlocked() starting hostname resolution for host '%s' port '%s'", _hostStr, _portStr );
        uvErr = uv_getaddrinfo( uv_default_loop(), &_resolver, _uv_on_resolved_cb, _hostStr, _portStr, &_hints );
        if( uvErr != 0 ) {
            HICAP_LOG_ERR( "cannot initiate reconnect: uv_getaddrinfo() failed: %s: %s", uv_err_name(uvErr), uv_strerror(uvErr) );
            _isResolveStarted = false;
        }
    }
    return false;
}

#define ENV_HOST    "HICAP_HOST"    //!< environment variable name to override logstash/netcat destination host name or IP address
#define ENV_PORT    "HICAP_PORT"    //!< environment variable name to override logstash/netcat destination port number or name
#define HOST_DEF    "127.0.0.1"     //!< default logstash/netcat destination host name or IP address
#define PORT_DEF    "12345"         //!< default logstash/netcat destination port number or name

/**
 * Is only processed once on startup when _isInitialized is still false.
 */
static bool _hicap_init_unlocked() {
    if( _isInitialized == false ) {
        _isInitialized = true;
        _hostStr = getenv(ENV_HOST);
        if(!_hostStr)
            _hostStr = HOST_DEF;
        _portStr = getenv(ENV_PORT);
        if(!_portStr)
            _portStr = PORT_DEF;
        memset(&_hints, 0, sizeof(_hints));
        _hints.ai_family = PF_INET;
        _hints.ai_socktype = SOCK_STREAM;
        _hints.ai_protocol = IPPROTO_TCP;
        _hints.ai_flags = 0;
        HICAP_LOG_NOTICE("HICAP interface successfully initialized using destination host '%s' and port '%s'", _hostStr, _portStr);
        HICAP_LOG_NOTICE("To override capture destination host name or IP address (default=" HOST_DEF ") use environment variable " ENV_HOST "!");
        HICAP_LOG_NOTICE("To override capture destination host port number or name (default=" PORT_DEF ") use environment variable " ENV_PORT "!");
        HICAP_LOG_NOTICE("For capturing use logstash or a quick <$ netcat -l -p %s> on %s", _portStr, _hostStr);
        _hicap_auto_reconnect_unlocked(); // try connect on startup, don't care about the result
    }
    return true;
}

static bool _hicap_init() {
    bool retval = false;
    pthread_mutex_lock( &_hicap_mutex );
    retval = _hicap_init_unlocked();
    pthread_mutex_unlock( &_hicap_mutex );
    return retval;
}

void hicap_startup() {
    HICAP_LOG_NOTICE("Starting HICAP interface...");
    _hicap_init();
}

void hicap_run() {
    int uvErr = uv_run(uv_default_loop(), UV_RUN_DEFAULT);
    if( uvErr != 0 ) {
        HICAP_LOG_ERR( "uv_run() failed: %s: %s", uv_err_name(uvErr), uv_strerror(uvErr) );
    }
}

static void _uv_on_close_cb( __attribute__((unused)) uv_handle_t* handle ) {
    HICAP_LOG_DEBUG();
    _isConnected = false;
    _isResolveStarted = false;
}

static void _hicap_shutdown_unlocked() {
    HICAP_LOG_DEBUG();
    if( !uv_is_closing((uv_handle_t*)&_uvSock) ) {
        uv_close( (uv_handle_t*)&_uvSock, _uv_on_close_cb );
    }
    uv_stop( uv_default_loop() );
    uv_loop_close( uv_default_loop() );
}

static void _hicap_capture_shutdown();

void hicap_shutdown() {
    HICAP_LOG_DEBUG();
    _hicap_capture_shutdown();
    pthread_mutex_lock( &_hicap_mutex );
    _hicap_shutdown_unlocked();
    pthread_mutex_unlock( &_hicap_mutex );
}

static void _uv_on_write_cb( uv_write_t *req, int uvErr ) {
    if( uvErr == 0 ) {
        HICAP_LOG_DEBUG("_uv_on_write() write successfull");
    } else {
        HICAP_LOG_ERR( "_uv_on_write() write failed: %s: %s", uv_err_name(uvErr), uv_strerror(uvErr) );
        _isConnected = false;
        _isResolveStarted = false;
        /*if( !uv_is_closing((uv_handle_t*)&_uvSock) ) {
            uv_close( (uv_handle_t*)&_uvSock, _uv_on_close_cb );
        }*/
    }
    if( req && req->data ) {
        free(req->data);
    }
    if( req ) {
        free(req);
    }
}

/**
 * NOTE: The caller must NOT free data in any case.
 */
static bool _hicap_write_raw( void *data, size_t dataLen ) {
    bool retval = false;
    int uvErr;
    pthread_mutex_lock( &_hicap_mutex );
    HICAP_LOG_DEBUG("writing %zd bytes", dataLen);
    if( _hicap_auto_reconnect_unlocked() == true ) { // otherwise we are still trying to resolve destination host
        //if( dataLen > PIPE_BUF ) {
        //    HICAP_LOG_WARN("atomar write of message (len:%zd) not guaranteed (max buf size:%d)", dataLen, PIPE_BUF);
        //}
        uv_write_t *req = (uv_write_t*) malloc(sizeof(uv_write_t));
        uv_buf_t buf = uv_buf_init(data, dataLen);
        req->data = data; // remember for later free
        //int isWritable = uv_is_writable( (uv_stream_t*)(&_uvSock) );
        //HICAP_LOG_DEBUG( "is writable: %s", isWritable?"yes":"no");
        uvErr = uv_write( req, (uv_stream_t*)(&_uvSock), &buf, 1, _uv_on_write_cb );
        if( uvErr == 0 ) {
            HICAP_LOG_DEBUG( "uv_write() success" );
            //int alive = uv_loop_alive( uv_default_loop() );
            //HICAP_LOG_DEBUG("loop alive: %s", alive != 0 ? "yes" : "stopped");
            retval = true;
            data = NULL;
        } else {
            HICAP_LOG_ERR( "uv_write() failed: %s: %s", uv_err_name(uvErr), uv_strerror(uvErr) );
            free(req);
            free(data);
            data = NULL;
        }
    } else {
        free( data );
    }
    pthread_mutex_unlock( &_hicap_mutex );
    return retval;
}

static bool _hicap_write( json_t *jsonRoot ) {
    bool res = false;
    if( jsonRoot != NULL ) {
        char *line = json_dumps(jsonRoot, 0);
        if( line != NULL ) {
            HICAP_LOG_DEBUG("line: '%s'\n", line!=NULL?line:"<NULL>");
            size_t len = strlen(line);
            line[len] = '\n';
            res = _hicap_write_raw( line, len+1 ); // the function cares about freeing line in any case
            //line[len] = '\0';
        } else {
            HICAP_LOG_ERR("cannot convert JSON root object into plain text format");
        }
    } else {
        HICAP_LOG_WARN("empty JSON root object given");
    }
    return res;
}

static int _hicap_add_kvp(json_t *jsonObj, char *keyName, json_t *jsonVal) {
    if( jsonObj != NULL ) {
        if( keyName != NULL ) {
            if( jsonVal == NULL ) {
                jsonVal = json_null();
            }
            if( jsonVal != NULL ) {
                int jsonRes = json_object_set(jsonObj, keyName, jsonVal);
                if( jsonRes == 0 ) {
                    return 0;
                } else {
                    HICAP_LOG_ERR("cannot add value: err=%d", jsonRes);
                }
            } else {
                HICAP_LOG_ERR("missing value");
            }
        } else {
            HICAP_LOG_ERR("missing key name");
        }
    } else {
        HICAP_LOG_ERR("missing json obj");
    }
    return -1;
}

#define _hicap_add_null(jsonObj, keyName) _hicap_add_kvp(jsonObj, keyName, NULL)

static int _hicap_add_str_len(json_t *jsonObj, char *keyName, char *value, size_t len) {
    json_t *jsonVal = NULL;
    if( value != NULL && len > 0 ) {
        jsonVal = json_stringn(value, len);
        if( jsonVal == NULL ) {
            HICAP_LOG_ERR("cannot create json string");
            return -1;
        }
    }
    return _hicap_add_kvp(jsonObj, keyName, jsonVal);
}

static int _hicap_add_str(json_t *jsonObj, char *keyName, char *value) {
    json_t *jsonVal = NULL;
    if( value != NULL ) {
        jsonVal = json_string(value);
        if( jsonVal == NULL ) {
            HICAP_LOG_ERR("cannot create json string");
            return -1;
        }
    }
    return _hicap_add_kvp(jsonObj, keyName, jsonVal);
}

static int _hicap_add_int(json_t *jsonObj, char *keyName, int value) {
    json_t *jsonVal = NULL;
    jsonVal = json_integer(value);
    if( jsonVal == NULL ) {
        HICAP_LOG_ERR("cannot create json int");
        return -1;
    }
    return _hicap_add_kvp(jsonObj, keyName, jsonVal);
}

static int _hicap_add_bool(json_t *jsonObj, char *keyName, bool value) {
    json_t *jsonVal = NULL;
    jsonVal = json_boolean(value);
    if( jsonVal == NULL ) {
        HICAP_LOG_ERR("cannot create json bool");
        return -1;
    }
    return _hicap_add_kvp(jsonObj, keyName, jsonVal);
}

static int _hicap_add_b64(json_t *jsonObj, char *keyName, void *data, uint32_t dataLen) {
    int retVal = -1;
    char *b64 = NULL;
    size_t b64sz = 0;
    if( data != NULL && dataLen > 0 ) {
        nsuerror nsuErr = nsu_base64_encode_alloc(data, dataLen, (uint8_t**)(&b64), &b64sz); // not null terminated
        HICAP_LOG_DEBUG("b64:%s b64sz:%zu err:%d", b64!=NULL?"OK":"NULL", b64sz, nsuErr);
        if( nsuErr == NSUERROR_OK ) {
            retVal = _hicap_add_str_len(jsonObj, keyName, b64, b64sz);
        } else {
            HICAP_LOG_ERR("base64 encode failed: err=%d", nsuErr);
            if(b64 != NULL)
                free(b64);
        }
    } else {
        retVal = _hicap_add_null(jsonObj, keyName);
    }
    return retVal;
}

static int _hicap_add_ssl_sn(json_t *jsonObj, X509 *client_cert) {
    int i;
    char buf[128];
    ASN1_INTEGER *serial;
    if( (serial = X509_get_serialNumber(client_cert)) ) {
        if(serial->length > 0 && (size_t)(serial->length*3) < sizeof(buf)) {
            for( i=0; i<serial->length; i++ ) {
                snprintf(buf+i*3, sizeof(buf)-i*3, "%02X:", serial->data[i]);
            }
            buf[serial->length*3-1] = '\0';
            HICAP_LOG_DEBUG("SN='%s'", buf);
            _hicap_add_str(jsonObj, "sslSN", buf);
            return 0;
        } else {
            HICAP_LOG_ERR("cannot extract serial");
        }
    } else {
        HICAP_LOG_ERR("cannot obtain serial");
    }
    return 1;
}

static int _hicap_add_ssl_cn(json_t *jsonObj, X509 *client_cert) {
    int i;
    X509_NAME *name;
    if( (name = X509_get_subject_name(client_cert)) ) {
        i = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
        if( i >= 0 ) {
            X509_NAME_ENTRY *name_entry = X509_NAME_get_entry(name, i);
            char *cn;
            if( (cn = (char *)ASN1_STRING_data(X509_NAME_ENTRY_get_data(name_entry))) ) {
                HICAP_LOG_DEBUG("CN='%s'", cn);
                _hicap_add_str(jsonObj, "sslCN", cn);
                return 0;
            } else {
                HICAP_LOG_ERR("cannot extract common name");
            }
        } else {
            HICAP_LOG_ERR("cannot obtain common name");
        }
    } else {
        HICAP_LOG_ERR("cannot obtain name");
    }
    return 1;
}

/**
 * $ openssl x509 -noout -in client.crt -text
 */
static void _hicap_add_ssl(json_t *jsonObj, SSL *ssl) {
    if(ssl != NULL) {
        // collect SSL connection information in case of client certificate authentication is used
        X509 *client_cert;
        if( (client_cert = SSL_get_peer_certificate(ssl)) ) {
            // use debug dump from openssl to dump all info available
            BIO *o;
            if( (o = BIO_new_fp(stdout,BIO_NOCLOSE)) ) {
                X509_print_ex(o, client_cert, XN_FLAG_COMPAT, X509_FLAG_COMPAT); // TODO remove verbose dump
                BIO_free(o);
            }
            // see also: openssl/crypto/asn1/t_x509.c:X509_print_ex()
            if( _hicap_add_ssl_sn(jsonObj, client_cert) == 0 ) {
                _hicap_add_ssl_cn(jsonObj, client_cert);
            }
            X509_free(client_cert);
        }
        else {
            HICAP_LOG_DEBUG("SSL is used without client certificate authentication");
        }

        //! \todo TODO collect SSL connection information in case of client certificate authentication is NOT used
        
    } else {
        HICAP_LOG_INFO("SSL is not used");
    }
}

static int _hicap_add_ts(json_t *jsonObj) {
    char buf[64];
    int retval = 0;
    time_t rawTime;
    time(&rawTime);
    struct tm localTime, utcTime;
    gmtime_r(&rawTime, &utcTime);
    localtime_r(&rawTime, &localTime);
    memset(buf, 0, sizeof(buf));
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ (%Z)", &utcTime); // %Z always print GMT in this case
    //HICAP_LOG_DEBUG("utc:   %s", buf);
    retval |= _hicap_add_str(jsonObj, "tsUTC", buf);
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S%z (%Z)", &localTime); // %Z print CEST (central european summer time) or CET or ...
    //HICAP_LOG_DEBUG("local: %s", buf);
    retval |= _hicap_add_str(jsonObj, "tsLocal", buf);
    // TODO add milli or nano seconds '.sss' (NOTE: not ISO 8601 compliant?)
    // TODO leave out ' (%Z)' for ISO 8601 compliance?
    // TODO error checking
    return retval;
}

static int _hicap_add_listeners(json_t *jsonObj) {
    struct mosquitto_db* db = mosquitto__get_db();
    json_t *jsonArray = json_array();
    if( db != NULL ) {
        for( int i=0; i<db->config->listener_count; i++) {
            struct mosquitto__listener *listener = &db->config->listeners[i];
            if( (listener != NULL) && (listener->protocol == mp_mqtt) ) {
                json_t *jsonArrObj = json_object();
                _hicap_add_str(jsonArrObj, "bind", listener->host != NULL ? listener->host : "");
                _hicap_add_int(jsonArrObj, "port", listener->port);
                json_array_append(jsonArray, jsonArrObj);
                json_decref(jsonArrObj);
            }
        }
    }
    return _hicap_add_kvp(jsonObj, "listeners", jsonArray);
}

void hicap_capture_publish(struct mosquitto *context, char *topic, void *payload, uint32_t payloadLen) {
    json_t *jsonObj = NULL, *jsonRoot = NULL;
    HICAP_LOG_DEBUG();
    if( _hicap_init() == true ) {
        jsonRoot = json_object();
        jsonObj = json_object();
        if( (jsonRoot!= NULL) && (jsonObj != NULL) ) {
            int res = 0;
            res |= _hicap_add_str(jsonObj, "action", "PUBLISH");
            _hicap_add_ssl(jsonObj, context ? context->ssl : NULL);                     // serial number (SN) and common name (CN) of client certificate
            res |= _hicap_add_str(jsonObj, "topic", topic);
            res |= _hicap_add_str(jsonObj, "clientIP", context ? context->address : NULL);  // IP of client, maybe NATed
            if( context && context->listener )
                res |= _hicap_add_int(jsonObj, "port", context->listener->port);        // incoming port (listen port of broker)
            else
                res |= _hicap_add_null(jsonObj, "port");
            res |= _hicap_add_str(jsonObj, "clientID", context ? context->id : NULL);   // sent by client or generated by broker
            res |= _hicap_add_ts(jsonObj);
            res |= _hicap_add_b64(jsonObj, "payload", payload, payloadLen);
            res |= _hicap_add_kvp(jsonRoot, "mqtt", jsonObj);
            if( res == 0 ) {
                _hicap_write( jsonRoot );
            } else {
                HICAP_LOG_ERR("cannot assemble json obj");
            }
        } else {
            HICAP_LOG_ERR("cannot create new json obj");
        }
    }
    json_decrefp(&jsonObj);
    json_decrefp(&jsonRoot);
}

void hicap_capture_subscribe(struct mosquitto *context, char *topic) {
    json_t *jsonObj = NULL, *jsonRoot = NULL;
    HICAP_LOG_DEBUG();
    if( _hicap_init() == true ) {
        jsonRoot = json_object();
        jsonObj = json_object();
        if( jsonRoot!= NULL && jsonObj != NULL ) {
            int res = 0;
            res |= _hicap_add_str(jsonObj, "action", "SUBSCRIBE");
            _hicap_add_ssl(jsonObj, context ? context->ssl : NULL);                 // serial number (SN) and common name (CN) of client certificate
            res |= _hicap_add_str(jsonObj, "topic", topic);
            res |= _hicap_add_str(jsonObj, "clientIP", context ? context->address : NULL);  // IP of client, maybe NATed
            if( context && context->listener )
                res |= _hicap_add_int(jsonObj, "port", context->listener->port);    // incoming port (listen port of broker)
            else
                res |= _hicap_add_null(jsonObj, "port");
            res |= _hicap_add_str(jsonObj, "clientID", context->id);                // sent by client or generated by broker
            res |= _hicap_add_ts(jsonObj);
            res |= _hicap_add_kvp(jsonRoot, "mqtt", jsonObj);
            if( res == 0 ) {
                _hicap_write( jsonRoot );
            } else {
                HICAP_LOG_ERR("cannot assemble json obj");
            }
        } else {
            HICAP_LOG_ERR("cannot create new json obj");
        }
    }
    json_decrefp(&jsonObj);
    json_decrefp(&jsonRoot);
}

/**
 * result is one of the defines CONNACK_ from mqtt3_protocol.h
 */
void hicap_capture_connect(struct mosquitto *context, int result) {
    json_t *jsonObj = NULL, *jsonRoot = NULL;
    HICAP_LOG_DEBUG();
    if( _hicap_init() == true ) {
        jsonRoot = json_object();
        jsonObj = json_object();
        if( (jsonRoot!= NULL) && (jsonObj != NULL) ) {
            int res = 0;
            res |= _hicap_add_str(jsonObj, "action", "CONNECT");
            res |= _hicap_add_str(jsonObj, "clientIP", context ? context->address : NULL);  // IP of client, maybe NATed
            if( context && context->listener )
                res |= _hicap_add_int(jsonObj, "port", context->listener->port);    // incoming port (listen port of broker)
            else
                res |= _hicap_add_null(jsonObj, "port");
            res |= _hicap_add_str(jsonObj, "clientID", context ? context->id : NULL);   // sent by client or generated by broker
            res |= _hicap_add_ts(jsonObj);
            res |= _hicap_add_bool(jsonObj, "success", result == CONNACK_ACCEPTED ? true : false);
            res |= _hicap_add_str(jsonObj, "state", result == CONNACK_ACCEPTED ? "ACCEPTED" : "REFUSED");
            if( result != CONNACK_ACCEPTED ) {
                res |= _hicap_add_int(jsonObj, "errCode", result);
                switch(result) { // see CONNACK_ in mqtt3_protocol.h
                    case CONNACK_REFUSED_PROTOCOL_VERSION: res |= _hicap_add_str(jsonObj, "reason", "CONNACK_REFUSED_PROTOCOL_VERSION"); break;
                    case CONNACK_REFUSED_IDENTIFIER_REJECTED: res |= _hicap_add_str(jsonObj, "reason", "CONNACK_REFUSED_IDENTIFIER_REJECTED"); break;
                    case CONNACK_REFUSED_SERVER_UNAVAILABLE: res |= _hicap_add_str(jsonObj, "reason", "CONNACK_REFUSED_SERVER_UNAVAILABLE"); break;
                    case CONNACK_REFUSED_BAD_USERNAME_PASSWORD: res |= _hicap_add_str(jsonObj, "reason", "CONNACK_REFUSED_BAD_USERNAME_PASSWORD"); break;
                    case CONNACK_REFUSED_NOT_AUTHORIZED: res |= _hicap_add_str(jsonObj, "reason", "CONNACK_REFUSED_NOT_AUTHORIZED"); break;
                    default: res |= _hicap_add_str(jsonObj, "reason", "CONNACK_REFUSED_UNKNOWN_REASON"); break;
                }
            }
            res |= _hicap_add_kvp(jsonRoot, "mqtt", jsonObj);
            if( res == 0 ) {
                _hicap_write( jsonRoot );
            } else {
                HICAP_LOG_ERR("cannot assemble json obj");
            }
        } else {
            HICAP_LOG_ERR("cannot create new json obj");
        }
    }
    json_decrefp(&jsonObj);
    json_decrefp(&jsonRoot);
}

void hicap_capture_disconnect(struct mosquitto *context) {
    json_t *jsonObj = NULL, *jsonRoot = NULL;
    HICAP_LOG_DEBUG();
    if( _hicap_init() == true ) {
        jsonRoot = json_object();
        jsonObj = json_object();
        if( jsonRoot!= NULL && jsonObj != NULL ) {
            int res = 0;
            res |= _hicap_add_str(jsonObj, "action", "DISCONNECT");
            res |= _hicap_add_str(jsonObj, "clientIP", context ? context->address : NULL);  // IP of client, maybe NATed
            if( context && context->listener )
                res |= _hicap_add_int(jsonObj, "port", context->listener->port);            // incoming port (listen port of broker)
            else
                res |= _hicap_add_null(jsonObj, "port");
            res |= _hicap_add_str(jsonObj, "clientID", context ? context->id : NULL);       // sent by client or generated by broker
            res |= _hicap_add_ts(jsonObj);
            res |= _hicap_add_kvp(jsonRoot, "mqtt", jsonObj);
            if( res == 0 ) {
                _hicap_write( jsonRoot );
            } else {
                HICAP_LOG_ERR("cannot assemble json obj");
            }
        } else {
            HICAP_LOG_ERR("cannot create new json obj");
        }
    }
    json_decrefp(&jsonObj);
    json_decrefp(&jsonRoot);
}

static void _hicap_capture_startup() {
    json_t *jsonObj = NULL, *jsonRoot = NULL;
    HICAP_LOG_DEBUG();
    if( _hicap_init() == true ) {
        jsonRoot = json_object();
        jsonObj = json_object();
        if( jsonRoot!= NULL && jsonObj != NULL ) {
            int res = 0;
            res |= _hicap_add_str(jsonObj, "action", "STARTUP");
            res |= _hicap_add_listeners(jsonObj);
            res |= _hicap_add_kvp(jsonRoot, "mqtt", jsonObj);
            if( res == 0 ) {
                _hicap_write( jsonRoot );
            } else {
                HICAP_LOG_ERR("cannot assemble json obj");
            }
        } else {
            HICAP_LOG_ERR("cannot create new json obj");
        }
    }
    json_decrefp(&jsonObj);
    json_decrefp(&jsonRoot);
}

static void _hicap_capture_shutdown() {
    json_t *jsonObj = NULL, *jsonRoot = NULL;
    HICAP_LOG_DEBUG();
    if( _hicap_init() == true ) {
        jsonRoot = json_object();
        jsonObj = json_object();
        if( jsonRoot!= NULL && jsonObj != NULL ) {
            int res = 0;
            res |= _hicap_add_str(jsonObj, "action", "SHUTDOWN");
            res |= _hicap_add_listeners(jsonObj);
            res |= _hicap_add_kvp(jsonRoot, "mqtt", jsonObj);
            if( res == 0 ) {
                _hicap_write( jsonRoot );
            } else {
                HICAP_LOG_ERR("cannot assemble json obj");
            }
        } else {
            HICAP_LOG_ERR("cannot create new json obj");
        }
    }
    json_decrefp(&jsonObj);
    json_decrefp(&jsonRoot);
}
