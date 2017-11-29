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

#include <nsutils/base64.h>
#include <jansson.h>

#include "hicap.h"

static pthread_mutex_t _hicap_mutex = PTHREAD_MUTEX_INITIALIZER;

static FILE *_hicap_fpnc = NULL; //!< File pointer reference to netcat process.

static bool _hicap_init_unlocked() {
    char *nc6cmd = "nc6 -vv -n --send-only --timeout=1 127.0.0.1 12345 ; echo '!!! nc6 has exited !!!'";
    bool retval = false;
    if( _hicap_fpnc != NULL ) {
        retval = true; // already running
    } else {
        HICAP_LOG_DEBUG( "%s", nc6cmd );
        _hicap_fpnc = popen( nc6cmd, "w" ); // this returns immediately
        if( _hicap_fpnc != NULL ) {
            int fd = fileno( _hicap_fpnc );
            if( fd >= 0 ) {
                int ret = fcntl( fd, F_SETFL, O_NONBLOCK );
                if( ret == 0 ) {
                    sleep(1); // waist as long as nc6 tries to connect
                    retval = true;
                } else {
                    HICAP_LOG_ERR( "cannot make pipe non-blocking: errno=%d (%s) ... will try again later", errno, strerror(errno) );
                    pclose( _hicap_fpnc );
                    _hicap_fpnc = NULL;
                }
            } else {
                HICAP_LOG_ERR( "cannot get file descriptor of pipe: errno=%d (%s) ... will try again later", errno, strerror(errno) );
                pclose( _hicap_fpnc );
                _hicap_fpnc = NULL;
            }
        } else {
            HICAP_LOG_ERR( "execuing '%s' failed currently ... will try again later", nc6cmd );
        }
    }
    return retval;
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
    HICAP_LOG_NOTICE("HICAP interface started.");
}

static void _hicap_shutdown_unlocked() {
    HICAP_LOG_DEBUG();
    char eof = EOF;
    if( _hicap_fpnc != NULL ) {
        fwrite( &eof, 1, 1, _hicap_fpnc );
        pclose( _hicap_fpnc );
    }
    _hicap_fpnc = NULL;
}

void hicap_shutdown() {
    HICAP_LOG_DEBUG();
    pthread_mutex_lock( &_hicap_mutex );
    _hicap_shutdown_unlocked();
    pthread_mutex_unlock( &_hicap_mutex );
}

static bool _hicap_can_write_unlocked() {
    HICAP_LOG_DEBUG();
    if( _hicap_fpnc != NULL ) {
        int fd = fileno( _hicap_fpnc );
        if( fd >= 0 ) {
            fd_set wfds;
            struct timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = 100000; // 100ms
            FD_ZERO(&wfds);
            FD_SET(fd, &wfds);
            int retval = select(1, NULL, &wfds, NULL, &tv);
            if( retval == 1 && FD_ISSET(fd, &wfds) ) {
                return true;
            } else {
                HICAP_LOG_ERR("can write test failed");
            }
        } else {
            HICAP_LOG_ERR("cannot obtain fd");
        }
    }
    return false;
}

static bool _hicap_write_once_unlocked( void *data, size_t dataLen ) {
    bool retval = true;
    HICAP_LOG_DEBUG("writing %zd bytes", dataLen);
    clearerr( _hicap_fpnc );
    size_t ret = fwrite( data, 1, dataLen, _hicap_fpnc );
    if( ret != dataLen ) {
        HICAP_LOG_NOTICE( "pipe write error: ret=%zd", ret );
        retval = false;
    }
    int err = feof( _hicap_fpnc );
    if( err != 0) {
        HICAP_LOG_NOTICE( "pipe is closed: err=%d", err );
        retval = false;
    }
    err = ferror( _hicap_fpnc );
    if( err != 0) {
        HICAP_LOG_NOTICE( "pipe write error: %d (%s)", err, strerror(err) );
        retval = false;
    }
    err = fflush( _hicap_fpnc );
    if( err != 0 ) {
        HICAP_LOG_NOTICE( "pipe flush error: %d (%s)", err, strerror(err) );
        retval = false;
    }
    if( retval == true ) {
        HICAP_LOG_DEBUG("writing %zd bytes succeeded", dataLen);
    }
    return retval;
}

static bool _hicap_write( void *data, size_t dataLen ) {
    bool retval = false;
    HICAP_LOG_DEBUG("writing %zd bytes", dataLen);
    if( dataLen > PIPE_BUF ) {
        HICAP_LOG_WARN("atomar write of message (len:%zd) not guaranteed (max buf size:%d)", dataLen, PIPE_BUF);
    }
    pthread_mutex_lock( &_hicap_mutex );
    if( _hicap_can_write_unlocked() && _hicap_write_once_unlocked(data, dataLen) == true) {
        retval = true;
    } else {
        HICAP_LOG_NOTICE("retrying now");
        _hicap_shutdown_unlocked();
        if( _hicap_init_unlocked() == true ) {
            if( _hicap_can_write_unlocked() && _hicap_write_once_unlocked(data, dataLen) == true) {
                retval = true;
            } else {
                HICAP_LOG_ERR("retry failed");
            }
        }
    }
    pthread_mutex_unlock( &_hicap_mutex );
    return retval;
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

static int _hicap_add_b64(json_t *jsonObj, char *keyName, void *data, uint32_t dataLen) {
    int retVal = -1;
    char *b64 = NULL;
    HICAP_LOG_DEBUG("jsonObj:%s data:%s dataLen:%u", jsonObj!=NULL?"OK":"NULL", data!=NULL?"OK":"NULL", dataLen);
    if( jsonObj != NULL ) {
        size_t b64sz = 0;
        if( data != NULL && dataLen > 0 ) {
            nsuerror nsuErr = nsu_base64_encode_alloc(data, dataLen, (uint8_t**)(&b64), &b64sz); // not null terminated
            HICAP_LOG_DEBUG("b64:%s b64sz:%zu err:%d", b64!=NULL?"OK":"NULL", b64sz, nsuErr);
            if( nsuErr != NSUERROR_OK ) {
                HICAP_LOG_ERR("base64 encode failed: err=%d", nsuErr);
                goto cleanup;
            }
        }
        retVal = _hicap_add_str_len(jsonObj, keyName, b64, b64sz);
    } else {
        HICAP_LOG_ERR("missing json obj");
    }
cleanup:
    if(b64 != NULL) {
        free(b64);
    }
    return retVal;
}

/**
 * \todo TODO maybe as thread
 */
void hicap_capture(struct mosquitto *context, char *topic, void *payload, uint32_t payloadLen) {
    json_t *jsonObj = NULL, *jsonRoot = NULL;
    char *line = NULL;
    HICAP_LOG_DEBUG();
    if( _hicap_init() == true ) {
        jsonRoot = json_object();
        jsonObj = json_object();
        if( jsonRoot!= NULL && jsonObj != NULL ) {
            int res = 0;
            res |= _hicap_add_str(jsonObj, "clientIP", context->address);
            res |= _hicap_add_int(jsonObj, "port", context->listener->port);
            res |= _hicap_add_str(jsonObj, "clientID", context->id);
            res |= _hicap_add_str(jsonObj, "topic", topic);
            res |= _hicap_add_b64(jsonObj, "payload", payload, payloadLen);
            res |= _hicap_add_kvp(jsonRoot, "mqtt", jsonObj);
            if( res == 0 ) {
                line = json_dumps(jsonRoot, 0);
                HICAP_LOG_DEBUG("line:%s\n", line!=NULL?line:"<NULL>");
                size_t len = strlen(line);
                line[len] = '\n';
                _hicap_write( line, len+1 );
                line[len] = '\0';
            }
        } else {
            HICAP_LOG_ERR("cannot create new json obj");
        }
    }

cleanup:
    if( line != NULL) {
        free(line);
        line = NULL;
    }
    if( jsonObj != NULL ) {
        json_decref(jsonObj);
        jsonObj = NULL;
    }
    if( jsonRoot != NULL ) {
        json_decref(jsonRoot);
        jsonRoot = NULL;
    }
}
