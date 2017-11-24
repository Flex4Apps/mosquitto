#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <mosquitto.h>
#include <logging_mosq.h>
#include <memory_mosq.h>
#include <messages_mosq.h>
#include <mqtt3_protocol.h>
#include <net_mosq.h>
#include <read_handle.h>
#include <send_mosq.h>
#include <time_mosq.h>
#include <util_mosq.h>

#include <pthread.h>

#include <nsutils/base64.h>
#include <jansson.h>

#include "hicap.h"

static pthread_once_t _hicap_init_once_control = PTHREAD_ONCE_INIT;

static FILE *_fpnc = NULL; //!< File pointer reference to netcat process.

static void _hicap_init_once() {
    HICAP_LOG_DEBUG();
    _fpnc = popen( "nc6 -vv -n --send-only 127.0.0.1 12345", "w" );
}

static void _hicap_init() {
    //HICAP_LOG_DEBUG();
    int res = pthread_once( &_hicap_init_once_control, &_hicap_init_once);
    if( res != 0 ) {
        HICAP_LOG_ERR("init failed");
    }
}

void hicap_shutdown() {
    HICAP_LOG_DEBUG();
    char eof = EOF;
    fwrite( &eof, 1, 1, _fpnc );
    pclose( _fpnc );
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

static int _hicap_add_payload(json_t *jsonObj, void *payload, uint32_t payloadLen) {
    int retVal = -1;
    char *b64 = NULL;
    HICAP_LOG_DEBUG("jsonObj:%s payload:%s payloadLen:%u", jsonObj!=NULL?"OK":"NULL", payload!=NULL?"OK":"NULL", payloadLen);
    if( jsonObj != NULL ) {
        size_t b64sz = 0;
        if( payload != NULL && payloadLen > 0 ) {
            nsuerror nsuErr = nsu_base64_encode_alloc(payload, payloadLen, (uint8_t**)(&b64), &b64sz); // not null terminated
            HICAP_LOG_DEBUG("b64:%s b64sz:%zu err:%d", b64!=NULL?"OK":"NULL", b64sz, nsuErr);
            if( nsuErr != NSUERROR_OK ) {
                HICAP_LOG_ERR("base64 encode failed: err=%d", nsuErr);
                goto cleanup;
            }
        }
        retVal = _hicap_add_str_len(jsonObj, "mqttPayload", b64, b64sz);
    } else {
        HICAP_LOG_ERR("missing json obj");
    }
cleanup:
    if(b64 != NULL) {
        free(b64);
    }
    return retVal;
}

void hicap_capture(struct mosquitto *context, char *topic, void *payload, uint32_t payloadLen) {
    json_t *jsonObj = NULL;
    char *line = NULL;
    HICAP_LOG_DEBUG();
    _hicap_init();
    jsonObj = json_object();
    if( jsonObj != NULL ) {
        int res = 0;
        res |= _hicap_add_payload(jsonObj, payload, payloadLen);
        res |= _hicap_add_str(jsonObj, "mqttClientIP", context->address);
        res |= _hicap_add_int(jsonObj, "mqttPort", context->listener->port);
        res |= _hicap_add_str(jsonObj, "mqttClientID", context->id);
        res |= _hicap_add_str(jsonObj, "mqttTopic", topic);
        if( res == 0 ) {
            line = json_dumps(jsonObj, 0);
            HICAP_LOG_DEBUG("line:%s\n", line!=NULL?line:"<NULL>");
            size_t len = strlen(line);
            line[len] = '\n';
            HICAP_LOG_DEBUG();
            fwrite( line, len+1, 1, _fpnc );
            line[len] = '\0';
            HICAP_LOG_DEBUG();
            // TODO im logstash json verarbeiten
            fflush( _fpnc );
        }
    } else {
        HICAP_LOG_ERR("cannot create new json obj");
    }

cleanup:
    if( line != NULL) {
        free(line);
    }
    if( jsonObj != NULL ) {
        json_decref(jsonObj);
    }
}
