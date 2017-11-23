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
}

/**
 * \todo TODO call shutdown
 */
static void _hicap_shutdown() {
    HICAP_LOG_DEBUG();
    char eof = EOF;
    fwrite( &eof, 1, 1, _fpnc );
    pclose( _fpnc );
}

void hicap_capture(struct mosquitto *context, char * str) {
    HICAP_LOG_DEBUG();
    _hicap_init();
    unsigned char *b64 = NULL;
    size_t b64sz = 0;
    nsuerror err = nsu_base64_encode_alloc(str, strlen(str), &b64, &b64sz);
    HICAP_LOG_DEBUG();
    if( err != NSUERROR_OK ) {
        HICAP_LOG_ERR("b64 encode failed");
    }
    json_t *json = json_pack("{ss}", "value", b64);
    HICAP_LOG_DEBUG();
    char *line = json_dumps(json, 0);
    HICAP_LOG_DEBUG("line:%s\n", line!=NULL?line:"<NULL>");
    size_t len = strlen(line);
    line[len] = '\n';
    HICAP_LOG_DEBUG();
    fwrite( line, len+1, 1, _fpnc ); // TODO replace \0 with \n
    HICAP_LOG_DEBUG();
    free(line);
    HICAP_LOG_DEBUG();
    free(b64);
    HICAP_LOG_DEBUG();
    json_decref(json);
    HICAP_LOG_DEBUG();
    json = NULL;
    //fwrite( "\n", 1, 1, _fpnc );
    fflush( _fpnc );
    // TODO im logstash json verarbeiten
}
