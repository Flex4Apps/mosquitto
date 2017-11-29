#ifdef WITH_HICAP

    #ifndef _HICAP_H_
    #define _HICAP_H_

    #include <mosquitto_broker.h>
    #include <logging_mosq.h>

    #define _HICAP_LOG(level, fmt, args...) _mosquitto_log_printf(NULL, level, "%s:%d:%s() "fmt, __FILE__, __LINE__, __FUNCTION__ , ##args)

    #define HICAP_LOG_DEBUG( fmt, args...) _HICAP_LOG(MOSQ_LOG_DEBUG,   fmt , ##args)
    #define HICAP_LOG_INFO(  fmt, args...) _HICAP_LOG(MOSQ_LOG_INFO,    fmt , ##args)
    #define HICAP_LOG_NOTICE(fmt, args...) _HICAP_LOG(MOSQ_LOG_NOTICE,  fmt , ##args)
    #define HICAP_LOG_WARN(  fmt, args...) _HICAP_LOG(MOSQ_LOG_WARNING, fmt , ##args)
    #define HICAP_LOG_ERR(   fmt, args...) _HICAP_LOG(MOSQ_LOG_ERR,     fmt , ##args)

    extern void hicap_capture(struct mosquitto *context, char *topic, void *payload, uint32_t payloadlen);

    extern void hicap_startup();
    extern void hicap_shutdown();

    #endif // _HICAP_H_

#else // WITH_HICAP

    #error "File 'hicap.h' is included but define WITH_HICAP is not set!"

#endif // WITH_HICAP
