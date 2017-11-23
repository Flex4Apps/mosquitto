#ifndef _HICAP_H_
#define _HICAP_H_

#include <mosquitto.h>

#define _HICAP_LOG(level, fmt, args...) _mosquitto_log_printf(NULL, level, "%s:%d:%s() "fmt, __FILE__, __LINE__, __FUNCTION__ , ##args)

#define HICAP_LOG_DEBUG( fmt, args...) _HICAP_LOG(MOSQ_LOG_DEBUG,   fmt , ##args)
#define HICAP_LOG_INFO(  fmt, args...) _HICAP_LOG(MOSQ_LOG_INFO,    fmt , ##args)
#define HICAP_LOG_NOTICE(fmt, args...) _HICAP_LOG(MOSQ_LOG_NOTICE,  fmt , ##args)
#define HICAP_LOG_WARN(  fmt, args...) _HICAP_LOG(MOSQ_LOG_WARNING, fmt , ##args)
#define HICAP_LOG_ERR(   fmt, args...) _HICAP_LOG(MOSQ_LOG_ERR,     fmt , ##args)

extern void hicap_capture(struct mosquitto *context, char * str);

#endif // _HICAP_H_
