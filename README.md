# Mosquitto with HICAP interface

The modified mosquitto broker includes the HICAP interface (HiConnect Capture interface).

It allows to capture all incoming publish messages and their connection metadata, such as SSL client certificate identification.

The collected information is sent over TCP/IP JSON to a remote logstash service.

See also https://github.com/Flex4Apps/mosquitto/wiki.

## General Usage

The destination host/IP and port of the listening logstash service or netcat can be given to the mosquitto commandline:

```
$ /usr/bin/env HICAP_HOST=10.10.10.201 HICAP_PORT=5555 /mosquitto/mosquitto -c /mosquitto/mosquitto.conf
```

A netcat listener can be used instead of logstash for testing purposes:

```
$ nc -l -p 5555
...
{"mqtt": {"topic": "topic", "clientIP": "172.17.0.1", "port": 1883, "clientID": "mosqpub|5704-t550", "tsUTC": "2018-05-29T09:30:00Z (GMT)", "tsLocal": "2018-05-29T09:30:00+0000 (UTC)", "payload": "bXNn"}}
...
```

## Usage with Docker

```
git clone https://github.com/Flex4Apps/mosquitto
cd mosquitto
docker build -t hiconnect:mqtt-hicap .
docker create --name mqtt-bin -i -t -e HICAP_HOST=10.10.10.201 -e HICAP_PORT=12345 hiconnect:mqtt-hicap
docker start -a -i mqtt-bin
```

## Configuring Logstash

Edit Logstash config file (e.g. /etc/logstash/conf.d/tcp-json.cfg):

```
input {
  tcp {
    mode => "server"
    host => "10.10.10.201" # address to listen on
    port => 12345          # port to listen on
    codec => "json"
  }
}

filter {
  mutate {
    update => { "host" => "%{[mqtt][clientIP]}" }
    update => { "port" => "%{[mqtt][port]}" }
    copy => { "[mqtt][payload]" => "mqtt-payload" }
  }
}

#output {
#  file {
#    path => "/tmp/mylogstash.log"
#    #codec => "json"
#  }
#}
```
