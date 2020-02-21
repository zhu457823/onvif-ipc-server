#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

//PORT
#define ONVIF_UDP_PORT 3702
#define ONVIF_TCP_PORT 5000

//IP
#define ONVIF_UDP_IP "239.255.255.250"
#define ONVIF_TCP_IP "192.168.189.129"

//获取接口IP地址
int get_ip_of_if(const char *if_name, int af, char *IP);


