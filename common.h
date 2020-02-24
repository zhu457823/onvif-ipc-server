#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

//PORT
#define ONVIF_UDP_PORT 3702
#define ONVIF_TCP_PORT 5000

//IP
#define ONVIF_UDP_IP "239.255.255.250"
#define ONVIF_TCP_IP "192.168.254.129"

/*
* @brief 获取设备的IP地址，可以获取ipv4或者ipv6地址
*/
int get_ip_of_if(const char *if_name, int af, char *IP);

/*
* @brief 获取设备制定接口的mac地址
*/
int get_mac_of_if(const char *if_name, char *mac_addr, int mac_len);

/*
* @brief 将mac地址转换为字符串形式
*/
int macaddr2str(char *mac_addr, char *mac_str, int mac_len);


