/**@file    onvif_server.c
* @note    Hangzhou Hikvision Automotive Technology Co., Ltd. All Right Reserved.
* @brief   onvif profile S Specification v1.0版本,Date Dec.2011
*
* @author  zhujinlin
* @date    2020-2-11
* @version V1.0
*
* @note History:
* @note 2020-2-11 zjl 实现两个接口，一个接口实现加入组播组，实现发现设备的功能，
一个接口监听soap报文，实现相应的操作。
*/

#include "common.h"
#include "soapH.h"

char LocalIp[64] = { 0x0 };
char LocalMac[64] = { 0x0 };

/*
* @brief 加入组播组，监听组播报文，实现设备发现功能
*/
static void * OnvifDiscovered(void *arg)
{
	struct soap UDPserverSoap = { 0x0 };
	struct ip_mreq mcast;	//组播结构体
	int m_fd = -1;
	int u_fd = -1;

	soap_init1(&UDPserverSoap, SOAP_IO_UDP | SOAP_XML_IGNORENS);
	soap_set_namespaces(&UDPserverSoap, namespaces);

	m_fd = soap_bind(&UDPserverSoap, NULL, ONVIF_UDP_PORT, 10);
	if (!soap_valid_socket(m_fd))
	{
		soap_print_fault(&UDPserverSoap, stderr);
		exit(1);
	}
	printf("mcast socket bind success, m_fd is %d\n", m_fd);

	mcast.imr_multiaddr.s_addr = inet_addr(ONVIF_UDP_IP);
	mcast.imr_interface.s_addr = htonl(INADDR_ANY);
	//IP_ADD_MEMBERSHIP用于加入某个多播组，之后就可以向这个多播组发送数据或者从多播组接收数据
	if (setsockopt(UDPserverSoap.master, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*)&mcast, sizeof(mcast)) < 0)
	{
		printf("setsockopt error! error code = %d,err string = %s\n", errno, strerror(errno));
		return 0;
	}

	while (1)
	{
		//等待客户端连接
		u_fd = soap_accept(&UDPserverSoap);
		if (!soap_valid_socket(u_fd))
		{
			soap_print_fault(&UDPserverSoap, stderr);
			exit(1);
		}

		//处理客户端发送的soap报文
		if (SOAP_OK != soap_serve(&UDPserverSoap))
		{
			soap_print_fault(&UDPserverSoap, stderr);
			printf("soap_print_fault\n");
		}

		printf("IP = %u.%u.%u.%u\n", ((UDPserverSoap.ip) >> 24) & 0xFF, ((UDPserverSoap.ip) >> 16) & 0xFF, ((UDPserverSoap.ip) >> 8) & 0xFF, (UDPserverSoap.ip) & 0xFF);
		soap_destroy(&UDPserverSoap);
		soap_end(&UDPserverSoap);

	}

	//分离运行时的环境
	soap_done(&UDPserverSoap);
	pthread_exit(0);

}

/*
* @brief 创建tcp server，监听客户端发送的soap报文，并处理
*/
static void* OnvifWebServices(void* arg)
{
	struct soap tcpsersoap = { 0x0 };
	int tcpfd = -1;
	int accept_fd = -1;

	soap_init(&tcpsersoap);
	tcpsersoap.port = 5000;
	tcpsersoap.bind_flags = SO_REUSEADDR;//socket 地址复用
	soap_set_namespaces(&tcpsersoap, namespaces);

	printf("local ip %s   ONVIF_TCP_IP is %s\n", LocalIp, ONVIF_TCP_IP);
	//tcpfd = soap_bind(&tcpsersoap, ONVIF_TCP_IP, ONVIF_TCP_PORT, 10);
	tcpfd = soap_bind(&tcpsersoap, LocalIp, ONVIF_TCP_PORT, 10);
	if (!soap_valid_socket(tcpfd))
	{
		printf("tcp serer socket bind failed!\n");
		soap_print_fault(&tcpsersoap, stderr);
		exit(1);
	}
	printf("tcp socket bind success, tcpfd is %d\n", tcpfd);

	while (1)
	{
		accept_fd = soap_accept(&tcpsersoap);
		if (!soap_valid_socket(accept_fd))
		{
			printf("tcp serer socket bind failed!\n");
			soap_print_fault(&tcpsersoap, stderr);
			exit(1);
		}
		printf("tcp server accept client connect, accept fd is %d\n", accept_fd);

		//处理客户端发送的soap报文
		if (SOAP_OK != soap_serve(&tcpsersoap))
		{
			soap_print_fault(&tcpsersoap, stderr);
			printf("soap_print_fault\n");
		}

		printf("IP = %u.%u.%u.%u\n", ((tcpsersoap.ip) >> 24) & 0xFF, ((tcpsersoap.ip) >> 16) & 0xFF,
			((tcpsersoap.ip) >> 8) & 0xFF, (tcpsersoap.ip) & 0xFF);

		soap_destroy(&tcpsersoap);
		soap_end(&tcpsersoap);
	}

	//分离运行时环境
	soap_done(&tcpsersoap);
	pthread_exit(0);

}

/*
* @brief 测试设备发现和soap报文监听接口
*/
int main(int argc, char *argv[])
{
	pthread_t udpserverthread = 0;
	pthread_t tcpserverthread = 0;
	char ip[64] = { 0x0 };
	char mac_addr[6] = { 0x0 };
	int ret = -1;

	if (argc != 2)
	{
		printf("please input ifname!\n");
		return -1;
	}

	ret = get_ip_of_if(argv[1], AF_INET, ip);
	if (0 != ret)
	{
		printf("get local interface ip failed!\n");
		return -1;
	}
	printf("ifname %s ip %s\n", argv[1], ip);
	memcpy(LocalIp, ip, strlen(ip));

	ret = get_mac_of_if(argv[1], mac_addr, 6);
	if (0 != ret)
	{
		printf("get local interface mac failed!\n");
		return -1;
	}
	ret = macaddr2str(mac_addr, LocalMac, 64);
	printf("ifname %s mac %s\n", argv[1], LocalMac);

	pthread_create(&udpserverthread, NULL, OnvifDiscovered, NULL);
	pthread_create(&tcpserverthread, NULL, OnvifWebServices, NULL);

	pthread_join(udpserverthread, 0);
	pthread_join(tcpserverthread, 0);

	return 0;
}

