package utils

import (
	"net"
	"os"
)

var globalPort string

func GetLocalIPs() []string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	var ips []string
	for _, iface := range interfaces {
		// 跳过禁用的接口
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		// 获取接口的所有地址
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				// 排除回环地址和 IPv6 地址
				if !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
					ips = append(ips, ipnet.IP.String())
				}
			}
		}
	}
	return ips
}

func SetGlobalPort(port string) {
	globalPort = port
}

func GetGlobalPort() string {
	return globalPort
}

// 获取服务地址
func GetServiceAddress() string {
	// 优先从环境变量获取宿主机IP（适用于k8s和docker部署）
	if hostIP := os.Getenv("HOST_IP"); hostIP != "" {
		return hostIP
	}

	// 二进制部署：使用本地IP
	ips := GetLocalIPs()
	if len(ips) > 0 {
		return ips[0]
	}
	return "localhost"
}
