package main

import (
	"fmt"
	"net"
)

func main() {
	// 监听本机所有网卡的 8888 端口
	addr, err := net.ResolveUDPAddr("udp", ":8888")
	if err != nil {
		panic(err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	fmt.Println("UDP server listening on", addr.String())

	buf := make([]byte, 65535)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("read error:", err)
			continue
		}
		fmt.Printf("recv from %s: %q\n", remoteAddr.String(), string(buf[:n]))
	}
}