package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

func main() {
	// 设置路由规则
	http.HandleFunc("/", handler)

	// 指定服务器监听的端口
	port := ":8080"

	// 启动服务器并监听指定端口
	fmt.Printf("Server is running on port %s\n", port)
	err := http.ListenAndServe(port, nil)
	if err != nil {
		fmt.Printf("Failed to start server: %s\n", err)
	}
}

func handler(w http.ResponseWriter, r *http.Request) {
	// 打印收到的请求信息
	// 返回3MB的内容
	const contentSize = 3 * 1024 * 1024 // 3MB
	content := strings.Repeat("a", contentSize)

	// 将内容写入响应
	_, err := io.WriteString(w, content)
	if err != nil {
		fmt.Printf("Failed to write response: %s\n", err)
	}
	// 在这里处理请求并给出响应
	// 此处示例简单地给出一个 "Hello, World!" 的响应
}
