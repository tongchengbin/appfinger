# 🔍 AppFinger - 全协议指纹规则匹配库

*[English](README.md) | 英文*

全面的协议指纹规则匹配库，用于应用程序识别。

### 📚 **指纹规则库**: [finger-rules](https://github.com/tongchengbin/finger-rules) - AppFinger 使用的指纹规则库

## ⚙️ 使用方法

```
参数:
APPFINGER:
-l, -url-file string     包含要扫描的URL的文件
-u, -url string[]        要扫描的目标URL (-u 输入1 -u 输入2)
-t, -threads int         并发线程数 (默认 10)
-timeout int             超时时间（秒）(默认 10)
-x, -proxy string        使用的HTTP代理 (例如 http://127.0.0.1:7890)
-s, -stdin               从标准输入读取URL
-d, -finger-home string  指纹YAML目录主目录（默认为内置）

帮助:
-debug                   启用调试模式

输出:
-o, -output string       输出文件路径
```

## 💻 示例

```
appfinger -u https://example.com
```

## 🔌 工作原理

AppFinger 通过分析应用程序的独特指纹来扫描网络应用，提供关于所使用技术的有价值见解。

- 深度检测比较

![Deep Detection Comparison](docs/img.png)


## 👥 贡献

欢迎通过在GitHub上提出问题或提交拉取请求来为 AppFinger 做出贡献。

## 🔐 License

AppFinger is licensed under the MIT License. See the LICENSE file for details.
