# ipt2socks(libev)

类似 [redsocks](https://github.com/darkk/redsocks)、[redsocks2](https://github.com/semigodking/redsocks) 的实用工具，将 iptables/nftables (REDIRECT/TPROXY) 传入的流量转为 socks5(tcp/udp) 流量，除此之外不提供任何不必要的功能。

用例 1：配合透明代理使用（如 [ss-tproxy](https://github.com/zfl9/ss-tproxy)），为那些只支持 socks5 传入协议的“代理进程”提供 **iptables/nftables 透明代理** 传入协议的支持，比如 ss/ssr 的 ss-local/ssr-local、v2ray 的 socks5 传入协议、trojan 的 socks5 客户端等等。

用例 2：将透明代理主机上的“代理进程”分离出来，因为“代理”通常涉及加解密等耗性能的操作，如果透明代理主机性能比较弱，最好将“代理进程”放到另外一个性能更强的局域网主机去运行（提供 socks5 传入），然后在透明代理主机上运行 ipt2socks 来对接这个“代理”。ipt2socks 在设计和编码上特意考虑了性能，尽可能实现零拷贝，降低开销。

## 简要说明

- 使用 splice() 系统调用，理想情况下可实现零拷贝。
- IPv4 和 IPv6 双栈支持，支持 **纯 TPROXY** 透明代理模式。
- TCP 透明代理提供 REDIRECT、TPROXY 两种方式，UDP 透明代理为 TPROXY 方式。
- UDP 透明代理支持 Full Cone NAT，前提是后端的 socks5 服务器支持 Full Cone NAT。
- 多线程 + SO_REUSEPORT 端口重用，每个线程运行各自独立的事件循环，性能提升显著。

## 如何编译

> 为了方便使用，[releases](https://github.com/zfl9/ipt2socks/releases) 页面发布了 linux 下常见架构的 musl 静态链接二进制。

```bash
git clone https://github.com/zfl9/ipt2socks
cd ipt2socks
make && sudo make install
```

ipt2socks 默认安装到 `/usr/local/bin/ipt2socks`，可安装到其它目录，如 `make install DESTDIR=/opt/local/bin`。

交叉编译时只需指定 CC 变量，如 `make CC=aarch64-linux-gnu-gcc`（若报错或异常，请执行 `make clean`，再试）。

## 如何运行

```bash
# -s 指定 socks5 服务器 ip
# -p 指定 socks5 服务器端口
ipt2socks -s 127.0.0.1 -p 1080

# 如果想后台运行，可以这样启动：
(ipt2socks -s 127.0.0.1 -p 1080 </dev/null &>>/var/log/ipt2socks.log &)
```

ipt2socks 启动后，配置相应 iptables/nftables 规则即可，关于 iptables 规则，可以看看：

- https://github.com/zfl9/ss-tproxy
- https://gist.github.com/zfl9/d52482118f38ce2c16195583dffc44d2

## 全部参数

```bash
$ ipt2socks --help
usage: ipt2socks <options...>. the existing options are as follows:
 -s, --server-addr <addr>           socks5 server ip, default: 127.0.0.1
 -p, --server-port <port>           socks5 server port, default: 1080
 -a, --auth-username <user>         username for socks5 authentication
 -k, --auth-password <passwd>       password for socks5 authentication
 -b, --listen-addr4 <addr>          listen ipv4 address, default: 127.0.0.1
 -B, --listen-addr6 <addr>          listen ipv6 address, default: ::1
 -l, --listen-port <port>           listen port number, default: 60080
 -S, --tcp-syncnt <cnt>             change the number of tcp syn retransmits
 -c, --cache-size <size>            udp context cache maxsize, default: 256
 -o, --udp-timeout <sec>            udp context idle timeout, default: 60
 -j, --thread-nums <num>            number of the worker threads, default: 1
 -n, --nofile-limit <num>           set nofile limit, may need root privilege
 -u, --run-user <user>              run as the given user, need root privilege
 -T, --tcp-only                     listen tcp only, aka: disable udp proxy
 -U, --udp-only                     listen udp only, aka: disable tcp proxy
 -4, --ipv4-only                    listen ipv4 only, aka: disable ipv6 proxy
 -6, --ipv6-only                    listen ipv6 only, aka: disable ipv4 proxy
 -R, --redirect                     use redirect instead of tproxy for tcp
 -r, --reuse-port                   enable so_reuseport for single thread
 -w, --tfo-accept                   enable tcp_fastopen for server socket
 -W, --tfo-connect                  enable tcp_fastopen for client socket
 -v, --verbose                      print verbose log, affect performance
 -V, --version                      print ipt2socks version number and exit
 -h, --help                         print ipt2socks help information and exit
```

- `-s`选项：socks5 服务器的 IP 地址，默认为 127.0.0.1。
- `-p`选项：socks5 服务器的监听端口，默认为 1080。
- `-a`选项：socks5 代理认证的用户（若需要认证）。
- `-k`选项：socks5 代理认证的密码（若需要认证）。
- `-b`选项：本地 IPv4 监听地址，默认为 127.0.0.1。
- `-B`选项：本地 IPv6 监听地址，默认为 ::1。
- `-l`选项：本地 IPv4/6 监听端口，默认为 60080。
- `-S`选项：与 socks5 服务器建立 TCP 连接的超时参数。
- `-c`选项：UDP 上下文的最大数量，默认为 256 个。
- `-o`选项：UDP 上下文的超时时间，默认为 60 秒。
- `-j`选项：需要启动的工作线程数量，默认为单个线程。
- `-n`选项：设置 ipt2socks 进程可打开的文件描述符限制。
- `-u`选项：即 run-as-user 功能，需要 root 权限才能生效。
- `-T`选项：仅启用 TCP 透明代理，也即关闭 UDP 透明代理。
- `-U`选项：仅启用 UDP 透明代理，也即关闭 TCP 透明代理。
- `-4`选项：仅启用 IPv4 透明代理，也即关闭 IPv6 透明代理。
- `-6`选项：仅启用 IPv6 透明代理，也即关闭 IPv4 透明代理。
- `-R`选项：使用 REDIRECT(DNAT) 而非 TPROXY（针对 TCP）。
- `-r`选项：若指定，则即使是单线程模式，也设置端口重用。
- `-w`选项：启用服务端的 TCP_Fast_Open（应设好内核参数）。
- `-W`选项：启用客户端的 TCP_Fast_Open（应设好内核参数）。
- `-v`选项：若指定此选项，则将会打印较为详尽的运行时日志。

## 以普通用户运行

- `sudo setcap cap_net_bind_service,cap_net_admin+ep /usr/local/bin/ipt2socks`
- 如果以 root 用户启动 ipt2socks，也可以指定 `-u nobody` 选项切换至 `nobody` 用户

## nofile limit

由于透明代理需要消耗较多文件描述符，为确保最佳体验，请务必留意 ipt2socks 的 nofile limit（可同时打开的文件描述符数量），默认的 nofile limit 非常小，对于透明代理场景基本是不够用的。

从 v1.1.4 版本开始，ipt2socks 启动时将打印进程的 nofile limit 信息，请确保这个值至少在 10000 以上（很多系统默认是 1024），你可以选择使用 `-n` 选项调整此限制（需要 CAP_SYS_RESOURCE 权限），也可以使用其他方式，如 systemd service 文件的 `LimitNOFILE`、`/etc/security/limits.conf` 配置文件。
