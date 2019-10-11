# ipt2socks
类似 [redsocks](https://github.com/darkk/redsocks)/[redsocks2](https://github.com/semigodking/redsocks) 的实用工具，用于将 iptables(REDIRECT/TPROXY) 流量转换为 socks5(tcp/udp) 流量。除此之外，ipt2socks 不提供任何非必要的功能（即：KISS 原则，`keep it simple, stupid`，保持简单和愚蠢）。ipt2socks 可以为仅支持 socks5 传入协议的“本地代理”提供 **iptables 透明代理** 传入协议的支持，比如 ss/ssr 的 ss-local/ssr-local、v2ray 的 socks5 传入协议、trojan 的 socks5 客户端等等。

## 相关特性
// TODO

## 如何编译
**动态链接 libuv**：适用于本地编译，使用包管理器安装 [libuv](https://github.com/libuv/libuv) 依赖库即可（如 `yum install libuv-devel`）：
```bash
git clone https://github.com/zfl9/ipt2socks
cd ipt2socks
make && sudo make install
```
ipt2socks 默认安装到 `/usr/local/bin/ipt2socks`，可安装到其它目录，如 `make install DESTDIR=/opt/local/bin`。

**静态链接 libuv**：适用于交叉编译，此方式编译出来的 `ipt2socks` 不依赖任何第三方库，可直接拷贝到目标系统运行：
```bash
# 进入某个目录
cd /opt

# 获取 libuv 源码包
libuv_version="1.32.0" # 定义 libuv 版本号
wget https://github.com/libuv/libuv/archive/v$libuv_version.tar.gz -Olibuv-$libuv_version.tar.gz
tar xvf libuv-$libuv_version.tar.gz

# 进入源码目录，编译
cd libuv-$libuv_version
./autogen.sh
./configure --prefix=/opt/libuv --enable-shared=no --enable-static=yes CC="gcc -O3"
make && sudo make install
cd ..

# 获取 ipt2socks 源码
git clone https://github.com/zfl9/ipt2socks

# 进入源码目录，编译
cd ipt2socks
make INCLUDES="-I/opt/libuv/include" LDFLAGS="-L/opt/libuv/lib" && sudo make install
```
