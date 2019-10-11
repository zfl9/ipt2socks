# ipt2socks

## 如何编译
```bash
git clone https://github.com/zfl9/ipt2socks
cd ipt2socks
make && sudo make install
```

```bash
# 进入某个目录
cd /opt

# 获取 libuv 源码包
libuv_version="1.31.0"
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
