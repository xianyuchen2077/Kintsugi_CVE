sudo apt update
sudo apt install python3-bpfcc bpfcc-tools linux-headers-$(uname -r)
sudo apt install -y libbpf-dev gcc make

# 验证安装
dpkg -l | grep libbpf

# 查看系统调用号
cat /usr/include/x86_64-linux-gnu/asm/unistd_64.h
