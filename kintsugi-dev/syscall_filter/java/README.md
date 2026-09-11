# Java Syscall Filter

Java 系统调用过滤库，通过 JNA 与 eBPF 通信实现系统调用白名单过滤。

## 依赖

- Java 11+
- JNA 5.14.0
- Linux x86-64

## 构建

```bash
cd syscall_filter/java
mvn package
```

生成的 JAR 文件位于 `target/syscall-filter-1.0.0.jar`。

## 使用方法

### 添加依赖

```xml
<dependency>
    <groupId>com.syscallfilter</groupId>
    <artifactId>syscall-filter</artifactId>
    <version>1.0.0</version>
</dependency>
```

### 函数式 API

```java
import com.syscallfilter.SyscallFilter;
import java.util.List;
import java.util.Map;

// 启用过滤
SyscallFilter.begin(Map.of(
    "read", List.of(),                    // 无路径约束
    "write", List.of(),
    "openat", List.of("/etc/", "/tmp/")   // 路径白名单
));

// ... 受保护代码 ...

// 禁用过滤
SyscallFilter.end(Map.of(
    "read", List.of(),
    "write", List.of(),
    "openat", List.of("/etc/", "/tmp/")
));
```

### try-with-resources

```java
import com.syscallfilter.SyscallFilter;
import java.util.List;
import java.util.Map;

try (var filter = new SyscallFilter(Map.of(
    "execve", List.of("/usr/bin/java"),
    "openat", List.of("/tmp/", "/etc/")
))) {
    // 受保护代码
    // 退出时自动关闭过滤
}
```

## API 说明

### SyscallFilter.begin(rules)

启用系统调用过滤。

- **参数**: `Map<String, List<String>>` - 系统调用名称到路径白名单的映射
- **返回**: `boolean` - 是否成功

### SyscallFilter.end(rules)

禁用系统调用过滤。

- **参数**: `Map<String, List<String>>` - 与 begin 相同的规则（用于精确删除）
- **返回**: `boolean` - 是否成功

### 规则格式

```java
Map.of(
    "syscall_name", List.of(),           // 无路径约束，允许所有路径
    "syscall_name", List.of("/path1/", "/path2/")  // 路径白名单
)
```

## 支持的系统调用

包含 Linux x86-64 的所有系统调用（基于内核 5.15），常用的包括：

| 类别 | 系统调用 |
|------|---------|
| 文件 I/O | read, write, open, close, openat |
| 进程 | fork, vfork, clone, execve, exit |
| 网络 | socket, connect, accept, bind |
| 目录 | mkdir, rmdir, unlink, rename |

完整列表见 `SyscallTable.java`。

## 原理

1. Java 通过 JNA 调用 `prctl` 系统调用
2. 数据包通过 `prctl(45, &packet, 0, 0, 0)` 发送到内核
3. eBPF 程序拦截 prctl 调用，解析数据包并更新白名单
4. 后续的系统调用会被 eBPF 检查是否在白名单中

## 前置条件

运行前需要先启动 eBPF 加载器：

```bash
cd syscall_filter
sudo python ebpf_load.py
```

## 测试

```bash
mvn test
```

注意：部分测试需要 eBPF 加载器运行才能通过。

## 文件结构

```
java/
├── source/
│   └── com/syscallfilter/
│       ├── SyscallFilter.java       # 主 API 类
│       ├── SyscallFilterPacket.java # 数据包结构
│       ├── SyscallTable.java        # 系统调用映射表
│       └── FnvHash.java             # FNV-1a 哈希
├── test/
│   └── com/syscallfilter/
│       ├── BasicTest.java
│       └── PathFilterTest.java
├── pom.xml
└── README.md
```
