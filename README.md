# Agent 项目

Agent 是一个基于Java的系统防火墙工具，提供SSH服务、防火墙管理、端口监控等功能。

## 功能特性

- SSH服务：提供SSH访问功能，支持公钥认证
- 防火墙管理：支持检测和管理系统防火墙（UFW和Firewalld）
- 端口监控：监控系统端口使用情况
- Redis集成：使用Redis进行数据存储和消息传递
- 系统信息收集：收集主机信息并定期上报

## 系统要求

- Java 11 或更高版本
- Redis 服务器（用于数据存储和消息传递）
- Linux系统（支持UFW或Firewalld防火墙）

## 快速开始

### 手动构建和运行

1. 使用Maven构建项目：

   ```bash
   mvn clean package
   ```

2. 运行生成的JAR文件：

   ```bash
   java -jar target/agent-1.0.0-with-dependencies.jar
   ```

## 配置

### 配置文件

应用程序使用`application.yaml`进行配置，主要包括：

#### SSH配置

```yaml
ssh:
  ssh_server_port: 2222
  ssh_public_key: "your-public-key"
```

#### Redis配置

```yaml
redis:
  host: "your-redis-host"
  port: 6379
  timeout: 120000
  password: "your-redis-password"
  database: 0
  ssl: true
  pool:
    maxTotal: 100
    maxIdle: 20
    minIdle: 5
    maxWaitMillis: 5000
    testOnBorrow: true
```

## 项目结构

```
agent/
├── src/
│   └── main/
│       ├── java/
│       │   └── cn/
│       │       └── hedeoer/
│       │           ├── Main.java                 # 主程序入口
│       │           ├── schedule/                 # 定时任务
│       │           ├── ssh/                      # SSH服务相关
│       │           ├── subscribe/                # 消息订阅
│       │           └── util/                     # 工具类
│       └── resources/
│           ├── application.yaml                  # 应用配置
│           └── logback.xml                       # 日志配置
└── pom.xml                                       # Maven项目配置
```

## 开发指南

### 依赖管理

项目使用Maven管理依赖，主要依赖包括：

- **snakeyaml**: YAML配置解析
- **sshd-core**: SSH服务实现
- **jedis**: Redis客户端
- **jackson-databind**: JSON处理
- **zt-exec**: Shell命令执行
- **oshi-core**: 系统信息获取
- **logback-classic**: 日志实现

### 构建项目

```bash
# 构建基本JAR
mvn clean package

# 构建包含所有依赖的JAR
mvn clean package assembly:single
```

## 日志

应用程序使用Logback进行日志记录，日志文件存储在`${user.home}/logs/`目录下：

- `application.log`: 所有日志
- `application-error.log`: 仅错误日志

## 故障排除

### 常见问题

1. **SSH连接失败**
   - 检查SSH端口是否正确配置
   - 确认SSH公钥是否正确配置

2. **Redis连接问题**
   - 检查Redis服务器地址和凭据
   - 确认Redis SSL配置是否正确

3. **权限问题**
   - 确保应用程序有足够的权限执行系统操作
   - 检查防火墙配置是否允许必要的连接

### 日志检查

查看应用日志：

```bash
tail -f ~/logs/application.log
```

## 许可证

[GNU GENERAL PUBLIC LICENSE Version 3](LICENSE)

## 贡献指南

欢迎贡献代码、报告问题或提出改进建议。请遵循以下步骤：

1. Fork 本仓库
2. 创建您的特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交您的更改 (`git commit -m 'Add some amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 开启一个 Pull Request

## 联系方式

项目维护者：[Hedeoer](mailto:hedeoer@linux.do)

---

