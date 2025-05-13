FROM eclipse-temurin:11-jre

# 设置工作目录
WORKDIR /app

# 设置环境变量
ENV RUNNING_IN_DOCKER=true
ENV SSH_SERVER_PORT=2222
ENV SSH_PUBLIC_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFnqcDG0yPisMvC9ehfSkzzrHa80n7YPAe6xv3bQMiDC H@DESKTOP-1AO4P84"

# 添加JAR文件参数
ARG JAR_FILE

# 复制JAR文件到容器
COPY ${JAR_FILE} /app/agent.jar

# 创建日志目录
RUN mkdir -p /root/logs

# 暴露SSH端口
EXPOSE 2222

# 启动应用
CMD ["java", "-jar", "/app/agent.jar"]
