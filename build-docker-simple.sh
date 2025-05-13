#!/bin/bash

# 设置变量
IMAGE_NAME="hedeoer/agent"
IMAGE_TAG="1.0.0"

# 检查是否有JAR文件
if [ ! -f "target/agent-1.0.0.jar" ] && [ ! -f "target/agent-1.0.0-with-dependencies.jar" ]; then
    echo "错误: 找不到JAR文件。请先使用Maven构建项目。"
    echo "您可以在有Maven的环境中运行: mvn clean package"
    exit 1
fi

# 使用已存在的JAR文件
if [ -f "target/agent-1.0.0-with-dependencies.jar" ]; then
    JAR_FILE="target/agent-1.0.0-with-dependencies.jar"
    echo "使用包含依赖的JAR文件: $JAR_FILE"
else
    JAR_FILE="target/agent-1.0.0.jar"
    echo "使用基本JAR文件: $JAR_FILE"
fi

# 构建Docker镜像
echo "=== 构建Docker镜像 ==="
docker build -t ${IMAGE_NAME}:${IMAGE_TAG} --build-arg JAR_FILE=${JAR_FILE} .

# 检查Docker构建是否成功
if [ $? -ne 0 ]; then
    echo "Docker镜像构建失败"
    exit 1
fi

echo "=== 构建完成 ==="
echo "镜像名称: ${IMAGE_NAME}:${IMAGE_TAG}"
echo ""
echo "运行容器示例:"
echo "docker run -d --name agent -p 2222:2222 --restart unless-stopped ${IMAGE_NAME}:${IMAGE_TAG}"
