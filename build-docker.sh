#!/bin/bash

# 设置变量
IMAGE_NAME="hedeoer/agent"
IMAGE_TAG="1.0.0"

# 清理并构建Maven项目
echo "=== 构建Maven项目 ==="
mvn clean package

# 检查Maven构建是否成功
if [ $? -ne 0 ]; then
    echo "Maven构建失败，退出构建过程"
    exit 1
fi

# 构建Docker镜像
echo "=== 构建Docker镜像 ==="
docker build -t ${IMAGE_NAME}:${IMAGE_TAG} .

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
