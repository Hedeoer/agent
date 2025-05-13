#!/bin/bash

# 使用Maven插件构建Docker镜像
echo "=== 使用Maven构建Docker镜像 ==="
mvn clean package dockerfile:build

# 检查构建是否成功
if [ $? -ne 0 ]; then
    echo "Docker镜像构建失败"
    exit 1
fi

echo "=== 构建完成 ==="
echo "镜像名称: hedeoer/agent:1.0.0"
echo ""
echo "运行容器示例:"
echo "docker run -d --name agent -p 2222:2222 --restart unless-stopped hedeoer/agent:1.0.0"
