#!/bin/bash

# 脚本：安装并启动 Java Agent 程序
# 功能：
# 0. 检查 Java 版本 (>= 11)
# 1. 检查免密 sudo 权限
# 2. 从 GitHub Releases 获取最新的 agent jar 下载链接 (Token via -k argument)
# 3. 下载 jar 文件到 ~/agent/ 目录 (使用固定名称并清理旧版本)
# 4. 使用 nohup 启动 jar 文件并检查状态 (同时设置 ssh_public_key 环境变量)

# --- 配置区 ---
REPO_OWNER="Hedeoer"
REPO_NAME="agent"
AGENT_INSTALL_DIR="$HOME/agent" # Agent 安装目录
JAR_NAME_PREFIX="agent"         # 在 GitHub assets 中查找的 jar 文件名前缀
FIXED_JAR_NAME="agent-latest.jar" # 下载到本地时使用的固定 JAR 文件名

# Shell 脚本的启动日志文件 (捕获 nohup 输出和 JVM 早期错误)
SCRIPT_STARTUP_LOG_FILE="$AGENT_INSTALL_DIR/agent_script_startup.log"
PID_FILE="$AGENT_INSTALL_DIR/agent.pid"

# Java 应用通过 Logback 配置的日志文件路径 (基于用户提供的 Logback 配置)
APP_LOG_BASE_DIR="$AGENT_INSTALL_DIR/logs"
APP_MAIN_LOG_FILE="$APP_LOG_BASE_DIR/logs.log"
APP_ERROR_LOG_FILE="$APP_LOG_BASE_DIR/logs-error.log"

# Script-level variables to hold CLI arguments
CLI_GITHUB_TOKEN=""
CLI_SSH_PUBLIC_KEY="" # 用于存储master节点的 SSH 公钥
SSH_SERVER_PORT="" # ssh服务器的绑定的进程端口号

# --- 函数定义 ---

# 函数：记录信息
log_info() {
    echo "[INFO] $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

# 函数：记录警告
log_warn() {
    echo "[WARN] $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

# 函数：记录错误并退出
log_error_exit() {
    echo "[ERROR] $(date '+%Y-%m-%d %H:%M:%S') - $1" >&2
    exit 1
}

# 函数：显示用法
usage() {
    echo "用法: $0 -k <github_token> -s <ssh_public_key>"
    echo "选项:"
    echo "  -k <token>         GitHub Personal Access Token，用于下载 agent (必需)"
    echo "  -s <ssh_public_key>   Master节点的SSH 公钥字符串 (必需), 将作为环境变量 SSH_PUBLIC_KEY 传递给 Java 应用"
    echo "  -p <ssh_server_port>   agent节点启动apache mina ssh服务时绑定的端口号(必需), 将作为环境变量 SSH_SERVER_PORT 传递给 Java 应用"
    echo "  -h                 显示此帮助信息"
    exit 1
}

# 函数：检查依赖命令是否存在
check_dependencies() {
    log_info "开始检查依赖工具..."
    local missing_deps=0
    for cmd in curl jq java wget find; do
        if ! command -v "$cmd" &> /dev/null; then
            log_warn "依赖工具 '$cmd' 未安装。"
            missing_deps=$((missing_deps + 1))
        fi
    done

    if [ "$missing_deps" -gt 0 ]; then
        log_error_exit "请先安装缺失的依赖工具 (curl, jq, java, wget, find) 后再运行脚本。"
    else
        log_info "所有依赖工具均已安装。"
    fi
}


# 0. 检查 Java 版本
check_java_version() {
    log_info "开始检查 Java 环境..."
    if ! command -v java &> /dev/null; then
        log_error_exit "未找到 Java 环境。请先安装 Java 11 或更高版本。"
    fi

    java_version_output=$(java -version 2>&1)
    if [[ $java_version_output =~ version\ \"(1\.)?([0-9]+) ]]; then
        current_major_version=${BASH_REMATCH[2]}
        if [ "$current_major_version" -lt 11 ]; then
            log_error_exit "Java 版本过低。需要 Java 11 或更高版本，当前版本的主版本号为: $current_major_version。完整版本信息如下：\n$java_version_output"
        else
            log_info "检测到 Java 版本符合要求 (主版本: $current_major_version)。完整版本信息如下：\n$java_version_output"
        fi
    else
        log_error_exit "无法解析 Java 版本信息。请确保 Java 已正确安装并配置。Java -version 输出：\n$java_version_output"
    fi
}

# 1. 检查免密 sudo 权限
check_sudo_privileges() {
    log_info "开始检查免密管理员权限..."
    if sudo -n true 2>/dev/null; then
        log_info "当前用户拥有免密 sudo 权限。"
    else
        log_error_exit "当前用户没有免密 sudo 权限。请配置免密 sudo 或使用具有免密 sudo 权限的用户执行此脚本。"
    fi
}

# 函数：获取 GitHub Token (now uses CLI_GITHUB_TOKEN)
get_github_token() {
    if [ -z "${CLI_GITHUB_TOKEN}" ]; then # Check the script-level variable
        log_error_exit "错误：GitHub Token 未通过 -k 参数提供。\n请使用 -k <your_github_pat_here> 提供 Token。"
    fi
    echo "${CLI_GITHUB_TOKEN}"
}

# 2. 获取 GitHub Release 的 Jar 下载链接
get_jar_download_url() {
    local current_github_token
    current_github_token=$(get_github_token) # This will now use the token from -k

    log_info "正在从 GitHub 获取 '${REPO_OWNER}/${REPO_NAME}' 的最新 release 信息..." >&2
    local api_url="https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/latest"
    local response
    response=$(curl -s -L \
      -H "Accept: application/vnd.github+json" \
      -H "Authorization: Bearer ${current_github_token}" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      --fail \
      "${api_url}")
    local curl_exit_code=$?
    if [ $curl_exit_code -ne 0 ]; then
        log_error_exit "获取 GitHub Release 信息失败。Curl 退出码: $curl_exit_code。请检查网络连接、仓库名称、Token (-k) 是否正确且有效。API URL: $api_url"
    fi
    if [ -z "$response" ]; then
        log_error_exit "获取 GitHub Release 信息失败，响应为空。"
    fi

    local download_url
    download_url=$(echo "$response" | jq -r --arg prefix "$JAR_NAME_PREFIX" '.assets[] | select(.name | startswith($prefix) and endswith(".jar")) | .browser_download_url' | head -n 1)

    if [ -z "$download_url" ] || [ "$download_url" == "null" ]; then
        log_error_exit "在最新的 release 中未找到名为 '${JAR_NAME_PREFIX}*.jar' 的资源文件。API响应(部分内容):\n$(echo "$response" | head -n 20)"
    fi

    log_info "成功获取到 Jar 下载链接: $download_url" >&2
    echo "$download_url"
}

# 3. 下载 Jar 文件
download_jar_file() {
    local jar_url="$1"
    local target_path="$AGENT_INSTALL_DIR/$FIXED_JAR_NAME"

    log_info "准备下载 Jar 文件 (从 $jar_url) 到: $target_path" >&2
    log_info "开始下载 '$FIXED_JAR_NAME' (源: $(basename "$jar_url")) ..." >&2

    if wget --timeout=600 -q -O "$target_path" "$jar_url"; then
        log_info "Jar 文件 '$FIXED_JAR_NAME' 下载成功，保存路径: $target_path" >&2
        log_info "开始清理目录 '$AGENT_INSTALL_DIR' 中其他匹配 '${JAR_NAME_PREFIX}*.jar' 的旧 Agent JAR 文件 (保留 '$FIXED_JAR_NAME')..." >&2
        find "$AGENT_INSTALL_DIR" -maxdepth 1 -type f -name "${JAR_NAME_PREFIX}*.jar" -not -name "$FIXED_JAR_NAME" -delete
        log_info "旧 Agent JAR 文件清理完成。" >&2
        echo "$target_path"
    else
        log_error_exit "下载 Jar 文件 '$FIXED_JAR_NAME' 失败。请检查下载链接和网络。"
    fi
}

# 4. 启动 Java 程序并检查状态
start_java_application() {
    local jar_path="$1"
    local jar_filename
    jar_filename=$(basename "$jar_path")

    if [ ! -f "$jar_path" ]; then
        log_error_exit "Jar 文件 '$jar_path' 不存在，无法启动。"
    fi

    if [ -f "$PID_FILE" ]; then
        local old_pid
        old_pid=$(cat "$PID_FILE")
        if ps -p "$old_pid" > /dev/null; then
            log_info "检测到旧的 Agent 进程 (PID: $old_pid) 正在运行。"
            read -r -p "是否尝试停止旧进程并启动新下载的 '$jar_filename'? (y/N): " confirm_stop
            if [[ "$confirm_stop" =~ ^[Yy]$ ]]; then
                log_info "正在尝试停止进程 PID: $old_pid..."
                if sudo kill "$old_pid" 2>/dev/null; then
                    log_info "已发送 SIGTERM 到 PID $old_pid。等待进程退出 (最多10秒)..."
                    for _ in $(seq 1 10); do
                        if ! ps -p "$old_pid" > /dev/null; then break; fi
                        sleep 1
                    done
                fi
                if ps -p "$old_pid" > /dev/null; then
                    log_info "进程 $old_pid (SIGTERM 后) 仍然存在，尝试发送 SIGKILL..."
                    if sudo kill -9 "$old_pid" 2>/dev/null; then
                        log_info "已发送 SIGKILL 到 PID $old_pid."
                        sleep 1
                    else
                        log_warn "发送 SIGKILL 到 PID $old_pid 失败。"
                    fi
                fi
                if ps -p "$old_pid" > /dev/null; then
                     log_error_exit "无法停止旧的 Agent 进程 (PID: $old_pid)。请手动处理。"
                else
                    log_info "旧进程 (PID: $old_pid) 已成功停止或先前已不存在。"
                    rm -f "$PID_FILE"
                fi
            else
                log_info "用户选择不停止旧进程。脚本退出。"
                exit 0
            fi
        else
            log_info "找到旧的 PID 文件，但对应进程 $old_pid 未运行。将删除旧的 PID 文件。"
            rm -f "$PID_FILE"
        fi
    fi

    log_info "准备启动 Java 程序: $jar_filename (路径: $jar_path)"
    log_info "Java 应用程序日志将由其内部 Logback 配置管理，脚本期望的路径:"
    log_info "  - 主应用日志: $APP_MAIN_LOG_FILE"
    log_info "  - 错误应用日志: $APP_ERROR_LOG_FILE"
    log_info "脚本启动过程和 JVM 早期输出将记录到: $SCRIPT_STARTUP_LOG_FILE"
    log_info "PID 文件将创建在: $PID_FILE"
    log_info "将为 Java 应用设置环境变量 SSH_PUBLIC_KEY"
    log_info "将为 Java 应用设置环境变量 SSH_SERVER_PORT"

    if [ ! -d "$APP_LOG_BASE_DIR" ]; then
        log_info "Java 应用日志目录 '$APP_LOG_BASE_DIR' 不存在，正在尝试创建..."
        if ! mkdir -p "$APP_LOG_BASE_DIR"; then
            log_warn "创建 Java 应用日志目录 '$APP_LOG_BASE_DIR' 失败。Java程序自身的Logback配置将尝试创建它。"
        else
            log_info "Java 应用日志目录 '$APP_LOG_BASE_DIR' 创建成功。"
        fi
    fi

    # 将 CLI_SSH_PUBLIC_KEY 的值作为环境变量 ssh_public_key 传递给 java 进程
    # 使用 sudo VAR=value command 的方式确保环境变量通过 sudo 传递
    sudo SSH_PUBLIC_KEY="${CLI_SSH_PUBLIC_KEY}" SSH_SERVER_PORT="${SSH_SERVER_PORT}" nohup java -jar "$jar_path" > "$SCRIPT_STARTUP_LOG_FILE" 2>&1 &
    local app_pid=$!

    log_info "等待程序启动 (PID: $app_pid)..."
    sleep 8

    if ps -p "$app_pid" > /dev/null; then
        echo "$app_pid" > "$PID_FILE"
        log_info "Java 程序 '$jar_filename' 已作为后台进程启动，PID: $app_pid。"
        log_info "环境变量 SSH_PUBLIC_KEY 已设置并传递给该进程。"
        log_info "环境变量 SSH_SERVER_PORT 已设置并传递给该进程。"
        log_info "请检查以下日志文件获取运行状态和可能的错误:"
        log_info "  1. Java 应用主日志 (预期位置): $APP_MAIN_LOG_FILE"
        log_info "  2. Java 应用错误日志 (预期位置): $APP_ERROR_LOG_FILE"
        log_info "  3. 脚本启动过程日志: $SCRIPT_STARTUP_LOG_FILE (可能包含 JVM 早期错误或 nohup 输出)"
        log_info "要查看实时应用主日志 (如果路径与预期一致)，请使用: tail -f $APP_MAIN_LOG_FILE"
        log_info "要停止程序，请使用: sudo kill \$(cat $PID_FILE)"

        sleep 2
        if [ -f "$APP_MAIN_LOG_FILE" ] || [ -f "$APP_ERROR_LOG_FILE" ]; then
            log_info "检测到 Logback 应用日志文件已在预期位置 ($APP_LOG_BASE_DIR) 生成或已存在。"
        else
            log_warn "Logback 管理的应用日志文件在预期位置 ($APP_MAIN_LOG_FILE 或 $APP_ERROR_LOG_FILE) 尚未检测到。"
            log_warn "这可能表示: a) 程序启动非常快且没有立即产生日志; b) Logback 配置存在问题; c) 程序未能正确初始化 Logback。"
            log_warn "请务必检查 '$SCRIPT_STARTUP_LOG_FILE' 以获取可能的 JVM 启动错误，并核实 Java Agent 内部的 Logback 配置。"
        fi
    else
        log_error_exit "Java 程序 '$jar_filename' 启动失败。请检查脚本启动过程日志 '$SCRIPT_STARTUP_LOG_FILE' 获取详细错误信息。"
    fi
}

# --- 主逻辑 ---
main() {
    # Parse command line options
    # The leading colon in ":k:s:h" enables silent error handling by getopts.
    # getopts will set OPTARG to the option character if an argument is missing,
    # and opt to '?' if an unknown option is used.
    while getopts ":k:s:p:h" opt; do # 添加 s: 到 getopts 字符串
        case ${opt} in
            k )
                CLI_GITHUB_TOKEN="$OPTARG"
                ;;
            s )
                CLI_SSH_PUBLIC_KEY="$OPTARG"
                ;;
            p )
                SSH_SERVER_PORT="$OPTARG"
                ;;
            h )
                usage
                ;;
            \? ) # Invalid option
                echo "无效选项: -$OPTARG" 1>&2
                usage
                ;;
            : ) # Missing option argument
                echo "选项 -$OPTARG 需要一个参数。" 1>&2
                usage
                ;;
        esac
    done
    shift $((OPTIND -1)) # Remove parsed options from positional arguments

    # 检查必需参数是否已提供
    if [ -z "${CLI_GITHUB_TOKEN}" ]; then
        log_error_exit "错误：必须通过 -k <token> 参数提供 GitHub Token。\n$(usage)"
    fi
    if [ -z "${CLI_SSH_PUBLIC_KEY}" ]; then
        log_error_exit "错误：必须通过 -s <ssh_public_key> 参数提供 SSH 公钥。\n$(usage)"
    fi
    if [ -z "${SSH_SERVER_PORT}" ]; then
            log_error_exit "错误：必须通过 -p <ssh_server_port> 参数提供 SSH服务启动占用的端口号。\n$(usage)"
        fi

    log_info "--- Agent 安装与启动脚本开始 ---"
    log_info "传入的 GitHub Token: [REDACTED]" # 不直接打印 token
    log_info "传入的 SSH Public Key: ${CLI_SSH_PUBLIC_KEY:0:30}..."
    log_info "传入的 SSH Server Port: ${SSH_SERVER_PORT:0:30}..."

    check_dependencies
    check_java_version
    check_sudo_privileges

    if [ ! -d "$AGENT_INSTALL_DIR" ]; then
        log_info "Agent 安装目录 '$AGENT_INSTALL_DIR' 不存在，正在创建..."
        if ! mkdir -p "$AGENT_INSTALL_DIR"; then
            log_error_exit "创建 Agent 安装目录 '$AGENT_INSTALL_DIR' 失败。请检查权限。"
        fi
        log_info "Agent 安装目录 '$AGENT_INSTALL_DIR' 创建成功。"
    fi

    local jar_download_url
    jar_download_url=$(get_jar_download_url)

    local downloaded_jar_path
    downloaded_jar_path=$(download_jar_file "$jar_download_url")

    start_java_application "$downloaded_jar_path"

    log_info "--- Agent 安装与启动脚本执行完毕 ---"
}

# 执行主函数
main "$@" # Pass all command line arguments to main