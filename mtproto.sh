#!/bin/bash

GITHUB_REPO="bryet/mtproto"

Red="\033[31m"         # 红色
Green="\033[32m"       # 绿色
Yellow="\033[33m"      # 黄色
Blue="\033[34m"        # 蓝色
Plain="\033[0m"           # 重置颜色
Red_globa="\033[41;37m"    # 红底白字
Green_globa="\033[42;37m"  # 绿底白字
Yellow_globa="\033[43;37m" # 黄底白字
Blue_globa="\033[44;37m"   # 蓝底白字
Info="${Green}[信息]${Plain}"
Error="${Red}[错误]${Plain}"
Tip="${Yellow}[提示]${Plain}"

mtp_dir="/var/mtproto"
mtp_file="${mtp_dir}/mtproto"
mtp_conf="${mtp_dir}/config.yaml"
mtp_info="${mtp_dir}/mtp_info"

# 检查是否为root用户
check_root(){
    if [ "$(id -u)" != "0" ]; then
        echo -e "${Error} 当前非ROOT账号(或没有ROOT权限)，无法继续操作，请更换ROOT账号或使用 ${Green_globa}sudo -i${Plain} 命令获取临时ROOT权限（执行后可能会提示输入当前账号的密码）。"
        exit 1
    fi
}

check_arch(){
    arch=$(uname -m)
    case "$arch" in
        x86_64|x64|amd64)
            arch="x86_64-unknown-linux-musl"
            ;;
        aarch64|arm64|armv8*)
            arch="aarch64-unknown-linux-musl"
            ;;
        *)
            echo -e "${Error} 检测到您的架构不支持: $arch"
            exit 1
            ;;
    esac
    echo -e "${Info} 架构 ${arch}"
}

check_release(){
    if [[ -e /etc/os-release ]]; then
        . /etc/os-release
        release=$ID
    elif [[ -e /usr/lib/os-release ]]; then
        . /usr/lib/os-release
        release=$ID
    fi
    os_version=$(echo $VERSION_ID | cut -d. -f1,2)

    if [[ "${release}" == "ol" ]]; then
        release=oracle
    elif [[ ! "${release}" =~ ^(kali|centos|ubuntu|fedora|debian|almalinux|rocky|alpine)$ ]]; then
        echo -e "${Error} 抱歉，此脚本不支持您的操作系统。"
        echo -e "${Info} 请确保您使用的是以下支持的操作系统之一："
        echo -e "-${Red} Ubuntu ${Plain}"
        echo -e "-${Red} Debian ${Plain}"
        echo -e "-${Red} CentOS ${Plain}"
        echo -e "-${Red} Fedora ${Plain}"
        echo -e "-${Red} Kali ${Plain}"
        echo -e "-${Red} AlmaLinux ${Plain}"
        echo -e "-${Red} Rocky Linux ${Plain}"
        echo -e "-${Red} Oracle Linux ${Plain}"
        echo -e "-${Red} Alpine Linux ${Plain}"
        exit 1
    fi
}

check_pmc(){
    check_release

    case "$release" in
        debian|ubuntu|kali)
            updates="apt update -y"
            installs="apt install -y"
            apps=("wget" "curl" "tar" "gzip")
            ;;
        almalinux|centos|rocky|oracle|fedora)
            if command -v dnf &>/dev/null; then
                updates="dnf update -y"
                installs="dnf install -y"
            else
                updates="yum update -y"
                installs="yum install -y"
            fi
            apps=("wget" "curl" "tar" "gzip")
            ;;
        opensuse-tumbleweed)
            updates="zypper refresh"
            installs="zypper install -y"
            apps=("wget" "curl" "tar" "gzip")
            ;;
        arch|manjaro|parch)
            updates="pacman -Syu"
            installs="pacman -Syu --noconfirm"
            apps=("wget" "curl" "tar" "gzip")
            ;;
        alpine)
            updates="apk update"
            installs="apk add"
            apps=("wget" "curl" "tar" "gzip")
            ;;
        *)
            echo -e "${Error} 不支持的发行版: $release"
            exit 1
            ;;
    esac
}

install_base(){
    check_pmc
    cmds=("wget" "curl" "tar" "gzip")
    DEPS=()
    echo -e "${Info} 你的系统是 ${Red}$release $os_version${Plain}"
    echo

    for i in "${!cmds[@]}"; do
        if ! command -v "${cmds[i]}" &>/dev/null; then
            DEPS+=("${apps[i]}")
        fi
    done
    
    if [ ${#DEPS[@]} -gt 0 ]; then
        echo -e "${Tip} 安装依赖列表：${Green}${DEPS[*]}${Plain} 请稍后..."
        $updates || exit 1
        $installs "${DEPS[@]}" || exit 1
    else
        echo -e "${Info} 所有依赖已存在，不需要额外安装。"
    fi
}

# 服务状态检查
check_service_status(){
    check_release
    if [[ "$release" == "alpine" ]]; then
        rc-service mtproto status >/dev/null 2>&1
    else
        systemctl status mtproto.service >/dev/null 2>&1
    fi
}

# 检查是否安装Mtproto
check_installed_status(){
    if [[ ! -e "${mtp_file}" ]]; then
        echo -e "${Error} Mtproto 没有安装，请检查 !"
        exit 1
    fi
}

# 启动服务
start_Mtproto(){
    check_release
    if [[ "$release" == "alpine" ]]; then
        rc-service mtproto start >/dev/null 2>&1
    else
        systemctl start mtproto.service >/dev/null 2>&1
    fi
}

# 停止服务
stop_Mtproto(){
    check_release
    if [[ "$release" == "alpine" ]]; then
        rc-service mtproto stop >/dev/null 2>&1
    else
        systemctl stop mtproto.service >/dev/null 2>&1
    fi
}

# 重启服务
restart_Mtproto(){
    check_release
    if [[ "$release" == "alpine" ]]; then
        rc-service mtproto restart >/dev/null 2>&1
    else
        systemctl restart mtproto.service >/dev/null 2>&1
    fi
}

# 启用开机自启
enable_Mtproto(){
    check_release
    if [[ "$release" == "alpine" ]]; then
        rc-update add mtproto default >/dev/null 2>&1
    else
        systemctl enable mtproto.service >/dev/null 2>&1
    fi
}

# 禁用开机自启
disable_Mtproto(){
    check_release
    if [[ "$release" == "alpine" ]]; then
        rc-update del mtproto default >/dev/null 2>&1
    else
        systemctl disable mtproto.service >/dev/null 2>&1
    fi
}

get_public_ip(){
    IPv4=""
    IPv6=""
    InFaces=($(ls /sys/class/net | grep -E '^(eth|ens|enp)'))
    IP_API=(
        "http://ip.gs"
        "http://ip.sb"
        "http://ident.me"
        "http://ifconfig.me"
        "http://api.ipify.org"
        "http://icanhazip.com"
    )

    for iface in "${InFaces[@]}"; do
        for ip_api in "${IP_API[@]}"; do
            IPv4=$(curl -s4 --max-time 2 --interface "$iface" "$ip_api")
            IPv6=$(curl -s6 --max-time 2 --interface "$iface" "$ip_api")

            if [[ -n "$IPv4" || -n "$IPv6" ]]; then # 检查是否获取到IP地址
                break 2 # 获取到任一IP类型停止循环
            fi
        done
    done
}

Download(){
    if [[ ! -e "${mtp_dir}" ]]; then
        mkdir -p "${mtp_dir}"
    fi
    get_public_ip
    cd "${mtp_dir}" || exit 1
    echo -e "${Info} 开始下载/安装..."
    last_version=$(curl -fLsS "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    if [[ -z "$last_version" ]]; then
        echo -e "${Error} 无法获取 mtproto 版本，这可能是由于 GitHub API 限制所致，请稍后再试"
        exit 1
    fi
    check_arch
    echo -e "已获取 mtproto 最新版本: ${last_version}, 开始安装..."
    local package="mtproto-${arch}-${last_version}.tar.gz"
    local download_dir
    download_dir=$(mktemp -d) || exit 1
    wget -O "$download_dir/$package" "https://github.com/${GITHUB_REPO}/releases/download/${last_version}/${package}"
    if [[ $? -ne 0 ]]; then
        echo -e "${Error} 下载 mtproto 失败, 请确保您的服务器能够访问GitHub"
        rm -rf "$download_dir"
        exit 1
    fi
    if ! tar xzf "$download_dir/$package" -C "$download_dir" mtproto config.example.yaml mtproto.service; then
        echo -e "${Error} 解压 mtproto 失败"
        rm -rf "$download_dir"
        exit 1
    fi
    install -m 755 "$download_dir/mtproto" "$mtp_file" || exit 1
    if [[ ! -e "$mtp_conf" ]]; then
        install -m 600 "$download_dir/config.example.yaml" "$mtp_conf" || exit 1
    fi

    if [[ "$release" == "alpine" ]]; then
        cat >/etc/init.d/mtproto <<'EOF'
#!/sbin/openrc-run
name="mtproto"
command="/var/mtproto/mtproto"
command_args="-c /var/mtproto/config.yaml"
directory="/var/mtproto"
supervisor="supervise-daemon"
respawn_delay=5
output_log="/var/mtproto/log_mtproto"
error_log="/var/mtproto/log_mtproto"
depend() {
    need net
}
EOF
        chmod +x /etc/init.d/mtproto || exit 1
    else
        install -D -m 644 "$download_dir/mtproto.service" /etc/systemd/system/mtproto.service || exit 1
        systemctl daemon-reload || exit 1
    fi
    rm -rf "$download_dir"

    # 保存版本信息
    echo "$last_version" > "${mtp_dir}/version"

    cat >"${mtp_info}" <<-EOF
IPv4=$IPv4
IPv6=$IPv6
PORT=8443
SECURE=dd0123456789abcdef0123456789abcdef
TAG=
EOF
}

Read_config(){
    IPv4=$(grep '^IPv4=' "${mtp_info}" | cut -d'=' -f2 | grep -F '.')
    IPv6=$(grep '^IPv6=' "${mtp_info}" | cut -d'=' -f2 | grep -F ':')
    PORT=$(grep 'PORT=' "${mtp_info}" | cut -d'=' -f2)
    SECURE=$(grep 'SECURE=' "${mtp_info}" | cut -d'=' -f2)
    TAG=$(grep 'TAG=' "${mtp_info}" | cut -d'=' -f2)
}

Set_port(){
    while true; do
        echo -e "${Tip} 请输入 Mtproto 端口 [10000-65535]"
        read -e -p "(默认：随机生成):" mtp_port
        [[ -z "${mtp_port}" ]] && mtp_port=$((10000 + (RANDOM + RANDOM) % 55536))
        if [[ ${mtp_port} =~ ^[1-9][0-9]{4}$ ]] && [[ ${mtp_port} -ge 10000 ]] && [[ ${mtp_port} -le 65535 ]]; then
            echo && echo "========================"
            echo -e "  端口 : ${Red_globa} ${mtp_port} ${Plain}"
            echo "========================" && echo
            break
        else
            echo "输入错误, 请输入正确的端口。"
        fi
    done
    sed -i -E "s/^#?[[:space:]]*PORT[[:space:]]*:.*/PORT: \"$mtp_port\"/" "$mtp_conf"
    sed -i "s/^#\?PORT.*/PORT=$mtp_port/g" "$mtp_info"
}

Set_passwd(){
    echo -e "${Tip} 请选择密匙模式："
    echo -e "  ${Green}1.${Plain} 普通模式 (32位十六进制字符)"
    echo -e "  ${Green}2.${Plain} 安全模式 (dd+32位十六进制字符)"
    echo -e "  ${Green}3.${Plain} TLS 模式 (ee+32位十六进制字符+TLS域名)${Red_globa}[默认]${Plain}"

    read -e -p "(请输入数字 1-3，默认：3):" mtp_mode
    [[ -z "${mtp_mode}" ]] && mtp_mode="3"

    # 生成基础密钥（32位十六进制字符，即16字节）
    mtp_passwd=$("$mtp_file" --generate-secret) || return 1

    case "${mtp_mode}" in
        1)
            # 普通模式
            sed -i -E "s/^#?[[:space:]]*MODES_CLASSIC[[:space:]]*:.*/MODES_CLASSIC: true/" "$mtp_conf"
            sed -i -E "s/^#?[[:space:]]*MODES_SECURE[[:space:]]*:.*/MODES_SECURE: false/" "$mtp_conf"
            sed -i -E "s/^#?[[:space:]]*MODES_TLS[[:space:]]*:.*/MODES_TLS: false/" "$mtp_conf"
            sed -i -E 's/^([[:space:]]*)TLS_DOMAIN[[:space:]]*:/\1# TLS_DOMAIN:/' "$mtp_conf"
            mtp_secure="$mtp_passwd"
            sed -i "s/^#\?SECURE.*/SECURE=$mtp_secure/g" "$mtp_info"
            echo && echo "========================"
            echo -e "  模式 : ${Green}普通模式${Plain}"
            echo -e "  密匙 : ${Red_globa}${mtp_secure}${Plain}"
            echo "========================" && echo
            ;;
        2)
            # 安全模式
            sed -i -E "s/^#?[[:space:]]*MODES_CLASSIC[[:space:]]*:.*/MODES_CLASSIC: false/" "$mtp_conf"
            sed -i -E "s/^#?[[:space:]]*MODES_SECURE[[:space:]]*:.*/MODES_SECURE: true/" "$mtp_conf"
            sed -i -E "s/^#?[[:space:]]*MODES_TLS[[:space:]]*:.*/MODES_TLS: false/" "$mtp_conf"
            sed -i -E 's/^([[:space:]]*)TLS_DOMAIN[[:space:]]*:/\1# TLS_DOMAIN:/' "$mtp_conf"
            mtp_secure="dd${mtp_passwd}"
            sed -i "s/^#\?SECURE.*/SECURE=$mtp_secure/g" "$mtp_info"
            echo && echo "========================"
            echo -e "  模式 : ${Green}安全模式${Plain}"
            echo -e "  密匙 : ${Red_globa}${mtp_secure}${Plain}"
            echo "========================" && echo
            ;;
        3)
            # TLS模式
            echo -e "${Tip} 请输入TLS伪装域名 ${Red}(无法使用被墙的域名。)${Plain}"
            read -e -p "(默认：itunes.apple.com):" fake_domain
            [[ -z "${fake_domain}" ]] && fake_domain="itunes.apple.com"
            if [[ ${#fake_domain} -gt 253 || ! "$fake_domain" =~ ^[A-Za-z0-9.-]+$ ]]; then
                echo -e "${Error} 请输入有效的TLS域名（国际化域名请使用 punycode）"
                return 1
            fi
            sed -i -E "s/^#?[[:space:]]*MODES_CLASSIC[[:space:]]*:.*/MODES_CLASSIC: false/" "$mtp_conf"
            sed -i -E "s/^#?[[:space:]]*MODES_SECURE[[:space:]]*:.*/MODES_SECURE: false/" "$mtp_conf"
            sed -i -E "s/^#?[[:space:]]*MODES_TLS[[:space:]]*:.*/MODES_TLS: true/" "$mtp_conf"
            sed -i -E "s/^#?[[:space:]]*TLS_DOMAIN[[:space:]]*:.*/TLS_DOMAIN: \"$fake_domain\"/" "$mtp_conf"
            mtp_secure="ee${mtp_passwd}$(printf '%s' "$fake_domain" | od -An -v -tx1 | tr -d ' \n')"
            sed -i "s/^#\?SECURE.*/SECURE=$mtp_secure/g" "$mtp_info"
            echo && echo "========================"
            echo -e "  模式 : ${Green}TLS模式${Plain}"
            echo -e "  域名 : ${Green}${fake_domain}${Plain}"
            echo -e "  密匙 : ${Red_globa}${mtp_secure}${Plain}"
            echo "========================" && echo
            ;;
        *)
            echo -e "${Error} 请输入正确数字 [1-3]"
            Set_passwd
            return $?
            ;;
    esac
    sed -i -E "s/^#?[[:space:]]*SECRET[[:space:]]*:.*/SECRET: \"$mtp_passwd\"/" "$mtp_conf"
}

Set_tag(){
    echo -e "${Tip} 请输入 Mtproto 的 TAG标签（TAG标签必须是32位，TAG标签只有在通过官方机器人 @Mtprotobot 分享代理账号后才会获得，不清楚请留空回车）"
    read -e -p "(默认：回车跳过):" mtp_tag
    if [[ -n "${mtp_tag}" ]]; then
        if [[ ! "$mtp_tag" =~ ^[A-Fa-f0-9]{32}$ ]]; then
            echo -e "${Error} TAG标签必须是32位十六进制字符"
            return 1
        fi
        echo && echo "========================"
        echo -e "  TAG : ${Red_globa} ${mtp_tag} ${Plain}"
        echo "========================"
        sed -i -E "s/^#?[[:space:]]*AD_TAG[[:space:]]*:.*/AD_TAG: \"$mtp_tag\"/" "$mtp_conf"
        sed -i "s/^#\?TAG.*/TAG=$mtp_tag/g" "$mtp_info"
    else
        sed -i -E 's/^#?[[:space:]]*AD_TAG[[:space:]]*:.*/AD_TAG: ""/' "$mtp_conf"
        sed -i "s/^#\?TAG.*/TAG=/g" "$mtp_info"
    fi
}

Set(){
    echo -e "${Tip} 开始设置 用户配置..."
    check_installed_status
    echo && echo -e "你要修改什么？
${Green} 1.${Plain}  修改 端口配置
${Green} 2.${Plain}  修改 密匙配置
${Green} 3.${Plain}  修改 TAG 配置
${Green} 4.${Plain}  修改 全部配置" && echo
    read -e -p "(默认: 取消):" mtp_modify
    [[ -z "${mtp_modify}" ]] && echo -e "${Error} 已取消..." && return 0
    case "${mtp_modify}" in
        1) Set_port && Restart ;;
        2) Set_passwd && Restart ;;
        3) Set_tag && Restart ;;
        4) Set_port && Set_passwd && Set_tag && Restart ;;
        *) echo -e "${Error} 请输入正确的数字(1-4)" ;;
    esac
}

Install(){
    [[ -e ${mtp_file} ]] && echo -e "${Error} 检测到 Mtproto 已安装 !" && exit 1
    install_base
    Download
    Set_port || exit 1
    Set_passwd || exit 1
    Set_tag || exit 1
    echo -e "${Info} 所有步骤 执行完毕，开始启动..."
    Start
}

Start(){
    check_installed_status
    if check_service_status; then
        echo -e "${Error} Mtproto 正在运行，请检查 !"
        sleep 1s
        menu
    else
        start_Mtproto
        sleep 2s
        if check_service_status; then
            enable_Mtproto
            View
        else
            echo -e "${Error} Mtproto 启动失败，请检查日志！"
            sleep 3s
            menu
        fi
    fi
}

Stop(){
    check_installed_status
    if ! check_service_status; then
        echo -e "${Error} Mtproto 没有运行，请检查 !"
        sleep 1s
        menu
    else
        stop_Mtproto
        sleep 2s
        if ! check_service_status; then
            echo -e "${Info} Mtproto 已停止"
        else
            echo -e "${Error} Mtproto 停止失败"
        fi
        sleep 1s
        menu
    fi
}

Restart(){
    check_installed_status
    if check_service_status; then
        stop_Mtproto
        sleep 2s
    fi
    start_Mtproto
    sleep 2s
    if check_service_status; then
        View
    else
        echo -e "${Error} Mtproto 重启失败，请检查日志！"
        sleep 3s
        menu
    fi
}

# 更新 mtproto 程序
Update(){
    check_installed_status
    echo -e "${Info} 开始更新 mtproto 程序..."

    local latest_version
    latest_version=$(curl -fLsS "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    if [[ -z "$latest_version" ]]; then
        echo -e "${Error} 无法获取最新版本，请检查网络连接"
        return 1
    fi

    local current_version=""
    [[ -f "${mtp_dir}/version" ]] && current_version=$(cat "${mtp_dir}/version")

    if [[ "$current_version" == "$latest_version" ]]; then
        echo -e "${Info} mtproto 已经是最新版本: ${latest_version}"
        sleep 2
        menu
        return 0
    fi

    echo -e "${Info} 发现新版本: ${latest_version}，当前版本: ${current_version:-未安装}"

    cd "${mtp_dir}" || exit 1
    check_arch
    local package="mtproto-${arch}-${latest_version}.tar.gz"
    local download_url="https://github.com/${GITHUB_REPO}/releases/download/${latest_version}/${package}"
    local download_dir
    download_dir=$(mktemp -d) || return 1
    echo -e "${Info} 下载地址: $download_url"

    wget -O "$download_dir/$package" "$download_url"
    if [[ $? -ne 0 ]]; then
        echo -e "${Error} 下载失败，请检查网络连接"
        rm -rf "$download_dir"
        return 1
    fi

    if ! tar xzf "$download_dir/$package" -C "$download_dir" mtproto mtproto.service; then
        echo -e "${Error} 解压 mtproto 失败"
        rm -rf "$download_dir"
        return 1
    fi

    if check_service_status; then
        echo -e "${Info} 停止当前服务..."
        stop_Mtproto || return 1
        sleep 2
    fi
    install -m 755 "$download_dir/mtproto" "$mtp_file" || return 1
    if [[ "$release" != "alpine" ]]; then
        install -D -m 644 "$download_dir/mtproto.service" /etc/systemd/system/mtproto.service || return 1
        systemctl daemon-reload || return 1
    fi
    rm -rf "$download_dir"

    echo "$latest_version" > "${mtp_dir}/version"

    start_Mtproto
    sleep 2
    if check_service_status; then
        echo -e "${Info} mtproto 更新完成！"
        enable_Mtproto
        View
    else
        echo -e "${Error} 服务启动失败，请检查日志"
        return 1
    fi
}

Uninstall(){
    check_installed_status
    echo -e "${Tip} 确定要卸载 Mtproto ? (y/N)"
    echo
    read -e -p "(默认: n):" unyn
    [[ -z ${unyn} ]] && unyn="n"
    if [[ ${unyn} == [Yy] ]]; then
        if check_service_status; then
            stop_Mtproto
        fi

        disable_Mtproto

        # 删除服务文件
        if [[ "$release" == "alpine" ]]; then
            rm -f /etc/init.d/mtproto
        else
            rm -f /etc/systemd/system/mtproto.service
            systemctl daemon-reload >/dev/null 2>&1
        fi

        rm -rf "${mtp_dir}"
        echo -e "${Info} Mtproto 卸载完成 !"
        echo
    else
        echo
        echo -e "${Tip} 卸载已取消..."
        echo
    fi
}

View(){
    check_installed_status
    Read_config
    clear && echo
    echo -e "Mtproto Proxy 用户配置："
    echo -e "————————————————"
    echo -e " 地址\t: ${Green}${IPv4}${Plain}"
    [[ -n "${IPv6}" ]] && echo -e " 地址\t: ${Green}${IPv6}${Plain}"
    echo -e " 端口\t: ${Green}${PORT}${Plain}"
    echo -e " 密匙\t: ${Green}${SECURE}${Plain}"
    [[ -n "${TAG}" ]] && echo -e " TAG \t: ${Green}${TAG}${Plain}"
    echo -e " IPv4 链接\t: ${Red}https://t.me/proxy?server=${IPv4}&port=${PORT}&secret=${SECURE}${Plain}"
    echo -e " IPv4 链接\t: ${Red}tg://proxy?server=${IPv4}&port=${PORT}&secret=${SECURE}${Plain}"
    [[ -n "${IPv6}" ]] && echo -e " IPv6 链接\t: ${Red}tg://proxy?server=${IPv6}&port=${PORT}&secret=${SECURE}${Plain}"
    [[ -n "${IPv6}" ]] && echo -e " IPv6 链接\t: ${Red}https://t.me/proxy?server=${IPv6}&port=${PORT}&secret=${SECURE}${Plain}"
    echo
    echo -e "${Tip} 密匙头部的 ${Green}ee${Plain} 字符是代表客户端启用 ${Green}TLS伪装模式${Plain} ，可以降低服务器被墙几率。"
    echo -e "${Tip} 密匙头部的 ${Green}dd${Plain} 字符是代表客户端启用 ${Green}安全混淆模式${Plain}（TLS伪装模式除外），可以降低服务器被墙几率。"
    backmenu
}

View_Log(){
    check_installed_status
    echo && echo -e "${Tip} 按 ${Red}Ctrl+C${Plain} 终止查看日志。"
    check_release
    if [[ "$release" == "alpine" ]]; then
        tail -f /var/mtproto/log_mtproto
    else
        journalctl -u mtproto.service -f
    fi
}

Esc_Shell(){
    exit 0
}

backmenu(){
    echo ""
    read -rp "请输入\"y\"退出, 或按任意键回到主菜单：" backmenuInput
    case "$backmenuInput" in
        y) exit 0 ;;
        *) menu ;;
    esac
}

menu(){
    clear
    echo -e "${Green}######################################
#          ${Red}Mtproto 一键脚本          ${Green}#
#         作者: ${Yellow}你挺好看啊🍏          ${Green}#
######################################

 0.${Plain} 退出脚本
———————————————————————
${Green} 1.${Plain} 安装 Mtproto
${Green} 2.${Plain} 卸载 Mtproto
${Green} 3.${Plain} 更新 Mtproto
———————————————————————
${Green} 4.${Plain} 启动 Mtproto
${Green} 5.${Plain} 停止 Mtproto
${Green} 6.${Plain} 重启 Mtproto
———————————————————————
${Green} 7.${Plain} 修改 Mtproto 配置
${Green} 8.${Plain} 查看 Mtproto 链接
${Green} 9.${Plain} 查看 Mtproto 日志
———————————————————————" && echo

    if [[ -e ${mtp_file} ]]; then
        if check_service_status; then
            echo -e " 当前状态: ${Green}已安装${Plain} 并 ${Green}已启动${Plain}"
            if [[ -f "$mtp_info" ]]; then
                Read_config
                echo -e "${Info} IPv4 链接: ${Red}https://t.me/proxy?server=${IPv4}&port=${PORT}&secret=${SECURE}${Plain}"
                [[ -n "${IPv6}" ]] && echo -e "${Info} IPv6 链接: ${Red}https://t.me/proxy?server=${IPv6}&port=${PORT}&secret=${SECURE}${Plain}"
            fi
        else
            echo -e " 当前状态: ${Green}已安装${Plain} 但 ${Red}未启动${Plain}"
        fi
    else
        echo -e " 当前状态: ${Red}未安装${Plain}"
    fi
    echo
    read -e -p " 请输入数字 [0-9]:" num
    case "$num" in
        0) Esc_Shell ;;
        1) Install ;;
        2) Uninstall ;;
        3) Update ;;
        4) Start ;;
        5) Stop ;;
        6) Restart ;;
        7) Set ;;
        8) View ;;
        9) View_Log ;;
        *) echo -e "${Error} 请输入正确数字 [0-9]" ;;
    esac
}

check_root
menu