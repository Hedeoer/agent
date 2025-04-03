package cn.hedeoer.util;

public class WallUtil {
    /*
    * 识别操作系统使用的防火墙工具
    * 针对centos，debian系统
    * 只对firewall，ufw处理
    * */

    public static void getWallType(){
        if (OperateSystemUtil.isLinux()) {
            // 判断操作系统具体类型， centos， debian..

            // 判断是否使用了 ufw 或者 firewall工具，且是否同时启用多种防火墙工具

            // 没有使用或者没有启用如何设置？
        }
    }

}
