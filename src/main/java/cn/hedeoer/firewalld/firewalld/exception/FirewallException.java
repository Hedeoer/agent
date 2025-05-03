package cn.hedeoer.firewalld.firewalld.exception;

/**
 * 防火墙异常类
 */
public class FirewallException extends Exception {
    public FirewallException(String message) {
        super(message);
    }

    public FirewallException(String message, Throwable cause) {
        super(message, cause);
    }
}