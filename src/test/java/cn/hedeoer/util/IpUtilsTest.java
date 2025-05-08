package cn.hedeoer.util;

import org.junit.Test;

import static org.junit.Assert.*;

public class IpUtilsTest {

    @Test
    public void isValidIp() {
//        assertTrue(IpUtils.isValidIp("192.168.1.1"));
//        assertTrue(IpUtils.isValidIp("2001:db8::1"));
//        assertFalse(IpUtils.isValidIp("256.0.0.1"));
//        assertFalse(IpUtils.isValidIp("invalid"));
        System.out.println(IpUtils.isValidIp("172.16.0.0/24"));
    }
}