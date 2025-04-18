package cn.hedeoer.util;


import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;

/**
 * Redis客户端工具类，基于Jedis实现
 */
public class RedisUtil {

    private static JedisPool jedisPool;

    // 默认连接参数
    private static final String DEFAULT_HOST = "vm79";
    private static final int DEFAULT_PORT = 6379;
    private static final int DEFAULT_TIMEOUT = 2000;
    private static final String DEFAULT_PASSWORD = null;
    private static final int DEFAULT_DATABASE = 0;

    /**
     * 初始化Redis连接池
     */
    public static void initPool() {
        initPool(DEFAULT_HOST, DEFAULT_PORT, DEFAULT_TIMEOUT, DEFAULT_PASSWORD, DEFAULT_DATABASE);
    }

    /**
     * 初始化Redis连接池（自定义参数）
     *
     * @param host Redis服务器地址
     * @param port Redis服务器端口
     * @param timeout 连接超时时间（毫秒）
     * @param password Redis密码（没有则传null）
     * @param database 数据库索引
     */
    public static void initPool(String host, int port, int timeout, String password, int database) {
        JedisPoolConfig config = new JedisPoolConfig();
        // 最大连接数
        config.setMaxTotal(100);
        // 最大空闲连接数
        config.setMaxIdle(20);
        // 最小空闲连接数
        config.setMinIdle(5);
        // 获取连接时最大等待毫秒数
        config.setMaxWaitMillis(5000);
        // 获取连接时检查有效性
        config.setTestOnBorrow(true);
        // 归还连接时检查有效性
        config.setTestOnReturn(false);
        // 空闲时检查有效性
        config.setTestWhileIdle(true);

        if (password != null && !password.isEmpty()) {
            jedisPool = new JedisPool(config, host, port, timeout, password, database);
        } else {
            jedisPool = new JedisPool(config, host, port, timeout);
        }
    }

    /**
     * 获取Jedis实例
     *
     * @return Jedis实例
     */
    public static Jedis getJedis() {
        if (jedisPool == null) {
            initPool();
        }
        return jedisPool.getResource();
    }

    /**
     * 关闭Jedis实例，将连接返回到连接池
     *
     * @param jedis Jedis实例
     */
    public static void close(Jedis jedis) {
        if (jedis != null) {
            jedis.close();
        }
    }

    /**
     * 销毁连接池
     */
    public static void destroyPool() {
        if (jedisPool != null && !jedisPool.isClosed()) {
            jedisPool.destroy();
        }
    }

    /**
     * 使用示例：执行带有自动资源管理的Redis操作
     *
     * @param callback Redis操作回调接口
     * @param <T> 返回类型
     * @return 操作结果
     */
    public static <T> T execute(RedisCallback<T> callback) {
        Jedis jedis = null;
        try {
            jedis = getJedis();
            return callback.doInRedis(jedis);
        } finally {
            close(jedis);
        }
    }

    /**
     * Redis操作回调接口
     */
    public interface RedisCallback<T> {
        T doInRedis(Jedis jedis);
    }

    // 以下是一些常用的Redis操作方法

    /**
     * 设置字符串值
     */
    public static String set(final String key, final String value) {
        return execute(jedis -> jedis.set(key, value));
    }

    /**
     * 获取字符串值
     */
    public static String get(final String key) {
        return execute(jedis -> jedis.get(key));
    }

    /**
     * 设置带过期时间的字符串值
     */
    public static String setex(final String key, final int seconds, final String value) {
        return execute(jedis -> jedis.setex(key, seconds, value));
    }

    /**
     * 删除键
     */
    public static Long del(final String... keys) {
        return execute(jedis -> jedis.del(keys));
    }

    /**
     * 检查键是否存在
     */
    public static Boolean exists(final String key) {
        return execute(jedis -> jedis.exists(key));
    }

    /**
     * 设置过期时间
     */
    public static Long expire(final String key, final int seconds) {
        return execute(jedis -> jedis.expire(key, seconds));
    }
}
