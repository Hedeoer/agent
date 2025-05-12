package cn.hedeoer.util;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.yaml.snakeyaml.Yaml;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;
import redis.clients.jedis.Protocol;
import redis.clients.jedis.exceptions.JedisException;

import java.io.InputStream;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Redis客户端工具类，基于Jedis实现
 */
public class RedisUtil{
    private static final Logger log = LoggerFactory.getLogger(RedisUtil.class);
    private static JedisPool jedisPool = null; // 初始化为null
    private static final String CONFIG_FILE_NAME = "application.yaml";
    private static boolean initializationFailed = false; // 标记初始化是否失败

    static {
        try {
            loadConfigAndInitializePool();
            if (jedisPool == null) { // 双重检查，确保initPool成功设置了jedisPool
                initializationFailed = true;
                log.error("FATAL: JedisPool initialization appears to have failed silently, jedisPool is still null after loadConfigAndInitializePool.");
            }
        } catch (Exception e) { // 捕获所有初始化期间的异常
            initializationFailed = true;
            log.error("FATAL: Critical error during Redis initialization, RedisUtil will be non-functional. Error: {}", e.getMessage(), e);
            // 不再向上抛出异常
        }
    }

    @SuppressWarnings("unchecked")
    private static void loadConfigAndInitializePool() {
        // 如果已经标记为失败，则不再尝试加载
        if (initializationFailed) {
            log.warn("Skipping Redis configuration loading as initialization previously failed.");
            return;
        }

        Yaml yaml = new Yaml();
        InputStream inputStream = null; // 在try外部声明，以便finally可以访问

        try {
            inputStream = RedisUtil.class.getClassLoader().getResourceAsStream(CONFIG_FILE_NAME);
            if (inputStream == null) {
                log.error("{} not found in classpath. Redis cannot be configured.", CONFIG_FILE_NAME);
                initializationFailed = true;
                return; // 中断加载
            }

            Map<String, Object> loadedYaml = yaml.load(inputStream);

            if (loadedYaml == null || !(loadedYaml.get("redis") instanceof Map)) {
                log.error("'{}' is missing 'redis' root key or it's not a map.", CONFIG_FILE_NAME);
                initializationFailed = true;
                return; // 中断加载
            }

            Map<String, Object> redisConfigMap = (Map<String, Object>) loadedYaml.get("redis");

            // 必需的配置
            String host = getRequiredConfig(redisConfigMap, "host", String.class);
            Integer portNum = getRequiredConfig(redisConfigMap, "port", Number.class).intValue();

            if (host == null || portNum == null) { // getRequiredConfig内部会处理null，但这里作为示例，如果它们返回null
                initializationFailed = true;
                return;
            }
            int port = portNum;


            // 可选的配置
            int timeout = getOptionalConfig(redisConfigMap, "timeout", Number.class)
                    .map(Number::intValue)
                    .orElse(Protocol.DEFAULT_TIMEOUT);
            String password = getOptionalConfig(redisConfigMap, "password", String.class)
                    .orElse(null);
            int database = getOptionalConfig(redisConfigMap, "database", Number.class)
                    .map(Number::intValue)
                    .orElse(Protocol.DEFAULT_DATABASE);

            boolean useSsl = getOptionalConfig(redisConfigMap, "ssl", Boolean.class).orElse(false);

            Map<String, Object> poolConfigMap = null;
            Object poolValue = redisConfigMap.get("pool");
            if (poolValue instanceof Map) {
                poolConfigMap = (Map<String, Object>) poolValue;
            } else if (redisConfigMap.containsKey("pool") && poolValue != null) {
                log.error("Redis 'pool' configuration in {} must be a map (object), but found: {}. Pool config will be ignored.",
                        CONFIG_FILE_NAME, poolValue.getClass().getSimpleName());
                // 不将此视为致命错误，而是忽略pool配置，使用JedisPoolConfig默认值
            }
            initPool(host, port, timeout, password, database, poolConfigMap,useSsl);

        } catch (Exception e) { // 捕获加载和解析过程中的所有异常
            log.error("Error during Redis configuration loading/parsing: {}. Redis will be unavailable.", e.getMessage(), e);
            initializationFailed = true;
            // 确保 jedisPool 为 null
            if (jedisPool != null) {
                try { jedisPool.destroy(); } catch (Exception ex) { log.warn("Exception destroying partially initialized pool", ex); }
                jedisPool = null;
            }
        } finally {
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (Exception ignored) {
                    log.warn("Failed to close input stream for {}: {}", CONFIG_FILE_NAME, ignored.getMessage());
                }
            }
        }
    }

    // 辅助方法：获取必需的配置项, 失败时记录日志并返回null
    private static <T> T getRequiredConfig(Map<String, Object> configMap, String key, Class<T> expectedType) {
        Object value = configMap.get(key);
        if (value == null) {
            log.error("Required Redis configuration '{}' is missing in {}.", key, CONFIG_FILE_NAME);
            initializationFailed = true; // 标记，即使我们返回null
            return null;
        }
        if (!expectedType.isInstance(value)) {
            if (expectedType == String.class && value instanceof Number) {
                return expectedType.cast(value.toString());
            }
            log.error("Redis configuration '{}' expected type {} but found {}. Configuration for '{}' is invalid.",
                    key, expectedType.getSimpleName(), value.getClass().getSimpleName(), key);
            initializationFailed = true; // 标记
            return null;
        }
        return expectedType.cast(value);
    }

    // 辅助方法：获取可选的配置项 (保持不变，因为它本身不抛异常)
    private static <T> Optional<T> getOptionalConfig(Map<String, Object> configMap, String key, Class<T> expectedType) {
        Object value = configMap.get(key);
        if (value == null) {
            return Optional.empty();
        }
        if (!expectedType.isInstance(value)) {
            if (expectedType == String.class && value instanceof Number) {
                return Optional.of(expectedType.cast(value.toString()));
            }
            log.warn("Redis configuration '{}' expected type {} but found {}. This optional configuration will be ignored.",
                    key, expectedType.getSimpleName(), value.getClass().getSimpleName());
            return Optional.empty();
        }
        return Optional.of(expectedType.cast(value));
    }


    public static void initPool(String host, int port, int timeout, String password, int database, Map<String, Object> poolSettingsMap, boolean useSSl) {
        // 如果之前的步骤已经标记失败，这里也应该避免初始化
        if (initializationFailed) {
            log.warn("Skipping JedisPool initialization because an earlier configuration step failed.");
            jedisPool = null; // 确保是null
            return;
        }

        try {
            JedisPoolConfig config = new JedisPoolConfig();

            if (poolSettingsMap != null) {
                getOptionalConfig(poolSettingsMap, "maxTotal", Number.class).map(Number::intValue).ifPresent(config::setMaxTotal);
                // ... (其他pool配置项设置，与之前相同)
                getOptionalConfig(poolSettingsMap, "maxIdle", Number.class).map(Number::intValue).ifPresent(config::setMaxIdle);
                getOptionalConfig(poolSettingsMap, "minIdle", Number.class).map(Number::intValue).ifPresent(config::setMinIdle);
                getOptionalConfig(poolSettingsMap, "maxWaitMillis", Number.class).map(Number::longValue).ifPresent(config::setMaxWaitMillis);
                getOptionalConfig(poolSettingsMap, "testOnBorrow", Boolean.class).ifPresent(config::setTestOnBorrow);
                getOptionalConfig(poolSettingsMap, "testOnReturn", Boolean.class).ifPresent(config::setTestOnReturn);
                getOptionalConfig(poolSettingsMap, "testWhileIdle", Boolean.class).ifPresent(config::setTestWhileIdle);
                getOptionalConfig(poolSettingsMap, "timeBetweenEvictionRunsMillis", Number.class).map(Number::longValue).ifPresent(config::setTimeBetweenEvictionRunsMillis);
                getOptionalConfig(poolSettingsMap, "minEvictableIdleTimeMillis", Number.class).map(Number::longValue).ifPresent(config::setMinEvictableIdleTimeMillis);
                getOptionalConfig(poolSettingsMap, "numTestsPerEvictionRun", Number.class).map(Number::intValue).ifPresent(config::setNumTestsPerEvictionRun);
            }

            String effectivePassword = (password != null && "null".equalsIgnoreCase(password)) ? null : password;

            // 关键：在这里创建 JedisPool
            jedisPool = new JedisPool(config, host, port, timeout, effectivePassword, database,useSSl);
            // 尝试连接以验证配置（可选，但推荐）
            try (Jedis testJedis = jedisPool.getResource()) {
                testJedis.ping(); // 如果连接失败，这里会抛出JedisException
                log.info("JedisPool initialized and connection test PING successful. Effective settings: host={}, port={}, timeout={}, database={}, passwordUsed={}, poolMaxTotal={}, poolMaxIdle={}, poolMinIdle={}, poolMaxWaitMillis={}, useSSl={}",
                        host, port, timeout, database, (effectivePassword != null),
                        config.getMaxTotal(), config.getMaxIdle(), config.getMinIdle(), config.getMaxWaitMillis(),useSSl);
                initializationFailed = false; // 明确标记成功
            } catch (JedisException je) {
                log.error("JedisPool created, but failed to connect to Redis at {}:{}. PING failed. Redis will be unavailable. Error: {}", host, port, je.getMessage(), je);
                if (jedisPool != null) {
                    jedisPool.destroy(); // 清理已创建但无法连接的池
                    jedisPool = null;
                }
                initializationFailed = true;
            }
        } catch (Exception e) { // 捕获创建JedisPoolConfig或JedisPool时的任何其他异常
            log.error("Failed to initialize JedisPool due to an unexpected error: {}. Redis will be unavailable.", e.getMessage(), e);
            if (jedisPool != null) { // 确保即使部分成功也清理
                try { jedisPool.destroy(); } catch (Exception ex) { log.warn("Exception destroying partially initialized pool", ex); }
            }
            jedisPool = null;
            initializationFailed = true;
        }
    }

    /**
     * 获取Jedis实例。如果初始化失败，此方法将返回null。
     * 调用者需要检查返回的Jedis实例是否为null。
     * @return Jedis实例，如果池未初始化或初始化失败则返回null。
     */
    public static Jedis getJedis() {
        if (initializationFailed || jedisPool == null) {
            log.warn("Attempted to get Jedis instance, but Redis initialization failed or pool is null. Returning null.");
            return null;
        }
        try {
            return jedisPool.getResource();
        } catch (JedisException e) {
            log.error("Failed to get Jedis resource from pool: {}", e.getMessage(), e);
            return null; // 获取资源失败也返回null
        }
    }

    public static void close(Jedis jedis) {
        if (jedis != null) {
            try {
                jedis.close();
            } catch (Exception e) {
                log.warn("Error closing Jedis connection: {}", e.getMessage(), e);
            }
        }
    }

    public static void destroyPool() {
        if (jedisPool != null) { // 检查jedisPool是否为null，因为初始化可能失败
            if (!jedisPool.isClosed()) {
                try {
                    jedisPool.destroy();
                    log.info("JedisPool destroyed successfully.");
                } catch (Exception e) {
                    log.error("Error destroying JedisPool: {}", e.getMessage(), e);
                }
            } else {
                log.info("JedisPool was already closed.");
            }
            jedisPool = null; // 无论如何都将其置为null
            initializationFailed = true; // 销毁后也标记为不可用状态
        } else {
            log.info("JedisPool was already null or uninitialized, nothing to destroy.");
            initializationFailed = true; // 确保状态一致
        }
    }

    /**
     * 执行Redis操作。
     * 如果RedisUtil初始化失败或获取Jedis连接失败，回调将不会执行，方法返回null。
     * 如果回调执行过程中发生异常，会记录日志并返回null。
     *
     * @param callback Redis操作回调接口
     * @param <T> 返回类型
     * @return 操作结果，或在发生错误时返回null
     */
    public static <T> T execute(RedisCallback<T> callback) {
        if (initializationFailed) {
            log.warn("Redis execute called, but initialization failed. Callback will not be executed.");
            return null;
        }
        Jedis jedis = null;
        try {
            jedis = getJedis();
            if (jedis == null) {
                // getJedis内部已经记录了日志
                return null;
            }
            return callback.doInRedis(jedis);
        } catch (JedisException je) { // Jedis特定异常
            log.error("JedisException during Redis command execution: {}", je.getMessage(), je);
            return null;
        } catch (Exception e) { // 其他通用异常
            log.error("Unexpected error during Redis command execution: {}", e.getMessage(), e);
            return null;
        } finally {
            close(jedis);
        }
    }

    public interface RedisCallback<T> {
        T doInRedis(Jedis jedis);
    }

    public static String getRedisServerTime() {
        return execute(jedis -> {
            List<String> timeResult = jedis.time();
            return (timeResult != null && !timeResult.isEmpty()) ? timeResult.get(0) : null;
        });
    }
}
