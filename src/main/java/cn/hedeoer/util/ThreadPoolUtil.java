package cn.hedeoer.util;

import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 线程池工具类，用于创建和管理各种类型的线程池
 */
public class ThreadPoolUtil {
    
    /**
     * 默认线程池配置
     */
    private static final int DEFAULT_CORE_POOL_SIZE = 5;
    private static final int DEFAULT_MAX_POOL_SIZE = 10;
    private static final int DEFAULT_KEEP_ALIVE_TIME = 60;
    private static final TimeUnit DEFAULT_TIME_UNIT = TimeUnit.SECONDS;
    private static final int DEFAULT_QUEUE_CAPACITY = 1000;
    private static final RejectedExecutionHandler DEFAULT_HANDLER = new ThreadPoolExecutor.CallerRunsPolicy();
    
    /**
     * 单例通用线程池
     */
    private static volatile ThreadPoolExecutor commonPool;
    
    /**
     * 获取通用线程池
     */
    public static ThreadPoolExecutor getCommonPool() {
        if (commonPool == null) {
            synchronized (ThreadPoolUtil.class) {
                if (commonPool == null) {
                    commonPool = new ThreadPoolExecutor(
                            DEFAULT_CORE_POOL_SIZE,
                            DEFAULT_MAX_POOL_SIZE,
                            DEFAULT_KEEP_ALIVE_TIME,
                            DEFAULT_TIME_UNIT,
                            new LinkedBlockingQueue<>(DEFAULT_QUEUE_CAPACITY),
                            new NamedThreadFactory("common-pool"),
                            DEFAULT_HANDLER
                    );
                }
            }
        }
        return commonPool;
    }
    
    /**
     * 创建自定义线程池
     */
    public static ThreadPoolExecutor createThreadPool(
            int corePoolSize,
            int maximumPoolSize,
            long keepAliveTime,
            TimeUnit unit,
            int queueCapacity,
            String poolName,
            RejectedExecutionHandler handler) {
        
        return new ThreadPoolExecutor(
                corePoolSize,
                maximumPoolSize,
                keepAliveTime,
                unit,
                new LinkedBlockingQueue<>(queueCapacity),
                new NamedThreadFactory(poolName),
                handler
        );
    }
    
    /**
     * 创建自定义线程池（使用默认拒绝策略）
     */
    public static ThreadPoolExecutor createThreadPool(
            int corePoolSize,
            int maximumPoolSize,
            long keepAliveTime,
            TimeUnit unit,
            int queueCapacity,
            String poolName) {
        
        return createThreadPool(
                corePoolSize,
                maximumPoolSize,
                keepAliveTime,
                unit,
                queueCapacity,
                poolName,
                DEFAULT_HANDLER
        );
    }
    
    /**
     * 创建固定大小的线程池
     */
    public static ThreadPoolExecutor createFixedThreadPool(int nThreads, String poolName) {
        return new ThreadPoolExecutor(
                nThreads,
                nThreads,
                0L,
                TimeUnit.MILLISECONDS,
                new LinkedBlockingQueue<>(),
                new NamedThreadFactory(poolName),
                DEFAULT_HANDLER
        );
    }
    
    /**
     * 创建单线程的线程池
     */
    public static ThreadPoolExecutor createSingleThreadPool(String poolName) {
        return createFixedThreadPool(1, poolName);
    }
    
    /**
     * 创建可缓存线程池
     */
    public static ThreadPoolExecutor createCachedThreadPool(String poolName) {
        return new ThreadPoolExecutor(
                0,
                Integer.MAX_VALUE,
                60L,
                TimeUnit.SECONDS,
                new SynchronousQueue<>(),
                new NamedThreadFactory(poolName),
                DEFAULT_HANDLER
        );
    }
    
    /**
     * 创建可调度线程池
     */
    public static ScheduledThreadPoolExecutor createScheduledThreadPool(int corePoolSize, String poolName) {
        return new ScheduledThreadPoolExecutor(
                corePoolSize,
                new NamedThreadFactory(poolName)
        );
    }
    
    /**
     * 关闭线程池
     */
    public static void shutdown(ExecutorService threadPool) {
        if (threadPool != null && !threadPool.isShutdown()) {
            threadPool.shutdown();
        }
    }
    
    /**
     * 立即关闭线程池
     */
    public static void shutdownNow(ExecutorService threadPool) {
        if (threadPool != null && !threadPool.isShutdown()) {
            threadPool.shutdownNow();
        }
    }
    
    /**
     * 优雅关闭线程池
     * 
     * @param threadPool 线程池
     * @param timeout 等待时间
     * @param unit 时间单位
     */
    public static void gracefulShutdown(ExecutorService threadPool, long timeout, TimeUnit unit) {
        if (threadPool != null && !threadPool.isShutdown()) {
            threadPool.shutdown();
            try {
                if (!threadPool.awaitTermination(timeout, unit)) {
                    threadPool.shutdownNow();
                    if (!threadPool.awaitTermination(timeout, unit)) {
                        System.err.println("线程池未能完全终止");
                    }
                }
            } catch (InterruptedException ie) {
                threadPool.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
    }
    
    /**
     * 获取线程池状态信息
     */
    public static String getThreadPoolStatus(ThreadPoolExecutor threadPool) {
        if (threadPool == null) {
            return "ThreadPool is null";
        }
        
        return String.format("ThreadPool Status: [%s], Active: %d, Completed: %d, Task: %d, Queue Size: %d",
                threadPool.isShutdown() ? "Shutdown" : "Running",
                threadPool.getActiveCount(),
                threadPool.getCompletedTaskCount(),
                threadPool.getTaskCount(),
                threadPool.getQueue().size());
    }
    
    /**
     * 自定义线程工厂，可以给线程指定名称
     */
    private static class NamedThreadFactory implements ThreadFactory {
        private static final AtomicInteger poolNumber = new AtomicInteger(1);
        private final ThreadGroup group;
        private final AtomicInteger threadNumber = new AtomicInteger(1);
        private final String namePrefix;
        
        NamedThreadFactory(String poolName) {
            SecurityManager s = System.getSecurityManager();
            group = (s != null) ? s.getThreadGroup() : Thread.currentThread().getThreadGroup();
            namePrefix = poolName + "-thread-";
        }
        
        @Override
        public Thread newThread(Runnable r) {
            Thread t = new Thread(group, r, namePrefix + threadNumber.getAndIncrement(), 0);
            if (t.isDaemon()) {
                t.setDaemon(false);
            }
            if (t.getPriority() != Thread.NORM_PRIORITY) {
                t.setPriority(Thread.NORM_PRIORITY);
            }
            return t;
        }
    }
    
    /**
     * 使用示例
     */
    public static void main(String[] args) {
        // 获取通用线程池
        ThreadPoolExecutor commonPool = ThreadPoolUtil.getCommonPool();
        commonPool.execute(() -> System.out.println("通用线程池任务执行"));
        
        // 创建自定义线程池
        ThreadPoolExecutor customPool = ThreadPoolUtil.createThreadPool(
                2, 4, 30, TimeUnit.SECONDS, 
                50, "custom-pool");
        
        // 提交任务
        Future<String> future = customPool.submit(() -> {
            System.out.println("自定义线程池任务执行");
            return "任务结果";
        });
        
        // 打印线程池状态
        System.out.println(ThreadPoolUtil.getThreadPoolStatus(customPool));
        
        // 创建定时任务线程池
        ScheduledThreadPoolExecutor scheduledPool = 
                ThreadPoolUtil.createScheduledThreadPool(2, "scheduled-pool");
        
        // 安排定时任务
        scheduledPool.scheduleAtFixedRate(
                () -> System.out.println("定时任务执行"), 
                1, 3, TimeUnit.SECONDS);
        
        try {
            Thread.sleep(10000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        
        // 优雅关闭线程池
        ThreadPoolUtil.gracefulShutdown(customPool, 5, TimeUnit.SECONDS);
        ThreadPoolUtil.gracefulShutdown(scheduledPool, 5, TimeUnit.SECONDS);
        // 注意：通常情况下不要关闭通用线程池，除非应用即将结束
    }
}
