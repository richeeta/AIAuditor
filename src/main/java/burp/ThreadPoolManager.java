package burp;

import java.time.Instant;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import burp.api.montoya.MontoyaApi;

public class ThreadPoolManager {
    private static final int CORE_POOL_SIZE = 3;
    private static final int MAX_POOL_SIZE = 5;
    private static final int KEEP_ALIVE_TIME = 60;
    private static final int QUEUE_CAPACITY = 100;

    private final ThreadPoolExecutor mainExecutor;
    private final ExecutorService localExecutor;
    private final Map<String, RateLimiter> rateLimiters;
    private final MontoyaApi api;

    private static class RateLimiter {
        private final int maxRequests;
        private final int timeWindowSeconds;
        private final Queue<Instant> requestTimes;

        public RateLimiter(int maxRequests, int timeWindowSeconds) {
            this.maxRequests = maxRequests;
            this.timeWindowSeconds = timeWindowSeconds;
            this.requestTimes = new LinkedList<>();
        }

        public synchronized boolean tryAcquire() {
            Instant now = Instant.now();
            while (!requestTimes.isEmpty() && 
                   now.minusSeconds(timeWindowSeconds).isAfter(requestTimes.peek())) {
                requestTimes.poll();
            }

            if (requestTimes.size() < maxRequests) {
                requestTimes.add(now);
                return true;
            }
            return false;
        }

        public synchronized long getNextAvailableSlot() {
            if (requestTimes.isEmpty()) return 0;
            
            Instant oldestRequest = requestTimes.peek();
            long timeToWait = timeWindowSeconds - 
                            (Instant.now().getEpochSecond() - oldestRequest.getEpochSecond());
            return Math.max(0, timeToWait);
        }
    }

    public ThreadPoolManager(MontoyaApi api) {
        this.api = api;
        this.rateLimiters = new HashMap<>();
        
        // Initialize rate limiters
        rateLimiters.put("openai", new RateLimiter(50, 60));    // 50 requests per minute
        rateLimiters.put("claude", new RateLimiter(100, 60));   // 100 requests per minute
        rateLimiters.put("gemini", new RateLimiter(60, 60));    // 60 requests per minute
        rateLimiters.put("local", new RateLimiter(5, 60));      // 2 requests per minute

        // Executor for OpenAI, Claude, Gemini (parallel)
        this.mainExecutor = new ThreadPoolExecutor(
            CORE_POOL_SIZE,
            MAX_POOL_SIZE,
            KEEP_ALIVE_TIME,
            TimeUnit.SECONDS,
            new ArrayBlockingQueue<>(QUEUE_CAPACITY),
            new ThreadFactory() {
                private final AtomicInteger threadCount = new AtomicInteger(1);
                @Override
                public Thread newThread(Runnable r) {
                    Thread thread = new Thread(r);
                    thread.setName("AIAuditor-Worker-" + threadCount.getAndIncrement());
                    thread.setDaemon(true);
                    return thread;
                }
            },
            new ThreadPoolExecutor.CallerRunsPolicy()
        );

        // Executor for Local LLM (serial execution)
        this.localExecutor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r);
            t.setName("AIAuditor-LocalWorker");
            t.setDaemon(true);
            return t;
        });
    }

    public <T> CompletableFuture<T> submitTask(String provider, Callable<T> task) {
        ExecutorService selectedExecutor = provider.equalsIgnoreCase("local") ? localExecutor : mainExecutor;

        return CompletableFuture.supplyAsync(() -> {
            try {
                RateLimiter limiter = rateLimiters.get(provider);
                while (!limiter.tryAcquire()) {
                    Thread.sleep(1000); // Wait 1 second before retrying
                }
                return task.call();
            } catch (Exception e) {
                api.logging().logToError("Error in AI analysis task: " + e.getMessage());
                throw new CompletionException(e);
            }
        }, selectedExecutor);
    }

    public void shutdown() {
        mainExecutor.shutdown();
        localExecutor.shutdown();
        try {
            if (!mainExecutor.awaitTermination(30, TimeUnit.SECONDS)) {
                mainExecutor.shutdownNow();
            }
            if (!localExecutor.awaitTermination(30, TimeUnit.SECONDS)) {
                localExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            mainExecutor.shutdownNow();
            localExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    public boolean isShutdown() {
        return mainExecutor.isShutdown() && localExecutor.isShutdown();
    }

    public int getActiveCount() {
        return mainExecutor.getActiveCount();
    }

    public long getTaskCount() {
        return mainExecutor.getTaskCount();
    }

    public int getQueueSize() {
        return mainExecutor.getQueue().size();
    }
}