package com.easybbs.aspect;

import com.easybbs.annotation.RateLimit;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Aspect
@Component
public class RateLimitAspect {

    @Autowired
    private StringRedisTemplate redisTemplate;

    @Around("@annotation(rateLimit)")
    public Object limit(ProceedingJoinPoint joinPoint, RateLimit rateLimit) throws Throwable {
        String key = buildKey(joinPoint, rateLimit);
        int limit = rateLimit.limit();
        int window = rateLimit.window();

        Long count = redisTemplate.opsForValue().increment(key);
        if (count == 1) {
            // 第一次访问，设置过期时间
            redisTemplate.expire(key, Duration.ofSeconds(window));
        }

        if (count != null && count > limit) {
            throw new RuntimeException("请求过于频繁，请稍后再试");
        }

        return joinPoint.proceed();
    }

    private String buildKey(ProceedingJoinPoint joinPoint, RateLimit rateLimit) {
        // 可根据需要拼接用户IP、接口路径等信息
        String prefix = "rate_limit:";
        return prefix + rateLimit.key();
    }
}
