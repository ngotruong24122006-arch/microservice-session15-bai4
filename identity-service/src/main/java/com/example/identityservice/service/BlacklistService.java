package com.example.identityservice.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

@Service
@RequiredArgsConstructor
public class BlacklistService {

    private final StringRedisTemplate redisTemplate;

    @Value("${app.jwt.secret}")
    private String jwtSecret;

    public void blacklistToken(String token) {

        Claims claims = Jwts.parserBuilder()
                .setSigningKey(
                        Keys.hmacShaKeyFor(
                                jwtSecret.getBytes(
                                        StandardCharsets.UTF_8
                                )
                        )
                )
                .build()
                .parseClaimsJws(token)
                .getBody();

        String jti = claims.getId();

        Date expiration = claims.getExpiration();

        long ttl =
                expiration.getTime()
                        - System.currentTimeMillis();

        if (ttl <= 0) {
            return;
        }

        String key = "blacklist:" + jti;

        redisTemplate.opsForValue().set(
                key,
                "revoked",
                Duration.ofMillis(ttl)
        );
    }

    public boolean isBlacklisted(String jti) {

        return Boolean.TRUE.equals(
                redisTemplate.hasKey(
                        "blacklist:" + jti
                )
        );
    }
}