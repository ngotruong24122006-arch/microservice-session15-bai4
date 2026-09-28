package com.example.identityservice.service;

import com.example.identityservice.dto.TokenResponseDTO;
import com.example.identityservice.entity.RefreshToken;
import com.example.identityservice.entity.User;
import com.example.identityservice.repository.RefreshTokenRepository;
import com.example.identityservice.repository.UserRepository;
import com.example.identityservice.security.JwtUtils;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final JwtUtils jwtUtils;

    @Value("${app.jwt.refresh-token-expiration}")
    private long refreshTokenExpiration;

    public RefreshToken createRefreshToken(UUID userId) {

        User user = userRepository.findById(userId)
                .orElseThrow(() ->
                        new RuntimeException("User not found"));

        RefreshToken refreshToken = RefreshToken.builder()
                .token(UUID.randomUUID().toString())
                .expiryDate(
                        Instant.now()
                                .plusMillis(refreshTokenExpiration)
                )
                .user(user)
                .build();

        return refreshTokenRepository.save(refreshToken);
    }

    public RefreshToken verifyExpiration(String token) {

        RefreshToken refreshToken =
                refreshTokenRepository.findByToken(token)
                        .orElseThrow(() ->
                                new RuntimeException(
                                        "Refresh token not found"));

        if (refreshToken.getExpiryDate().isBefore(Instant.now())) {

            refreshTokenRepository.delete(refreshToken);

            throw new RuntimeException(
                    "Refresh token was expired");
        }

        return refreshToken;
    }

    @Transactional
    public TokenResponseDTO refreshToken(String requestToken) {

        RefreshToken oldToken =
                refreshTokenRepository.findByToken(requestToken)
                        .orElseThrow(() ->
                                new RuntimeException(
                                        "Refresh token not found"));

        if (oldToken.getExpiryDate().isBefore(Instant.now())) {

            refreshTokenRepository.delete(oldToken);

            throw new RuntimeException(
                    "Refresh token expired");
        }

        User user = oldToken.getUser();

        UUID userId = user.getId();

        refreshTokenRepository.delete(oldToken);

        String newAccessToken =
                jwtUtils.generateAccessToken(user);

        RefreshToken newRefreshToken =
                createRefreshToken(userId);

        return TokenResponseDTO.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken.getToken())
                .build();
    }
}