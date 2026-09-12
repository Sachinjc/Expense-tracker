package com.expensetracker.service.impl;

import com.expensetracker.entity.RefreshToken;
import com.expensetracker.entity.User;
import com.expensetracker.repository.RefreshTokenRepository;
import com.expensetracker.repository.UserRepository;
import com.expensetracker.service.RefreshTokenService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
public class RefreshTokenServiceImpl implements RefreshTokenService {

    @Value("${app.jwt.refresh-expiration}")
    private Long refreshTokenDurationMs;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private UserRepository userRepository;

    @Override
    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    @Override
    @Transactional
    public RefreshToken createRefreshToken(Long userId) {

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        Optional<RefreshToken> existingToken =
                refreshTokenRepository.findByUser(user);

        RefreshToken refreshToken;

        if (existingToken.isPresent()) {
            // Existing refresh token found.
            // Update the same database row instead of inserting a new one.
            refreshToken = existingToken.get();
        } else {
            // No refresh token exists for this user.
            // Create a new one.
            refreshToken = new RefreshToken();
            refreshToken.setUser(user);
        }

        // Generate a new token for every login
        refreshToken.setToken(UUID.randomUUID().toString());

        // Set new expiration time
        refreshToken.setExpiryDate(
                Instant.now().plusMillis(refreshTokenDurationMs)
        );

        // Save new token OR update existing token
        return refreshTokenRepository.save(refreshToken);
    }

    @Override
    public RefreshToken verifyExpiration(RefreshToken token) {

        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {

            refreshTokenRepository.delete(token);

            throw new RuntimeException(
                    "Refresh token was expired. Please make a new signin request"
            );
        }

        return token;
    }

    @Override
    @Transactional
    public int deleteByUserId(Long userId) {

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        return refreshTokenRepository.deleteByUser(user);
    }
}