package com.example.identityservice.service;

import com.example.identityservice.entity.User;
import com.example.identityservice.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;

    public User findByUsername(String username){
        return userRepository.findByUsername(username).orElseThrow(() -> new RuntimeException("Khong tim thay user voi username "+username));
    }

    public User findById(UUID id){
        return userRepository.findById(id).orElseThrow(() -> new RuntimeException("Khong tim thay user voi id "+id));
    }
}
