package com.toda.User_Service.repository;

import com.toda.User_Service.entity.JwtToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface JwtRepository extends JpaRepository<JwtToken, Long> {
    List<JwtToken> findByUser_Email(String email);
    Optional<JwtToken> findByToken(String token);
}