package com.toda.User_Service.repository;

import com.toda.User_Service.entity.ResetPasswordToken;
import com.toda.User_Service.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface ResetPasswordTokenRepository extends JpaRepository<ResetPasswordToken, Long> {

    Optional<ResetPasswordToken> findTopByUserOrderByCreatedAtDesc(User user);
}