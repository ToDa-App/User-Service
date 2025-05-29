package com.toda.User_Service.repository;

import com.toda.User_Service.entity.Otp;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface OtpRepository extends JpaRepository<Otp, Long> {
    List<Otp> findByUser_Email(String email);
    Optional<Otp> findTopByUser_EmailOrderByExpirationTimeDesc(String email);
}