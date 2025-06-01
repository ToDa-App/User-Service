# User Service Documentation

## Overview
User Service is a RESTful API built with Spring Boot that handles user management and authentication for the application. It provides secure user registration, login, profile management, password reset, and token management using JWT and OTP verification.

---

## Key Features
- User registration with email and password validation.
- Email-based OTP verification to activate accounts.
- Secure login returning JWT tokens.
- Refresh token handling for session management.
- Password reset via OTP verification.
- User profile retrieval and update.
- Logout functionality to invalidate tokens.
- Validation on all critical input fields.
- Role-based access control (if applicable).

---

## Technologies Used
- **Java 17**
- **Spring Boot**
- **Spring Security + JWT**
- **Hibernate + JPA**
- **MySQL** (or configured relational DB)
- **Maven** for build & dependency management
- **Postman** for API testing

---

## Architecture Overview
- **Layers:** Controller, Service, Repository, Model (Entity)
- **Security:** JWT token authentication on protected endpoints
- **Validation:** Bean Validation annotations and custom validators
- **Exception Handling:** Global exception handlers to send consistent error responses

---

## API Endpoints Summary

| Method | Endpoint                | Description                          | Auth Required |
|--------|-------------------------|------------------------------------|---------------|
| POST   | `/auth/register`        | Register a new user                 | No            |
| POST   | `/auth/activate`        | Activate user account via OTP       | No            |
| POST   | `/auth/login`           | Login and receive JWT token          | No            |
| POST   | `/auth/logout`          | Logout and invalidate tokens         | Yes           |
| POST   | `/auth/refresh-token`   | Refresh JWT token                    | Yes           |
| POST   | `/auth/forgot-password` | Request OTP to reset password        | No            |
| POST   | `/auth/reset-password`  | Reset password with OTP              | No            |
| GET    | `/users/profile`        | Get current logged-in user profile  | Yes           |
| PUT    | `/users/profile`        | Update logged-in user profile        | Yes           |

---

## Detailed API Descriptions with Examples

## 🔐 Authentication APIs

---

### 📝 Register User

- **POST** `/auth/register`  
- **Description:** Create new user with email & password.

#### ✅ Request Body (JSON)
```json
{
  "email": "user@example.com",
  "password": "MyPass123!",
  "confirmPassword": "MyPass123!"
}
```

#### ✅ Response `201 Created`
```json
{
  "message": "User registered successfully. Please check your email for the OTP."
}
```

#### ❌ Errors
- `400 Bad Request` – Validation error  
- `409 Conflict` – Email already exists

---

### 🔐 Activate Account (OTP)

- **POST** `/auth/activate`

#### ✅ Request Body
```json
{
  "email": "user@example.com",
  "otp": "123456"
}
```

#### ✅ Response
```json
{
  "message": "Account activated successfully"
}
```

#### ❌ Errors
- `400 Bad Request`, `404 Not Found` – Invalid OTP or email

---

### 🔑 Login

- **POST** `/auth/login`

#### ✅ Request Body
```json
{
  "email": "user@example.com",
  "password": "MyPass123!"
}
```

#### ✅ Response
```json
{
  "accessToken": "<JWT_ACCESS_TOKEN>",
  "refreshToken": "<REFRESH_TOKEN>"
}
```

#### ❌ Errors
- `401 Unauthorized`, `400 Bad Request`

---

### 🚪 Logout

- **POST** `/auth/logout`  
- **Headers:** `Authorization: Bearer <access_token>`

#### ✅ Response
```json
{
  "message": "Logout successful"
}
```

#### ❌ Errors
- `401 Unauthorized`

---

### 🔄 Refresh Token

- **POST** `/auth/refresh-token`

#### ✅ Request Body
```json
{
  "refreshToken": "<REFRESH_TOKEN>"
}
```

#### ✅ Response
```json
{
  "accessToken": "<NEW_JWT_ACCESS_TOKEN>"
}
```

#### ❌ Errors
- `403 Forbidden`, `401 Unauthorized`

---

## 🔑 Password Reset APIs

---

### 📩 Forgot Password

- **POST** `/auth/forgot-password`

#### ✅ Request Body
```json
{
  "email": "user@example.com"
}
```

#### ✅ Response
```json
{
  "message": "OTP sent to email for password reset"
}
```

#### ❌ Errors
- `400`, `404` – Invalid email

---

### 🔁 Reset Password

- **POST** `/auth/reset-password`

#### ✅ Request Body
```json
{
  "email": "user@example.com",
  "otp": "123456",
  "newPassword": "NewPassword123!",
  "confirmPassword": "NewPassword123!"
}
```

#### ✅ Response
```json
{
  "message": "Password has been reset successfully"
}
```

#### ❌ Errors
- `400`, `403` – Invalid OTP or password mismatch

---

## 👤 User Profile APIs

---

### 👁️‍🗨️ Get Profile

- **GET** `/users/profile`  
- **Headers:** `Authorization: Bearer <access_token>`

#### ✅ Response
```json
{
  "id": 1,
  "email": "user@example.com",
  "nickname": "John",
  "profilePictureUrl": "https://cdn.example.com/profile/1.jpg"
}
```

#### ❌ Errors
- `401 Unauthorized`

---

### ✏️ Update Profile

- **PUT** `/users/profile`  
- **Headers:** `Authorization: Bearer <access_token>`  
- **Content-Type:** `multipart/form-data`

#### ✅ Request Body Example (Form Data)
- `nickname`: Johnny  
- `profilePicture`: (upload image file)

#### ✅ Response
```json
{
  "message": "Profile updated successfully"
}
```

#### ❌ Errors
- `400`, `401` – Validation, unauthenticated, invalid file

---

### 🔁 Resend OTP

- **POST** `/auth/resend-otp`

#### ✅ Request Body
```json
{
  "email": "user@example.com"
}
```

#### ✅ Response
```json
{
  "message": "OTP has been resent"
}
```

---

## 🛡️ Authorization

All authenticated routes require the following header:

```http
Authorization: Bearer <JWT_ACCESS_TOKEN>
```

---

## 📸 Profile Picture Notes

- Profile pictures are uploaded as `multipart/form-data`.
- Stored as URLs, e.g., `https://cdn.example.com/profile/<userId>.jpg`.

---
