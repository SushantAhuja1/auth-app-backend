package com.substring.auth.auth_app.services;

import com.substring.auth.auth_app.dtos.UserDto;

public interface AuthService {
    //register-user
    UserDto registerUser(UserDto userDto);
    //login-user
}