package com.substring.auth.auth_app.services;

import com.substring.auth.auth_app.dtos.UserDto;
import com.substring.auth.auth_app.entities.User;

public interface UserService {
    //create-user
    UserDto createUser(UserDto userDto);
    //get-user-by-email
    UserDto getUserByEmail(String email);
    //update-user
    UserDto updateUser(UserDto userDto, String userId);
    //delete-user
    void deleteUser(String userId);
    //get-user-by-id
    UserDto getUserById(String id);
    //get-all-users
    Iterable<UserDto> getAllUsers();
}