package com.substring.auth.auth_app.services.impl;

import com.substring.auth.auth_app.dtos.UserDto;
import com.substring.auth.auth_app.entities.Provider;
import com.substring.auth.auth_app.entities.User;
import com.substring.auth.auth_app.exceptions.ResourceNotFoundException;
import com.substring.auth.auth_app.helpers.UserHelper;
import com.substring.auth.auth_app.repositories.UserRepository;
import com.substring.auth.auth_app.services.UserService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
    private final ModelMapper modelMapper;

    @Override
    @Transactional
    public UserDto createUser(UserDto userDto) {
        if(userDto.getEmail()==null || userDto.getEmail().isBlank()) {
            throw new IllegalArgumentException("Email is required");
        }
        if(userRepository.existsByEmail(userDto.getEmail())) {
            throw new IllegalArgumentException("User with this email already exists");
        }
        User user = modelMapper.map(userDto,User.class);
        user.setProvider(user.getProvider()!=null?user.getProvider(): Provider.LOCAL);
        //Role Assign here to new user for authorization
        //TODO:
        User savedUser = userRepository.save(user);
        return modelMapper.map(savedUser,UserDto.class);
    }

    @Override
    @Transactional
    public UserDto getUserByEmail(String email) {
        User user = userRepository
                .findByEmail(email)
                .orElseThrow(()->new ResourceNotFoundException("User not found with given email id"));
        return modelMapper.map(user,UserDto.class);
    }

    @Override
    @Transactional
    public UserDto updateUser(UserDto userDto, String userId) {
        UUID helperUUID = UserHelper.parseUUID(userId);
        User existingUser = userRepository
                .findById(helperUUID)
                .orElseThrow(()-> new ResourceNotFoundException("User not found with given id"));
        //we are not going to change email id for this project
        if(userDto.getName()!=null) existingUser.setName(userDto.getName());
        if(userDto.getImage()!=null)  existingUser.setImage(userDto.getImage());
        if(userDto.getProvider()!=null) existingUser.setProvider(userDto.getProvider());
        //TODO: change password logic here.....
        if(userDto.getPassword()!=null) existingUser.setPassword(userDto.getPassword());
        existingUser.setEnable(userDto.isEnable());
        existingUser.setUpdatedAt(Instant.now());
        User savedUser = userRepository.save(existingUser);
        return modelMapper.map(savedUser,UserDto.class);
    }

    @Override
    @Transactional
    public void deleteUser(String userId) {
        UUID helperUUID = UserHelper.parseUUID(userId);
        User existingUser = userRepository
                .findById(helperUUID)
                .orElseThrow(()-> new ResourceNotFoundException("User not found with given id"));
        userRepository.delete(existingUser);
    }

    @Override
    @Transactional
    public UserDto getUserById(String id) {
        UUID helperUUID = UserHelper.parseUUID(id);
        User user = userRepository
                .findById(helperUUID)
                .orElseThrow(()->new ResourceNotFoundException("User not found with given id"));
        return modelMapper.map(user,UserDto.class);
    }

    @Override
    @Transactional
    public Iterable<UserDto> getAllUsers() {
        return userRepository.findAll()
                .stream()
                .map(user -> modelMapper.map(user,UserDto.class)).
                toList();
    }
}