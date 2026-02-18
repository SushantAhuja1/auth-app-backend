package com.substring.auth.auth_app.controllers;

import com.substring.auth.auth_app.dtos.LoginRequest;
import com.substring.auth.auth_app.dtos.RefreshTokenRequest;
import com.substring.auth.auth_app.dtos.TokenResponse;
import com.substring.auth.auth_app.dtos.UserDto;
import com.substring.auth.auth_app.entities.RefreshToken;
import com.substring.auth.auth_app.entities.User;
import com.substring.auth.auth_app.repositories.RefreshTokenRepository;
import com.substring.auth.auth_app.repositories.UserRepository;
import com.substring.auth.auth_app.security.CookieService;
import com.substring.auth.auth_app.security.JwtService;
import com.substring.auth.auth_app.services.AuthService;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final ModelMapper modelMapper;
    private final RefreshTokenRepository refreshTokenRepository;
    private final CookieService cookieService;

    //login-controller
    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(
            @RequestBody LoginRequest loginRequest,
            HttpServletResponse response
    ) {
        //authenticate the user
        Authentication authenticate = authenticate(loginRequest);
        User user = userRepository.findByEmail(loginRequest.email()).orElseThrow(()->new BadCredentialsException("Invalid Email or Password"));
        if(!user.isEnable()) {
            throw  new DisabledException("User account is disabled");
        }

        String jti = UUID.randomUUID().toString();
        var refreshTokenOb = RefreshToken.builder()
                .jti(jti)
                .user(user)
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(jwtService.getRefreshTtlSeconds()))
                .revoked(false)
                .build();
        //refresh-token-information-saved
        refreshTokenRepository.save(refreshTokenOb);

        //access-token-generate
        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user, refreshTokenOb.getJti());

        //use cookie service to attach refresh token to cookie
        cookieService.attachRefreshCookie(response,refreshToken,(int)jwtService.getRefreshTtlSeconds());
        cookieService.addNoStoreHeaders(response);
        TokenResponse tokenResponse = TokenResponse.of(accessToken,refreshToken,jwtService.getAccessTtlSeconds(),modelMapper.map(user, UserDto.class));
        return ResponseEntity.ok(tokenResponse);
    }

    private Authentication authenticate(LoginRequest loginRequest) {
        try {
            return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.email(), loginRequest.password()));
        } catch (Exception e) {
            throw new BadCredentialsException("Username or password is incorrect");
        }
    }


    @PostMapping("/register")
    public ResponseEntity<UserDto> registerUser(@RequestBody UserDto userDto) {
        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(authService.registerUser(userDto));
    }


    //access-token-refresh-controller-renew-access-token
    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refreshToken(
            @RequestBody(required = false) RefreshTokenRequest body,
            HttpServletResponse response,
            HttpServletRequest request
    ) {
        String refreshToken = readRefreshTokenFromRequest(body, request).orElseThrow(()->new BadCredentialsException("Refresh token is missing"));
        if(!jwtService.isRefreshToken(refreshToken)) {
            throw new BadCredentialsException("Invalid refresh token type");
        }
        String jti = jwtService.getJti(refreshToken);
        UUID userId = jwtService.getUserId(refreshToken);
        RefreshToken storedRefreshToken = refreshTokenRepository.findByJti(jti).orElseThrow(()->new BadCredentialsException("Refresh token is not recognized"));
        if(storedRefreshToken.isRevoked()) {
            throw new BadCredentialsException("Refresh token is revoked");
        }
        if(storedRefreshToken.getExpiresAt().isBefore(Instant.now())) {
            throw new BadCredentialsException("Refresh token is expired");
        }
        if(!storedRefreshToken.getUser().getId().equals(userId)) {
            throw new BadCredentialsException("Token user mismatch");
        }
        //refresh token rotate
        storedRefreshToken.setRevoked(true);
        String newJti = UUID.randomUUID().toString();
        storedRefreshToken.setReplacedBy(newJti);
        refreshTokenRepository.save(storedRefreshToken);
        User user = storedRefreshToken.getUser();
        var newRefreshToken = RefreshToken.builder()
                .jti(newJti)
                .user(user)
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(jwtService.getRefreshTtlSeconds()))
                .revoked(false)
                .build();
        refreshTokenRepository.save(newRefreshToken);
        String newAccessToken = jwtService.generateAccessToken(user);
        String newRefreshTokenStr = jwtService.generateRefreshToken(user, newJti);
        cookieService.attachRefreshCookie(response,newRefreshTokenStr,(int)jwtService.getRefreshTtlSeconds());
        cookieService.addNoStoreHeaders(response);
        return ResponseEntity.ok(TokenResponse.of(newAccessToken,newRefreshTokenStr,jwtService.getAccessTtlSeconds(),modelMapper.map(user, UserDto.class)));
    }

    private Optional<String> readRefreshTokenFromRequest(RefreshTokenRequest body, HttpServletRequest request) {
        // 1) prefer reading refresh token from cookie
        if(request.getCookies()!=null) {
            Optional<String> fromCookie = Arrays.stream(request.getCookies())
                    .filter(c->cookieService.getRefreshTokenCookieName().equals(c.getName()))
                    .map(Cookie::getValue)
                    .filter(v->!v.isBlank())
                    .findFirst();
            if(fromCookie.isPresent()) {
                return fromCookie;
            }
        }
        // 2) fallback to reading refresh token from request body
        if(body!=null && body.refreshToken()!=null && !body.refreshToken().isBlank()) {
            return Optional.of(body.refreshToken());
        }
        // custom header
        String refreshHeader = request.getHeader("X-Refresh-Token");
        if(refreshHeader!=null && !refreshHeader.isBlank()) {
            return Optional.of(refreshHeader.trim());
        }
        // authorization header
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if(authHeader!=null && authHeader.regionMatches(true,0,"Bearer ",0,7)) {
            String token = authHeader.substring(7).trim();
            if(!token.isEmpty()) {
                try {
                    if(jwtService.isAccessToken(token)) {
                        return Optional.of(token);
                    }
                } catch (Exception ignored) {
                    // ignore parsing exceptions and return empty
                }
            }
        }
        //no refresh token found
        return Optional.empty();
    }

    //logout-controller
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request, HttpServletResponse response) {
       readRefreshTokenFromRequest(null,request).ifPresent(token->{
           try {
               if(jwtService.isRefreshToken(token)) {
                   String jti = jwtService.getJti(token);
                   refreshTokenRepository.findByJti(jti).ifPresent(rt->{
                       rt.setRevoked(true);
                       refreshTokenRepository.save(rt);
                   });
               }
           }
              catch (JwtException e) {
                //invalid token, ignore
              }
       });
       cookieService.clearRefreshCookie(response);
       cookieService.addNoStoreHeaders(response);
       SecurityContextHolder.clearContext();
       return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }

}