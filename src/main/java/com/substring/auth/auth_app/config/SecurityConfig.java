package com.substring.auth.auth_app.config;

import com.substring.auth.auth_app.dtos.ApiError;
import com.substring.auth.auth_app.security.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import tools.jackson.databind.ObjectMapper;

import java.util.Map;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    //this is only for practice. This is not a production ready practice
    //learn only for knowledge and testing
    //but learn
    /*
    @Bean
    public UserDetailsService users() {
        User.UserBuilder userBuilder = User.withDefaultPasswordEncoder();
        UserDetails user1 = userBuilder
                .username("user1")
                .password("abc")
                .roles("ADMIN")
                .build();
        UserDetails user2 = userBuilder
                .username("user2")
                .password("xyz")
                .roles("USER")
                .build();
        UserDetails user3 = userBuilder
                .username("user3")
                .password("pqr")
                .roles("ADMIN")
                .build();
        return new InMemoryUserDetailsManager(user1, user2, user3);
    }*/
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(Customizer.withDefaults())
                .sessionManagement(sm->sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(requests -> requests
                .requestMatchers("/api/v1/auth/login").permitAll()
                .requestMatchers("/api/v1/auth/register").permitAll()
                .anyRequest().authenticated()
        );
        http.exceptionHandling(ex->ex.authenticationEntryPoint((req,res,e)->{
            e.printStackTrace();
            res.setStatus(401);
            res.setContentType("application/json");
            String message = e.getMessage();
            String error = (String) req.getAttribute("error");
            if(error!=null) {
                message = error;
            }
            //Map<String,Object> errMap = Map.of("message",message,"status code",401) ;
            var apiError = ApiError.of(HttpStatus.UNAUTHORIZED.value(),"Unauthorized Access",message,req.getRequestURI());
            var objectMapper = new ObjectMapper();
            res.getWriter().write(objectMapper.writeValueAsString(apiError));
        }));
        http.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) {
        return configuration.getAuthenticationManager();
    }

}