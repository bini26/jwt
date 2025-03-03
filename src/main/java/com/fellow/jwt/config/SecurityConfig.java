package com.fellow.jwt.config;

import com.fellow.jwt.service.AuthService;
import com.fellow.jwt.util.JwtUtil;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig  {

    @Bean
    protected UserDetailsService uds()  {
        var uds = new InMemoryUserDetailsManager();

        uds.createUser(User.withUsername("user").password("password").authorities("Read","ROLE_USER").build());
        var admin = User.withUsername("admin")
                .password("password")
                .authorities("Read", "Write","ROLE_ADMIN")
                .build();
        uds.createUser(admin);


        return uds;


    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return  NoOpPasswordEncoder.getInstance();
    }
    @Bean
    protected SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(c->c.disable())
                .authorizeHttpRequests(a->a.requestMatchers("/authenticate").permitAll());
        http.authorizeHttpRequests(a->a.anyRequest().authenticated());
        return http.build();
}

    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity httpSecurity) throws Exception {
        AuthenticationManagerBuilder authenticationManagerBuilder = httpSecurity.getSharedObject(AuthenticationManagerBuilder.class);

        authenticationManagerBuilder.userDetailsService(uds()).passwordEncoder(passwordEncoder());

        return authenticationManagerBuilder.build();
    }
    @Bean
    public JwtUtil jwtUtil() {
        return new JwtUtil();
    }

    // Provide AuthService as a bean
    @Bean
    public AuthService authService() {
        return new AuthService(); // Update this based on your AuthService implementation
    }

}
