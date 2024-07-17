package com.example.demo.config;


	import org.springframework.context.annotation.Bean;
	import org.springframework.context.annotation.Configuration;
	import org.springframework.security.config.annotation.web.builders.HttpSecurity;
	import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
	import org.springframework.security.web.SecurityFilterChain;

	@Configuration
	@EnableWebSecurity
	public class SecurityConfigg {

	    @Bean
	    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	        http
	            .authorizeRequests(authorizeRequests ->
	                authorizeRequests
	                    .antMatchers("/", "/contact", "/store/**", "/register", "/login", "/logout").permitAll()
	                    .anyRequest().authenticated()
	            )
	            .formLogin(form -> form
	                .defaultSuccessUrl("/", true)
	            )
	            .logout(logout -> logout
	                .logoutSuccessUrl("/")
	            )
	            .csrf().disable(); // Disable CSRF for simplicity (you may want to enable it in a real application)

	        return http.build();
	    }
	}