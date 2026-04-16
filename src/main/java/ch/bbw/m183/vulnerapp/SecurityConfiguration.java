package ch.bbw.m183.vulnerapp;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import ch.bbw.m183.vulnerapp.repository.UserRepository;
import ch.bbw.m183.vulnerapp.service.RestfulFormService;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

	@Bean
	public UserDetailsService userDetailsService(UserRepository userRepository) {
		return username -> userRepository.findById(username)
			.map(x -> new User(
				x.getUsername(),
				"{noop}" + x.getPassword(),
				List.of()
			))
			.orElseThrow();
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http, RestfulFormService restfulFormService) throws Exception {
		return http
			.csrf(csrf -> csrf.disable())
			.authorizeHttpRequests(requests -> requests
				.requestMatchers("/", "/index.html", "/script.js", "/robots.txt").permitAll()
				.requestMatchers(HttpMethod.POST, "/login", "/logout").permitAll()
				.requestMatchers(HttpMethod.GET, "/api/blog").permitAll()
				.requestMatchers(HttpMethod.GET, "/api/blog/health").permitAll()
				.requestMatchers("/api/**").authenticated()
				.anyRequest().authenticated()
			)
			.formLogin(restfulFormService.restfulFormLogin())
			.exceptionHandling(restfulFormService.unauthorizedPerDefault())
			.build();
	}
}
