package com.idaltchion.ifxfood.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.inMemoryAuthentication()
			.withUser("admin")
				.password(passwordEncoder().encode("12345"))
				.roles("ADMIN")
			.and()
			.withUser("user")
				.password(passwordEncoder().encode("12345"))
				.roles("USUARIO");
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		/*
		 * 1: permite somente autenticacao basica, ou seja, desabilita o formLogin
		 * 2: autoriza requests para o endpoint sem passar user/pwd
		 * 3: para os demais endpoints, é necessario estar autenticado para poder fazer as requests
		 * 4: nao cria um cookie na request, ou seja, nao mantem o estado da sessao. Logo, sempre deve passar user/pwd na request
		 * 5: TODO: estudar csrf
		 */
		http.httpBasic() //1
			.and()
				.authorizeRequests()
					.antMatchers("/v1/estados/**").permitAll() //2
					.anyRequest().authenticated() //3
			.and()
				.sessionManagement()
					.sessionCreationPolicy(SessionCreationPolicy.STATELESS) //4
			.and()
				.csrf().disable(); //5
	}
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	@Override
	protected AuthenticationManager authenticationManager() throws Exception {
		return super.authenticationManager();
	}
	
}
