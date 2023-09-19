package com.idaltchion.ifxfood.auth.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Autowired
	private PasswordEncoder passwordEncoder;
	
	@Autowired
	private UserDetailsService userDetailsService;
	
	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients.inMemory()
			.withClient("ifxfood-web")
				.secret(passwordEncoder.encode("12345"))
				.authorizedGrantTypes("password", "refresh_token")
				.scopes("read", "write")
				.accessTokenValiditySeconds(6 * 60 * 60) //6 horas
				.refreshTokenValiditySeconds(24 * 60 * 60) //24 horas
		.and()
			/* esse client tem a funcao de somente validar o token pelo resource server (/check_token) */
			.withClient("resource-server-client") 
				.secret(passwordEncoder.encode("54321"));
			
	}
	
	/* método necessario quando o grant type for do tipo:
	 * password: authenticationManager
	 * refresh_token: userDetailsService */
	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		endpoints
			.authenticationManager(authenticationManager)
			.userDetailsService(userDetailsService)
			.reuseRefreshTokens(false);
	}
	
	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
//		security.checkTokenAccess("permitAll()");
		security.checkTokenAccess("isAuthenticated()");
	}
	
}
