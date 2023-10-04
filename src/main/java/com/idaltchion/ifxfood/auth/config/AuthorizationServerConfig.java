package com.idaltchion.ifxfood.auth.config;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

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
			/* client utilizado no Password Credentials Flow */
			.withClient("ifxfood-web")
				.secret(passwordEncoder.encode("12345"))
				.authorizedGrantTypes("password", "refresh_token")
				.scopes("read", "write")
				.accessTokenValiditySeconds(6 * 60 * 60) //6 horas
				.refreshTokenValiditySeconds(24 * 60 * 60) //24 horas
		.and()
			/* client utilizado no Client Credentials Flow */
			.withClient("ifxfood-thirty")
				.secret(passwordEncoder.encode("12345"))
				.authorizedGrantTypes("client_credentials")
				.scopes("read", "write")
		.and()
			/* client utilizado no Authorization Code Flow 
			 * redirect-url: http://auth.ifxfood.local:8081/oauth/authorize?response_type=code&client_id=<client-id>&state=<state>&redirect_uri=<url de redirecionamento>
			 * */
			.withClient("ifxfood-code")
				.secret(passwordEncoder.encode("12345"))
				.authorizedGrantTypes("authorization_code")
				.redirectUris("http://ui.ifxfood.local:8082")
				.scopes("read", "write")
		.and()
			/* client utilizado no Implicit Flow 
			 * redirect-url: http://auth.ifxfood.local:8081/oauth/authorize?response_type=token&client_id=<client-id>&state=<state>&redirect_uri=<url de redirecionamento>
			 * */
			.withClient("ifxfood-implicit")
				.authorizedGrantTypes("implicit")
				.redirectUris("http://ui.ifxfood.local:8082")
				.scopes("read", "write")
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
			.reuseRefreshTokens(false)
			.accessTokenConverter(jwtAccessTokenConverter())
			.tokenGranter(tokenGranter(endpoints));
	}
	
	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
//		security.checkTokenAccess("permitAll()");
		security.checkTokenAccess("isAuthenticated()");
	}
	
	private TokenGranter tokenGranter(AuthorizationServerEndpointsConfigurer endpoints) {
		var pkceAuthorizationCodeTokenGranter = new PkceAuthorizationCodeTokenGranter(endpoints.getTokenServices(),
				endpoints.getAuthorizationCodeServices(), endpoints.getClientDetailsService(),
				endpoints.getOAuth2RequestFactory());
		
		var granters = Arrays.asList(
				pkceAuthorizationCodeTokenGranter, endpoints.getTokenGranter());
		
		return new CompositeTokenGranter(granters);
	}
	
	@Bean
	public JwtAccessTokenConverter jwtAccessTokenConverter() {
		/* The secret length must be at least 256 bits */
		var key = "12345678901234567890123456789012";
		JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter();
		jwtAccessTokenConverter.setSigningKey(key);
		return jwtAccessTokenConverter;
	}
	
}
