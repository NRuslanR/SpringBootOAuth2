package edu.example.springoauth2;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@SpringBootApplication
@RestController
@RequestMapping(path = "/")
public class OAuth2WebApplication {

	public static void main(String[] args) {
		
		SpringApplication.run(OAuth2WebApplication.class, args);
	}

	@GetMapping(path = "/user")
	public Map<String, Object> user(@AuthenticationPrincipal OAuth2User user)
	{
		List<String> validAttrs = Arrays.asList("login", "name", "email", "bio", "location");

		return 
				user
					.getAttributes()
					.entrySet()
					.stream()
					.filter(e -> !Objects.isNull(e.getValue()) && validAttrs.contains(e.getKey()))
					.collect(Collectors.toUnmodifiableMap(e -> e.getKey(), e -> e.getValue()));
	}
	
	@GetMapping("/oidc-user")
	public OidcUser getOidcUser()
	{
		var principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		
		if (principal instanceof OidcUser)
			return (OidcUser)principal;
		
		return null;
	}
	
	@GetMapping(path = "/error")
	public String getCurrentError(HttpServletRequest request)
	{
		String errorMessage = (String)request.getSession().getAttribute("error.message");
		
		request.getSession().removeAttribute("error.message");
		
		return errorMessage;
	}
	
	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception
	{
		CsrfTokenRequestAttributeHandler attributeHandler = new CsrfTokenRequestAttributeHandler();
		
		attributeHandler.setCsrfRequestAttributeName(null);
	
		OidcUserService oidcUserService = new OidcUserService();
		
		Set<String> scopes = new HashSet<>();
		
		scopes.add("https://www.googleapis.com/auth/userinfo.email");
		scopes.add("https://www.googleapis.com/auth/userinfo.profile");
		
		oidcUserService.setAccessibleScopes(scopes);
		
		return 
			http
				.cors(cust -> cust.disable())
				.authorizeHttpRequests(a ->
					a.requestMatchers("/", "/error", "/index.html", "/webjars/**", "/js/**").permitAll()
					.anyRequest().authenticated()
				)
				.exceptionHandling(e -> 
					e.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
				)
				.oauth2Login(
					cust -> {
						
						cust
							.loginPage("/login.html").permitAll()
							.userInfoEndpoint(u -> u.oidcUserService(oidcUserService))
							.defaultSuccessUrl("/")
							.authorizationEndpoint(ac -> ac.baseUri("/login/oauth2"))
							.failureHandler(
								new SimpleUrlAuthenticationFailureHandler("/index.html") {
									
									@Override
									public void onAuthenticationFailure(
											HttpServletRequest request, 
											HttpServletResponse response,
											AuthenticationException exception
									) throws IOException, ServletException 
									{
										request.getSession().setAttribute("error.message", exception.getMessage());
										
										super.onAuthenticationFailure(request, response, exception);
									}
									
								}
							);
					}
				)
				.logout(cust -> 
					cust.logoutUrl("/logout")
					.logoutSuccessUrl("/")
					.invalidateHttpSession(true)
					.deleteCookies("JSESSIONID")
					.clearAuthentication(true)
				)
				.csrf(csrf -> 
					csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
					.csrfTokenRequestHandler(attributeHandler)
				)
				.build();
	}
}
