package com.auth.security.jwt;

import com.auth.security.services.UserDetailsServiceImpl;
import io.jsonwebtoken.ExpiredJwtException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AuthTokenFilter extends OncePerRequestFilter {
	@Autowired
	private JwtUtils jwtUtils;

	@Autowired
	private UserDetailsServiceImpl userDetailsService;

	private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		String jwt = parseJwtFromCookie(request);

		if(jwt != null) {
			try {
				if(jwtUtils.validateJwtToken(jwt)) {
				String username = jwtUtils.getUserNameFromJwtToken(jwt);

				UserDetails userDetails = userDetailsService.loadUserByUsername(username);
				UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
						userDetails, null, userDetails.getAuthorities());
				authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

				SecurityContextHolder.getContext().setAuthentication(authentication);
				}
			} catch (ExpiredJwtException e) {

				String refreshToken = parseRefreshTokenFromCookie(request);

				try {

					if (jwtUtils.validateJwtToken(refreshToken)) {
//						logger.error("Refresh token is not expired: {}", refreshToken);
						String activeUser = jwtUtils.getUserNameFromRefreshToken(refreshToken);
						String newJwt = jwtUtils.generateTokenFromUsername(activeUser);

						Cookie jwtCookie = new Cookie("jwt", newJwt);
						jwtCookie.setMaxAge(24 * 60 * 60);
						jwtCookie.setHttpOnly(true);
						jwtCookie.setPath("/");
						response.addCookie(jwtCookie);

						String username = jwtUtils.getUserNameFromJwtToken(newJwt);

						UserDetails userDetails = userDetailsService.loadUserByUsername(username);
						UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
								userDetails, null, userDetails.getAuthorities());
						authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

						SecurityContextHolder.getContext().setAuthentication(authentication);

					}
				} catch (ExpiredJwtException f) {
//					logger.error("Refresh token is expired: {}", refreshToken);

					Cookie jwtCookie = new Cookie("jwt", null);
					jwtCookie.setMaxAge(0);
					jwtCookie.setHttpOnly(true);
					jwtCookie.setPath("/");
					response.addCookie(jwtCookie);

					Cookie refreshTokenCookie = new Cookie("refreshToken", null);
					refreshTokenCookie.setMaxAge(0);
					refreshTokenCookie.setHttpOnly(true);
					refreshTokenCookie.setPath("/");
					response.addCookie(refreshTokenCookie);
				}
			}

			catch (Exception e) {
				logger.error("Cannot set user authentication: {}", e.getMessage());
			}
		}

		filterChain.doFilter(request, response);
	}

	private String parseJwtFromCookie(HttpServletRequest request) {
		Cookie[] cookies = request.getCookies();
		if(cookies == null)
			return null;
		else {
			for (Cookie cookie : cookies) {
				if ("jwt".equals(cookie.getName())) {
					String accessToken = cookie.getValue();
					if (accessToken == null) return null;
					return accessToken;
				}
			}
		}
		return null;
	}

	private String parseRefreshTokenFromCookie(HttpServletRequest request) {
		Cookie[] cookies = request.getCookies();
		if(cookies == null)
			return null;
		else {
			for (Cookie cookie : cookies) {
				if ("refreshToken".equals(cookie.getName())) {
					String accessToken = cookie.getValue();
					if (accessToken == null) return null;
					return accessToken;
				}
			}
		}
		return null;
	}
}