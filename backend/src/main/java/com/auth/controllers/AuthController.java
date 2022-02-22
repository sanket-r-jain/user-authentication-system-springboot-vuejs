package com.auth.controllers;

import com.auth.models.ERole;
import com.auth.models.Role;
import com.auth.models.User;
import com.auth.payload.request.LoginRequest;
import com.auth.payload.request.SignupRequest;
import com.auth.payload.response.JwtResponse;
import com.auth.payload.response.MessageResponse;
import com.auth.repository.RoleRepository;
import com.auth.repository.UserRepository;
import com.auth.security.jwt.JwtUtils;
import com.auth.security.services.UserDetailsImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@CrossOrigin(origins = "http://localhost:8081", maxAge = 3600, allowCredentials = "true")
@RestController
@RequestMapping("/api/auth")
public class AuthController {
	@Autowired
	AuthenticationManager authenticationManager;

	@Autowired
	UserRepository userRepository;

	@Autowired
	RoleRepository roleRepository;

	@Autowired
	PasswordEncoder encoder;

	@Autowired
	JwtUtils jwtUtils;

	@PostMapping("/signin")
	public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {

		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

		SecurityContextHolder.getContext().setAuthentication(authentication);

		UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

		String jwt = jwtUtils.generateJwtToken(authentication);
		String refreshToken = jwtUtils.generateRefreshToken(authentication);

		List<String> roles = userDetails.getAuthorities().stream()
				.map(item -> item.getAuthority())
				.collect(Collectors.toList());

		ResponseCookie jwtCookie = ResponseCookie.from("jwt", jwt)
                .httpOnly(true)
				.path("/")
                .maxAge(24 * 60 * 60)
                .build();

		ResponseCookie refreshTokenCookie = ResponseCookie.from("refreshToken", refreshToken)
				.httpOnly(true)
				.path("/")
				.maxAge(24 * 60 * 60)
				.build();

		return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, jwtCookie.toString(), refreshTokenCookie.toString()).body(new JwtResponse(
				userDetails.getId(),
				userDetails.getUsername(),
				roles));
	}

	@PostMapping("/signup")
	public ResponseEntity<?> registerUser(@RequestBody SignupRequest signUpRequest) {
		if (userRepository.existsByUsername(signUpRequest.getUsername())) {
			return ResponseEntity
					.badRequest()
					.body(new MessageResponse("Error: Username is already taken!"));
		}

		if (userRepository.existsByEmail(signUpRequest.getEmail())) {
			return ResponseEntity
					.badRequest()
					.body(new MessageResponse("Error: Email is already in use!"));
		}

		User user = new User(signUpRequest.getUsername(),
							 signUpRequest.getEmail(),
							 encoder.encode(signUpRequest.getPassword()));

		Set<String> strRoles = signUpRequest.getRole();
		Set<Role> roles = new HashSet<>();

		if (strRoles == null) {
			Role userRole = roleRepository.findByName(ERole.ROLE_USER)
					.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
			roles.add(userRole);
		} else {
			strRoles.forEach(role -> {
				switch (role) {
				case "admin":
					Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
							.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
					roles.add(adminRole);

					break;
				case "mod":
					Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
							.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
					roles.add(modRole);

					break;
				default:
					Role userRole = roleRepository.findByName(ERole.ROLE_USER)
							.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
					roles.add(userRole);
				}
			});
		}

		user.setRoles(roles);
		userRepository.save(user);

		return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
	}

	@PostMapping("/refreshtoken")
	public ResponseEntity<?> refreshtoken(@CookieValue(name = "jwt") String jwt,
										  @CookieValue(name = "refreshToken") String refreshToken) {
		if(!(jwtUtils.validateJwtToken(jwt))) {
			if (jwtUtils.validateJwtToken(refreshToken)) {
				String activeUser = jwtUtils.getUserNameFromRefreshToken(refreshToken);
				String newJwt = jwtUtils.generateTokenFromUsername(activeUser);

				ResponseCookie jwtCookie = ResponseCookie.from("jwt", newJwt)
						.httpOnly(true)
						.path("/")
						.maxAge(24 * 60 * 60)
						.build();

				return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
						.body(new MessageResponse("New jwt generated successfully!"));
			} else {
				ResponseCookie jwtCookie = ResponseCookie.from("jwt", null)
						.httpOnly(true)
						.path("/")
						.maxAge(0)
						.build();

				ResponseCookie refreshTokenCookie = ResponseCookie.from("refreshToken", null)
						.httpOnly(true)
						.path("/")
						.maxAge(0)
						.build();

				return ResponseEntity.badRequest().header(HttpHeaders.SET_COOKIE, jwtCookie.toString(), refreshTokenCookie.toString())
						.body(new MessageResponse("Refresh token was expired. Please make a new sign in request"));
			}
		}
		else {
			return ResponseEntity.badRequest().body(new MessageResponse("Jwt has not yet, expired"));
		}
	}

	@PostMapping("/logout")
	public ResponseEntity<?> logoutUser() {

		ResponseCookie jwtCookie = ResponseCookie.from("jwt", null)
				.httpOnly(true)
				.path("/")
				.maxAge(0)
				.build();

		ResponseCookie refreshTokenCookie = ResponseCookie.from("refreshToken", null)
				.httpOnly(true)
				.path("/")
				.maxAge(0)
				.build();

		return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, jwtCookie.toString(), refreshTokenCookie.toString())
				.body(new MessageResponse("Logged out successfully!"));
	}
}