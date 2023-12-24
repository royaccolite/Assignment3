package com.bezkoder.springjwt.controllers;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import com.bezkoder.springjwt.dto.LocationDto;
import com.bezkoder.springjwt.dto.WalletBalanceDto;
import com.bezkoder.springjwt.models.ERole;
import com.bezkoder.springjwt.models.Role;
import com.bezkoder.springjwt.models.User;
import com.bezkoder.springjwt.payload.request.LoginRequest;
import com.bezkoder.springjwt.payload.request.SignupRequest;
import com.bezkoder.springjwt.payload.response.JwtResponse;
import com.bezkoder.springjwt.payload.response.MessageResponse;
import com.bezkoder.springjwt.repository.RoleRepository;
import com.bezkoder.springjwt.repository.UserRepository;
import com.bezkoder.springjwt.security.jwt.JwtUtils;
import com.bezkoder.springjwt.security.services.UserDetailsImpl;
import com.bezkoder.springjwt.security.services.UserService;
import com.bezkoder.springjwt.security.services.WalletService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.bind.annotation.*;

import com.roy.payment.security.services.*;

@CrossOrigin(origins = "*", maxAge = 3600)
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
  public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

    Authentication authentication = authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

    SecurityContextHolder.getContext().setAuthentication(authentication);
    String jwt = jwtUtils.generateJwtToken(authentication);
    
    UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
    List<String> roles = userDetails.getAuthorities().stream()
        .map(item -> item.getAuthority())
        .collect(Collectors.toList());

    return ResponseEntity.ok(new JwtResponse(jwt,
                         userDetails.getId(), 
                         userDetails.getUsername(), 
                         userDetails.getEmail(),
                         roles));
  }

  @PostMapping("/signup")
  public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
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

    // Create new user's account
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


  @GetMapping("/user")
  public String currentUserName(Authentication authentication) {
    return authentication.getName();
  }


  SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();

  @PostMapping("/logout")
  public String performLogout(Authentication authentication, HttpServletRequest request, HttpServletResponse response) {
    this.logoutHandler.logout(request, response, authentication);
    return "redirect:/home";
  }


  @Autowired
  private WalletService walletService;

  @GetMapping("/balance")
  public ResponseEntity<?> getWalletBalance(@AuthenticationPrincipal UserDetailsImpl userDetails) {
    Long userId = userDetails.getId();
    int balance = walletService.getWalletBalance(userId);


    return ResponseEntity.ok(new WalletBalanceDto(balance));
  }

  @PostMapping("/deposit")
  public ResponseEntity<String> depositToWallet(@AuthenticationPrincipal UserDetailsImpl userDetails,
                                                @RequestParam int amount) {
    Long userId = userDetails.getId();
    walletService.depositToWallet(userId, amount);
    return ResponseEntity.ok("Deposit successful");
  }

  @PostMapping("/withdraw")
  public ResponseEntity<String> withdrawFromWallet(@AuthenticationPrincipal UserDetailsImpl userDetails,
                                                   @RequestParam int amount) {
    Long userId = userDetails.getId();
    walletService.withdrawFromWallet(userId, amount);
    return ResponseEntity.ok("Withdrawal successful");

  }


  @Autowired
  private UserService userService;
  @GetMapping("/location")
  public ResponseEntity<LocationDto> getUserLocation(@AuthenticationPrincipal UserDetailsImpl userDetails) {
    Long userId = userDetails.getId();
    LocationDto location = UserService.getUserLocation(userId);
    return ResponseEntity.ok(location);
  }

  @PostMapping("/update-location")
  public ResponseEntity<String> updateLocation(
          @AuthenticationPrincipal UserDetailsImpl userDetails,
          @RequestBody LocationDto locationDto) {
    Long userId = userDetails.getId();
    UserService.updateUserLocation(userId, LocationDto.getLatitude(), LocationDto.getLongitude());
    return ResponseEntity.ok("Location updated successfully");
  }


}
// {
//         "username": "amitabha",
//         "email": "amit@mail.com",
//         "role":[
//         "ROLE_USER"
//         ],
//         "password": "amitabha"
//         }