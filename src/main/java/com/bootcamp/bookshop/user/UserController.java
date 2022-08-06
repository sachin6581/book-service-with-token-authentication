package com.bootcamp.bookshop.user;

import com.bootcamp.bookshop.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.util.Optional;

@RestController
@RequestMapping("/users")
public class UserController {
    @Autowired
    private UserService userService;

    @Autowired
    private AuthenticationManager authenticationManager;

    JwtUtil jwtUtil = new JwtUtil();

    @PostMapping
    ResponseEntity<UserResponse> create(@RequestBody CreateUserRequest userRequest) throws InvalidEmailException {
        User user = userService.create(userRequest);
        return new ResponseEntity<>(new UserResponse(user), HttpStatus.CREATED);
    }

    @PostMapping("/authenticate")
    ResponseEntity<?> createAuthenticationToken(@RequestBody CreateUserRequest userRequest) throws Exception {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(userRequest.getEmail(), userRequest.getPassword()));
        }catch (BadCredentialsException e){
            return ResponseEntity.badRequest().body(e.getMessage());
        }
        Optional<User> user = userService.findByEmail(userRequest.getEmail());
        final String jwt = jwtUtil.generateToken(user);
        return ResponseEntity.ok(new AuthenticationResponse(jwt));
    }

    @PatchMapping("/{id}")
    ResponseEntity<Object> update(@PathVariable Long id, @RequestBody UpdateUserRequest updateUserRequest) throws UserNotFoundException {
        userService.update(id, updateUserRequest);
        return ResponseEntity.accepted().build();
    }
}
