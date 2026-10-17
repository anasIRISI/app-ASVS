package be.energy.appasvs.service;

import be.energy.appasvs.dto.ChangePasswordRequest;
import be.energy.appasvs.dto.RegisterRequest;
import be.energy.appasvs.entity.Role;
import be.energy.appasvs.entity.User;
import be.energy.appasvs.exception.EmailAlreadyExistsException;
import be.energy.appasvs.exception.WeakPasswordException;
import be.energy.appasvs.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * Tests unitaires pour UserService.
 * 
 * Vérifie la conformité ASVS :
 * - V6.1.1 : Hash des mots de passe
 * - V6.2.1 : Email unique
 * - V6.2.2 : Politique de mot de passe
 * - V6.2.5 : Protection brute force
 */
@ExtendWith(MockitoExtension.class)
class UserServiceTest {
    
    @Mock
    private UserRepository userRepository;
    
    @Mock
    private PasswordEncoder passwordEncoder;
    
    @Mock
    private PasswordValidationService passwordValidationService;
    
    @InjectMocks
    private UserService userService;
    
    private RegisterRequest validRegisterRequest;
    
    @BeforeEach
    void setUp() {
        validRegisterRequest = new RegisterRequest();
        validRegisterRequest.setFullName("Jean Dupont");
        validRegisterRequest.setEmail("jean.dupont@example.com");
        validRegisterRequest.setPassword("SecurePass123!");
        validRegisterRequest.setConfirmPassword("SecurePass123!");
    }
    
    @Test
    @DisplayName("Test 1 ASVS : Inscription avec données valides doit réussir")
    void testRegisterUserWithValidData() {
        when(userRepository.existsByEmail(anyString())).thenReturn(false);
        when(passwordEncoder.encode(anyString())).thenReturn("$2a$10$hashedPassword");
        when(userRepository.save(any(User.class))).thenAnswer(i -> i.getArguments()[0]);
        
        User user = userService.registerUser(validRegisterRequest);
        
        assertNotNull(user);
        assertEquals("Jean Dupont", user.getFullName());
        assertEquals("jean.dupont@example.com", user.getEmail());
        assertEquals(Role.USER, user.getRole());
        verify(passwordValidationService).validatePasswordStrength("SecurePass123!");
        verify(passwordEncoder).encode("SecurePass123!");
        verify(userRepository).save(any(User.class));
    }
    
    @Test
    @DisplayName("Test 2 ASVS : Refus d'une adresse email déjà utilisée")
    void testRejectDuplicateEmail() {
        when(userRepository.existsByEmail("jean.dupont@example.com")).thenReturn(true);
        
        assertThrows(
            EmailAlreadyExistsException.class,
            () -> userService.registerUser(validRegisterRequest)
        );
        
        verify(userRepository, never()).save(any(User.class));
    }
    
    @Test
    @DisplayName("Test 3 ASVS : Refus d'un mot de passe trop court")
    void testRejectShortPassword() {
        validRegisterRequest.setPassword("short");
        validRegisterRequest.setConfirmPassword("short");
        
        when(userRepository.existsByEmail(anyString())).thenReturn(false);
        doThrow(new WeakPasswordException("Mot de passe trop court"))
            .when(passwordValidationService).validatePasswordStrength("short");
        
        assertThrows(
            WeakPasswordException.class,
            () -> userService.registerUser(validRegisterRequest)
        );
    }
    
    @Test
    @DisplayName("Test 4 ASVS : Refus d'un mot de passe courant")
    void testRejectCommonPassword() {
        validRegisterRequest.setPassword("password");
        validRegisterRequest.setConfirmPassword("password");
        
        when(userRepository.existsByEmail(anyString())).thenReturn(false);
        doThrow(new WeakPasswordException("Mot de passe trop courant"))
            .when(passwordValidationService).validatePasswordStrength("password");
        
        assertThrows(
            WeakPasswordException.class,
            () -> userService.registerUser(validRegisterRequest)
        );
    }
    
    @Test
    @DisplayName("Test 5 ASVS : Vérification que le mot de passe est hashé")
    void testPasswordIsHashed() {
        when(userRepository.existsByEmail(anyString())).thenReturn(false);
        when(passwordEncoder.encode(anyString())).thenReturn("$2a$10$hashedPassword");
        when(userRepository.save(any(User.class))).thenAnswer(i -> i.getArguments()[0]);
        
        User user = userService.registerUser(validRegisterRequest);
        
        assertNotEquals("SecurePass123!", user.getPasswordHash());
        assertTrue(user.getPasswordHash().startsWith("$2a$")); // Format BCrypt
        verify(passwordEncoder).encode("SecurePass123!");
    }
    
    @Test
    @DisplayName("Test 15 ASVS : Vérification qu'un utilisateur ne peut pas s'attribuer le rôle ADMIN")
    void testUserCannotBecomeAdmin() {
        when(userRepository.existsByEmail(anyString())).thenReturn(false);
        when(passwordEncoder.encode(anyString())).thenReturn("$2a$10$hashedPassword");
        when(userRepository.save(any(User.class))).thenAnswer(i -> i.getArguments()[0]);
        
        User user = userService.registerUser(validRegisterRequest);
        
        assertEquals(Role.USER, user.getRole());
        assertNotEquals(Role.ADMIN, user.getRole());
    }
    
    @Test
    @DisplayName("Test 12 ASVS : Changement de mot de passe avec ancien mot de passe incorrect doit échouer")
    void testChangePasswordWithWrongCurrentPassword() {
        User existingUser = new User();
        existingUser.setEmail("jean.dupont@example.com");
        existingUser.setPasswordHash("$2a$10$oldHashedPassword");
        
        when(userRepository.findByEmail("jean.dupont@example.com"))
            .thenReturn(Optional.of(existingUser));
        when(passwordEncoder.matches(anyString(), anyString())).thenReturn(false);
        
        ChangePasswordRequest request = new ChangePasswordRequest();
        request.setCurrentPassword("wrongPassword");
        request.setNewPassword("NewSecurePass123!");
        request.setConfirmNewPassword("NewSecurePass123!");
        
        assertThrows(
            IllegalArgumentException.class,
            () -> userService.changePassword("jean.dupont@example.com", request)
        );
        
        verify(userRepository, never()).save(any(User.class));
    }
    
    @Test
    @DisplayName("Test 14 ASVS : Enregistrement des tentatives de connexion échouées")
    void testRecordFailedLoginAttempt() {
        User user = new User();
        user.setEmail("test@example.com");
        user.setFailedLoginAttempts(0);
        
        when(userRepository.findByEmail("test@example.com"))
            .thenReturn(Optional.of(user));
        when(userRepository.save(any(User.class))).thenAnswer(i -> i.getArguments()[0]);
        
        userService.recordFailedLoginAttempt("test@example.com");
        
        verify(userRepository).save(argThat(u -> 
            u.getFailedLoginAttempts() == 1
        ));
    }
    
    @Test
    @DisplayName("Test 14 ASVS : Verrouillage du compte après 5 tentatives échouées")
    void testAccountLockedAfterMaxAttempts() {
        User user = new User();
        user.setEmail("test@example.com");
        user.setFailedLoginAttempts(4);
        
        when(userRepository.findByEmail("test@example.com"))
            .thenReturn(Optional.of(user));
        when(userRepository.save(any(User.class))).thenAnswer(i -> i.getArguments()[0]);
        
        userService.recordFailedLoginAttempt("test@example.com");
        
        verify(userRepository).save(argThat(u -> 
            u.getFailedLoginAttempts() == 5 && u.getLockoutUntil() != null
        ));
    }
    
    @Test
    @DisplayName("Réinitialisation des tentatives après connexion réussie")
    void testResetFailedAttemptsAfterSuccessfulLogin() {
        User user = new User();
        user.setEmail("test@example.com");
        user.setFailedLoginAttempts(3);
        
        when(userRepository.findByEmail("test@example.com"))
            .thenReturn(Optional.of(user));
        when(userRepository.save(any(User.class))).thenAnswer(i -> i.getArguments()[0]);
        
        userService.resetFailedLoginAttempts("test@example.com");
        
        verify(userRepository).save(argThat(u -> 
            u.getFailedLoginAttempts() == 0 && u.getLockoutUntil() == null
        ));
    }
}
