package be.energy.appasvs.service;

import be.energy.appasvs.exception.WeakPasswordException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests pour le service de validation des mots de passe.
 * 
 * Vérifie la conformité ASVS V6.2.5 :
 * - Refus des mots de passe courants
 * - Refus des séquences évidentes
 */
class PasswordValidationServiceTest {
    
    private PasswordValidationService passwordValidationService;
    
    @BeforeEach
    void setUp() {
        passwordValidationService = new PasswordValidationService();
    }
    
    @Test
    @DisplayName("Test 4 ASVS : Doit rejeter un mot de passe courant 'password'")
    void testRejectCommonPassword() {
        WeakPasswordException exception = assertThrows(
            WeakPasswordException.class,
            () -> passwordValidationService.validatePasswordStrength("password")
        );
        assertTrue(exception.getMessage().contains("trop courant"));
    }
    
    @Test
    @DisplayName("Test 4 ASVS : Doit rejeter le mot de passe '12345678'")
    void testRejectNumericCommonPassword() {
        WeakPasswordException exception = assertThrows(
            WeakPasswordException.class,
            () -> passwordValidationService.validatePasswordStrength("12345678")
        );
        assertTrue(exception.getMessage().contains("trop courant"));
    }
    
    @Test
    @DisplayName("Test 4 ASVS : Doit rejeter les séquences évidentes")
    void testRejectSequentialPassword() {
        WeakPasswordException exception = assertThrows(
            WeakPasswordException.class,
            () -> passwordValidationService.validatePasswordStrength("abcd1234")
        );
        assertTrue(exception.getMessage().contains("séquences évidentes"));
    }
    
    @Test
    @DisplayName("Doit accepter un mot de passe fort")
    void testAcceptStrongPassword() {
        assertDoesNotThrow(
            () -> passwordValidationService.validatePasswordStrength("MyS3cur3P@ssw0rd!")
        );
    }
    
    @Test
    @DisplayName("Doit accepter un mot de passe long et complexe")
    void testAcceptLongPassword() {
        String longPassword = "ThisIsAVeryLongAndSecurePasswordThatMeetsAllRequirements2024!";
        assertDoesNotThrow(
            () -> passwordValidationService.validatePasswordStrength(longPassword)
        );
    }
    
    @Test
    @DisplayName("Doit rejeter un mot de passe vide")
    void testRejectEmptyPassword() {
        assertThrows(
            WeakPasswordException.class,
            () -> passwordValidationService.validatePasswordStrength("")
        );
    }
    
    @Test
    @DisplayName("Doit rejeter un mot de passe null")
    void testRejectNullPassword() {
        assertThrows(
            WeakPasswordException.class,
            () -> passwordValidationService.validatePasswordStrength(null)
        );
    }
}
