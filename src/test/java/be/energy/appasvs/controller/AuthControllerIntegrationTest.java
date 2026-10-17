package be.energy.appasvs.controller;

import be.energy.appasvs.entity.User;
import be.energy.appasvs.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import org.springframework.test.context.TestPropertySource;

/**
 * Tests d'intégration pour AuthController.
 * 
 * Vérifie la conformité ASVS :
 * - V6.2.1 : Email unique
 * - V6.2.2 : Validation des mots de passe
 * - V6.2.3 : Protection CSRF
 * - V6.2.5 : Messages d'erreur génériques
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
@TestPropertySource(locations = "classpath:application-test.properties")
class AuthControllerIntegrationTest {
    
    @Autowired
    private MockMvc mockMvc;
    
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    @BeforeEach
    void setUp() {
        userRepository.deleteAll();
    }
    
    @Test
    @DisplayName("Test 1 ASVS : Inscription avec données valides doit réussir")
    void testRegisterWithValidData() throws Exception {
        mockMvc.perform(post("/register")
                .param("fullName", "Jean Dupont")
                .param("email", "jean.dupont@example.com")
                .param("password", "SecurePass123!")
                .param("confirmPassword", "SecurePass123!")
                .with(csrf()))
            .andExpect(status().is3xxRedirection())
            .andExpect(redirectedUrl("/login"));
        
        User user = userRepository.findByEmail("jean.dupont@example.com").orElse(null);
        assertNotNull(user);
        assertEquals("Jean Dupont", user.getFullName());
    }
    
    @Test
    @DisplayName("Test 2 ASVS : Refus d'une adresse email déjà utilisée")
    void testRejectDuplicateEmail() throws Exception {
        // Créer un utilisateur existant
        User existingUser = new User();
        existingUser.setFullName("Utilisateur Existant");
        existingUser.setEmail("existing@example.com");
        existingUser.setPasswordHash(passwordEncoder.encode("Password123!"));
        userRepository.save(existingUser);
        
        // Tenter d'inscrire un autre utilisateur avec le même email
        mockMvc.perform(post("/register")
                .param("fullName", "Nouveau Utilisateur")
                .param("email", "existing@example.com")
                .param("password", "AnotherPass123!")
                .param("confirmPassword", "AnotherPass123!")
                .with(csrf()))
            .andExpect(status().isOk())
            .andExpect(view().name("register"))
            .andExpect(model().attributeExists("error"));
    }
    
    @Test
    @DisplayName("Test 3 ASVS : Refus d'un mot de passe trop court (validation)")
    void testRejectShortPasswordValidation() throws Exception {
        mockMvc.perform(post("/register")
                .param("fullName", "Jean Dupont")
                .param("email", "jean@example.com")
                .param("password", "short")
                .param("confirmPassword", "short")
                .with(csrf()))
            .andExpect(status().isOk())
            .andExpect(view().name("register"))
            .andExpect(model().hasErrors());
    }
    
    @Test
    @DisplayName("Test 4 ASVS : Refus d'un mot de passe courant 'password'")
    void testRejectCommonPassword() throws Exception {
        mockMvc.perform(post("/register")
                .param("fullName", "Jean Dupont")
                .param("email", "jean@example.com")
                .param("password", "password")
                .param("confirmPassword", "password")
                .with(csrf()))
            .andExpect(status().isOk())
            .andExpect(view().name("register"))
            .andExpect(model().attributeExists("error"));
    }
    
    @Test
    @DisplayName("Test 5 ASVS : Vérification que le mot de passe est hashé en base")
    void testPasswordIsHashedInDatabase() throws Exception {
        mockMvc.perform(post("/register")
                .param("fullName", "Jean Dupont")
                .param("email", "test@example.com")
                .param("password", "MySecurePassword123!")
                .param("confirmPassword", "MySecurePassword123!")
                .with(csrf()))
            .andExpect(status().is3xxRedirection());
        
        User user = userRepository.findByEmail("test@example.com").orElse(null);
        assertNotNull(user);
        assertNotEquals("MySecurePassword123!", user.getPasswordHash());
        assertTrue(user.getPasswordHash().startsWith("$2a$")); // Format BCrypt
        assertTrue(passwordEncoder.matches("MySecurePassword123!", user.getPasswordHash()));
    }
    
    @Test
    @DisplayName("Test 6 ASVS : Connexion avec identifiants corrects doit réussir")
    void testLoginWithCorrectCredentials() throws Exception {
        // Créer un utilisateur
        User user = new User();
        user.setFullName("Jean Dupont");
        user.setEmail("jean@example.com");
        user.setPasswordHash(passwordEncoder.encode("CorrectPassword123!"));
        userRepository.save(user);
        
        // Tenter de se connecter
        mockMvc.perform(post("/login")
                .param("email", "jean@example.com")
                .param("password", "CorrectPassword123!")
                .with(csrf()))
            .andExpect(status().is3xxRedirection())
            .andExpect(redirectedUrl("/profile"));
    }
    
    @Test
    @DisplayName("Test 7 ASVS : Refus de connexion avec mot de passe incorrect")
    void testLoginWithIncorrectPassword() throws Exception {
        // Créer un utilisateur
        User user = new User();
        user.setFullName("Jean Dupont");
        user.setEmail("jean@example.com");
        user.setPasswordHash(passwordEncoder.encode("CorrectPassword123!"));
        userRepository.save(user);
        
        // Tenter de se connecter avec mauvais mot de passe
        mockMvc.perform(post("/login")
                .param("email", "jean@example.com")
                .param("password", "WrongPassword")
                .with(csrf()))
            .andExpect(status().is3xxRedirection())
            .andExpect(redirectedUrl("/login?error=true"));
    }
    
    @Test
    @DisplayName("Test 8 ASVS : Message d'erreur générique lors d'un échec d'authentification")
    void testGenericErrorMessageOnFailedLogin() throws Exception {
        mockMvc.perform(get("/login")
                .param("error", "true"))
            .andExpect(status().isOk())
            .andExpect(view().name("login"))
            .andExpect(model().attribute("error", "Identifiants incorrects. Veuillez réessayer."));
    }
    
    @Test
    @DisplayName("Test 13 ASVS : Protection CSRF activée sur le formulaire d'inscription")
    void testCsrfProtectionOnRegister() throws Exception {
        // Sans token CSRF, la requête doit échouer
        mockMvc.perform(post("/register")
                .param("fullName", "Jean Dupont")
                .param("email", "jean@example.com")
                .param("password", "SecurePass123!")
                .param("confirmPassword", "SecurePass123!"))
            .andExpect(status().isForbidden());
    }
    
    @Test
    @DisplayName("Test 13 ASVS : Protection CSRF activée sur le formulaire de connexion")
    void testCsrfProtectionOnLogin() throws Exception {
        // Sans token CSRF, la requête doit échouer
        mockMvc.perform(post("/login")
                .param("email", "jean@example.com")
                .param("password", "Password123!"))
            .andExpect(status().isForbidden());
    }
}
