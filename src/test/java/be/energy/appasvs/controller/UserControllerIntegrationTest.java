package be.energy.appasvs.controller;

import be.energy.appasvs.entity.Role;
import be.energy.appasvs.entity.User;
import be.energy.appasvs.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import org.springframework.test.context.TestPropertySource;

/**
 * Tests d'intégration pour UserController.
 * 
 * Vérifie la conformité ASVS :
 * - V6.3.1 : Accès aux pages protégées
 * - V6.3.2 : Changement de mot de passe sécurisé
 * - V6.3.3 : Déconnexion et invalidation de session
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
@TestPropertySource(locations = "classpath:application-test.properties")
class UserControllerIntegrationTest {
    
    @Autowired
    private MockMvc mockMvc;
    
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    private User testUser;
    
    @BeforeEach
    void setUp() {
        userRepository.deleteAll();
        
        testUser = new User();
        testUser.setFullName("Jean Dupont");
        testUser.setEmail("jean@example.com");
        testUser.setPasswordHash(passwordEncoder.encode("CurrentPass123!"));
        testUser.setRole(Role.USER);
        testUser = userRepository.save(testUser);
    }
    
    @Test
    @DisplayName("Test 9 ASVS : Accès à /profile sans authentification doit être refusé")
    void testAccessProfileWithoutAuthentication() throws Exception {
        mockMvc.perform(get("/profile"))
            .andExpect(status().is3xxRedirection())
            .andExpect(redirectedUrlPattern("**/login"));
    }
    
    @Test
    @DisplayName("Test 10 ASVS : Accès à /profile après authentification doit réussir")
    @WithMockUser(username = "jean@example.com")
    void testAccessProfileWithAuthentication() throws Exception {
        mockMvc.perform(get("/profile"))
            .andExpect(status().isOk())
            .andExpect(view().name("profile"))
            .andExpect(model().attributeExists("user"));
    }
    
    @Test
    @DisplayName("Test 11 ASVS : Déconnexion et invalidation de session")
    void testLogout() throws Exception {
        mockMvc.perform(post("/logout")
                .with(csrf())
                .with(user("jean@example.com")))
            .andExpect(status().is3xxRedirection())
            .andExpect(redirectedUrl("/login?logout=true"));
    }
    
    @Test
    @DisplayName("Test 12 ASVS : Changement de mot de passe avec ancien mot de passe incorrect")
    void testChangePasswordWithWrongCurrentPassword() throws Exception {
        mockMvc.perform(post("/change-password")
                .param("currentPassword", "WrongPassword")
                .param("newPassword", "NewSecurePass123!")
                .param("confirmNewPassword", "NewSecurePass123!")
                .with(csrf())
                .with(user("jean@example.com")))
            .andExpect(status().isOk())
            .andExpect(view().name("change-password"))
            .andExpect(model().attributeExists("error"));
    }
    
    @Test
    @DisplayName("Changement de mot de passe avec bon mot de passe actuel doit réussir")
    void testChangePasswordWithCorrectCurrentPassword() throws Exception {
        mockMvc.perform(post("/change-password")
                .param("currentPassword", "CurrentPass123!")
                .param("newPassword", "NewSecurePass456!")
                .param("confirmNewPassword", "NewSecurePass456!")
                .with(csrf())
                .with(user("jean@example.com")))
            .andExpect(status().is3xxRedirection())
            .andExpect(redirectedUrl("/profile"));
        
        // Vérifier que le nouveau mot de passe a été enregistré
        User updatedUser = userRepository.findByEmail("jean@example.com").orElse(null);
        assertNotNull(updatedUser);
        assertTrue(passwordEncoder.matches("NewSecurePass456!", updatedUser.getPasswordHash()));
        assertFalse(passwordEncoder.matches("CurrentPass123!", updatedUser.getPasswordHash()));
    }
    
    @Test
    @DisplayName("Test 13 ASVS : Protection CSRF sur changement de mot de passe")
    void testCsrfProtectionOnChangePassword() throws Exception {
        // Sans token CSRF, la requête doit échouer
        mockMvc.perform(post("/change-password")
                .param("currentPassword", "CurrentPass123!")
                .param("newPassword", "NewSecurePass456!")
                .param("confirmNewPassword", "NewSecurePass456!")
                .with(user("jean@example.com")))
            .andExpect(status().isForbidden());
    }
    
    @Test
    @DisplayName("Refus de changement avec nouveau mot de passe courant")
    void testRejectCommonPasswordOnChange() throws Exception {
        mockMvc.perform(post("/change-password")
                .param("currentPassword", "CurrentPass123!")
                .param("newPassword", "password")
                .param("confirmNewPassword", "password")
                .with(csrf())
                .with(user("jean@example.com")))
            .andExpect(status().isOk())
            .andExpect(view().name("change-password"))
            .andExpect(model().attributeExists("error"));
    }
    
    @Test
    @DisplayName("Refus de changement avec nouveaux mots de passe non correspondants")
    void testRejectMismatchedNewPasswords() throws Exception {
        mockMvc.perform(post("/change-password")
                .param("currentPassword", "CurrentPass123!")
                .param("newPassword", "NewSecurePass456!")
                .param("confirmNewPassword", "DifferentPass789!")
                .with(csrf())
                .with(user("jean@example.com")))
            .andExpect(status().isOk())
            .andExpect(view().name("change-password"))
            .andExpect(model().attributeExists("error"));
    }
}
