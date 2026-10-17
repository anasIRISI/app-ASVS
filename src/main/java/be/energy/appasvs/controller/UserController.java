package be.energy.appasvs.controller;

import be.energy.appasvs.dto.ChangePasswordRequest;
import be.energy.appasvs.entity.User;
import be.energy.appasvs.exception.WeakPasswordException;
import be.energy.appasvs.repository.UserRepository;
import be.energy.appasvs.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.List;

/**
 * Contrôleur pour les pages utilisateur protégées.
 * 
 * Conformité ASVS :
 * - V6.3.1 : Pages accessibles uniquement après authentification
 * - V6.3.2 : Changement de mot de passe sécurisé
 * - V6.3.3 : Invalidation des sessions après changement de mot de passe
 */
@Controller
@RequiredArgsConstructor
@Slf4j
public class UserController {
    
    private final UserService userService;
    private final UserRepository userRepository;
    private final SessionRegistry sessionRegistry;
    
    /**
     * Page de profil utilisateur.
     * Accessible uniquement après authentification.
     */
    @GetMapping("/profile")
    public String profilePage(Model model, Authentication authentication) {
        String email = authentication.getName();
        
        User user = userRepository.findByEmail(email)
            .orElseThrow(() -> new IllegalStateException("Utilisateur non trouvé"));
        
        model.addAttribute("user", user);
        return "profile";
    }
    
    /**
     * Affiche le formulaire de changement de mot de passe.
     */
    @GetMapping("/change-password")
    public String changePasswordPage(Model model) {
        model.addAttribute("changePasswordRequest", new ChangePasswordRequest());
        return "change-password";
    }
    
    /**
     * Traite le changement de mot de passe.
     * 
     * Sécurité :
     * - Vérifie le mot de passe actuel
     * - Applique la même politique de validation que l'inscription
     * - Invalide les autres sessions de l'utilisateur (ASVS V6.3.3)
     */
    @PostMapping("/change-password")
    public String changePassword(
            @Valid @ModelAttribute ChangePasswordRequest request,
            BindingResult bindingResult,
            Authentication authentication,
            HttpServletRequest httpRequest,
            RedirectAttributes redirectAttributes,
            Model model) {
        
        // Vérification des erreurs de validation
        if (bindingResult.hasErrors()) {
            return "change-password";
        }
        
        // Vérification de la correspondance des nouveaux mots de passe
        if (!request.isNewPasswordMatching()) {
            model.addAttribute("error", "Les nouveaux mots de passe ne correspondent pas");
            return "change-password";
        }
        
        try {
            String email = authentication.getName();
            
            // Changement du mot de passe
            userService.changePassword(email, request);
            
            // Invalidation de toutes les autres sessions de cet utilisateur (ASVS V6.3.3)
            invalidateOtherUserSessions(email, httpRequest.getSession().getId());
            
            log.info("Mot de passe changé avec succès pour : {}", email);
            redirectAttributes.addFlashAttribute("message", 
                "Votre mot de passe a été changé avec succès. Vos autres sessions ont été déconnectées.");
            return "redirect:/profile";
            
        } catch (IllegalArgumentException e) {
            model.addAttribute("error", e.getMessage());
            return "change-password";
            
        } catch (WeakPasswordException e) {
            model.addAttribute("error", e.getMessage());
            return "change-password";
            
        } catch (Exception e) {
            log.error("Erreur lors du changement de mot de passe", e);
            model.addAttribute("error", "Une erreur est survenue. Veuillez réessayer.");
            return "change-password";
        }
    }
    
    /**
     * Invalide toutes les sessions d'un utilisateur sauf la session actuelle.
     * Conformité ASVS V6.3.3 : Invalidation des sessions après changement de mot de passe.
     */
    private void invalidateOtherUserSessions(String username, String currentSessionId) {
        List<SessionInformation> sessions = sessionRegistry.getAllSessions(username, false);
        
        for (SessionInformation session : sessions) {
            if (!session.getSessionId().equals(currentSessionId)) {
                session.expireNow();
                log.debug("Session expirée pour {} : {}", username, session.getSessionId());
            }
        }
    }
}
