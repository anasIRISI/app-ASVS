package be.energy.appasvs.controller;

import be.energy.appasvs.dto.RegisterRequest;
import be.energy.appasvs.exception.AccountLockedException;
import be.energy.appasvs.exception.EmailAlreadyExistsException;
import be.energy.appasvs.exception.WeakPasswordException;
import be.energy.appasvs.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/**
 * Contrôleur pour l'authentification (inscription et connexion).
 * 
 * Conformité ASVS :
 * - V6.2.1 : Validation côté serveur des données d'inscription
 * - V6.2.2 : Messages d'erreur génériques pour la connexion
 * - V6.2.5 : Protection contre les mots de passe compromis
 */
@Controller
@RequiredArgsConstructor
@Slf4j
public class AuthController {
    
    private final UserService userService;
    
    /**
     * Page d'accueil.
     */
    @GetMapping("/")
    public String home() {
        return "redirect:/login";
    }
    
    /**
     * Affiche le formulaire de connexion.
     */
    @GetMapping("/login")
    public String loginPage(
            @RequestParam(required = false) String error,
            @RequestParam(required = false) String logout,
            @RequestParam(required = false) String locked,
            Model model) {
        
        if (error != null) {
            // Message d'erreur générique (ASVS V6.2.2)
            // Ne révèle pas si le compte existe ou si le mot de passe est incorrect
            model.addAttribute("error", "Identifiants incorrects. Veuillez réessayer.");
        }
        
        if (logout != null) {
            model.addAttribute("message", "Vous avez été déconnecté avec succès.");
        }
        
        if (locked != null) {
            model.addAttribute("error", 
                "Votre compte est temporairement verrouillé suite à trop de tentatives de connexion échouées. " +
                "Veuillez réessayer dans quelques minutes.");
        }
        
        return "login";
    }
    
    /**
     * Affiche le formulaire d'inscription.
     */
    @GetMapping("/register")
    public String registerPage(Model model) {
        model.addAttribute("registerRequest", new RegisterRequest());
        return "register";
    }
    
    /**
     * Traite le formulaire d'inscription.
     * 
     * Validation :
     * - Validation Jakarta automatique (@Valid)
     * - Vérification côté serveur de l'unicité de l'email
     * - Vérification de la robustesse du mot de passe
     * - Vérification de la correspondance des mots de passe
     */
    @PostMapping("/register")
    public String registerUser(
            @Valid @ModelAttribute RegisterRequest registerRequest,
            BindingResult bindingResult,
            RedirectAttributes redirectAttributes,
            Model model) {
        
        // Vérification des erreurs de validation Jakarta
        if (bindingResult.hasErrors()) {
            return "register";
        }
        
        // Vérification de la correspondance des mots de passe
        if (!registerRequest.isPasswordMatching()) {
            model.addAttribute("error", "Les mots de passe ne correspondent pas");
            return "register";
        }
        
        try {
            // Tentative de vérification du verrouillage (au cas où l'email existe)
            userService.checkAccountLockStatus(registerRequest.getEmail());
            
            // Enregistrement de l'utilisateur
            userService.registerUser(registerRequest);
            
            log.info("Inscription réussie pour : {}", registerRequest.getEmail());
            redirectAttributes.addFlashAttribute("message", 
                "Inscription réussie ! Vous pouvez maintenant vous connecter.");
            return "redirect:/login";
            
        } catch (EmailAlreadyExistsException e) {
            model.addAttribute("error", e.getMessage());
            return "register";
            
        } catch (WeakPasswordException e) {
            model.addAttribute("error", e.getMessage());
            return "register";
            
        } catch (AccountLockedException e) {
            model.addAttribute("error", e.getMessage());
            return "register";
            
        } catch (Exception e) {
            log.error("Erreur lors de l'inscription", e);
            model.addAttribute("error", "Une erreur est survenue. Veuillez réessayer.");
            return "register";
        }
    }
}
