package be.energy.appasvs.service;

import be.energy.appasvs.dto.ChangePasswordRequest;
import be.energy.appasvs.dto.RegisterRequest;
import be.energy.appasvs.entity.Role;
import be.energy.appasvs.entity.User;
import be.energy.appasvs.exception.AccountLockedException;
import be.energy.appasvs.exception.EmailAlreadyExistsException;
import be.energy.appasvs.exception.WeakPasswordException;
import be.energy.appasvs.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

/**
 * Service de gestion des utilisateurs.
 * 
 * Conformité ASVS V6 :
 * - V6.1.1 : Hash sécurisé des mots de passe avec BCrypt
 * - V6.2.1 : Email unique
 * - V6.2.2 : Politique de mot de passe (8-128 caractères)
 * - V6.2.5 : Protection contre mots de passe compromis et brute force
 * - V6.3.1 : Renouvellement de session après changement de mot de passe
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class UserService {
    
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final PasswordValidationService passwordValidationService;
    
    // Configuration de la protection brute force
    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final int LOCKOUT_DURATION_MINUTES = 15;
    
    /**
     * Enregistre un nouvel utilisateur.
     * 
     * @param request Données d'inscription
     * @return L'utilisateur créé
     * @throws EmailAlreadyExistsException Si l'email existe déjà
     * @throws WeakPasswordException Si le mot de passe est trop faible
     */
    @Transactional
    public User registerUser(RegisterRequest request) {
        log.debug("Tentative d'inscription pour l'email : {}", request.getEmail());
        
        // Vérification de l'unicité de l'email
        if (userRepository.existsByEmail(request.getEmail())) {
            log.warn("Tentative d'inscription avec un email existant : {}", request.getEmail());
            throw new EmailAlreadyExistsException("Cette adresse email est déjà utilisée");
        }
        
        // Validation de la correspondance des mots de passe
        if (!request.isPasswordMatching()) {
            throw new IllegalArgumentException("Les mots de passe ne correspondent pas");
        }
        
        // Validation de la robustesse du mot de passe
        passwordValidationService.validatePasswordStrength(request.getPassword());
        
        // Création de l'utilisateur
        User user = new User();
        user.setFullName(request.getFullName());
        user.setEmail(request.getEmail());
        
        // Hash du mot de passe avec BCrypt
        // BCrypt génère automatiquement un salt unique et utilise un coût adapté
        String passwordHash = passwordEncoder.encode(request.getPassword());
        user.setPasswordHash(passwordHash);
        
        // Attribution du rôle USER par défaut (JAMAIS ADMIN via inscription)
        user.setRole(Role.USER);
        
        User savedUser = userRepository.save(user);
        log.info("Nouvel utilisateur enregistré avec succès : {}", savedUser.getEmail());
        
        return savedUser;
    }
    
    /**
     * Change le mot de passe d'un utilisateur.
     * 
     * @param email Email de l'utilisateur
     * @param request Demande de changement de mot de passe
     * @throws IllegalArgumentException Si le mot de passe actuel est incorrect
     * @throws WeakPasswordException Si le nouveau mot de passe est trop faible
     */
    @Transactional
    public void changePassword(String email, ChangePasswordRequest request) {
        log.debug("Tentative de changement de mot de passe pour : {}", email);
        
        User user = userRepository.findByEmail(email)
            .orElseThrow(() -> new IllegalArgumentException("Utilisateur non trouvé"));
        
        // Vérification du mot de passe actuel
        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPasswordHash())) {
            log.warn("Tentative de changement de mot de passe avec mot de passe actuel incorrect : {}", email);
            throw new IllegalArgumentException("Le mot de passe actuel est incorrect");
        }
        
        // Validation de la correspondance des nouveaux mots de passe
        if (!request.isNewPasswordMatching()) {
            throw new IllegalArgumentException("Les nouveaux mots de passe ne correspondent pas");
        }
        
        // Validation de la robustesse du nouveau mot de passe
        passwordValidationService.validatePasswordStrength(request.getNewPassword());
        
        // Mise à jour du hash du mot de passe
        String newPasswordHash = passwordEncoder.encode(request.getNewPassword());
        user.setPasswordHash(newPasswordHash);
        
        userRepository.save(user);
        log.info("Mot de passe changé avec succès pour : {}", email);
        
        // Note : L'invalidation des autres sessions est gérée par Spring Security
        // via la configuration SessionRegistry
    }
    
    /**
     * Enregistre une tentative de connexion échouée.
     * Verrouille le compte si trop de tentatives échouées.
     * 
     * Conformité ASVS V6.2.5 : Protection contre le brute force.
     */
    @Transactional
    public void recordFailedLoginAttempt(String email) {
        userRepository.findByEmail(email).ifPresent(user -> {
            int attempts = user.getFailedLoginAttempts() + 1;
            user.setFailedLoginAttempts(attempts);
            
            if (attempts >= MAX_FAILED_ATTEMPTS) {
                LocalDateTime lockoutUntil = LocalDateTime.now().plusMinutes(LOCKOUT_DURATION_MINUTES);
                user.setLockoutUntil(lockoutUntil);
                log.warn("Compte verrouillé suite à {} tentatives échouées : {}", attempts, email);
            }
            
            userRepository.save(user);
        });
    }
    
    /**
     * Réinitialise les tentatives de connexion échouées après une connexion réussie.
     */
    @Transactional
    public void resetFailedLoginAttempts(String email) {
        userRepository.findByEmail(email).ifPresent(user -> {
            if (user.getFailedLoginAttempts() > 0 || user.getLockoutUntil() != null) {
                user.setFailedLoginAttempts(0);
                user.setLockoutUntil(null);
                userRepository.save(user);
                log.debug("Tentatives de connexion réinitialisées pour : {}", email);
            }
        });
    }
    
    /**
     * Vérifie si un compte est verrouillé.
     * 
     * @param email Email de l'utilisateur
     * @throws AccountLockedException Si le compte est verrouillé
     */
    public void checkAccountLockStatus(String email) {
        User user = userRepository.findByEmail(email)
            .orElse(null);
        
        if (user != null && user.isAccountLocked()) {
            throw new AccountLockedException(
                "Votre compte est temporairement verrouillé suite à trop de tentatives de connexion échouées. " +
                "Veuillez réessayer dans quelques minutes."
            );
        }
    }
}
