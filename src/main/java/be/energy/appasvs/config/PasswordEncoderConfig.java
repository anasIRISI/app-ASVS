package be.energy.appasvs.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Configuration séparée pour le PasswordEncoder.
 * 
 * Cette classe est séparée de SecurityConfig pour éviter les dépendances circulaires.
 * Le PasswordEncoder est utilisé par UserService, qui est lui-même utilisé par SecurityConfig.
 * 
 * Conformité ASVS V6.1.1 : Algorithme de hash adaptatif et résistant.
 */
@Configuration
public class PasswordEncoderConfig {
    
    /**
     * Configuration du PasswordEncoder.
     * Utilise BCrypt avec un coût par défaut de 10 (2^10 itérations).
     * 
     * BCrypt :
     * - Génère automatiquement un salt unique pour chaque mot de passe
     * - Résistant aux attaques par rainbow tables
     * - Configurable en termes de coût computationnel
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        // Strength par défaut : 10 (bon compromis sécurité/performance)
        // Pour augmenter la sécurité en production : new BCryptPasswordEncoder(12)
        return new BCryptPasswordEncoder();
    }
}
