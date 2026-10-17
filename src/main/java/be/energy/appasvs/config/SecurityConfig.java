package be.energy.appasvs.config;

import be.energy.appasvs.service.CustomUserDetailsService;
import be.energy.appasvs.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;

/**
 * Configuration de Spring Security pour l'application.
 * 
 * Conformité OWASP ASVS V6 :
 * - V6.1.1 : Utilisation de BCrypt pour hasher les mots de passe
 * - V6.2.3 : Protection CSRF activée sur tous les formulaires
 * - V6.3.1 : Gestion sécurisée des sessions
 * - V6.3.2 : Cookies HttpOnly, Secure (en prod), SameSite
 * - V6.3.3 : Invalidation de session à la déconnexion
 * - V6.3.4 : Renouvellement de session après authentification
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    
    private final CustomUserDetailsService userDetailsService;
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    
    /**
     * Configuration du provider d'authentification.
     * Utilise notre UserDetailsService personnalisé et BCrypt.
     */
    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder);
        return authProvider;
    }
    
    /**
     * Expose l'AuthenticationManager pour l'utiliser dans les contrôleurs si nécessaire.
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }
    
    /**
     * Handler personnalisé pour les échecs d'authentification.
     * Enregistre les tentatives échouées pour la protection brute force.
     */
    @Bean
    public AuthenticationFailureHandler authenticationFailureHandler() {
        return (request, response, exception) -> {
            String email = request.getParameter("username");
            if (email != null && !email.isBlank()) {
                userService.recordFailedLoginAttempt(email);
            }
            
            // Message d'erreur générique (ASVS V6.2.2)
            // Ne révèle pas si le compte existe ou non
            response.sendRedirect("/login?error=true");
        };
    }
    
    /**
     * Handler personnalisé pour les authentifications réussies.
     * Réinitialise le compteur de tentatives échouées.
     */
    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler() {
        return (request, response, authentication) -> {
            String email = authentication.getName();
            
            // Vérification du verrouillage du compte
            try {
                userService.checkAccountLockStatus(email);
            } catch (Exception e) {
                response.sendRedirect("/login?locked=true");
                return;
            }
            
            // Réinitialisation des tentatives échouées
            userService.resetFailedLoginAttempts(email);
            
            // Redirection vers la page de profil
            response.sendRedirect("/profile");
        };
    }
    
    /**
     * Configuration principale de la sécurité.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // Configuration des autorisations
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/", "/register", "/login", "/css/**", "/js/**", "/error").permitAll()
                .requestMatchers("/profile", "/change-password").authenticated()
                .anyRequest().authenticated()
            )
            
            // Configuration du formulaire de connexion
            .formLogin(form -> form
                .loginPage("/login")
                .loginProcessingUrl("/login")
                .usernameParameter("email")
                .passwordParameter("password")
                .successHandler(authenticationSuccessHandler())
                .failureHandler(authenticationFailureHandler())
                .permitAll()
            )
            
            // Configuration de la déconnexion
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login?logout=true")
                .invalidateHttpSession(true)  // Invalide la session (ASVS V6.3.3)
                .deleteCookies("JSESSIONID")  // Supprime le cookie de session
                .permitAll()
            )
            
            // Protection CSRF activée (par défaut, ASVS V6.2.3)
            // Ne JAMAIS désactiver en production !
            .csrf(csrf -> {})  // CSRF activé partout par défaut
            
            // Configuration des sessions
            .sessionManagement(session -> session
                .sessionFixation().migrateSession()  // Renouvelle la session après login (ASVS V6.3.4)
                .maximumSessions(3)  // Max 3 sessions simultanées par utilisateur
                .maxSessionsPreventsLogin(false)  // Nouvelle session expulse l'ancienne
                .sessionRegistry(sessionRegistry())  // Enregistre les sessions pour les gérer
            )
            
            // En-têtes de sécurité
            .headers(headers -> headers
                .contentSecurityPolicy(csp -> csp
                    .policyDirectives("default-src 'self'; style-src 'self' 'unsafe-inline';")
                )
                .frameOptions(frame -> frame.deny())  // Pas d'iframe
            );
        
        return http.build();
    }
    
    /**
     * Bean nécessaire pour détecter les événements de session
     * (création, destruction, expiration).
     */
    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }
    
    /**
     * Bean pour enregistrer et gérer les sessions actives.
     * Nécessaire pour l'invalidation des sessions après changement de mot de passe.
     */
    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }
}
