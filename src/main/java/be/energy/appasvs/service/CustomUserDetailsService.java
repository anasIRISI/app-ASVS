package be.energy.appasvs.service;

import be.energy.appasvs.entity.User;
import be.energy.appasvs.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;

/**
 * Service personnalisé pour charger les détails utilisateur depuis la base de données.
 * Utilisé par Spring Security pour l'authentification.
 * 
 * Conformité ASVS :
 * - V6.2.1 : Authentification basée sur l'email unique
 * - V6.3.1 : Chargement sécurisé des informations utilisateur
 */
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {
    
    private final UserRepository userRepository;
    
    /**
     * Charge un utilisateur par son email (utilisé comme username).
     * 
     * @param email L'adresse email de l'utilisateur
     * @return Les détails de l'utilisateur pour Spring Security
     * @throws UsernameNotFoundException Si l'utilisateur n'existe pas
     */
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(email)
            .orElseThrow(() -> new UsernameNotFoundException("Utilisateur non trouvé : " + email));
        
        // Ne pas exposer si le compte est verrouillé ici
        // La vérification du verrouillage se fait dans l'AuthenticationSuccessHandler
        
        return org.springframework.security.core.userdetails.User.builder()
            .username(user.getEmail())
            .password(user.getPasswordHash())
            .authorities(Collections.singletonList(
                new SimpleGrantedAuthority("ROLE_" + user.getRole().name())
            ))
            .accountExpired(false)
            .accountLocked(false)  // Géré séparément dans le service
            .credentialsExpired(false)
            .disabled(false)
            .build();
    }
}
