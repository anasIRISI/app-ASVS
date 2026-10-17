package be.energy.appasvs.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Entité User représentant un utilisateur dans la base de données.
 * 
 * Champs importants :
 * - email : unique, utilisé comme identifiant de connexion
 * - passwordHash : stocke le hash BCrypt du mot de passe (jamais en clair)
 * - role : attribué côté serveur, USER par défaut
 * - createdAt : date de création du compte
 * 
 * Conformité ASVS :
 * - V6.1.1 : Le mot de passe n'est jamais stocké en clair
 * - V6.2.1 : L'adresse email est unique (contrainte en base)
 */
@Entity
@Table(name = "users", uniqueConstraints = {
    @UniqueConstraint(columnNames = "email")
})
@Data
@NoArgsConstructor
@AllArgsConstructor
public class User {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @NotBlank(message = "Le nom complet est obligatoire")
    @Size(min = 2, max = 100, message = "Le nom doit contenir entre 2 et 100 caractères")
    @Column(nullable = false, length = 100)
    private String fullName;
    
    @NotBlank(message = "L'adresse email est obligatoire")
    @Email(message = "L'adresse email doit être valide")
    @Column(nullable = false, unique = true, length = 255)
    private String email;
    
    /**
     * Hash BCrypt du mot de passe.
     * Ne stocke JAMAIS le mot de passe en clair.
     */
    @NotBlank
    @Column(nullable = false)
    private String passwordHash;
    
    /**
     * Rôle de l'utilisateur.
     * USER par défaut lors de l'inscription.
     * Ne peut être ADMIN que via une attribution côté serveur.
     */
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Role role = Role.USER;
    
    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;
    
    /**
     * Compteur de tentatives de connexion échouées.
     * Utilisé pour la protection contre le brute force.
     */
    @Column(nullable = false)
    private int failedLoginAttempts = 0;
    
    /**
     * Date de verrouillage du compte suite à trop de tentatives échouées.
     * Null si le compte n'est pas verrouillé.
     */
    @Column
    private LocalDateTime lockoutUntil;
    
    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }
    
    /**
     * Vérifie si le compte est actuellement verrouillé.
     * Un compte est verrouillé si lockoutUntil est défini et dans le futur.
     */
    public boolean isAccountLocked() {
        return lockoutUntil != null && LocalDateTime.now().isBefore(lockoutUntil);
    }
}
