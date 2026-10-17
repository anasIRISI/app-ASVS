package be.energy.appasvs.repository;

import be.energy.appasvs.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Repository pour accéder aux utilisateurs dans la base de données.
 * 
 * Utilise Spring Data JPA qui génère automatiquement les requêtes SQL
 * de manière sécurisée (requêtes paramétrées, protection contre l'injection SQL).
 * 
 * Conformité ASVS :
 * - V6.2.1 : Recherche par email unique
 * - Protection injection SQL : requêtes paramétrées par défaut
 */
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    
    /**
     * Recherche un utilisateur par son adresse email.
     * Utilisé pour :
     * - Vérifier qu'un email n'existe pas déjà lors de l'inscription
     * - Charger les informations utilisateur lors de l'authentification
     */
    Optional<User> findByEmail(String email);
    
    /**
     * Vérifie si un email existe déjà en base de données.
     * Utile pour la validation lors de l'inscription.
     */
    boolean existsByEmail(String email);
}
