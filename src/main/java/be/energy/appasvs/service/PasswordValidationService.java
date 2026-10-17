package be.energy.appasvs.service;

import be.energy.appasvs.exception.WeakPasswordException;
import org.springframework.stereotype.Service;

import java.util.Set;

/**
 * Service de validation de la robustesse des mots de passe.
 * 
 * Conformité ASVS V6.2.5 :
 * - Refus des mots de passe courants et compromis
 * - Utilisation d'une liste de blocage
 * 
 * Note pour la production :
 * Cette implémentation utilise une liste statique simple.
 * Pour une application de production, utilisez :
 * - Pwned Passwords API (haveibeenpwned.com)
 * - Une liste plus complète de mots de passe compromis
 * - Un fichier de configuration externe
 */
@Service
public class PasswordValidationService {
    
    /**
     * Liste des mots de passe les plus courants et compromis à bloquer.
     * Source : Top 100 des mots de passe les plus utilisés.
     * 
     * En production, cette liste devrait être bien plus complète.
     */
    private static final Set<String> COMMON_PASSWORDS = Set.of(
        "password", "123456", "12345678", "qwerty", "abc123", 
        "monkey", "1234567", "letmein", "trustno1", "dragon",
        "baseball", "111111", "iloveyou", "master", "sunshine",
        "ashley", "bailey", "passw0rd", "shadow", "123123",
        "654321", "superman", "qazwsx", "michael", "football",
        "password1", "welcome", "jesus", "ninja", "mustang",
        "admin", "root", "user", "test", "guest",
        "changeme", "password123", "12341234", "azerty", "qwertz"
    );
    
    /**
     * Valide qu'un mot de passe n'est pas faible ou compromis.
     * 
     * @param password Le mot de passe à valider
     * @throws WeakPasswordException Si le mot de passe est considéré comme faible
     */
    public void validatePasswordStrength(String password) {
        if (password == null || password.isBlank()) {
            throw new WeakPasswordException("Le mot de passe ne peut pas être vide");
        }
        
        // Vérification contre les mots de passe courants (case-insensitive)
        String lowerPassword = password.toLowerCase();
        if (COMMON_PASSWORDS.contains(lowerPassword)) {
            throw new WeakPasswordException(
                "Ce mot de passe est trop courant et ne peut pas être utilisé. " +
                "Veuillez choisir un mot de passe plus fort."
            );
        }
        
        // Vérification de motifs faibles évidents
        if (isSequentialPassword(password)) {
            throw new WeakPasswordException(
                "Le mot de passe ne doit pas contenir de séquences évidentes comme '12345' ou 'abcde'"
            );
        }
        
        // Note : en production, ajoutez ici :
        // - Vérification contre Pwned Passwords API
        // - Vérification de patterns répétitifs (aaaa, 1111, etc.)
        // - Vérification de la complexité selon la politique de l'entreprise
    }
    
    /**
     * Détecte les séquences numériques ou alphabétiques simples.
     */
    private boolean isSequentialPassword(String password) {
        String lowerPassword = password.toLowerCase();
        
        // Séquences numériques
        String[] numericSequences = {"0123", "1234", "2345", "3456", "4567", 
                                     "5678", "6789", "9876", "8765", "7654"};
        for (String seq : numericSequences) {
            if (lowerPassword.contains(seq)) {
                return true;
            }
        }
        
        // Séquences alphabétiques
        String[] alphaSequences = {"abcd", "bcde", "cdef", "defg", "efgh",
                                   "fghi", "ghij", "hijk", "ijkl", "jklm"};
        for (String seq : alphaSequences) {
            if (lowerPassword.contains(seq)) {
                return true;
            }
        }
        
        return false;
    }
}
