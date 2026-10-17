package be.energy.appasvs.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO pour la demande d'inscription d'un nouvel utilisateur.
 * 
 * Validation conforme ASVS V6 :
 * - V6.2.1 : Validation de l'email et vérification d'unicité
 * - V6.2.2 : Politique de mot de passe (min 8 chars, max 64+ chars)
 * - V6.2.3 : Confirmation du mot de passe
 * - V6.2.5 : Vérification contre mots de passe compromis (dans le service)
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class RegisterRequest {
    
    @NotBlank(message = "Le nom complet est obligatoire")
    @Size(min = 2, max = 100, message = "Le nom doit contenir entre 2 et 100 caractères")
    private String fullName;
    
    @NotBlank(message = "L'adresse email est obligatoire")
    @Email(message = "L'adresse email doit être valide")
    private String email;
    
    /**
     * Mot de passe : minimum 8 caractères, maximum 128 caractères.
     * ASVS V6.2.2 : Accepter au moins 64 caractères (ici on va jusqu'à 128).
     * La validation des mots de passe compromis se fait dans le service.
     */
    @NotBlank(message = "Le mot de passe est obligatoire")
    @Size(min = 8, max = 128, message = "Le mot de passe doit contenir entre 8 et 128 caractères")
    private String password;
    
    @NotBlank(message = "La confirmation du mot de passe est obligatoire")
    private String confirmPassword;
    
    /**
     * Vérifie que le mot de passe et sa confirmation correspondent.
     */
    public boolean isPasswordMatching() {
        return password != null && password.equals(confirmPassword);
    }
}
