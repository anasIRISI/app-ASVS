package be.energy.appasvs.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO pour la demande de changement de mot de passe.
 * 
 * Conformité ASVS :
 * - V6.2.2 : Même politique de mot de passe que l'inscription
 * - V6.2.4 : Vérification du mot de passe actuel avant changement
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class ChangePasswordRequest {
    
    @NotBlank(message = "Le mot de passe actuel est obligatoire")
    private String currentPassword;
    
    @NotBlank(message = "Le nouveau mot de passe est obligatoire")
    @Size(min = 8, max = 128, message = "Le nouveau mot de passe doit contenir entre 8 et 128 caractères")
    private String newPassword;
    
    @NotBlank(message = "La confirmation du nouveau mot de passe est obligatoire")
    private String confirmNewPassword;
    
    /**
     * Vérifie que le nouveau mot de passe et sa confirmation correspondent.
     */
    public boolean isNewPasswordMatching() {
        return newPassword != null && newPassword.equals(confirmNewPassword);
    }
}
