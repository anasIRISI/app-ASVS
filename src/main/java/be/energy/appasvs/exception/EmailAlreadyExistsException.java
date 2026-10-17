package be.energy.appasvs.exception;

/**
 * Exception levée lorsqu'un utilisateur tente de s'inscrire
 * avec une adresse email déjà utilisée.
 * 
 * Conformité ASVS V6.2.1 : Email unique.
 */
public class EmailAlreadyExistsException extends RuntimeException {
    
    public EmailAlreadyExistsException(String message) {
        super(message);
    }
}
