package be.energy.appasvs.exception;

/**
 * Exception levée lorsqu'un mot de passe est considéré comme trop faible
 * (mot de passe courant, compromis, etc.).
 * 
 * Conformité ASVS V6.2.5 : Refus des mots de passe compromis.
 */
public class WeakPasswordException extends RuntimeException {
    
    public WeakPasswordException(String message) {
        super(message);
    }
}
