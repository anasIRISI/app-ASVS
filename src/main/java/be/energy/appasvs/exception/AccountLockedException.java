package be.energy.appasvs.exception;

/**
 * Exception levée lorsqu'un compte est temporairement verrouillé
 * suite à trop de tentatives de connexion échouées.
 * 
 * Conformité ASVS V6.2.5 : Protection contre le brute force.
 */
public class AccountLockedException extends RuntimeException {
    
    public AccountLockedException(String message) {
        super(message);
    }
}
