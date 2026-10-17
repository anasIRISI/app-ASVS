package be.energy.appasvs.entity;

/**
 * Énumération des rôles disponibles dans l'application.
 * USER : rôle par défaut pour tous les utilisateurs inscrits.
 * ADMIN : rôle administrateur (ne peut pas être attribué via l'inscription).
 */
public enum Role {
    USER,
    ADMIN
}
