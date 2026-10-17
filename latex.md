```latex
\documentclass[12pt,a4paper]{article}

% Packages
\usepackage[utf8]{inputenc}
\usepackage[french]{babel}
\usepackage{geometry}
\usepackage{hyperref}
\usepackage{graphicx}
\usepackage{listings}
\usepackage{xcolor}
\usepackage{fancyhdr}
\usepackage{titlesec}

% Configuration de la page
\geometry{margin=2.5cm}
\pagestyle{fancy}
\fancyhf{}
\rhead{\thepage}
\lhead{Application d'Authentification Conforme OWASP ASVS}

% Configuration des listings de code
\lstset{
    basicstyle=\small\ttfamily,
    breaklines=true,
    frame=single,
    language=Java,
    showstringspaces=false,
    commentstyle=\color{gray},
    keywordstyle=\color{blue},
    stringstyle=\color{red},
    numbers=left,
    numberstyle=\tiny\color{gray},
    backgroundcolor=\color{lightgray!10}
}

\hypersetup{
    colorlinks=true,
    linkcolor=blue,
    urlcolor=blue,
    citecolor=blue
}

\begin{document}

% Page de titre
\begin{titlepage}
    \centering
    \vspace*{2cm}
    
    {\Huge\bfseries Application d'Authentification Sécurisée\par}
    \vspace{0.5cm}
    {\Large Conforme OWASP ASVS Niveau 1\par}
    \vspace{2cm}
    
    {\Large\itshape Votre Nom\par}
    \vspace{0.5cm}
    {\large Votre Université\par}
    {\large Année Académique 2024-2025\par}
    
    \vfill
    
    {\large \today\par}
\end{titlepage}

\tableofcontents
\newpage

% ============================================================================
\section{Introduction}

Ce rapport présente le développement d'une application web d'authentification sécurisée conforme aux exigences du niveau 1 de l'OWASP Application Security Verification Standard (ASVS) version 5.0. L'application a été développée avec Spring Boot et implémente les meilleures pratiques de sécurité pour l'authentification, la gestion des sessions et la protection des mots de passe.

\subsection{Objectifs du projet}

\begin{itemize}
    \item Développer un système d'authentification conforme OWASP ASVS niveau 1
    \item Implémenter les fonctionnalités : inscription, connexion, gestion de profil
    \item Protéger contre les attaques courantes (brute force, CSRF, injection SQL)
    \item Appliquer les bonnes pratiques de hashage des mots de passe
\end{itemize}

\subsection{Technologies utilisées}

\begin{itemize}
    \item \textbf{Backend :} Spring Boot 4.1.1, Spring Security 7.1.1
    \item \textbf{Base de données :} PostgreSQL
    \item \textbf{ORM :} Hibernate (JPA)
    \item \textbf{Frontend :} Thymeleaf, HTML5, CSS3
    \item \textbf{Validation :} Jakarta Validation
    \item \textbf{Hashage :} BCrypt
\end{itemize}

% ============================================================================
\section{Architecture de l'Application}

\subsection{Structure du projet}

L'application suit une architecture en couches MVC (Modèle-Vue-Contrôleur) :

\begin{itemize}
    \item \textbf{Entity :} Entités JPA (User, Role)
    \item \textbf{Repository :} Accès aux données via Spring Data JPA
    \item \textbf{Service :} Logique métier et règles de sécurité
    \item \textbf{Controller :} Gestion des requêtes HTTP
    \item \textbf{DTO :} Objets de transfert avec validation
    \item \textbf{Config :} Configuration Spring Security
\end{itemize}

\subsection{Fonctionnalités implémentées}

\begin{enumerate}
    \item Inscription avec validation des données
    \item Connexion avec protection contre le brute force
    \item Gestion du profil utilisateur
    \item Changement de mot de passe sécurisé
    \item Déconnexion avec invalidation de session
\end{enumerate}

% ============================================================================
\section{Conformité OWASP ASVS V6 - Authentication}

Cette section détaille comment chaque exigence ASVS a été implémentée dans le code.

\subsection{V6.1.1 : Hashage Sécurisé des Mots de Passe}

\textbf{Exigence :} Les mots de passe doivent être stockés avec un algorithme de hash adaptatif résistant (bcrypt, Argon2, scrypt, PBKDF2).

\textbf{Implémentation :} Utilisation de BCrypt avec un coût de 10 itérations.

\begin{lstlisting}[caption=PasswordEncoderConfig.java]
@Configuration
public class PasswordEncoderConfig {
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        // BCrypt avec cout par defaut de 10
        return new BCryptPasswordEncoder();
    }
}
\end{lstlisting}

\begin{lstlisting}[caption=Hashage lors de l'inscription - UserService.java]
public User registerUser(RegisterRequest request) {
    // Validation du mot de passe
    passwordValidationService.validatePasswordStrength(
        request.getPassword()
    );
    
    User user = new User();
    user.setFullName(request.getFullName());
    user.setEmail(request.getEmail());
    
    // Hash du mot de passe avec BCrypt
    String passwordHash = passwordEncoder.encode(
        request.getPassword()
    );
    user.setPasswordHash(passwordHash);
    user.setRole(Role.USER); // Role par defaut
    
    return userRepository.save(user);
}
\end{lstlisting}

\textbf{Points clés :}
\begin{itemize}
    \item BCrypt génère automatiquement un salt unique par mot de passe
    \item Le coût de 10 représente $2^{10}$ = 1024 itérations
    \item Le mot de passe en clair n'est jamais stocké
    \item Format du hash : \texttt{\$2a\$10\$[salt][hash]}
\end{itemize}

% ----------------------------------------------------------------------------
\subsection{V6.2.1 : Email Unique}

\textbf{Exigence :} L'identifiant d'authentification doit être unique.

\textbf{Implémentation :} Contrainte d'unicité sur l'email en base de données.

\begin{lstlisting}[caption=Contrainte unique - User.java]
@Entity
@Table(name = "users", uniqueConstraints = {
    @UniqueConstraint(columnNames = "email")
})
public class User {
    
    @Email(message = "L'adresse email doit etre valide")
    @Column(nullable = false, unique = true, length = 255)
    private String email;
    
    // ...
}
\end{lstlisting}

\begin{lstlisting}[caption=Verification cote service - UserService.java]
public User registerUser(RegisterRequest request) {
    // Verification de l'unicite de l'email
    if (userRepository.existsByEmail(request.getEmail())) {
        throw new EmailAlreadyExistsException(
            "Cette adresse email est deja utilisee"
        );
    }
    // ...
}
\end{lstlisting}

% ----------------------------------------------------------------------------
\subsection{V6.2.2 : Politique de Mot de Passe}

\textbf{Exigence :} Les mots de passe doivent faire au minimum 8 caractères et accepter jusqu'à 64+ caractères.

\textbf{Implémentation :} Validation côté serveur avec Jakarta Validation.

\begin{lstlisting}[caption=Validation du mot de passe - RegisterRequest.java]
@Data
public class RegisterRequest {
    
    @NotBlank(message = "Le mot de passe est obligatoire")
    @Size(min = 8, max = 128, 
          message = "Le mot de passe doit contenir entre 8 et 128 caracteres")
    private String password;
    
    @NotBlank(message = "La confirmation est obligatoire")
    private String confirmPassword;
    
    public boolean isPasswordMatching() {
        return password != null && 
               password.equals(confirmPassword);
    }
}
\end{lstlisting}

% ----------------------------------------------------------------------------
\subsection{V6.2.5 : Protection Mots de Passe Compromis}

\textbf{Exigence :} L'application doit rejeter les mots de passe courants et compromis.

\textbf{Implémentation :} Liste de blocage des mots de passe courants.

\begin{lstlisting}[caption=Validation robustesse - PasswordValidationService.java]
@Service
public class PasswordValidationService {
    
    private static final Set<String> COMMON_PASSWORDS = Set.of(
        "password", "123456", "12345678", "qwerty", 
        "abc123", "monkey", "letmein", "admin", "root"
        // ... liste complete de 40+ mots de passe
    );
    
    public void validatePasswordStrength(String password) {
        String lowerPassword = password.toLowerCase();
        
        // Verification contre mots de passe courants
        if (COMMON_PASSWORDS.contains(lowerPassword)) {
            throw new WeakPasswordException(
                "Ce mot de passe est trop courant"
            );
        }
        
        // Verification sequences evidentes
        if (isSequentialPassword(password)) {
            throw new WeakPasswordException(
                "Le mot de passe contient des sequences evidentes"
            );
        }
    }
}
\end{lstlisting}

% ----------------------------------------------------------------------------
\subsection{V6.2.5 : Protection contre le Brute Force}

\textbf{Exigence :} Protection contre les attaques par force brute.

\textbf{Implémentation :} Verrouillage temporaire après 5 tentatives échouées.

\begin{lstlisting}[caption=Gestion tentatives echouees - UserService.java]
private static final int MAX_FAILED_ATTEMPTS = 5;
private static final int LOCKOUT_DURATION_MINUTES = 15;

public void recordFailedLoginAttempt(String email) {
    userRepository.findByEmail(email).ifPresent(user -> {
        int attempts = user.getFailedLoginAttempts() + 1;
        user.setFailedLoginAttempts(attempts);
        
        if (attempts >= MAX_FAILED_ATTEMPTS) {
            LocalDateTime lockoutUntil = LocalDateTime.now()
                .plusMinutes(LOCKOUT_DURATION_MINUTES);
            user.setLockoutUntil(lockoutUntil);
        }
        
        userRepository.save(user);
    });
}

public void checkAccountLockStatus(String email) {
    User user = userRepository.findByEmail(email).orElse(null);
    
    if (user != null && user.isAccountLocked()) {
        throw new AccountLockedException(
            "Compte verrouille temporairement"
        );
    }
}
\end{lstlisting}

% ----------------------------------------------------------------------------
\subsection{V6.2.6 : Messages d'Erreur Génériques}

\textbf{Exigence :} Les messages d'erreur d'authentification doivent être génériques pour ne pas révéler l'existence d'un compte.

\textbf{Implémentation :} Message unique pour tous les échecs.

\begin{lstlisting}[caption=Handler echec authentification - SecurityConfig.java]
@Bean
public AuthenticationFailureHandler 
       authenticationFailureHandler() {
    return (request, response, exception) -> {
        String email = request.getParameter("username");
        if (email != null && !email.isBlank()) {
            userService.recordFailedLoginAttempt(email);
        }
        
        // Message generique (ASVS V6.2.6)
        response.sendRedirect("/login?error=true");
    };
}
\end{lstlisting}

\begin{lstlisting}[caption=Message generique - AuthController.java]
@GetMapping("/login")
public String loginPage(@RequestParam(required = false) String error,
                        Model model) {
    if (error != null) {
        // Ne revele pas si le compte existe
        model.addAttribute("error", 
            "Identifiants incorrects. Veuillez reessayer.");
    }
    return "login";
}
\end{lstlisting}

% ----------------------------------------------------------------------------
\subsection{V6.2.3 : Protection CSRF}

\textbf{Exigence :} Les formulaires d'authentification doivent être protégés contre les attaques CSRF.

\textbf{Implémentation :} Protection CSRF activée par défaut avec Spring Security.

\begin{lstlisting}[caption=Configuration CSRF - SecurityConfig.java]
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) 
       throws Exception {
    http
        // CSRF active par defaut (ASVS V6.2.3)
        .csrf(csrf -> {})  // Ne JAMAIS desactiver en production
        
        .formLogin(form -> form
            .loginPage("/login")
            .loginProcessingUrl("/login")
            .usernameParameter("email")
            .passwordParameter("password")
            .permitAll()
        );
    
    return http.build();
}
\end{lstlisting}

\begin{lstlisting}[caption=Token CSRF dans les vues - login.html, language=HTML]
<form th:action="@{/login}" method="post">
    <!-- Token CSRF automatique par Thymeleaf -->
    <input type="hidden" 
           th:name="${_csrf.parameterName}" 
           th:value="${_csrf.token}"/>
    
    <input type="email" name="email" required>
    <input type="password" name="password" required>
    <button type="submit">Se connecter</button>
</form>
\end{lstlisting}

% ----------------------------------------------------------------------------
\subsection{V6.3.1 : Gestion Sécurisée des Sessions}

\textbf{Exigence :} Les sessions doivent être renouvelées après l'authentification.

\textbf{Implémentation :} Protection contre la fixation de session.

\begin{lstlisting}[caption=Configuration sessions - SecurityConfig.java]
http
    .sessionManagement(session -> session
        // Renouvelle la session (ASVS V6.3.1)
        .sessionFixation().migrateSession()
        
        // Max 3 sessions simultanees par utilisateur
        .maximumSessions(3)
        .maxSessionsPreventsLogin(false)
        .sessionRegistry(sessionRegistry())
    );
\end{lstlisting}

% ----------------------------------------------------------------------------
\subsection{V6.3.2 : Cookies Sécurisés}

\textbf{Exigence :} Les cookies de session doivent être HttpOnly et Secure.

\textbf{Implémentation :} Configuration dans application.properties.

\begin{lstlisting}[caption=Configuration cookies - application.properties, language=bash]
# Session Configuration
server.servlet.session.timeout=30m
server.servlet.session.cookie.http-only=true
server.servlet.session.cookie.secure=false
server.servlet.session.cookie.same-site=lax
\end{lstlisting}

\textbf{Note :} \texttt{secure=false} en développement, \texttt{true} en production avec HTTPS.

% ----------------------------------------------------------------------------
\subsection{V6.3.3 : Invalidation de Session}

\textbf{Exigence :} La déconnexion doit invalider complètement la session.

\textbf{Implémentation :} Invalidation session + suppression cookie.

\begin{lstlisting}[caption=Configuration deconnexion - SecurityConfig.java]
http
    .logout(logout -> logout
        .logoutUrl("/logout")
        .logoutSuccessUrl("/login?logout=true")
        .invalidateHttpSession(true)  // Invalide session
        .deleteCookies("JSESSIONID")  // Supprime cookie
        .permitAll()
    );
\end{lstlisting}

% ----------------------------------------------------------------------------
\subsection{V6.3.4 : Invalidation Autres Sessions}

\textbf{Exigence :} Lors du changement de mot de passe, les autres sessions doivent être invalidées.

\textbf{Implémentation :} Expiration des sessions via SessionRegistry.

\begin{lstlisting}[caption=Invalidation sessions - UserController.java]
@PostMapping("/change-password")
public String changePassword(
        @Valid @ModelAttribute ChangePasswordRequest request,
        Authentication authentication,
        HttpServletRequest httpRequest,
        RedirectAttributes redirectAttributes) {
    
    String email = authentication.getName();
    
    // Changement du mot de passe
    userService.changePassword(email, request);
    
    // Invalidation autres sessions (ASVS V6.3.4)
    invalidateOtherUserSessions(
        email, 
        httpRequest.getSession().getId()
    );
    
    return "redirect:/profile";
}

private void invalidateOtherUserSessions(
        String username, 
        String currentSessionId) {
    List<SessionInformation> sessions = 
        sessionRegistry.getAllSessions(username, false);
    
    for (SessionInformation session : sessions) {
        if (!session.getSessionId().equals(currentSessionId)) {
            session.expireNow();
        }
    }
}
\end{lstlisting}

% ============================================================================
\section{Protections Supplémentaires Implémentées}

\subsection{Injection SQL}

\textbf{Protection :} Utilisation de Spring Data JPA avec requêtes paramétrées automatiques.

\begin{lstlisting}[caption=Requetes securisees - UserRepository.java]
@Repository
public interface UserRepository 
       extends JpaRepository<User, Long> {
    
    // Requete parametree automatique
    Optional<User> findByEmail(String email);
    
    // Protection injection SQL par JPA
    boolean existsByEmail(String email);
}
\end{lstlisting}

\subsection{Validation Côté Serveur}

\textbf{Protection :} Validation Jakarta avant traitement.

\begin{lstlisting}[caption=Validation controleur - AuthController.java]
@PostMapping("/register")
public String registerUser(
        @Valid @ModelAttribute RegisterRequest registerRequest,
        BindingResult bindingResult,
        Model model) {
    
    // Verification erreurs validation
    if (bindingResult.hasErrors()) {
        return "register";
    }
    
    // Verification correspondance mots de passe
    if (!registerRequest.isPasswordMatching()) {
        model.addAttribute("error", 
            "Les mots de passe ne correspondent pas");
        return "register";
    }
    
    // Traitement...
}
\end{lstlisting}

\subsection{En-têtes de Sécurité}

\textbf{Protection :} Configuration des headers HTTP de sécurité.

\begin{lstlisting}[caption=Headers securite - SecurityConfig.java]
http
    .headers(headers -> headers
        .contentSecurityPolicy(csp -> csp
            .policyDirectives(
                "default-src 'self'; " +
                "style-src 'self' 'unsafe-inline';"
            )
        )
        .frameOptions(frame -> frame.deny())
    );
\end{lstlisting}

% ============================================================================
\section{Tests et Vérification}

\subsection{Tests Unitaires Implémentés}

15 tests automatisés couvrent toutes les exigences ASVS :

\begin{enumerate}
    \item Inscription avec données valides
    \item Refus email déjà utilisé
    \item Refus mot de passe trop court
    \item Refus mot de passe courant
    \item Vérification hash du mot de passe
    \item Connexion avec identifiants corrects
    \item Refus connexion mot de passe incorrect
    \item Message d'erreur générique
    \item Accès refusé sans authentification
    \item Accès autorisé après authentification
    \item Déconnexion et invalidation session
    \item Changement mot de passe avec ancien incorrect
    \item Protection CSRF sur formulaires
    \item Limitation tentatives connexion
    \item Impossible s'attribuer rôle ADMIN
\end{enumerate}

\subsection{Exécution des Tests}

\begin{lstlisting}[language=bash, caption=Commande pour executer les tests]
./gradlew test
\end{lstlisting}

Les tests utilisent H2 en mémoire pour ne pas dépendre de PostgreSQL.

% ============================================================================
\section{Configuration et Déploiement}

\subsection{Prérequis}

\begin{itemize}
    \item Java 17 ou supérieur
    \item PostgreSQL 14+
    \item Gradle 7+
\end{itemize}

\subsection{Configuration PostgreSQL}

\begin{lstlisting}[language=bash, caption=Creation base de donnees]
psql -U postgres
CREATE DATABASE auth_db;
\q
\end{lstlisting}

\subsection{Variables d'Environnement}

\begin{lstlisting}[language=bash, caption=Configuration Windows PowerShell]
$env:DB_USERNAME="postgres"
$env:DB_PASSWORD="votre_mot_de_passe"
\end{lstlisting}

\subsection{Lancement de l'Application}

\begin{lstlisting}[language=bash, caption=Demarrage avec Gradle]
./gradlew bootRun
\end{lstlisting}

L'application sera accessible sur \url{http://localhost:8080}

% ============================================================================
\section{Conclusion}

Cette application démontre l'implémentation concrète des exigences OWASP ASVS niveau 1 pour l'authentification. Tous les aspects critiques de la sécurité ont été couverts :

\begin{itemize}
    \item \textbf{Hashage sécurisé} avec BCrypt
    \item \textbf{Protection brute force} par verrouillage temporaire
    \item \textbf{Validation robuste} des mots de passe
    \item \textbf{Gestion sécurisée} des sessions
    \item \textbf{Protection CSRF} sur tous les formulaires
    \item \textbf{Messages génériques} ne révélant pas d'informations
    \item \textbf{Validation côté serveur} systématique
\end{itemize}

Le code source est entièrement commenté et les tests automatisés garantissent la conformité aux exigences. L'application est prête pour un déploiement en environnement de production après configuration appropriée (HTTPS, augmentation du coût BCrypt, intégration Pwned Passwords API).

% ============================================================================
\section*{Références}

\begin{itemize}
    \item OWASP ASVS 5.0 - \url{https://github.com/OWASP/ASVS}
    \item Spring Security Documentation - \url{https://spring.io/projects/spring-security}
    \item BCrypt Algorithm - \url{https://en.wikipedia.org/wiki/Bcrypt}
\end{itemize}

\end{document}
```
