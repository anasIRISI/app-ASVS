# Application d'Authentification Sécurisée - Conformité OWASP ASVS Niveau 1

## 📋 Vue d'ensemble

Cette application Spring Boot implémente un système d'authentification sécurisé conforme aux exigences du chapitre V6 (Authentication) de l'OWASP ASVS 5.0.0 niveau 1.

## 🏗️ Architecture

### Structure du projet

```
src/main/java/be/energy/appasvs/
├── config/                    # Configuration Spring Security
│   └── SecurityConfig.java
├── controller/                # Contrôleurs web
│   ├── AuthController.java    (inscription, connexion)
│   └── UserController.java    (profil, changement mot de passe)
├── dto/                       # Objets de transfert avec validation
│   ├── RegisterRequest.java
│   ├── LoginRequest.java
│   └── ChangePasswordRequest.java
├── entity/                    # Entités JPA
│   ├── User.java
│   └── Role.java
├── exception/                 # Exceptions métier
│   ├── EmailAlreadyExistsException.java
│   ├── WeakPasswordException.java
│   └── AccountLockedException.java
├── repository/                # Accès aux données
│   └── UserRepository.java
└── service/                   # Logique métier
    ├── UserService.java
    ├── CustomUserDetailsService.java
    └── PasswordValidationService.java
```

### Rôle de chaque couche

1. **Entity (Entités)** : Représentation des tables de la base de données
   - `User` : Stocke les informations utilisateur (email, hash du mot de passe, rôle, etc.)
   - `Role` : Énumération des rôles (USER, ADMIN)

2. **Repository** : Accès aux données via Spring Data JPA
   - Génère automatiquement les requêtes SQL de manière sécurisée
   - Protection contre l'injection SQL

3. **Service** : Logique métier
   - `UserService` : Inscription, changement de mot de passe, gestion brute force
   - `PasswordValidationService` : Validation de la robustesse des mots de passe
   - `CustomUserDetailsService` : Chargement des utilisateurs pour Spring Security

4. **DTO (Data Transfer Objects)** : Objets de transfert avec validation
   - Valident les données d'entrée côté serveur
   - Protègent contre les données malveillantes

5. **Controller** : Gestion des requêtes HTTP
   - `AuthController` : Inscription et connexion
   - `UserController` : Profil et changement de mot de passe

6. **Config** : Configuration de sécurité
   - `SecurityConfig` : Configuration Spring Security complète

## 🔧 Configuration de PostgreSQL

### 1. Installer PostgreSQL

Si PostgreSQL n'est pas encore installé :
- Télécharger depuis : https://www.postgresql.org/download/
- Suivre les instructions d'installation
- Noter le mot de passe de l'utilisateur postgres

### 2. Créer la base de données

Ouvrir psql ou pgAdmin et exécuter :

```sql
CREATE DATABASE auth_db;
```

### 3. Configurer les variables d'environnement

**Windows PowerShell :**
```powershell
$env:DB_USERNAME="postgres"
$env:DB_PASSWORD="votre_mot_de_passe"
```

**Windows CMD :**
```cmd
set DB_USERNAME=postgres
set DB_PASSWORD=votre_mot_de_passe
```

**Linux/Mac :**
```bash
export DB_USERNAME=postgres
export DB_PASSWORD=votre_mot_de_passe
```

⚠️ **IMPORTANT** : Ne JAMAIS committer le mot de passe dans le code source !

## 🚀 Lancement de l'application

### Méthode 1 : Avec Gradle

```powershell
# Compiler le projet
./gradlew clean build

# Lancer l'application
./gradlew bootRun
```

### Méthode 2 : Avec Java directement

```powershell
# Compiler
./gradlew clean build

# Lancer
java -jar build/libs/app-ASVS-0.0.1-SNAPSHOT.jar
```

### Méthode 3 : Depuis votre IDE

- Ouvrir le projet dans IntelliJ IDEA ou Eclipse
- Configurer les variables d'environnement dans la configuration de lancement
- Exécuter `AppAsvsApplication.java`

## 🧪 Exécution des tests

### Tous les tests

```powershell
./gradlew test
```

### Tests spécifiques

```powershell
# Tests du service utilisateur
./gradlew test --tests UserServiceTest

# Tests de validation des mots de passe
./gradlew test --tests PasswordValidationServiceTest

# Tests d'intégration
./gradlew test --tests "*IntegrationTest"
```

### Rapport de tests

Après l'exécution, le rapport HTML est disponible dans :
```
build/reports/tests/test/index.html
```

## 🌐 URLs de l'application

Une fois l'application lancée, accéder aux pages suivantes :

- **Page d'accueil** : http://localhost:8080/
- **Inscription** : http://localhost:8080/register
- **Connexion** : http://localhost:8080/login
- **Profil** (authentification requise) : http://localhost:8080/profile
- **Changement de mot de passe** (authentification requise) : http://localhost:8080/change-password

## ✅ Conformité OWASP ASVS V6 - Niveau 1

### Tableau de correspondance

| ID ASVS | Exigence | Implémentation | Fichier(s) concerné(s) | Tests |
|---------|----------|----------------|------------------------|-------|
| **V6.1.1** | Les mots de passe doivent être stockés de manière sécurisée avec un algorithme de hash adaptatif | ✅ BCrypt avec salt automatique | `SecurityConfig.java`, `UserService.java` | Test 5 |
| **V6.2.1** | L'authentification par mot de passe doit utiliser un identifiant unique | ✅ Email unique en base | `User.java` (contrainte unique), `UserRepository.java` | Test 2 |
| **V6.2.2** | Les mots de passe doivent faire au minimum 8 caractères et accepter jusqu'à 64+ caractères | ✅ Min 8, max 128 caractères | `RegisterRequest.java`, `ChangePasswordRequest.java` | Tests 3, validation |
| **V6.2.3** | Le changement de mot de passe requiert le mot de passe actuel | ✅ Vérification obligatoire | `UserService.changePassword()` | Test 12 |
| **V6.2.4** | Les formulaires d'authentification doivent être protégés contre CSRF | ✅ CSRF activé par défaut | `SecurityConfig.java`, templates HTML | Test 13 |
| **V6.2.5** | L'application doit rejeter les mots de passe compromis/courants | ✅ Liste de blocage + validation | `PasswordValidationService.java` | Test 4 |
| **V6.2.5** | Protection contre les attaques par force brute | ✅ Verrouillage temporaire après 5 tentatives | `UserService.recordFailedLoginAttempt()` | Test 14 |
| **V6.2.6** | Les messages d'erreur d'authentification doivent être génériques | ✅ Message unique pour tous les échecs | `SecurityConfig.authenticationFailureHandler()` | Test 8 |
| **V6.3.1** | Les sessions doivent être renouvelées après authentification | ✅ Session fixation protection | `SecurityConfig.sessionFixation().migrateSession()` | Configuration |
| **V6.3.2** | Les cookies de session doivent être HttpOnly et Secure | ✅ Configuré | `application.properties`, `SecurityConfig` | Configuration |
| **V6.3.3** | La déconnexion doit invalider la session | ✅ Invalidation complète | `SecurityConfig.logout()` | Test 11 |
| **V6.3.4** | Lors du changement de mot de passe, les autres sessions doivent être invalidées | ✅ Invalidation des autres sessions | `UserController.invalidateOtherUserSessions()` | Logique implémentée |
| **V6.4.1** | Les identifiants ne doivent pas être exposés dans les logs | ✅ Aucun log de mot de passe | Configuration logs | Vérification code |

### Tests ASVS implémentés

| N° | Test | Statut | Classe de test |
|----|------|--------|----------------|
| 1 | Inscription avec données valides | ✅ | `UserServiceTest`, `AuthControllerIntegrationTest` |
| 2 | Refus email déjà utilisé | ✅ | `UserServiceTest`, `AuthControllerIntegrationTest` |
| 3 | Refus mot de passe trop court | ✅ | `UserServiceTest`, `AuthControllerIntegrationTest` |
| 4 | Refus mot de passe courant | ✅ | `PasswordValidationServiceTest`, `UserServiceTest` |
| 5 | Vérification hash du mot de passe | ✅ | `UserServiceTest`, `AuthControllerIntegrationTest` |
| 6 | Connexion avec identifiants corrects | ✅ | `AuthControllerIntegrationTest` |
| 7 | Refus connexion mot de passe incorrect | ✅ | `AuthControllerIntegrationTest` |
| 8 | Message d'erreur générique | ✅ | `AuthControllerIntegrationTest` |
| 9 | Accès refusé sans authentification | ✅ | `UserControllerIntegrationTest` |
| 10 | Accès autorisé après authentification | ✅ | `UserControllerIntegrationTest` |
| 11 | Déconnexion et invalidation session | ✅ | `UserControllerIntegrationTest` |
| 12 | Changement mdp avec ancien incorrect | ✅ | `UserServiceTest`, `UserControllerIntegrationTest` |
| 13 | Protection CSRF sur formulaires | ✅ | `AuthControllerIntegrationTest`, `UserControllerIntegrationTest` |
| 14 | Limitation tentatives connexion | ✅ | `UserServiceTest` |
| 15 | Impossible de s'attribuer rôle ADMIN | ✅ | `UserServiceTest` |

## 🔒 Fonctionnalités de sécurité

### 1. Hash des mots de passe
- Algorithme : **BCrypt**
- Coût : 10 (2^10 itérations)
- Salt : Généré automatiquement et unique pour chaque mot de passe
- Pas de stockage en clair jamais !

### 2. Protection contre le brute force
- Max tentatives : 5 tentatives échouées
- Durée de verrouillage : 15 minutes
- Verrouillage temporaire (pas de blocage permanent)
- Réinitialisation automatique après connexion réussie

### 3. Politique de mot de passe
- Longueur minimale : 8 caractères
- Longueur maximale : 128 caractères
- Refus des mots de passe courants (password, 123456, etc.)
- Refus des séquences évidentes (1234, abcd, etc.)
- Validation côté serveur obligatoire

### 4. Protection CSRF
- Activée sur tous les formulaires
- Token CSRF généré automatiquement par Thymeleaf
- Impossible de soumettre des formulaires sans token valide

### 5. Gestion des sessions
- Renouvellement de session après authentification
- Cookies HttpOnly (protection XSS)
- Cookies Secure en production (HTTPS)
- SameSite=Lax (protection CSRF)
- Durée de session : 30 minutes
- Invalidation complète à la déconnexion
- Max 3 sessions simultanées par utilisateur

### 6. Messages d'erreur génériques
- Pas de révélation si un compte existe
- Message unique pour tous les échecs d'authentification
- Protection contre l'énumération des comptes

### 7. Protection injection SQL
- Utilisation de Spring Data JPA
- Requêtes paramétrées automatiquement
- Pas de concaténation de chaînes SQL

### 8. Validation des données
- Validation côté serveur avec Jakarta Validation
- Vérification de tous les champs obligatoires
- Validation du format email
- Vérification de la correspondance des mots de passe

## 📝 Utilisation de l'application

### Scénario 1 : Inscription d'un nouvel utilisateur

1. Accéder à http://localhost:8080/register
2. Remplir le formulaire :
   - Nom complet : Jean Dupont
   - Email : jean.dupont@example.com
   - Mot de passe : MonMotDePasse2024!
   - Confirmation : MonMotDePasse2024!
3. Cliquer sur "S'inscrire"
4. Redirection vers la page de connexion avec message de succès

### Scénario 2 : Connexion

1. Accéder à http://localhost:8080/login
2. Saisir l'email et le mot de passe
3. Cliquer sur "Se connecter"
4. Redirection vers la page de profil

### Scénario 3 : Changement de mot de passe

1. Se connecter
2. Sur la page de profil, cliquer sur "Changer mon mot de passe"
3. Remplir le formulaire :
   - Mot de passe actuel
   - Nouveau mot de passe
   - Confirmation du nouveau mot de passe
4. Cliquer sur "Changer le mot de passe"
5. Les autres sessions de l'utilisateur sont déconnectées

### Scénario 4 : Protection brute force

1. Essayer de se connecter avec un mauvais mot de passe
2. Répéter 5 fois
3. Le compte est verrouillé pour 15 minutes
4. Message : "Votre compte est temporairement verrouillé..."

## ⚠️ Points d'attention pour la production

### Sécurité renforcée

1. **HTTPS obligatoire**
   - Activer `server.servlet.session.cookie.secure=true`
   - Obtenir un certificat SSL/TLS valide

2. **Mots de passe compromis**
   - Intégrer l'API Pwned Passwords (haveibeenpwned.com)
   - Utiliser une liste plus complète de mots de passe compromis

3. **Coût BCrypt**
   - Augmenter à 12 ou plus selon la capacité du serveur
   - Modifier dans `SecurityConfig.passwordEncoder()`

4. **Logs**
   - Configurer un système de logs centralisé
   - Monitorer les tentatives de connexion échouées
   - Alertes sur activités suspectes

5. **Rate limiting**
   - Ajouter un rate limiting global (pas seulement par compte)
   - Utiliser Spring Boot Rate Limiting ou un reverse proxy

6. **Headers de sécurité**
   - Vérifier tous les headers HTTP de sécurité
   - Utiliser un scanner de sécurité (OWASP ZAP, Burp Suite)

7. **Authentification multi-facteurs (MFA)**
   - Ajouter l'authentification à deux facteurs pour niveau 2+
   - TOTP, SMS, ou application d'authentification

8. **Audit et monitoring**
   - Journaliser toutes les actions sensibles
   - Implémenter un système d'audit complet
   - Alertes en temps réel

### Variables d'environnement

En production, définir :
```
DB_USERNAME=utilisateur_prod
DB_PASSWORD=mot_de_passe_sécurisé
SPRING_PROFILES_ACTIVE=prod
```

Ne jamais committer ces valeurs !

## 🐛 Dépannage

### Problème : Connexion refusée à PostgreSQL

**Solution** :
1. Vérifier que PostgreSQL est démarré
2. Vérifier les variables d'environnement
3. Vérifier le fichier `application.properties`
4. Tester la connexion manuellement : `psql -U postgres -d auth_db`

### Problème : Erreur CSRF sur les formulaires

**Solution** :
1. Vérifier que le token CSRF est présent dans le HTML
2. Ne pas désactiver CSRF dans `SecurityConfig`
3. Utiliser Thymeleaf pour générer les formulaires

### Problème : Session perdue après connexion

**Solution** :
1. Vérifier la configuration des cookies
2. Vérifier que `HttpSessionEventPublisher` est configuré
3. Vérifier les logs Spring Security

### Problème : Tests échouent

**Solution** :
1. Vérifier la configuration de la base de données de test
2. Utiliser H2 en mémoire pour les tests si PostgreSQL n'est pas disponible
3. Vérifier que toutes les dépendances sont présentes

## 📚 Ressources

### Documentation officielle
- [OWASP ASVS 5.0.0](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x15-V6-Authentication.md)
- [Spring Security Reference](https://docs.spring.io/spring-security/reference/)
- [Spring Boot Documentation](https://docs.spring.io/spring-boot/docs/current/reference/html/)

### Sécurité
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [Have I Been Pwned](https://haveibeenpwned.com/)

## 👨‍🎓 Notes pédagogiques

Ce projet est conçu pour les étudiants. Voici quelques points importants :

1. **Ne réinventez pas la roue** : Spring Security fournit des mécanismes éprouvés. Utilisez-les !

2. **La sécurité est un processus** : Ce projet couvre le niveau 1 de l'ASVS. Les applications de production nécessitent souvent niveau 2 ou 3.

3. **Testez tout** : La sécurité ne se vérifie pas à l'œil. Écrivez et exécutez des tests.

4. **Lisez le code** : Chaque classe contient des commentaires expliquant les décisions de sécurité.

5. **Restez à jour** : Les vulnérabilités évoluent. Mettez à jour régulièrement vos dépendances.

## 📄 Licence

Ce projet est à but pédagogique.

---

**Développé avec ❤️ pour apprendre la sécurité applicative**
