#  Password Hasher en Python

**Auteur :** Yacine SEHLI  
**Langage :** Python 3  
**Sécurité :** Bcrypt, Scrypt, PBKDF2  

---

##  Description
Ce projet est un outil en ligne de commande (CLI) développé en Python pour **hacher** et **vérifier** des mots de passe de manière sécurisée. Il implémente les meilleures pratiques de l'industrie en utilisant des algorithmes lents et robustes pour contrer les attaques par force brute.

##  Fonctionnalités
* **Algorithmes supportés :**
    1.  **Bcrypt** (Par défaut, standard de l'industrie).
    2.  **Scrypt** (Fallback si bcrypt absent, résistant aux ASICs).
    3.  **PBKDF2-HMAC-SHA256** (Dernier recours).
* **Salage automatique :** Chaque hash possède un sel unique.
* **Interface CLI :** Utilisation simple via arguments (`hash`, `verify`).

##  Installation
1.  Cloner le dépôt.
2.  Installer les dépendances :
    ```bash
    pip install -r requirements.txt
    ```

##  Utilisation

### Hacher un mot de passe
```bash
python3 password_hasher.py hash --password "MonSuperMotDePasse123!"
# Sortie : $2b$12$LQ... (Hash Bcrypt)