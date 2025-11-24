
from __future__ import annotations
import sys
import argparse
import os
import binascii
import hashlib
import hmac


try:
    import bcrypt
    HAS_BCRYPT = True
except ImportError:
    HAS_BCRYPT = False


BCRYPT_ROUNDS = 12
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_SALT_LEN = 16
SCRYPT_DKLEN = 64
PBKDF2_ITER = 100_000
PBKDF2_SALT_LEN = 16
PBKDF2_DKLEN = 64

def hash_password(password: str) -> str:
    """Hache un mot de passe avec l'algorithme le plus fort disponible."""
    if HAS_BCRYPT:
        
        salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        
        return hashed.decode('utf-8')
    
    try:
    
        salt = os.urandom(SCRYPT_SALT_LEN)
        key = hashlib.scrypt(
            password.encode('utf-8'), 
            salt=salt, 
            n=SCRYPT_N, 
            r=SCRYPT_R, 
            p=SCRYPT_P, 
            dklen=SCRYPT_DKLEN
        )
    
        return "scrypt$" + binascii.hexlify(salt).decode() + "$" + binascii.hexlify(key).decode()
    except Exception:
       
        salt = os.urandom(PBKDF2_SALT_LEN)
        key = hashlib.pbkdf2_hmac(
            "sha256", 
            password.encode('utf-8'), 
            salt, 
            PBKDF2_ITER, 
            PBKDF2_DKLEN
        )
        return "pbkdf2$" + binascii.hexlify(salt).decode() + "$" + binascii.hexlify(key).decode()

def verify_password(password: str, hashed_str: str) -> bool:
    """Vérifie un mot de passe contre son hash."""
    try:
        
        if hashed_str.startswith("$2b$") or hashed_str.startswith("$2a$") or hashed_str.startswith("bcrypt$"):
          
            clean_hash = hashed_str.replace("bcrypt$", "")
            return bcrypt.checkpw(password.encode('utf-8'), clean_hash.encode('utf-8'))
        
        elif hashed_str.startswith("scrypt$"):
            _, salt_hex, key_hex = hashed_str.split("$")
            salt = binascii.unhexlify(salt_hex)
            original_key = binascii.unhexlify(key_hex)
            
            new_key = hashlib.scrypt(
                password.encode('utf-8'), 
                salt=salt, 
                n=SCRYPT_N, 
                r=SCRYPT_R, 
                p=SCRYPT_P, 
                dklen=SCRYPT_DKLEN
            )
            return hmac.compare_digest(original_key, new_key)
            
        elif hashed_str.startswith("pbkdf2$"):
            _, salt_hex, key_hex = hashed_str.split("$")
            salt = binascii.unhexlify(salt_hex)
            original_key = binascii.unhexlify(key_hex)
            
            new_key = hashlib.pbkdf2_hmac(
                "sha256", 
                password.encode('utf-8'), 
                salt, 
                PBKDF2_ITER, 
                PBKDF2_DKLEN
            )
            return hmac.compare_digest(original_key, new_key)
            
        else:
            print("Erreur: Format de hash non reconnu.")
            return False
            
    except Exception as e:
        print(f"Erreur lors de la vérification: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Outil de hachage de mots de passe sécurisé.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    parser_hash = subparsers.add_parser("hash", help="Hacher un mot de passe")
    parser_hash.add_argument("--password", type=str, help="Le mot de passe à hacher (interactif si vide)")

    parser_verify = subparsers.add_parser("verify", help="Vérifier un mot de passe")
    parser_verify.add_argument("--password", type=str, required=True, help="Le mot de passe en clair")
    parser_verify.add_argument("--hash", type=str, required=True, help="Le hash complet à vérifier")

    args = parser.parse_args()

    if args.command == "hash":
        pwd = args.password
        if not pwd:
            pwd = input("Entrez le mot de passe à hacher : ")
        print(f"Hash généré : {hash_password(pwd)}")

    elif args.command == "verify":
        if verify_password(args.password, args.hash):
            print("[SUCCESS] Le mot de passe est VALIDE.")
        else:
            print("[FAILURE] Le mot de passe est INVALIDE.")

if __name__ == "__main__":
    print("=== Password Hasher ===")
    main()