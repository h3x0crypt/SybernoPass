import random
import string
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes


class PasswordManager:
    @staticmethod
    def replace_characters(word):
        replacements = {'O': '0', 'o': '0', 'e': '3', 'a': '@', 'i': '1', 's': '$'}
        word_list = list(word)
        for i in range(len(word_list)):
            if word_list[i] in replacements and random.choice([True, False]):
                word_list[i] = replacements[word_list[i]]
        return ''.join(word_list)

    def generate_password(self, keywords, date):
        combined_parts = keywords + [date]
        random.shuffle(combined_parts)

        password = ""
        special_characters = '!@#$%^&*()-_+='

        for part in combined_parts:
            part = self.replace_characters(part)
            password += part + random.choice(special_characters)

        if len(password) < 10:
            password += random.choice(special_characters) * (10 - len(password))

        return password

    @staticmethod
    def hash_passphrase(passphrase):
        return hashlib.sha256(passphrase.encode()).hexdigest()

    @staticmethod
    def encrypt_password(public_key_pem, password, label):
        public_key = serialization.load_pem_public_key(public_key_pem)
        encrypted_password = public_key.encrypt(
            password.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=label.encode()
            )
        )
        return encrypted_password

    @staticmethod
    def decrypt_password(private_key_pem, encrypted_password, passphrase, label):
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=passphrase.encode()
        )
        decrypted_password = private_key.decrypt(
            encrypted_password,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=label.encode()
            )
        )
        return decrypted_password.decode()

    def verify_master_passphrase(self, passphrase, stored_hash):
        return self.hash_passphrase(passphrase) == stored_hash

