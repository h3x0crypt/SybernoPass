import os
import json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


class FileManager:
    def __init__(self, base_dir='.files'):
        self.base_dir = base_dir
        self.master_passphrase_file = os.path.join(base_dir, "master_passphrase.json")
        self.private_key_file = os.path.join(base_dir, "private_key.pem")
        self.public_key_file = os.path.join(base_dir, "public_key.pem")
        self.passwords_file = os.path.join(base_dir, "encrypted_passwords.json")

        if not os.path.exists(base_dir):
            os.makedirs(base_dir)

    def save_master_passphrase_hash(self, passphrase_hash):
        data = {"passphrase_hash": passphrase_hash}
        with open(self.master_passphrase_file, "w") as file:
            json.dump(data, file)

    def load_master_passphrase_hash(self):
        if not os.path.exists(self.master_passphrase_file):
            return None
        with open(self.master_passphrase_file, "r") as file:
            data = json.load(file)
            return data.get("passphrase_hash")

    @staticmethod
    def is_master_passphrase_set():
        return os.path.exists("master_passphrase.json")

    def generate_and_save_rsa_keys(self, passphrase):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()

        pem_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode())
        )

        pem_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open(self.private_key_file, "wb") as private_file:
            private_file.write(pem_private_key)

        with open(self.public_key_file, "wb") as public_file:
            public_file.write(pem_public_key)

    def load_rsa_keys(self):
        with open(self.private_key_file, "rb") as private_file:
            private_key_pem = private_file.read()

        with open(self.public_key_file, "rb") as public_file:
            public_key_pem = public_file.read()

        return private_key_pem, public_key_pem

    def save_password(self, title, encrypted_password):
        data = {
            "title": title,
            "encrypted_password": encrypted_password.hex()
        }
        with open(self.passwords_file, "a") as file:
            json.dump(data, file)
            file.write("\n")

    def load_passwords(self):
        if not os.path.exists(self.passwords_file):
            return []
        with open(self.passwords_file, "r") as file:
            lines = file.readlines()
            return [json.loads(line) for line in lines]

    def get_existing_titles(self):
        if not os.path.exists(self.passwords_file):
            return []

        existing_titles = []
        with open(self.passwords_file, "r") as file:
            lines = file.readlines()
            for line in lines:
                data = json.loads(line)
                existing_titles.append(data["title"])
        return existing_titles

    def delete_password(self, title):
        if not os.path.exists(self.passwords_file):
            return

        with open(self.passwords_file, "r") as file:
            lines = file.readlines()

        with open(self.passwords_file, "w") as file:
            for line in lines:
                data = json.loads(line)
                if data["title"] != title:
                    file.write(line)
