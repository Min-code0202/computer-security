from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import base64
import json

def generate_rsa_keys():
    """RSA 키 쌍 생성"""
    # 2048비트 RSA 키 쌍 생성
    key = RSA.generate(2048)
    private_key = key.export_key()  # 개인키
    public_key = key.publickey().export_key()  # 공개키
    return private_key, public_key


def encrypt_message(public_key, message):
    """메시지 RSA 암호화"""
    try:
        # 공개키 문자열을 키 객체로 변환
        if isinstance(public_key, str):
            public_key = RSA.import_key(public_key.encode('utf-8'))
        elif isinstance(public_key, bytes):
            public_key = RSA.import_key(public_key)
        
        # PKCS1_OAEP 암호화
        cipher = PKCS1_OAEP.new(public_key)
        
        # 메시지 인코딩 및 암호화
        message_bytes = message.encode('utf-8')
        encrypted_message = cipher.encrypt(message_bytes)
        
        # Base64 인코딩하여 반환
        return base64.b64encode(encrypted_message).decode('utf-8')
    except Exception as e:
        print(f"암호화 오류: {e}")
        return None

def decrypt_message(private_key, encrypted_message):
    """메시지 RSA 복호화"""
    try:
        # 개인키 문자열을 키 객체로 변환
        if isinstance(private_key, str):
            private_key = RSA.import_key(private_key.encode('utf-8'))
        elif isinstance(private_key, bytes):
            private_key = RSA.import_key(private_key)
        
        # PKCS1_OAEP 복호화
        cipher = PKCS1_OAEP.new(private_key)
        
        # Base64 디코딩 및 복호화
        decoded_message = base64.b64decode(encrypted_message)
        decrypted_message = cipher.decrypt(decoded_message)
        
        return decrypted_message.decode('utf-8')
    except Exception as e:
        print(f"복호화 오류: {e}")
        return None