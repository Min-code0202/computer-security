import socket
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import pickle
import sys

class Client:
    def __init__(self, name, host='127.0.0.1', port=5555):
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect((host, port))
        self.name = name
        
        # 서버로부터 키 수신
        key_data = pickle.loads(self.client.recv(4096))
        self.private_key = RSA.import_key(key_data['private_key'])
        self.public_key = RSA.import_key(key_data['public_key'])
        self.server_public_key = RSA.import_key(key_data['server_public_key'])
        self.signature = key_data['signature']
        
        # 이름 전송
        self.client.send(name.encode())
        
        # 상대방 키 수신 대기
        self.other_public_key = None
        self.receive_thread = threading.Thread(target=self.receive_messages)
        self.receive_thread.start()

    def verify_key(self, public_key, signature):
        """공개키 검증"""
        try:
            key_hash = SHA256.new(public_key.export_key())
            pkcs1_15.new(self.server_public_key).verify(key_hash, signature)
            return True
        except:
            return False

    def encrypt_message(self, message):
        """메시지 암호화"""
        cipher = PKCS1_OAEP.new(self.other_public_key)
        return cipher.encrypt(message.encode())

    def decrypt_message(self, encrypted_message):
        """메시지 복호화"""
        cipher = PKCS1_OAEP.new(self.private_key)
        return cipher.decrypt(encrypted_message).decode()

    def receive_messages(self):
        """메시지 수신"""
        while True:
            try:
                data = self.client.recv(4096)
                if not data:
                    break
                
                # 상대방 키 정보 수신
                if not self.other_public_key:
                    key_data = pickle.loads(data)
                    other_key = RSA.import_key(key_data['other_public_key'])
                    if self.verify_key(other_key, key_data['signature']):
                        self.other_public_key = other_key
                        print("상대방과 안전한 연결이 설정되었습니다.")
                    else:
                        print("키 검증 실패!")
                        break
                else:
                    # 메시지 복호화 및 출력
                    decrypted_message = self.decrypt_message(data)
                    print(f"\n상대방: {decrypted_message}")
            except Exception as e:
                print(f"오류 발생: {e}")
                break

    def send_message(self, message):
        """메시지 전송"""
        if self.other_public_key:
            encrypted_message = self.encrypt_message(message)
            self.client.send(encrypted_message)
        else:
            print("아직 상대방과 연결되지 않았습니다.")

    def start(self):
        """채팅 시작"""
        while True:
            message = input(f"{self.name}: ")
            if message.lower() == 'quit':
                break
            self.send_message(message)
        
        self.client.close()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("사용법: python client.py <사용자이름>")
        print("예시: python client.py Alice")
        sys.exit(1)
    
    client = Client(sys.argv[1])
    client.start()