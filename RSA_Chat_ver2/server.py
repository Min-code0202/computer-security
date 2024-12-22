import socket
import threading
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import pickle
import base64
from datetime import datetime

class Server:
    def __init__(self, host='127.0.0.1', port=5555):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((host, port))
        self.server.listen()
        
        # 서버의 키쌍 생성
        self.private_key = RSA.generate(2048)
        self.public_key = self.private_key.publickey()
        
        # 클라이언트 정보 저장
        self.clients = {}
        self.addresses = {}
        
        print("서버가 시작되었습니다...")

    def log_message(self, sender, receiver, encrypted_message):
        """암호화된 메시지 로깅"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # base64로 인코딩하여 암호화된 메시지를 문자열로 변환
        encoded_message = base64.b64encode(encrypted_message).decode('utf-8')
        log_entry = f"[{timestamp}] {sender} -> {receiver}: {encoded_message}"
        print(log_entry)

    def generate_client_keys(self):
        """클라이언트용 키쌍 생성"""
        private_key = RSA.generate(2048)
        public_key = private_key.publickey()
        return private_key, public_key

    def sign_public_key(self, public_key):
        """공개키에 대한 서명 생성"""
        key_hash = SHA256.new(public_key.export_key())
        signature = pkcs1_15.new(self.private_key).sign(key_hash)
        return signature

    def handle_client(self, client, address):
        """클라이언트 처리"""
        # 클라이언트용 키쌍 생성 및 전송
        priv_key, pub_key = self.generate_client_keys()
        signature = self.sign_public_key(pub_key)
        
        # 키 정보 전송
        key_data = {
            'private_key': priv_key.export_key().decode(),
            'public_key': pub_key.export_key().decode(),
            'server_public_key': self.public_key.export_key().decode(),
            'signature': signature
        }
        client.send(pickle.dumps(key_data))
        
        # 클라이언트 정보 저장
        client_name = client.recv(1024).decode()
        self.clients[client_name] = {
            'socket': client,
            'public_key': pub_key,
            'address': address
        }
        
        print(f"\n[시스템] {client_name}님이 접속했습니다. (IP: {address[0]}:{address[1]})")
        
        # 다른 클라이언트가 있다면 키 교환
        if len(self.clients) == 2:
            for name, info in self.clients.items():
                if name != client_name:
                    other_client = info
                    other_name = name
                    break
            
            print(f"\n[시스템] {client_name}님과 {other_name}님의 키 교환이 시작되었습니다.")
            
            # 상대방 키 정보 전송
            other_key_data = {
                'other_public_key': other_client['public_key'].export_key().decode(),
                'signature': self.sign_public_key(other_client['public_key'])
            }
            client.send(pickle.dumps(other_key_data))
            
            this_key_data = {
                'other_public_key': pub_key.export_key().decode(),
                'signature': signature
            }
            other_client['socket'].send(pickle.dumps(this_key_data))
            
            print(f"[시스템] 키 교환이 완료되었습니다.")
        
        # 메시지 중계
        while True:
            try:
                message = client.recv(1024)
                if not message:
                    break
                
                # 다른 클라이언트에게 전달
                for name, info in self.clients.items():
                    if name != client_name:
                        # 로그 출력
                        self.log_message(client_name, name, message)
                        # 메시지 전달
                        info['socket'].send(message)
            except Exception as e:
                print(f"\n[오류] {client_name}의 메시지 처리 중 오류 발생: {str(e)}")
                break
        
        # 연결 종료 처리
        del self.clients[client_name]
        client.close()
        print(f"\n[시스템] {client_name}님이 연결을 종료했습니다.")

    def start(self):
        """서버 시작"""
        print("[시스템] 클라이언트 연결 대기 중...")
        while True:
            client, address = self.server.accept()
            thread = threading.Thread(target=self.handle_client, args=(client, address))
            thread.start()
            print(f"\n[시스템] 새로운 연결이 감지되었습니다. (IP: {address[0]}:{address[1]})")

if __name__ == "__main__":
    server = Server()
    server.start()