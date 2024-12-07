import socket
import threading
import json
import select
import os
from crypto_utils import generate_rsa_keys, encrypt_message, decrypt_message

class ChatClient:
    def __init__(self, host='127.0.0.1', port=55555, username=None):
        self.host = host
        self.port = port
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # 클라이언트 고유 RSA 키 생성
        self.private_key, self.public_key = generate_rsa_keys()
        self.server_public_key = None
        
        # 사용자 이름 설정
        self.username = username or self.generate_username()

    def generate_username(self):
        """임의의 사용자 이름 생성"""
        import random
        adjectives = ['행복한', '멋진', '즐거운', '신나는', '친절한']
        nouns = ['고양이', '개발자', '학생', '여행자', '음악가']
        return f"{random.choice(adjectives)} {random.choice(nouns)}"

    def clear_screen(self):
        """화면 지우기"""
        os.system('cls' if os.name == 'nt' else 'clear')

    def connect(self):
        """서버에 연결"""
        self.client_socket.connect((self.host, self.port))
        
        # 공개키와 사용자 이름을 서버에 전송
        client_data = json.dumps({
            'public_key': self.public_key.decode('utf-8'),
            'username': self.username
        })
        self.client_socket.send(client_data.encode('utf-8'))

        # 서버의 공개키 수신
        server_key_data = self.client_socket.recv(4096).decode('utf-8')
        self.server_public_key = json.loads(server_key_data)['public_key']
        
        self.clear_screen()
        print(f"🌐 {self.username}으로 서버에 연결되었습니다.")
        print("💬 채팅을 시작하세요. 'quit'로 종료할 수 있습니다.\n")

    def send_message(self, message):
        """서버로 암호화된 메시지 전송"""
        if not self.server_public_key:
            print("서버 공개키가 없습니다.")
            return

        # 서버의 공개키로 메시지 암호화
        encrypted_message = encrypt_message(self.server_public_key, message)
        if encrypted_message:
            self.client_socket.send(encrypted_message.encode('utf-8'))
            print(f"[{self.username}] {message}")

    def receive_messages(self):
        """서버로부터 메시지 수신"""
        while True:
            try:
                ready, _, _ = select.select([self.client_socket], [], [], 1)
                if ready:
                    encrypted_message = self.client_socket.recv(4096)
                    if not encrypted_message:
                        break
                    
                    # 클라이언트의 개인키로 메시지 복호화
                    decrypted_message = decrypt_message(self.private_key, 
                                                        encrypted_message.decode('utf-8'))
                    
                    if decrypted_message:
                        # 사용자 이름과 메시지 분리
                        message_data = json.loads(decrypted_message)
                        username = message_data['username']
                        message = message_data['message']
                        print(f"[{username}] {message}")
            except Exception as e:
                print(f"메시지 수신 중 오류: {e}")
                break

def main_client():
    # 사용자 이름 입력 받기
    username = input("사용자 이름을 입력하세요 (Enter로 랜덤 이름): ").strip()
    
    client = ChatClient(username=username if username else None)
    client.connect()

    # 메시지 수신 스레드 시작
    receive_thread = threading.Thread(target=client.receive_messages)
    receive_thread.daemon = True
    receive_thread.start()

    # 메시지 전송
    while True:
        try:
            message = input()
            if message.lower() == 'quit':
                break
            if message.strip():
                client.send_message(message)
        except KeyboardInterrupt:
            break

if __name__ == "__main__":
    main_client()