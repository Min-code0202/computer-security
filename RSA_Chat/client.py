import socket
import threading
import json
import select
import os
from crypto_utils import generate_rsa_keys, encrypt_message, decrypt_message

class ChatClient:
    def __init__(self, host='127.0.0.1', port=55555, username=None):
        """
        채팅 클라이언트를 초기화합니다.
        - host: 서버의 IP 주소
        - port: 서버의 포트 번호
        - username: 사용자의 이름
        """
        self.host = host
        self.port = port
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # RSA 키 생성 (개인키 및 공개키)
        self.private_key, self.public_key = generate_rsa_keys()
        self.server_public_key = None  # 서버의 공개키 저장용
        
        # 사용자 이름이 없으면 임의로 생성
        self.username = username or self.generate_username()

    def generate_username(self):
        """임의의 사용자 이름 생성 (형식: 형용사 + 명사)"""
        import random
        adjectives = ['행복한', '멋진', '즐거운', '신나는', '친절한']
        nouns = ['고양이', '개발자', '학생', '여행자', '음악가']
        return f"{random.choice(adjectives)} {random.choice(nouns)}"

    def clear_screen(self):
        """화면을 지웁니다 (운영체제에 따라 명령어 다름)."""
        os.system('cls' if os.name == 'nt' else 'clear')

    def connect(self):
        """서버에 연결하고 초기 설정을 완료합니다."""
        self.client_socket.connect((self.host, self.port))  # 서버와 소켓 연결
        
        # 자신의 공개키와 사용자 이름을 서버에 전송
        client_data = json.dumps({
            'public_key': self.public_key.decode('utf-8'),  # 공개키를 문자열로 변환
            'username': self.username  # 사용자 이름 포함
        })
        self.client_socket.send(client_data.encode('utf-8'))  # 데이터를 서버로 전송

        # 서버로부터 공개키 수신
        server_key_data = self.client_socket.recv(4096).decode('utf-8')
        self.server_public_key = json.loads(server_key_data)['public_key']
        
        # 화면 초기화 및 연결 성공 메시지 출력
        self.clear_screen()
        print(f"🌐 {self.username}으로 서버에 연결되었습니다.")
        print("💬 채팅을 시작하세요. 'quit'로 종료할 수 있습니다.\n")

    def send_message(self, message):
        """서버에 암호화된 메시지를 전송합니다."""
        if not self.server_public_key:
            print("서버 공개키가 없습니다.")
            return

        # 서버 공개키로 메시지 암호화
        encrypted_message = encrypt_message(self.server_public_key, message)
        if encrypted_message:
            self.client_socket.send(encrypted_message.encode('utf-8'))  # 암호화된 메시지 전송
            print(f"[{self.username}] {message}")  # 전송 메시지를 클라이언트에도 출력

    def receive_messages(self):
        """서버로부터 메시지를 수신하고 출력합니다."""
        while True:
            try:
                # 서버로부터 데이터 수신 가능 여부 확인
                ready, _, _ = select.select([self.client_socket], [], [], 1)
                if ready:
                    # 서버로부터 암호화된 메시지 수신
                    encrypted_message = self.client_socket.recv(4096)
                    if not encrypted_message:  # 연결 종료 시
                        break
                    
                    # 개인키로 메시지 복호화
                    decrypted_message = decrypt_message(self.private_key, 
                                                        encrypted_message.decode('utf-8'))
                    
                    if decrypted_message:
                        # 복호화된 데이터를 JSON 형태로 로드하여 사용자와 메시지 출력
                        message_data = json.loads(decrypted_message)
                        username = message_data['username']
                        message = message_data['message']
                        print(f"[{username}] {message}")
            except Exception as e:
                print(f"메시지 수신 중 오류: {e}")
                break

def main_client():
    """클라이언트 실행의 진입점"""
    # 사용자 이름을 입력받고 입력이 없으면 None으로 전달
    username = input("사용자 이름을 입력하세요 (Enter로 랜덤 이름): ").strip()
    
    # ChatClient 인스턴스 생성
    client = ChatClient(username=username if username else None)
    client.connect()  # 서버 연결
    
    # 수신용 스레드 실행 (데몬 스레드로 설정하여 프로그램 종료 시 자동 종료)
    receive_thread = threading.Thread(target=client.receive_messages)
    receive_thread.daemon = True
    receive_thread.start()

    # 메시지 전송 루프
    while True:
        try:
            message = input()  # 메시지 입력
            if message.lower() == 'quit':  # 'quit' 입력 시 종료
                break
            if message.strip():  # 빈 메시지 무시
                client.send_message(message)
        except KeyboardInterrupt:  # Ctrl+C로 종료
            break

if __name__ == "__main__":
    main_client()  # 클라이언트 실행
