import socket
import threading
import json
import select
from crypto_utils import generate_rsa_keys, encrypt_message, decrypt_message

class ChatServer:
    def __init__(self, host='127.0.0.1', port=55555):
        # 서버의 IP 주소와 포트를 설정
        self.host = host
        self.port = port

        # 서버 소켓 생성 (IPv4, TCP 소켓)
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # 소켓 옵션 설정: SO_REUSEADDR는 포트 재사용을 허용
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # 서버 소켓 바인딩
        self.server_socket.bind((self.host, self.port))
        
        # 연결 대기 상태로 설정, 최대 5개의 연결 대기 가능
        self.server_socket.listen(5)
        
        # 서버 RSA 키 쌍 생성
        self.private_key, self.public_key = generate_rsa_keys()
        
        # 연결된 클라이언트 목록 및 각 클라이언트의 공개키 저장
        self.clients = {}  # {클라이언트 소켓: 클라이언트 주소}
        self.client_public_keys = {}  # {클라이언트 소켓: {'public_key': 키, 'username': 이름}}

    def handle_client(self, client_socket):
        """개별 클라이언트의 연결 및 메시지 처리"""
        try:
            # 클라이언트의 공개키와 사용자 이름 수신
            client_data = client_socket.recv(4096).decode('utf-8')
            client_info = json.loads(client_data)
            client_public_key = client_info['public_key']
            client_username = client_info['username']
            
            # 클라이언트 정보를 저장 (공개키와 사용자 이름)
            self.client_public_keys[client_socket] = {
                'public_key': client_public_key,
                'username': client_username
            }
            
            # 서버의 공개키를 클라이언트에게 전송
            server_key_data = json.dumps({
                'public_key': self.public_key.decode('utf-8')
            })
            client_socket.send(server_key_data.encode('utf-8'))

            print(f"클라이언트 연결: {client_username}")

            while True:
                # 클라이언트로부터 데이터를 읽기 대기 (1초 대기)
                ready, _, _ = select.select([client_socket], [], [], 1)
                if ready:
                    # 클라이언트로부터 암호화된 메시지 수신
                    encrypted_message = client_socket.recv(4096)
                    if not encrypted_message:  # 연결이 종료되었을 경우
                        break

                    # 수신된 암호문 출력
                    print(f"[수신 암호문] {client_username}: {encrypted_message.decode('utf-8')}")

                    # 서버의 개인키로 메시지 복호화
                    decrypted_message = decrypt_message(self.private_key, 
                                                        encrypted_message.decode('utf-8'))
                    
                    if decrypted_message is None:  # 복호화 실패 시 처리
                        print("메시지 복호화 실패")
                        continue

                    print(f"[수신 메시지] {client_username}: {decrypted_message}")
                    
                    # 다른 클라이언트들에게 메시지 브로드캐스트
                    for dest_socket, dest_info in self.client_public_keys.items():
                        if dest_socket != client_socket:  # 자신에게는 전송하지 않음
                            # 메시지에 발신자 이름 추가
                            message_with_username = json.dumps({
                                'username': client_username,
                                'message': decrypted_message
                            })
                            
                            # 대상 클라이언트의 공개키로 메시지 암호화
                            encrypted_broadcast = encrypt_message(dest_info['public_key'], message_with_username)
                            if encrypted_broadcast:  # 암호화 성공 시 전송
                                # 송신 암호문 출력
                                print(f"[송신 암호문] to {dest_info['username']}: {encrypted_broadcast}")
                                dest_socket.send(encrypted_broadcast.encode('utf-8'))

        except Exception as e:
            print(f"클라이언트 처리 중 오류: {e}")
        finally:
            # 클라이언트 연결 종료 처리
            self.remove_client(client_socket)

    def remove_client(self, client_socket):
        """클라이언트 연결 종료 처리"""
        if client_socket in self.clients:
            del self.clients[client_socket]  # 클라이언트 목록에서 제거
        if client_socket in self.client_public_keys:
            username = self.client_public_keys[client_socket]['username']
            del self.client_public_keys[client_socket]  # 클라이언트 키 정보 제거
            print(f"{username} 연결 종료")  # 사용자 이름 출력
        client_socket.close()  # 소켓 닫기

    def start(self):
        """서버 시작"""
        print(f"서버가 {self.host}:{self.port}에서 시작되었습니다.")
        while True:
            # 새 클라이언트 연결 대기
            client_socket, address = self.server_socket.accept()
            print(f"새로운 연결: {address}")
            
            # 연결된 클라이언트 관리
            self.clients[client_socket] = address
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
            client_thread.start()  # 클라이언트 처리 스레드 시작

def main_server():
    """메인 서버 실행"""
    server = ChatServer()
    server.start()

if __name__ == "__main__":
    main_server()