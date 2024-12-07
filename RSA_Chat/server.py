import socket
import threading
import json
import select
from crypto_utils import generate_rsa_keys, encrypt_message, decrypt_message

class ChatServer:
    def __init__(self, host='127.0.0.1', port=55555):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        
        # 서버의 RSA 키 쌍 생성
        self.private_key, self.public_key = generate_rsa_keys()
        
        self.clients = {}
        self.client_public_keys = {}

    def handle_client(self, client_socket):
        """개별 클라이언트 처리"""
        try:
            # 클라이언트의 공개키와 사용자 이름 수신
            client_data = client_socket.recv(4096).decode('utf-8')
            client_info = json.loads(client_data)
            client_public_key = client_info['public_key']
            client_username = client_info['username']
            
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
                ready, _, _ = select.select([client_socket], [], [], 1)
                if ready:
                    encrypted_message = client_socket.recv(4096)
                    if not encrypted_message:
                        break

                    # 서버의 개인키로 메시지 복호화
                    decrypted_message = decrypt_message(self.private_key, 
                                                        encrypted_message.decode('utf-8'))
                    
                    if decrypted_message is None:
                        print("메시지 복호화 실패")
                        continue

                    print(f"{client_username}: {decrypted_message}")
                    
                    # 다른 클라이언트들에게 전송
                    for dest_socket, dest_info in self.client_public_keys.items():
                        if dest_socket != client_socket:
                            # 각 클라이언트의 공개키로 메시지 암호화
                            # 발신자 이름과 함께 메시지 전송
                            message_with_username = json.dumps({
                                'username': client_username,
                                'message': decrypted_message
                            })
                            
                            encrypted_broadcast = encrypt_message(dest_info['public_key'], message_with_username)
                            if encrypted_broadcast:
                                dest_socket.send(encrypted_broadcast.encode('utf-8'))

        except Exception as e:
            print(f"클라이언트 처리 중 오류: {e}")
        finally:
            self.remove_client(client_socket)

    def remove_client(self, client_socket):
        """클라이언트 제거"""
        if client_socket in self.clients:
            del self.clients[client_socket]
        if client_socket in self.client_public_keys:
            username = self.client_public_keys[client_socket]['username']
            del self.client_public_keys[client_socket]
            print(f"{username} 연결 종료")
        client_socket.close()

    def start(self):
        """서버 시작"""
        print(f"서버가 {self.host}:{self.port}에서 시작되었습니다.")
        while True:
            client_socket, address = self.server_socket.accept()
            print(f"새로운 연결: {address}")
            
            self.clients[client_socket] = address
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
            client_thread.start()

def main_server():
    server = ChatServer()
    server.start()

if __name__ == "__main__":
    main_server()