import socket
import random

class EllipticCurve:
    def __init__(self, a, b, p):
        self.a = a
        self.b = b
        self.p = p

    def is_point_on_curve(self, point):
        x, y = point
        return (y**2) % self.p == (x**3 + self.a*x + self.b) % self.p

    def point_addition(self, point1, point2):
        if point1 == (0, 0):
            return point2
        if point2 == (0, 0):
            return point1

        x1, y1 = point1
        x2, y2 = point2

        if point1 != point2:
            m = (y2 - y1) * pow(x2 - x1, -1, self.p) % self.p
        else:
            m = (3*x1**2 + self.a) * pow(2*y1, -1, self.p) % self.p

        x3 = (m**2 - x1 - x2) % self.p
        y3 = (m*(x1 - x3) - y1) % self.p

        return (x3, y3)

    def point_multiply(self, point, scalar):
        result = (0, 0)
        while scalar > 0:
            if scalar % 2 == 1:
                result = self.point_addition(result, point)
            point = self.point_addition(point, point)
            scalar //= 2
        return result

class FileEncryptionWithECC:
    def __init__(self, curve):
        self.curve = curve
        self.ephemeral_point = None

    def encrypt_file(self, file_path, public_key):
        with open(file_path, 'rb') as file:
            plaintext = file.read()

        scalar = random.randint(1, self.curve.p - 1)
        self.ephemeral_point = self.curve.point_multiply(self.curve.g, scalar)
        shared_key = self.curve.point_multiply(public_key, scalar)[0]

        encrypted_data = bytes([b ^ shared_key for b in plaintext])

        return encrypted_data, self.ephemeral_point

    def decrypt_file(self, ciphertext, private_key):
        shared_key = self.curve.point_multiply(self.ephemeral_point, private_key)[0]
        decrypted_data = bytes([b ^ shared_key for b in ciphertext])

        return decrypted_data

def start_server(host, port, file_encryptor):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)

    print(f"Server listening on {host}:{port}")

    client_socket, client_address = server_socket.accept()
    print(f"Connection established with {client_address}")

    # İstemciden açık anahtarı al
    client_public_key_x = int.from_bytes(client_socket.recv(8), byteorder='big')
    client_public_key_y = int.from_bytes(client_socket.recv(8), byteorder='big')
    client_public_key = (client_public_key_x, client_public_key_y)

    # İstemciye g ve p parametrelerini gönder
    g, p = file_encryptor.curve.g, file_encryptor.curve.p
    client_socket.sendall(g[0].to_bytes(8, byteorder='big'))
    client_socket.sendall(g[1].to_bytes(8, byteorder='big'))
    client_socket.sendall(p.to_bytes(8, byteorder='big'))

    # Şifreleme işlemleri için geçici bir nokta oluştur
    scalar = random.randint(1, file_encryptor.curve.p - 1)
    ephemeral_point = file_encryptor.curve.point_multiply(file_encryptor.curve.g, scalar)

    # İstemciye geçici noktayı gönder
    client_socket.sendall(ephemeral_point[0].to_bytes(8, byteorder='big'))
    client_socket.sendall(ephemeral_point[1].to_bytes(8, byteorder='big'))

    # Şifreli dosyayı al
    file_size = int.from_bytes(client_socket.recv(8), byteorder='big')
    encrypted_data = client_socket.recv(file_size)

    # Dosyayı çöz
    decrypted_data = file_encryptor.decrypt_file(encrypted_data, scalar)

    with open("decrypted_file.txt", 'wb') as file:
        file.write(decrypted_data)

    print("File received and decrypted successfully")

    server_socket.close()

# Server bilgisayarın IP adresi ve kullanılacak port numarası
server_host = ""  # Server bilgisayarın IP adresi
server_port = 12345

# Eğri parametreleri
a = 2
b = 2
p = 17

# Server tarafındaki şifreleme nesnesini oluştur
server_curve = EllipticCurve(a, b, p)
server_curve.g = (5, 1)
server_file_encryptor = FileEncryptionWithECC(server_curve)

# Server tarafındaki kodu çalıştır
start_server(server_host, server_port, server_file_encryptor)
