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

def generate_key_pair(curve):
    private_key = random.randint(1, curve.p - 1)
    public_key = curve.point_multiply(curve.g, private_key)
    return private_key, public_key

class FileEncryptionWithECC:
    def __init__(self, curve):
        self.curve = curve
        self.ephemeral_point = None  # Ephemeral point'i başlangıçta None olarak tanımla

    def encrypt_file(self, file_path, public_key):
        with open(r"C:\Users\Eyup\Desktop\Python Mini Projeler\eliptikSifreleme\eliptik sifreleme demo.txt", 'rb') as file:
            plaintext = file.read()

        scalar = random.randint(1, self.curve.p - 1)
        self.ephemeral_point = self.curve.point_multiply(self.curve.g, scalar)
        shared_key = self.curve.point_multiply(public_key, scalar)[0]

        encrypted_data = bytes([b ^ shared_key for b in plaintext])

        return encrypted_data, self.ephemeral_point

    def decrypt_file(self, ciphertext, private_key):
        # Ephemeral point'i kullanarak shared key'i hesapla
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

    file_path = "sample.txt"
    public_key = (5, 1)  # Example public key

    encrypted_data, ephemeral_point = file_encryptor.encrypt_file(r"C:\Users\Eyup\Desktop\Python Mini Projeler\eliptikSifreleme\eliptik sifreleme demo.txt", public_key)

    file_size = len(encrypted_data)
    client_socket.sendall(file_size.to_bytes(8, byteorder='big'))
    client_socket.sendall(encrypted_data)

    print(f"File '{file_path}' sent successfully")

    server_socket.close()

def start_client(host, port, file_encryptor, private_key):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))

    file_size = int.from_bytes(client_socket.recv(8), byteorder='big')
    encrypted_data = client_socket.recv(file_size)

    ephemeral_point = (5, 1)  # Example ephemeral point
    decrypted_text = file_encryptor.decrypt_file(encrypted_data, private_key)

    print(f"File received and decrypted successfully")

    client_socket.close()

def main():
    a = 2
    b = 2
    p = 17
    curve = EllipticCurve(a, b, p)
    curve.g = (5, 1)

    file_encryptor = FileEncryptionWithECC(curve)

    # Server
    server_host = "127.0.0.1"
    server_port = 12345
    start_server(server_host, server_port, file_encryptor)

    # Client
    client_host = "127.0.0.1"
    client_port = 12345
    private_key, public_key = generate_key_pair(curve)
    start_client(client_host, client_port, file_encryptor, private_key)

if __name__ == "__main__":
    main()
