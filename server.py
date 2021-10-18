import socket
import threading
import secrets
import aes

connections = []
total_connections = 0

def get_random_bytes(count):
    number = secrets.token_bytes(16)
    return number

mode = ''
crypted = b''
K = get_random_bytes(16)

class Client(threading.Thread):
    def __init__(self, socket, address, id, name, signal):
        threading.Thread.__init__(self)
        self.socket = socket
        self.address = address
        self.id = id
        self.name = name
        self.signal = signal
        self.mode = ''

        self.Kprim = b'Ka\x03\x87vkd*\xbbw(\xc3\xa9\xbfn\x07'
        self.IV = b'Cx\xa1\xb4\x1fm\xd1$\x01c\xc5\xbb\x8a\x05*{'

        self.AES = aes.AES(self.Kprim)

    def pad(self,plaintext):
        padding_len = 16 - (len(plaintext) % 16)
        padding = bytes([padding_len] * padding_len)
        return plaintext + padding

    def unpad(self,plaintext):
        padding_len = plaintext[-1]
        
        assert padding_len > 0

        message, padding = plaintext[:-padding_len], plaintext[-padding_len:]
        assert all(p == padding_len for p in padding)
        return message


        
    def xor_arrays(self,a, b):
        """ Returns a new byte array with the elements xor'ed. """
        return bytes(i^j for i, j in zip(a, b))

    def split_blocks(self, text, block_size):
        return [text[i:i+block_size] for i in range(0, len(text),block_size)]


    def ECB_mode_encrypt(self, plaintext):
        blocks = []

        plaintext = self.pad(plaintext)

        for block in self.split_blocks(plaintext, 16):
            ciphertext = self.AES.encrypt_block(block)
            blocks.append(ciphertext)

        return b''.join(blocks)


    def ECB_mode_decrypt(self, ciphertext):
        blocks = []
        for ciphertext_block in self.split_blocks(ciphertext,16):
            plaintext = self.AES.decrypt_block(ciphertext_block)
            blocks.append(plaintext)

        return self.unpad(b''.join(blocks))
    

    def CFB_mode_encrypt(self, plaintext):
        blocks = []
        previous = self.IV
        for block in self.split_blocks(plaintext, 16):
            ciphertext = self.xor_arrays(block,self.AES.encrypt_block(previous))
            blocks.append(ciphertext)
            previous = ciphertext
        
        return b''.join(blocks)
 
           
    def CFB_mode_decrypt(self, ciphertext):

        blocks = []
        previous = self.IV
        for ciphertext_block in self.split_blocks(ciphertext,16):
            plaintext_block = self.xor_arrays(ciphertext_block, self.AES.encrypt_block(previous))
            blocks.append(plaintext_block)
            previous = ciphertext_block

        return b''.join(blocks)
    

    def __str__(self):
        return str(self.id) + " " + str(self.address)
    
    def run(self):
        global mode, crypted
        first_message = True

        if mode != '':
            self.socket.sendall(mode.encode())
        if crypted:
            self.socket.sendall(crypted)

        while self.signal:
            try:
                data = self.socket.recv(12800)
            except:
                print("Client " + str(self.address) + " has been disconnected.")
                self.signal = False
                connections.remove(self)
                break
            
            if data != "" and data != b"":
                print("[Client " + str(self.id) + "] " + str(data))

                for client in connections:
                    if client.id != self.id:
                        client.socket.sendall(data)

                if first_message:
                    if mode == '':
                        mode = str(data.decode("utf-8"))

                        if mode == 'CFB':
                            self.KCrypted = self.CFB_mode_encrypt(K)
                        else:
                            self.KCrypted = self.ECB_mode_encrypt(K)
                        crypted = self.KCrypted
                        for client in connections:
                            client.socket.sendall(crypted)
                    
                    first_message = False
            else:
                print("Client " + str(self.address) + " has been disconnected.")
                self.signal = False
                connections.remove(self)
                break

# wait for new connections
def newConnections(socket):
    while True:
        sock, address = socket.accept()
        global total_connections

        connections.append(Client(sock, address, total_connections, "Name", True))
        connections[len(connections) - 1].start()
        
        print("Client " + str(connections[len(connections) - 1]) + " is connected.")
        total_connections += 1

        if len(connections) >= 2 :
            break

def main():
    print('====> SERVER RUNNING...')
    host = '127.0.0.1' # you may change host to your own IP address
    port = 5105 # you may change this port to your custom port as long as server and client are a match

    # create a socket service
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((host, port))
    sock.listen(2)

    # create new thread to wait for connections
    newConnectionsThread = threading.Thread(target = newConnections, args = (sock,))
    newConnectionsThread.start()
    print('====> SERVER LISTENING...')
    
if __name__ == '__main__':
    main()