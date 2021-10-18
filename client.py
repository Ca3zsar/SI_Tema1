import socket
import threading
import sys
import aes
import time

mode = ''
first_message = True

Kprim = b'Ka\x03\x87vkd*\xbbw(\xc3\xa9\xbfn\x07'
IV = b'Cx\xa1\xb4\x1fm\xd1$\x01c\xc5\xbb\x8a\x05*{'
K = ''

class Client():
    mode = ''
    KPrim = Kprim
    IV = IV
    AES = aes.AES(KPrim)
    K = ''

    def pad(plaintext):
        padding_len = 16 - (len(plaintext) % 16)
        padding = bytes([padding_len] * padding_len)
        return plaintext + padding

    def unpad(plaintext):
        padding_len = plaintext[-1]
        
        assert padding_len > 0

        message, padding = plaintext[:-padding_len], plaintext[-padding_len:]
        assert all(p == padding_len for p in padding)
        return message

    def split_blocks(text, block_size=16):
        return [text[i:i+block_size] for i in range(0, len(text),block_size)]

    def xor_arrays(a, b):
        """ Returns a new byte array with the elements xor'ed. """
        return bytes(i^j for i, j in zip(a, b))


    def ECB_mode_encrypt(plaintext):
        blocks = []

        plaintext = Client.pad(plaintext)

        for block in Client.split_blocks(plaintext, 16):
            ciphertext = Client.AES.encrypt_block(block)
            blocks.append(ciphertext)

        return b''.join(blocks)


    def ECB_mode_decrypt(ciphertext):
        blocks = []
        for ciphertext_block in Client.split_blocks(ciphertext,16):
            plaintext = Client.AES.decrypt_block(ciphertext_block)
            blocks.append(plaintext)

        return b''.join(blocks)
    

    def CFB_mode_encrypt(plaintext):
        blocks = []

        plaintext = Client.pad(plaintext)

        previous = Client.IV
        for block in Client.split_blocks(plaintext, 16):
            ciphertext = Client.xor_arrays(block,Client.AES.encrypt_block(previous))
            blocks.append(ciphertext)
            previous = ciphertext
        
        return b''.join(blocks)
 
           
    def CFB_mode_decrypt(ciphertext):

        blocks = []
        previous = Client.IV

        for ciphertext_block in Client.split_blocks(ciphertext,16):
            plaintext_block = Client.xor_arrays(ciphertext_block, Client.AES.encrypt_block(previous))
            blocks.append(plaintext_block)
            previous = ciphertext_block

        return b''.join(blocks)

def receive(socket):
    global mode, first_message, K

    signal = True
    thread = threading.current_thread()

    if mode != '' :
        Client.mode = mode

    key_received = False

    while getattr(thread, "do_run", True) and signal:
        # try:
            data = socket.recv(4096)

            if not key_received and mode != '':
                if mode == "ECB":
                    Client.K = Client.ECB_mode_decrypt(data)
                else:
                    Client.K = Client.CFB_mode_decrypt(data)
                key_received = True

                print(f"Key : {Client.K}")
                continue

            if mode == '':
                mode = str(data.decode('utf-8'))
                Client.mode = mode
                first_message = False
            else:
                if Client.mode == 'ECB':
                    message = Client.ECB_mode_decrypt(data)
                else:
                    message = Client.CFB_mode_decrypt(data)
                
                print(message.decode('utf-8'),sep='')

        # except:
        #     print("You have been disconnected from the server")
        #     signal = False
        #     break

def main():
    global mode, first_message
    if len(sys.argv) == 2:
        mode = sys.argv[1]

        if mode != 'ECB' and mode != 'CFB' :
            print("The only accepted modes are ECB and CFB")
            return

    host = '127.0.0.1'
    port = 5105

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
    except:
        print("Connection failed. Cannot find server. Make sure host and port are the same.")
        sys.exit(0)

    receiveThread = threading.Thread(target = receive, args = (sock,))
    receiveThread.start()

    if mode != '':
        Client.mode = mode
        sock.sendall(str.encode(mode))

    while Client.mode == '' or Client.K == '':
        pass

    if len(sys.argv) >= 2:
        with open('input.txt','r') as file:
            content = 'something'
            while len(content) > 0:
                content = file.read(256).encode('utf-8')
                time.sleep(0.2)
                if Client.mode == 'ECB':
                    sock.send(Client.ECB_mode_encrypt(content))
                else:
                    sock.send(Client.CFB_mode_encrypt(content))
            print(len(content))
        receiveThread.do_run = False
        
if __name__ == '__main__':
    main()