import receiver_dh
import sender_dh
import server_dh

import threading

if __name__ == "__main__":
    port = 4433

    def run_server():
        server_dh.app.run(host='127.0.0.1', port=port)

    server_thread = threading.Thread(target=run_server)
    server_thread.daemon = True 
    server_thread.start()

    sender_user_id = "Alice"
    message_id = "1"
    receiver_user_id = "Bob"


    sender = sender_dh.Sender(sender_user_id, port)
    receiver = receiver_dh.Receiver(receiver_user_id, port)

    print("Sender registration started!")


    plaintext_message = "Just for testing..... diffie hellman"

    sender.send(receiver_user_id, plaintext_message)
    print("Message 1 sent successfully!")
    plaintext_message = "HHHHHHHH"
    sender.send(receiver_user_id, plaintext_message)
    print("Message 2 sent successfully!")

    msg = receiver.receive()
    for m in msg:
        print("Message received successfully!: " + m)



