import receiver
import sender
import server

import threading

if __name__ == "__main__":
    port = 4433

    # Function to run Flask app in a separate thread
    def run_server():
        server.app.run(host='127.0.0.1', port=port)

    # Start the Flask server in a separate thread
    server_thread = threading.Thread(target=run_server)
    server_thread.daemon = True  # This ensures the thread will exit when the main program exits
    server_thread.start()

    # Continue with your script after starting the server
    sender_user_id = "Alice"
    message_id = "1"

    print("Sender registration started!")
    sender.register(sender_user_id, port)
    print("Sender registered successfully!")

    receiver_user_id = "Bob"
    receiver.register(receiver_user_id, port)
    print("Receiver registered successfully!")

    # Generate shared keys
    sender_aes_key, sender_hmac_key = sender.shared_key_gen()
    
    # Get receiver's public key
    receiver_public_key = sender.get_public_key(receiver_user_id, port)

    plaintext_message = "Just for testing....."

    # Encrypt the message
    encrypted_aes_key, encrypted_hmac_key, encrypted_message, message_hmac = sender.encryption(receiver_public_key, sender_aes_key, sender_hmac_key, plaintext_message)

    print("Message HMAC" + message_hmac)

    # Send the encrypted message
    sender.send(sender_user_id, receiver_user_id, message_id, encrypted_aes_key, encrypted_hmac_key, encrypted_message, message_hmac, port)
    print("Message 1 sent successfully!")


    plaintext_message = "See you later!"
    encrypted_aes_key, encrypted_hmac_key, encrypted_message, message_hmac = sender.encryption(receiver_public_key, sender_aes_key, sender_hmac_key, plaintext_message)

    # Send the encrypted message
    sender.send(sender_user_id, receiver_user_id, "2", encrypted_aes_key, encrypted_hmac_key, encrypted_message, message_hmac, port)
    print("Message 2 sent successfully!")

    # Receiver retrieves and decrypts the message
    msg = receiver.receive(receiver_user_id, port)
    for m in msg:
        print("Message received successfully!: " + m)



