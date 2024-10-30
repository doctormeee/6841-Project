import receiver_dh
import sender_dh
import server_dh

import threading

if __name__ == "__main__":
    port = 4433

    # Function to run Flask app in a separate thread
    def run_server():
        server_dh.app.run(host='127.0.0.1', port=port)

    # Start the Flask server in a separate thread
    server_thread = threading.Thread(target=run_server)
    server_thread.daemon = True  # This ensures the thread will exit when the main program exits
    server_thread.start()

    # Continue with your script after starting the server
    sender_user_id = "Alice"
    message_id = "1"
    receiver_user_id = "Bob"


    sender = sender_dh.Sender(sender_user_id, port)
    receiver = receiver_dh.Receiver(receiver_user_id, port)

    print("Sender registration started!")


    plaintext_message = "Just for testing....."

    # Send the encrypted message
    sender.send(receiver_user_id, plaintext_message)
    print("Message 1 sent successfully!")
    plaintext_message = "HHHHHHHH"
    sender.send(receiver_user_id, plaintext_message)
    print("Message 2 sent successfully!")

    # Receiver retrieves and decrypts the message
    msg = receiver.receive()
    for m in msg:
        print("Message received successfully!: " + m)



