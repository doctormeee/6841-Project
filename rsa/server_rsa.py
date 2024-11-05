# Import necessary libraries
from flask import Flask, request, jsonify  # Flask for creating the web server, request and jsonify for handling and formatting HTTP requests and responses

# Initialize the Flask application
app = Flask(__name__)

# Initialize dictionaries to store messages and public keys
stored_messages = {}  # A dictionary to store sent messages by their message ID
stored_public_keys = {}  # A dictionary to store users' public keys by user ID

# Route to get a public key by user ID
@app.route('/get_public_key/<user_id>', methods=['GET'])
def get_public_key(user_id):
    # Retrieve the public key associated with the user_id from stored_public_keys dictionary
    # Return the public key in JSON format; if not found, return None
    return jsonify({'public_key': stored_public_keys.get(user_id)})

# Route to register a user's public key
@app.route('/register', methods=['POST'])
def register():
    # Extract user_id and public_key from the JSON request data
    user_id = request.json.get('user_id')
    public_key = request.json.get('public_key')  
    # Store the public key in stored_public_keys using the user_id as the key
    stored_public_keys[user_id] = public_key
    # Respond with a success message
    return jsonify({'status': 'public key registered successfully'})

# Route to store a sent message
@app.route('/send_message', methods=['POST'])
def send_message():
    # Retrieve JSON data from the POST request
    data = request.get_json()
    message_id = data.get('message_id')
    # Store the message details in the stored_messages dictionary using message_id as the key
    stored_messages[message_id] = {
        'sender_user_id': data['sender_user_id'],
        'receiver_user_id': data['receiver_user_id'],
        'message_id': data['message_id'],
        'encrypted_aes_key': data['encrypted_aes_key'],
        'encrypted_hmac_key': data['encrypted_hmac_key'],
        'encrypted_message': data['encrypted_message'],
        'message_hmac': data['message_hmac']
    }
    # Print stored messages for debugging purposes
    print(stored_messages)
    # Respond with a success message, including the message_id
    return jsonify({'status': 'success', 'message_id': message_id})

# Route to retrieve messages for a specific receiver user ID
@app.route('/get_message/<receiver_user_id>', methods=['GET'])
def get_message(receiver_user_id):
    # Initialize an empty dictionary to store messages for the specified receiver
    message = {}
    # Loop through stored messages and find messages addressed to the specified receiver
    for message_id in stored_messages:
        if stored_messages[message_id]['receiver_user_id'] == receiver_user_id:
            message[message_id] = stored_messages[message_id]
    # Return messages if found; otherwise, return a 404 error
    if message:
        return jsonify(message)
    else:
        return jsonify({'error': 'Message not found'}), 404

# Route to generate and retrieve a new message ID
@app.route('/get_msg_id', methods=['GET'])
def get_msg_id():
    # Return the next available message ID, calculated based on the current number of stored messages
    return jsonify({'message_id': len(stored_messages) + 1})

# Main entry point to run the application
if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)  # Run the app on localhost and port 5000
