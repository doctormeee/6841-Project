# server.py
from flask import Flask, request, jsonify

app = Flask(__name__)

stored_messages = {}
stored_public_keys = {}

@app.route('/get_public_key/<user_id>', methods=['GET'])
def get_public_key(user_id):
    return jsonify({'public_key': stored_public_keys.get(user_id)})

@app.route('/register', methods=['POST'])
def register():
    user_id = request.json.get('user_id')
    public_key = request.json.get('public_key')  
    stored_public_keys[user_id] = public_key
    return jsonify({'status': 'public key registered successfully'})

@app.route('/send_message', methods=['POST'])
def send_message():
    data = request.get_json()
    message_id = data.get('message_id')
    stored_messages[message_id] = {
        'sender_user_id': data['sender_user_id'],
        'receiver_user_id': data['receiver_user_id'],
        'message_id': data['message_id'],
        'encrypted_aes_key': data['encrypted_aes_key'],
        'encrypted_hmac_key': data['encrypted_hmac_key'],
        'encrypted_message': data['encrypted_message'],
        'message_hmac': data['message_hmac']
    }
    print(stored_messages)
    return jsonify({'status': 'success', 'message_id': message_id})

@app.route('/get_message/<receiver_user_id>', methods=['GET'])
def get_message(receiver_user_id):
    message = {}
    for message_id in stored_messages:
        if stored_messages[message_id]['receiver_user_id'] == receiver_user_id:
            message[message_id] = stored_messages[message_id]

    if message:
        return jsonify(message)
    else:
        return jsonify({'error': 'Message not found'}), 404
    
@app.route('/get_msg_id', methods=['GET'])
def get_msg_id():
    return jsonify({'message_id': len(stored_messages) + 1})


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)
