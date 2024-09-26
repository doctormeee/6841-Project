# server.py
from flask import Flask, request, jsonify

app = Flask(__name__)

# 临时存储加密的消息
stored_messages = {}

# 接收并存储加密消息
@app.route('/send_message', methods=['POST'])
def send_message():
    data = request.get_json()
    message_id = data.get('message_id')
    stored_messages[message_id] = {
        'encrypted_aes_key': data['encrypted_aes_key'],
        'encrypted_message': data['encrypted_message'],
        'message_hmac': data['message_hmac']
    }
    return jsonify({'status': 'success', 'message_id': message_id})

# 接收端获取加密消息
@app.route('/get_message/<message_id>', methods=['GET'])
def get_message(message_id):
    message_data = stored_messages.get(message_id)
    if message_data:
        return jsonify(message_data)
    else:
        return jsonify({'error': 'Message not found'}), 404

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)
