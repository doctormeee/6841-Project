# server.py
from flask import Flask, request, jsonify
import random

app = Flask(__name__)

# 临时存储加密的消息
stored_messages = {}
stored_public_keys = {}
stored_dh_pg = []

# 假设这是用户的注册流程
@app.route('/get_public_key/<user_id>', methods=['GET'])
def get_public_key(user_id):
    return jsonify({'public_key': stored_public_keys.get(user_id)})

# 假设这是用户的注册流程
@app.route('/register', methods=['POST'])
def register():
    user_id = request.json.get('user_id')
    public_key = request.json.get('public_key')  # 客户端上传的公钥
    # 存储公钥到数据库
    stored_public_keys[user_id] = public_key
    return jsonify({'status': 'public key registered successfully'})


# 接收并存储加密消息
@app.route('/send_message', methods=['POST'])
def send_message():
    data = request.get_json()
    message_id = data.get('message_id')
    stored_messages[message_id] = {
        'sender_user_id': data['sender_user_id'],
        'receiver_user_id': data['receiver_user_id'],
        'message_id': data['message_id'],
        'encrypted_message': data['encrypted_message'],
        'message_hmac': data['message_hmac']
    }
    return jsonify({'status': 'success', 'message_id': message_id})

# 接收端获取加密消息
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


@app.route('/pg_get/<receiver_user_id>', methods=['GET'])
def pg_get(receiver_user_id):
    dh_pair_list = []
    for dh_pair in stored_dh_pg:
        if dh_pair['receiver'] == receiver_user_id:
            dh_pair_list.append(dh_pair)
    return jsonify(dh_pair_list)


@app.route('/pg_gen', methods=['GET'])
def generate_2048_bit_prime():
    sender_user_id = request.json.get('sender_user_id')
    receiver_user_id = request.json.get('receiver_user_id') 
    # if there is already a pair of p and g for the sender and receiver, return it
    for dh_pair in stored_dh_pg:
        if dh_pair['sender'] == sender_user_id and dh_pair['receiver'] == receiver_user_id:
            return dh_pair

    # else, generate a 2048-bit prime number
    while True:
        # Generate a random 2048-bit integer
        candidate = random.getrandbits(2048)
        # Set the most and least significant bits to 1 to ensure it is 2048 bits and odd
        candidate |= (1 << 2047) | 1
        # Check if it's prime
        if is_prime(candidate):
            dh_pair = jsonify({'sender': sender_user_id,
                                'receiver': receiver_user_id,
                                'p': candidate, 
                                'g': 2})
            stored_dh_pg.append(dh_pair)
            return dh_pair

# Miller-Rabin primality test (simplified for demonstration)
def is_prime(n, k=5):  # k is the number of tests
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False
    # Write n as d*2^r + 1
    r, d = 0, n - 1
    while d % 2 == 0:
        d //= 2
        r += 1
    # Witness loop
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)