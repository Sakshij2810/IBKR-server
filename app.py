import os
import jwt
import datetime
import secrets
import logging
from flask import Flask, request, jsonify
from ib_insync import *
from flask_cors import CORS
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # For session management

# Enable CORS with credentials support
CORS(app, resources={r"/*": {"origins": ["http://localhost:5173"]}}, supports_credentials=True)

# Use environment variables
JWT_SECRET = os.getenv('JWT_SECRET', secrets.token_hex(16))  # Fallback to a random secret if not set
JWT_ALGORITHM = 'HS256'
JWT_EXP_DELTA_SECONDS = 3600  # 1 hour expiration

USER_CREDENTIALS = {
    'username': os.getenv('USER_USERNAME'),  # Get from environment variables
    'password': os.getenv('USER_PASSWORD'),  # Get from environment variables
}

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')

        if username == USER_CREDENTIALS['username'] and password == USER_CREDENTIALS['password']:
            payload = {
                'username': username,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=JWT_EXP_DELTA_SECONDS)
            }
            token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

            logging.info(f"User {username} logged in successfully.")
            return jsonify({'status': 'success', 'token': token})
        else:
            return jsonify({'status': 'error', 'message': 'Invalid credentials'}), 401
    except Exception as e:
        logging.error(f"An error occurred during login: {e}")
        return jsonify({'status': 'error', 'message': 'An unexpected error occurred'}), 500

# The rest of your code remains unchanged


@app.route('/api/place-order', methods=['POST'])
async def place_order():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({'status': 'error', 'message': 'Authorization token is missing'}), 401

    token = auth_header.split(" ")[1]

    try:
        decoded_token = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username = decoded_token['username']
        logging.debug(f"Authenticated user: {username}")

        data = request.json
        required_fields = ['clientId', 'host', 'port', 'stockSymbol', 'exchange', 'currency', 'orderType', 'action', 'quantity']
        
        for field in required_fields:
            if field not in data:
                return jsonify({'status': 'error', 'message': f'Missing field: {field}'}), 400

        # Extract order data
        client_id = data['clientId']
        host = data['host']
        port = data['port']
        stock_symbol = data['stockSymbol']
        exchange = data['exchange']
        currency = data['currency']
        order_type = data['orderType']
        action = data['action']
        quantity = data['quantity']
        price = data.get('price', None)  # Optional for Limit orders

        ib = IB()
        await ib.connectAsync(host, port, clientId=client_id)
        
        # Create and qualify the contract
        contract = Stock(stock_symbol, exchange, currency)
        contract = await ib.qualifyContractsAsync(contract)
        logging.debug(f"Qualified contract: {contract}")

        # Place order
        order = MarketOrder(action, quantity) if order_type == 'Market' else LimitOrder(action=action, totalQuantity=quantity, lmtPrice=price)
        trade = await ib.placeOrderAsync(contract, order)

        return jsonify({'status': 'success', 'trade': str(trade)})
    
    except jwt.ExpiredSignatureError:
        return jsonify({'status': 'error', 'message': 'Token has expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'status': 'error', 'message': 'Invalid token'}), 401
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        return jsonify({'status': 'error', 'message': 'An unexpected error occurred'}), 500

if __name__ == '__main__':
    app.run(debug=True, port=4000)
