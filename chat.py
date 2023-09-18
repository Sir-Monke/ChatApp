from flask import Flask, render_template, request, redirect, make_response, session, url_for
from flask_socketio import SocketIO
import json
import datetime
import secrets
import time
from passlib.hash import pbkdf2_sha256

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
socketio = SocketIO(app)

HOST_IP_ADDRESS = "LOCAL IP ADDR HERE"

CHAT_MESSAGES_JSON_PATH = 'chats\messages.json'
MAX_SERVER_MESSAGES_HISTORY = 100  
MAX_CLIENT_MESSAGES_HISTORY = 100
MAX_FAILED_LOGIN_ATTEMPTS = 3
COOLDOWN = 300
failed_login_attempts = 0

chat_messages = []

#PASSWORD FOR admin ACCOUNT IS password
def load_admin_credentials():
    with open('admin_credentials.json', 'r') as json_file:
        credentials = json.load(json_file)
        return credentials

admin_credentials = load_admin_credentials()

def verify_admin_credentials(username, password):
    for admin in admin_credentials:
        if admin['username'] == username and pbkdf2_sha256.verify(password, admin['password_hash']):
            return True
    return False

#fuction to verify if username is avaliable
def is_username_available(username):
    return username != "admin" and not any(admin['username'] == username for admin in admin_credentials)

@app.route('/')
def chat():
    username = request.cookies.get('username')
    print(username)
    if not username:
        user_ip = request.remote_addr
        username = user_ip
    return render_template('chat.html', messages=chat_messages[-MAX_CLIENT_MESSAGES_HISTORY:], username=username)

@app.route('/set_username', methods=['POST'])
def set_username():
    username = request.form.get('username')
    if username:
        if is_username_available(username):
            print("DEBUG: Username set succcessfully")
            response = make_response('Username set successfully')
            response.set_cookie('username', username)
            return response
        else:
            print("DEBUG: unavaliable username entered")
            return 'Username is not available'
    else:
        print("DEBUG: GLITCH IN THE MATRIX THIS SHOULD BE IMPOSSIBLE")
        return 'GLITCH IN THE MATRIX THIS SHOULD BE IMPOSSIBLE'


@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    global failed_login_attempts

    if request.method == 'POST':
        if failed_login_attempts >= MAX_FAILED_LOGIN_ATTEMPTS:
            if 'cool_down_start' not in session:
                session['cool_down_start'] = time.time()
            else:
                elapsed_time = time.time() - session['cool_down_start']
                if elapsed_time < COOLDOWN:
                    return f"Too many failed attempts. Please wait {int(COOLDOWN - elapsed_time)} seconds before trying again."
        username = request.form.get('username')
        password = request.form.get('password')
        if verify_admin_credentials(username, password):
            session['admin_logged_in'] = True
            failed_login_attempts = 0
            return redirect(url_for('admin_panel'))
        else:
            failed_login_attempts += 1
            return "Authentication failed. Please check your username and password."

    return render_template('login.html')

@app.route('/adminpanel')
def admin_panel():
    #Give admin panel page if device logged in in this session else give login page.
    if 'admin_logged_in' in session and session['admin_logged_in']:
        connected_devices = read_connected_devices()
        return render_template('admin_panel.html', connected_devices=connected_devices)
    else:
        return redirect(url_for('admin_login'))

#Called on message send
@socketio.on('message')
def handle_message(data):
    print("DEBUG: message recived")
    message = data['message']                               #Message
    timestamp = datetime.datetime.now().strftime('%H:%M')   #Timestamp
    username = data['username']                             #Username
    save_message_to_json(username, message, timestamp)
    socketio.emit('message', {'username': username, 'message': message, 'timestamp': timestamp})

def save_connected_devices(devices):
    with open('connected_devices.json', 'w') as json_file:
        json.dump(devices, json_file)

def read_connected_devices():
    with open('connected_devices.json', 'r') as json_file:
        return json.load(json_file)

#save a new message called when new message sent
def save_message_to_json(username, message, timestamp):
    print("DEBUG: messages saved")
    load_messages_from_json()
    with open(CHAT_MESSAGES_JSON_PATH, 'w') as json_file:
        chat_messages.append({'username': username, 'message': message, 'timestamp': timestamp})
        if len(chat_messages) > MAX_SERVER_MESSAGES_HISTORY:
            chat_messages.pop(0)
        json.dump(chat_messages, json_file)

#load contents of json into chat_messages var
def load_messages_from_json():
    print("DEBUG: messages loaded")
    with open(CHAT_MESSAGES_JSON_PATH, 'r') as json_file:
        global chat_messages
        chat_messages = json.load(json_file)
        
"""
password = "password" #"To Set Up Pass Enter Here The Run Py File It Will Print Out"
hashed_password = pbkdf2_sha256.hash(password)
print("This is the hash of pass: " + hashed_password)
"""

if __name__ == "__main__":
    load_messages_from_json()
    socketio.run(app, host=HOST_IP_ADDRESS, port=5000, debug=True)



"""
ChangeLog:

-Fixed a bug where it was possible to send a message withought ever first loading the page causeing all the message history to be 
deleted because the json would be overwritten with only the messgae just sent. Ye hard to explain

-IP address no longer saved in messages.json or chat_messages var (It wasent being used for anything so i just removed it, easy enought to add back)

-Fixed a bug where styling for username would not be correct until page refresh

-Removed SSH (mainly because idk how to use it) (should be easy enought to add back if you wanted to)

-Chat_messages var no longer updated on every page refresh by any client as this was unneccecary. It is now only updated when a new message is sent

-You can now press enter on keyboard to sent a message

-Changed the way the message length limit works. Instead of just sliceing the received message string server side, the message length limit
is now hard coded into the message input box in the chat.html file. (There is a variable in the html file to change the limit)
^ This was harder than you might think

-Placed timestamp next to username
"""

"""
ISSUES:

-When message history surpassed, old messages are not removed from client side web view until page refresh
-You can change the max message lenght var using inspect on web browser.... but its not super obvious as you gotta go into the js code. cba fixing rn
"""