import threading
import jwt
import random
from threading import Thread
import json
import requests
import google.protobuf
from protobuf_decoder.protobuf_decoder import Parser
import json
import datetime
from datetime import datetime
from google.protobuf.json_format import MessageToJson
import my_message_pb2
import data_pb2
import base64
import logging
import re
import socket
from google.protobuf.timestamp_pb2 import Timestamp
import jwt_generator_pb2
import os
import binascii
import sys
import psutil
import MajorLoginRes_pb2
from time import sleep
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import time
import urllib3
from important_zitado import *
from byte import *

tempid = None
sent_inv = False
start_par = False
pleaseaccept = False
nameinv = "none"
idinv = 0
senthi = False
statusinfo = False
tempdata1 = None
tempdata = None
leaveee = False
leaveee1 = False
data22 = None
isroom = False
isroom2 = False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
client_secret = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
chat_ip = "202.81.106.90"
chat_port = 39698

# --- Text Formatting Function ---
def format_text(text):
    """
    Applies a special font style to the text.
    The first letter of each word is capitalized, and the rest are converted.
    """
    font_map = {
        'a': 'ꫝ', 'b': 'ʙ', 'c': 'ᴄ', 'd': 'ᴅ', 'e': 'ᴇ', 'f': 'ғ', 'g': 'ɢ',
        'h': 'ʜ', 'i': 'ɪ', 'j': 'ᴊ', 'k': 'ᴋ', 'l': 'ʟ', 'm': 'ᴍ', 'n': 'ɴ',
        'o': 'ᴏ', 'p': 'ᴘ', 'q': 'ǫ', 'r': 'ʀ', 's': 's', 't': 'ᴛ', 'u': 'ᴜ',
        'v': 'ꪜ', 'w': 'ᴡ', 'x': 'x', 'y': 'ʏ', 'z': 'ᴢ'
    }

    words = text.split(' ')
    formatted_words = []
    for word in words:
        if not word:
            continue
        
        first_letter = word[0].upper()
        rest_of_word = ''.join([font_map.get(char.lower(), char) for char in word[1:]])
        formatted_words.append(first_letter + rest_of_word)
        
    return ' '.join(formatted_words)

def encrypt_packet(plain_text, key, iv):
    plain_text = bytes.fromhex(plain_text)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

def gethashteam(hexxx):
    a = zitado_get_proto(hexxx)
    if not a:
        raise ValueError("Invalid hex format or empty response from zitado_get_proto")
    data = json.loads(a)
    return data['5']['7']

def getownteam(hexxx):
    a = zitado_get_proto(hexxx)
    if not a:
        raise ValueError("Invalid hex format or empty response from zitado_get_proto")
    data = json.loads(a)
    return data['5']['1']

def get_player_status(packet):
    json_result = get_available_room(packet)
    parsed_data = json.loads(json_result)

    if "5" not in parsed_data or "data" not in parsed_data["5"]:
        return "OFFLINE"

    json_data = parsed_data["5"]["data"]

    if "1" not in json_data or "data" not in json_data["1"]:
        return "OFFLINE"

    data = json_data["1"]["data"]

    if "3" not in data:
        return "OFFLINE"

    status_data = data["3"]

    if "data" not in status_data:
        return "OFFLINE"

    status = status_data["data"]

    if status == 1:
        return "SOLO"
    
    if status == 2:
        if "9" in data and "data" in data["9"]:
            group_count = data["9"]["data"]
            countmax1 = data["10"]["data"]
            countmax = countmax1 + 1
            return f"IN SQUAD ({group_count}/{countmax})"

        return "IN SQUAD"
    
    if status in [3, 5]:
        return "IN GAME"
    if status == 4:
        return "IN ROOM"
    
    if status in [6, 7]:
        return "IN SOCIAL ISLAND"

    return "NOT FOUND"

def get_idroom_by_idplayer(packet):
    json_result = get_available_room(packet)
    parsed_data = json.loads(json_result)
    json_data = parsed_data["5"]["data"]
    data = json_data["1"]["data"]
    idroom = data['15']["data"]
    return idroom

def get_leader(packet):
    json_result = get_available_room(packet)
    parsed_data = json.loads(json_result)
    json_data = parsed_data["5"]["data"]
    data = json_data["1"]["data"]
    leader = data['8']["data"]
    return leader

def generate_random_color():
    color_list = [
        "[00FF00][b][c]", "[FFDD00][b][c]", "[3813F3][b][c]", "[FF0000][b][c]",
        "[0000FF][b][c]", "[FFA500][b][c]", "[DF07F8][b][c]", "[11EAFD][b][c]",
        "[DCE775][b][c]", "[A8E6CF][b][c]", "[7CB342][b][c]", "[FF0000][b][c]",
        "[FFB300][b][c]", "[90EE90][b][c]"
    ]
    return random.choice(color_list)

def fix_num(num):
    fixed = ""
    count = 0
    num_str = str(num)
    for char in num_str:
        if char.isdigit():
            count += 1
        fixed += char
        if count == 3:
            fixed += "[c]"
            count = 0
    return fixed

def fix_word(num):
    fixed = ""
    count = 0
    for char in num:
        if char:
            count += 1
        fixed += char
        if count == 3:
            fixed += "[c]"
            count = 0
    return fixed

def check_banned_status(player_id):
    url = f"http://amin-team-api.vercel.app/check_banned?player_id={player_id}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"Failed to fetch data. Status code: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def send_visit(uid):
    # This URL seems to be a placeholder.
    # Replace "Here is the api visit" with the actual API endpoint.
    visit_api_response = requests.get(f"https://visit-api-modx-v2.vercel.app/bd/{uid}")
    
    if visit_api_response.status_code == 200:
        api_data = visit_api_response.json()
        
        if api_data.get("success", 0) == 0:
            # Daily limit case (red color)
            return {
                "status": "failed",
                "message": (
                    f"[C][B][FFFFFF]━━━━━━━━━\n"
                f"[C][B][FF0000]Failed to send Visit (Error code: {visit_api_response.status_code})\n"
                f"[C][B][FFFFFF]━━━━━━━━━\n"
                )
            }
        else:
            # Success case with details (green color)
            return {
                "status": "ok",
                "message": (
                    f"[C][B][11EAFD]‎━━━━━━━━━━━━\n"
                    f"[FFFFFF]Visit Status:\n\n"
                    f"[00FF00]Visit Sent Successfully!\n\n"
                    f"[FFFFFF]Player Name : [00FF00] {api_data['nickname']}\n"
                    f"[FFFFFF]Player ID : [00FF00] {fix_num(uid)}\n"
                    f"[FFFFFF]Number Of Visits : [00FF00]{api_data['success']}\n"
                    f"[FFFFFF]Player Level : [00FF00]{api_data['level']}\n"
                    f"[FFFFFF]Player Region : [00FF00]{api_data['region']}\n"
                    f"[C][B][11EAFD]‎━━━━━━━━━━━━\n"
                    f"[C][B][FFB300]Credits: [FFFFFF]NIROB X [00FF00]CODEX!!\n"
                    
                )
            }
    else:
        # General failure case (red color)
        return {
            "status": "failed",
            "message": (
                f"[C][B][FF0000]━━━━━\n"
                f"[C][B][FFFFFF]Visit API Error!\n"
                f"[C][B][FFFFFF]Status Code: {visit_api_response.status_code} Please check if the API is running correctly.\n"
                f"[C][B][FFFFFF]━━━━━"
            )
        }        

def rrrrrrrrrrrrrr(number):
    if isinstance(number, str) and '***' in number:
        return number.replace('***', '106')
    return number

def newinfo(uid):
    # API call
    info_api_response = requests.get(
        f"https://jnl-tcp-info.vercel.app//player-info?uid={uid}"
    )

    if info_api_response.status_code == 200:
        api_data = info_api_response.json()
        
        print("API Response:", api_data)


        # Daily limit case (red color)
        if "LikesbeforeCommand" in api_data:  
            return {
                "status": "failed",
                "message": (
                    f"[C][B][FF0000]━━━━━━━━━━━━\n"
                    f"[FFFFFF]No Info Fetch!\n"
                    f"[FF0000]You Pls Enter Correct UID.\nTry again With Correct UID.\n"
                    f"[C][B][FFFFFF]Status Code: {info_api_response.status_code} Please check if the API is running correctly.\n"
                    f"[C][B][FF0000]━━━━━━━━━━━━"
                )
            }
        else:
            # Success case with details (green color)
            return {
                "status": "ok",
                "message": (
                    f"[C][B][11EAFD]‎━━━━━━━━━━━━\n"
                    f"[FFFFFF]Player Name : [00FF00] {api_data['AccountName']}\n"
                    f"[FFFFFF]UID : [00FF00] {fix_num(uid)}\n"
                    f"[FFFFFF]Likes : [00FF00] {api_data['AccountLikes']}\n"
                    f"[FFFFFF]Level : [00FF00]{api_data['AccountLevel']}\n"
                    f"[FFFFFF]Server : [00FF00]{api_data['AccountRegion']}\n"
f"[FFFFFF]-------------------------------\n"
                    f"[FFFFFF]Player Guild : [00FF00]{api_data['GuildName']}\n"
                    f"[FFFFFF]Guild ID : [00FF00]{fix_num(api_data['GuildID'])}\n"
                    f"[FFFFFF]Guild Capacity : [00FF00]{fix_num(api_data['GuildCapacity'])}\n"
                    f"[FFFFFF]Guild Owner : [00FF00]{fix_num(api_data['GuildOwner'])}\n"
                    f"[FFFFFF]Guild Member : [00FF00]{fix_num(api_data['GuildMember'])}\n"
                    f"[FFFFFF]Guild Level : [00FF00]{fix_num(api_data['GuildLevel'])}\n"
f"[FFFFFF]-------------------------------\n"
                    f"[FFFFFF]Sesion ID : [00FF00]{api_data['AccountSeasonId']}\n"
                    f"[FFFFFF]BP Badge: [00FF00]{api_data['AccountBPBadges']}\n"
                    f"[FFFFFF]BR Rank Score : [00FF00]{api_data['BrRankPoint']}\n"
                    f"[FFFFFF]Release Version : [00FF00]{api_data['ReleaseVersion']}\n"
                    f"[FFFFFF]CS Rank Point : [00FF00]{api_data['CsRankPoint']}\n"
                    f"[C][B][11EAFD]‎━━━━━━━━━━━━\n"
                    f"[C][B][FFB300]Credits: [FFFFFF]NIROB [00FF00]CODEX!!\n"
                )
            }
    else:
        # General failure case (red color)
        return {
            "status": "failed",
            "message": (
                f"[C][B][FF0000]━━━━━\n"
                f"[C][B][FFFFFF]Info API Error!\n"
                f"[C][B][FFFFFF]Status Code: 2\nPlease check if the API is running correctly.\n"
                f"[C][B][FFFFFF]━━━━━"
            )
        }

def attack_profail(player_id):
    url = f"https://visit-api-delta.vercel.app/bd/{player_id}"
    res = requests.get(url)
    if res.status_code() == 200:
        print("Done-Attack")
    else:
        print("Fuck-Attack")

def send_likes(uid):
    # NOTE: You need to replace "Here is the api likes" with your actual API endpoint.
    likes_api_response = requests.get(f"https://vip-like-api.vercel.app/like?server_name=bd&uid={uid}")
    
    if likes_api_response.status_code == 200:
        api_data = likes_api_response.json()
        if api_data.get("LikesGivenByAPI", 0) == 0:
            return {
                "status": "ok",
                "message": (
                    f"[C][B][00FF00]________________________\n"
                    f" ✅ {format_text('Added')} {api_data['LikesGivenByAPI']} {format_text('Likes')}\n"
                    f" {format_text('Name:')} {api_data['PlayerNickname']}\n"
                    f" {format_text('Previous Likes:')} {api_data['LikesbeforeCommand']}\n"
                    f" {format_text('New Likes:')} {api_data['LikesafterCommand']}\n"
                    f" {format_text('©DEVELOPMENT: NIROB X CODX..!!')}\n"
                    f"________________________"
                )
            }
        else:
            return {
                "status": "ok",
                "message": (
                    f"[C][B][00FF00]________________________\n"
                    f" ✅ {format_text('Added')} {api_data['LikesGivenByAPI']} {format_text('Likes')}\n"
                    f" {format_text('Name:')} {api_data['PlayerNickname']}\n"
                    f" {format_text('Previous Likes:')} {api_data['LikesbeforeCommand']}\n"
                    f" {format_text('New Likes:')} {api_data['LikesafterCommand']}\n"
                    f"________________________"
                )
            }
    else:
        return {
            "status": "failed",
            "message": (
                f"[C][B][FF0000]________________________\n"
                f" ❌ {format_text('Error Sending!')}\n"
                f" {format_text('Make Sure The User ID Is Correct')}\n"
                f"________________________"
            )
        }

def Encrypt(number):
    number = int(number)
    encoded_bytes = []
    while True:
        byte = number & 0x7F
        number >>= 7
        if number:
            byte |= 0x80
        encoded_bytes.append(byte)
        if not number:
            break
    return bytes(encoded_bytes).hex()

def get_random_avatar():
    avatar_list = [
        '902000061', '902000060', '902000064', '902000065', '902000066',
        '902000074', '902000075', '902000077', '902000078', '902000084',
        '902000085', '902000093', '902000091', '902000094', '902000306',
        '902000091', '902000208', '902000209', '902000210', '902000211',
        '902047016', '902047016', '902000347'
    ]
    return random.choice(avatar_list)

class FF_CLIENT(threading.Thread):
    def __init__(self, id, password):
        self.id = id
        self.password = password
        self.key = None
        self.iv = None
        self.get_tok()

    def connect(self, tok, host, port, packet, key, iv):
        global clients
        clients = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        port = int(port)
        clients.connect((host, port))
        clients.send(bytes.fromhex(tok))
        while True:
            data = clients.recv(9999)
            if data == b"":
                print("Connection closed by remote host")
                break

def get_available_room(input_text):
    try:
        parsed_results = Parser().parse(input_text)
        parsed_results_objects = parsed_results
        parsed_results_dict = parse_results(parsed_results_objects)
        json_data = json.dumps(parsed_results_dict)
        return json_data
    except Exception as e:
        print(f"error {e}")
        return None

def parse_results(parsed_results):
    result_dict = {}
    for result in parsed_results:
        field_data = {}
        field_data["wire_type"] = result.wire_type
        if result.wire_type == "varint":
            field_data["data"] = result.data
        if result.wire_type == "string":
            field_data["data"] = result.data
        if result.wire_type == "bytes":
            field_data["data"] = result.data
        elif result.wire_type == "length_delimited":
            field_data["data"] = parse_results(result.data.results)
        result_dict[result.field] = field_data
    return result_dict

def dec_to_hex(ask):
    ask_result = hex(ask)
    final_result = str(ask_result)[2:]
    if len(final_result) == 1:
        final_result = "0" + final_result
    return final_result

def encrypt_message(plaintext):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    encrypted_message = cipher.encrypt(padded_message)
    return binascii.hexlify(encrypted_message).decode('utf-8')

def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

def extract_jwt_from_hex(hex):
    byte_data = binascii.unhexlify(hex)
    message = jwt_generator_pb2.Garena_420()
    message.ParseFromString(byte_data)
    json_output = MessageToJson(message)
    token_data = json.loads(json_output)
    return token_data

def format_timestamp(timestamp):
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

def restart_program():
    p = psutil.Process(os.getpid())
    open_files = p.open_files()
    connections = psutil.net_connections()
    for handler in open_files:
        try:
            os.close(handler.fd)
        except Exception:
            pass
    for conn in connections:
        try:
            conn.close()
        except Exception:
            pass
    sys.path.append(os.path.dirname(os.path.abspath(sys.argv[0])))
    python = sys.executable
    os.execl(python, python, *sys.argv)

class FF_CLIENT(threading.Thread):
    def __init__(self, id, password):
        super().__init__()
        self.id = id
        self.password = password
        self.key = None
        self.iv = None
        self.get_tok()

    def parse_my_message(self, serialized_data):
        try:
            MajorLogRes = MajorLoginRes_pb2.MajorLoginRes()
            MajorLogRes.ParseFromString(serialized_data)
            key = MajorLogRes.ak
            iv = MajorLogRes.aiv
            if isinstance(key, bytes):
                key = key.hex()
            if isinstance(iv, bytes):
                iv = iv.hex()
            self.key = key
            self.iv = iv
            print(f"Key: {self.key} | IV: {self.iv}")
            return self.key, self.iv
        except Exception as e:
            print(f"{e}")
            return None, None

    def nmnmmmmn(self, data):
        key, iv = self.key, self.iv
        try:
            key = key if isinstance(key, bytes) else bytes.fromhex(key)
            iv = iv if isinstance(iv, bytes) else bytes.fromhex(iv)
            data = bytes.fromhex(data)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            cipher_text = cipher.encrypt(pad(data, AES.block_size))
            return cipher_text.hex()
        except Exception as e:
            print(f"Error in nmnmmmmn: {e}")
    # ... (The rest of the protobuf packet creation methods remain the same) ...
    def spam_room(self, idroom, idplayer):
        fields = {
        1: 78,
        2: {
            1: int(idroom),
            2: "7ama",
            4: 330,
            5: 6000,
            6: 201,
            10: int(get_random_avatar()),
            11: int(idplayer),
            12: 1
        }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0E15000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "0E1500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "0E150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0E15000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def send_squad(self, idplayer):
        fields = {
            1: 33,
            2: {
                1: int(idplayer),
                2: "BD",
                3: 1,
                4: 1,
                7: 330,
                8: 19459,
                9: 100,
                12: 1,
                16: 1,
                17: {
                2: 94,
                6: 11,
                8: "1.109.5",
                9: 3,
                10: 2
                },
                18: 201,
                23: {
                2: 1,
                3: 1
                },
                24: int(get_random_avatar()),
                26: {},
                28: {}
            }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def start_autooo(self):
        fields = {
        1: 9,
        2: {
            1: 11371687918
        }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def invite_skwad(self, idplayer):
        fields = {
        1: 2,
        2: {
            1: int(idplayer),
            2: "BD",
            4: 1
        }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def request_skwad(self, idplayer):
        fields = {
        1: 33,
        2: {
            1: int(idplayer),
            2: "BD",
            3: 1,
            4: 1,
            7: 330,
            8: 19459,
            9: 100,
            12: 1,
            16: 1,
            17: {
            2: 94,
            6: 11,
            8: "1.109.5",
            9: 3,
            10: 2
            },
            18: 201,
            23: {
            2: 1,
            3: 1
            },
            24: int(get_random_avatar()),
            26: {},
            28: {}
        }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def skwad_maker(self):
        fields = {
        1: 1,
        2: {
            2: "\u0001",
            3: 1,
            4: 1,
            5: "en",
            9: 1,
            11: 1,
            13: 1,
            14: {
            2: 5756,
            6: 11,
            8: "1.109.5",
            9: 3,
            10: 2
            },
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def changes(self, num):
        fields = {
        1: 17,
        2: {
            1: 11371687918,
            2: 1,
            3: int(num),
            4: 62,
            5: "\u001a",
            8: 5,
            13: 329
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)

    def leave_s(self):
        fields = {
        1: 7,
        2: {
            1: 11371687918
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def leave_room(self, idroom):
        fields = {
        1: 6,
        2: {
            1: int(idroom)
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0E15000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "0E1500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "0E150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0E15000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def stauts_infoo(self, idd):
        fields = {
        1: 7,
        2: {
            1: 11371687918
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)

    def GenResponsMsg(self, Msg, Enc_Id):
        fields = {
            1: 1,
            2: {
                1: 12947146032,
                2: Enc_Id,
                3: 2,
                4: str(Msg),
                5: int(datetime.now().timestamp()),
                7: 2,
                9: {
                    1: "RON PROTO", #RON PROTO DONT CHANGE 
                    2: int(get_random_avatar()),
                    3: 901049014,
                    4: 330,
                    5: 800000304,
                    8: "Friend",
                    10: 1,
                    11: 1,
                    13: {
                        1: 2,
                        2: 1,
                    },
                    14: {
                        1: 11017917409,
                        2: 8,
                        3: "\u0010\u0015\b\n\u000b\u0013\f\u000f\u0011\u0004\u0007\u0002\u0003\r\u000e\u0012\u0001\u0005\u0006"
                    }
                },
                10: "BD",
                13: {
                    1: "https://graph.facebook.com/v9.0/253082355523299/picture?width=160&height=160",
                    2: 1,
                    3: 1
                },
                14: {
                    1: {
                        1: random.choice([1, 4]),
                        2: 1,
                        3: random.randint(1, 180),
                        4: 1,
                        5: int(datetime.now().timestamp()),
                        6: "BD"
                    }
                }
            }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "1215000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "121500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "12150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "1215000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def createpacketinfo(self, idddd):
        ida = Encrypt(idddd)
        packet = f"080112090A05{ida}1005"
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0F15000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "0F1500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "0F150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0F15000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def accept_sq(self, hashteam, idplayer, ownerr):
        fields = {
        1: 4,
        2: {
            1: int(ownerr),
            3: int(idplayer),
            4: "\u0001\u0007\t\n\u0012\u0019\u001a ",
            8: 1,
            9: {
            2: 1393,
            4: "headers-b174m4",
            6: 11,
            8: "1.109.5",
            9: 3,
            10: 2
            },
            10: hashteam,
            12: 1,
            13: "en",
            16: "OR"
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def info_room(self, idrooom):
        fields = {
        1: 1,
        2: {
            1: int(idrooom),
            3: {},
            4: 1,
            6: "en"
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0E15000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "0E1500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "0E150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0E15000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)

    def sockf1(self, tok, online_ip, online_port, packet, key, iv):
        global socket_client, sent_inv, tempid, start_par, clients, pleaseaccept
        global tempdata1, nameinv, idinv, senthi, statusinfo, tempdata, data22
        global leaveee, isroom, isroom2
        
        socket_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        online_port = int(online_port)

        socket_client.connect((online_ip, online_port))
        print(f"Connected to Online Server: Port {online_port}, Host {online_ip}")
        socket_client.send(bytes.fromhex(tok))
        
        while True:
            data2 = socket_client.recv(9999)
            if not data2:
                print("Connection closed by remote host")
                restart_program()
                break
            
            hex_data = data2.hex()
            
            if "0500" in hex_data[:4]:
                accept_packet = f'08{hex_data.split("08", 1)[1]}'
                kk = get_available_room(accept_packet)
                parsed_data = json.loads(kk)
                fark = parsed_data.get("4", {}).get("data")
                if fark is not None:
                    if fark == 18 and sent_inv:
                        aa = gethashteam(accept_packet)
                        ownerid = getownteam(accept_packet)
                        ss = self.accept_sq(aa, tempid, int(ownerid))
                        socket_client.send(ss)
                        sleep(1)
                        startauto = self.start_autooo()
                        socket_client.send(startauto)
                        start_par = False
                        sent_inv = False
                    elif fark == 6:
                        leaveee = True
                    elif fark == 50:
                        pleaseaccept = True
            
            elif "0600" in hex_data[:4] and len(hex_data) > 700:
                accept_packet = f'08{hex_data.split("08", 1)[1]}'
                kk = get_available_room(accept_packet)
                parsed_data = json.loads(kk)
                idinv = parsed_data["5"]["data"]["1"]["data"]
                nameinv = parsed_data["5"]["data"]["3"]["data"]
                senthi = True
            
            elif "0f00" in hex_data[:4]:
                packett = f'08{hex_data.split("08", 1)[1]}'
                kk = get_available_room(packett)
                parsed_data = json.loads(kk)
                asdj = parsed_data["2"]["data"]
                tempdata = get_player_status(packett)
                if asdj == 15:
                    if tempdata == "OFFLINE":
                        tempdata = f"The ID is {tempdata}"
                    else:
                        idplayer = parsed_data["5"]["data"]["1"]["data"]["1"]["data"]
                        idplayer1 = fix_num(idplayer)
                        if tempdata == "IN ROOM":
                            idrooom = get_idroom_by_idplayer(packett)
                            idrooom1 = fix_num(idrooom)
                            tempdata = f"ID: {idplayer1}\nStatus: {tempdata}\nRoom ID: {idrooom1}"
                            data22 = packett
                        elif "IN SQUAD" in tempdata:
                            idleader = get_leader(packett)
                            idleader1 = fix_num(idleader)
                            tempdata = f"ID: {idplayer1}\nStatus: {tempdata}\nLeader ID: {idleader1}"
                        else:
                            tempdata = f"ID: {idplayer1}\nStatus: {tempdata}"
                    statusinfo = True
            
            elif "0e00" in hex_data[:4]:
                packett = f'08{hex_data.split("08", 1)[1]}'
                kk = get_available_room(packett)
                parsed_data = json.loads(kk)
                asdj = parsed_data["2"]["data"]
                if asdj == 14:
                    nameroom = parsed_data["5"]["data"]["1"]["data"]["2"]["data"]
                    maxplayer = parsed_data["5"]["data"]["1"]["data"]["7"]["data"]
                    nowplayer = parsed_data["5"]["data"]["1"]["data"]["6"]["data"]
                    tempdata1 = f"{tempdata}\nRoom Name: {nameroom}\nMax Players: {maxplayer}\nCurrent Players: {nowplayer}"

    def connect(self, tok, packet, key, iv, whisper_ip, whisper_port, online_ip, online_port):
        global clients, socket_client, sent_inv, tempid, leaveee, start_par, nameinv, idinv, senthi, statusinfo, tempdata, pleaseaccept, tempdata1, data22
        
        clients = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        clients.connect((whisper_ip, whisper_port))
        clients.send(bytes.fromhex(tok))
        
        thread = threading.Thread(target=self.sockf1, args=(tok, online_ip, online_port, "anything", key, iv))
        threads.append(thread)
        thread.start()

        while True:
            data = clients.recv(9999)
            if data == b"":
                print("Connection closed by remote host")
                break
            
            if senthi:
                clients.send(self.GenResponsMsg(format_text("Hello! How Can I Help You Today? Type /help For Commands."), idinv))
                senthi = False
            
            hex_data = data.hex()
            if "1200" in hex_data[:4]:
                json_result = get_available_room(hex_data[10:])
                parsed_data = json.loads(json_result)
                try:
                    uid = parsed_data["5"]["data"]["1"]["data"]
                except KeyError:
                    uid = None
                
                if "8" in parsed_data["5"]["data"] and "data" in parsed_data["5"]["data"]["8"]:
                    emoji = parsed_data["5"]["data"]["8"]["data"]
                    if emoji != "DefaultMessageWithKey":
                        clients.send(self.GenResponsMsg(format_text("Hello! Type /help For Commands."), uid))

            if "1200" in hex_data[:4] and b"/dev" in data:
                json_result = get_available_room(hex_data[10:])
                parsed_data = json.loads(json_result)
                uid = parsed_data["5"]["data"]["1"]["data"]
                clients.send(self.GenResponsMsg(format_text("Developer: NIROB X CODX.!!!] | Contact:!!01960835449"), uid))
            
            if "1200" in hex_data[:4] and b"/x" in data:
                try:
                    command_split = re.split("/x ", str(data))
                    if len(command_split) > 1:
                        player_id = command_split[1].split('(')[0].strip()
                        player_id = rrrrrrrrrrrrrr(player_id)
                        
                        json_result = get_available_room(hex_data[10:])
                        parsed_data = json.loads(json_result)
                        uid = parsed_data["5"]["data"]["1"]["data"]
                        clients.send(self.GenResponsMsg(f"[C][B][1E90FF]{format_text('Sending Join Requests...!!!')}", uid))
                        
                        tempid = player_id
                        
                        def send_invite():
                            invskwad = self.request_skwad(player_id)
                            socket_client.send(invskwad)
                        
                        threadss = [threading.Thread(target=send_invite) for _ in range(30)]
                        for thread in threadss:
                            thread.start()
                        for thread in threadss:
                            thread.join()
                        
                        sent_inv = True
                except Exception as e:
                    print(f"Error in /x command: {e}")

            if "1200" in hex_data[:4] and b"/3" in data:
                json_result = get_available_room(hex_data[10:])
                parsed_data = json.loads(json_result)
                uid = parsed_data["5"]["data"]["1"]["data"]
                
                socket_client.send(self.skwad_maker())
                sleep(0.5)
                socket_client.send(self.changes(2)) # Change to 3-player mode
                sleep(0.5)

                iddd = uid # Default to the sender
                if b'(' in data:
                    player_id_str = data.split(b'/3')[1].split(b'(')[0].decode().strip()
                    if player_id_str:
                        iddd = player_id_str
                
                socket_client.send(self.invite_skwad(iddd))
                clients.send(self.GenResponsMsg(f"[C][B][1E90FF]-----------------------------\n{format_text('Converting Team To Trio')}\n-----------------------------", uid))
                
                sleep(5)
                socket_client.send(self.leave_s())
                sleep(1)
                socket_client.send(self.changes(1)) # Change back to solo

            if "1200" in hex_data[:4] and b"/5" in data:
                json_result = get_available_room(hex_data[10:])
                parsed_data = json.loads(json_result)
                uid = parsed_data["5"]["data"]["1"]["data"]

                socket_client.send(self.skwad_maker())
                sleep(1)
                socket_client.send(self.changes(4)) # Change to 5-player mode

                iddd = uid
                if b'(' in data:
                    player_id_str = data.split(b'/5')[1].split(b'(')[0].decode().strip()
                    if player_id_str:
                        iddd = player_id_str

                socket_client.send(self.invite_skwad(iddd))
                clients.send(self.GenResponsMsg(f"[C][B][1E90FF]-----------------------------\n{format_text('Converting Team To Quintet')}\n-----------------------------", uid))

                sleep(5)
                socket_client.send(self.leave_s())
                sleep(2)
                socket_client.send(self.changes(1))

            if "1200" in hex_data[:4] and b"/6" in data:
                json_result = get_available_room(hex_data[10:])
                parsed_data = json.loads(json_result)
                uid = parsed_data["5"]["data"]["1"]["data"]

                socket_client.send(self.skwad_maker())
                sleep(0.5)
                socket_client.send(self.changes(5)) # Change to 6-player mode

                iddd = uid
                if b'(' in data:
                    player_id_str = data.split(b'/6')[1].split(b'(')[0].decode().strip()
                    if player_id_str:
                        iddd = player_id_str
                
                socket_client.send(self.invite_skwad(iddd))
                clients.send(self.GenResponsMsg(f"[C][B][1E90FF]-----------------------------\n{format_text('Converting Team To Sextet')}\n-----------------------------", uid))

                sleep(4)
                socket_client.send(self.leave_s())
                sleep(0.5)
                socket_client.send(self.changes(1))
            
            if "1200" in hex_data[:4] and b"/status" in data:
                try:
                    split_data = re.split(rb'/status', data)
                    room_data = split_data[1].split(b'(')[0].decode().strip().split()
                    json_result = get_available_room(hex_data[10:])
                    parsed_data = json.loads(json_result)
                    uid = parsed_data["5"]["data"]["1"]["data"]

                    if room_data:
                        player_id = room_data[0]
                        packetmaker = self.createpacketinfo(player_id)
                        socket_client.send(packetmaker)
                        statusinfo1 = True
                        while statusinfo1:
                            if statusinfo:
                                if "IN ROOM" in tempdata:
                                    inforoooom = self.info_room(data22)
                                    socket_client.send(inforoooom)
                                    sleep(0.5)
                                    clients.send(self.GenResponsMsg(f"{tempdata1}", uid))
                                else:
                                    clients.send(self.GenResponsMsg(f"{tempdata}", uid))
                                tempdata = None
                                tempdata1 = None
                                statusinfo = False
                                statusinfo1 = False
                                break
                    else:
                        clients.send(self.GenResponsMsg(f"[C][B][FF0000]{format_text('Please Enter a Player ID!')}", uid))
                except Exception as e:
                    print(f"Error in /status command: {e}")
                    clients.send(self.GenResponsMsg(f"[C][B][FF0000]{format_text('ERROR!')}", uid))

            if "1200" in hex_data[:4] and b"/inv" in data:
                json_result = get_available_room(hex_data[10:])
                parsed_data = json.loads(json_result)
                uid = parsed_data["5"]["data"]["1"]["data"]
                split_data = re.split(rb'/inv', data)
                room_data = split_data[1].split(b'(')[0].decode().strip().split()
                if room_data:
                    iddd = room_data[0]
                    numsc1 = "5" # Default to 5
                    
                    if len(room_data) > 1 and room_data[1].isdigit():
                        numsc1 = room_data[1]

                    if int(numsc1) < 3 or int(numsc1) > 6:
                        clients.send(self.GenResponsMsg(f"[C][B][FF0000]{format_text('Usage: /inv <uid> <Squad Type 3-6>')}", uid))
                    else:
                        numsc = int(numsc1) - 1
                        socket_client.send(self.skwad_maker())
                        sleep(1)
                        socket_client.send(self.changes(int(numsc)))
                        
                        socket_client.send(self.invite_skwad(iddd))
                        socket_client.send(self.invite_skwad(uid)) # Invite the sender too
                        clients.send(self.GenResponsMsg(f"[C][B][00ff00]{format_text('Creating a team and sending you an invite!')}", uid))

                        sleep(5)
                        socket_client.send(self.leave_s())
                        sleep(2)
                        socket_client.send(self.changes(1))
                        clients.send(self.GenResponsMsg(f"[C][B][FF00FF]{format_text('The bot is now in solo mode.')}", uid))
            
            if "1200" in hex_data[:4] and b"/room" in data:
                json_result = get_available_room(hex_data[10:])
                parsed_data = json.loads(json_result)
                uid = parsed_data["5"]["data"]["1"]["data"]
                split_data = re.split(rb'/room', data)
                room_data = split_data[1].split(b'(')[0].decode().strip().split()
                if room_data:
                    player_id = room_data[0]
                    if player_id.isdigit():
                        player_id = rrrrrrrrrrrrrr(player_id)
                        socket_client.send(self.createpacketinfo(player_id))
                        sleep(0.5)
                        if "IN ROOM" in tempdata:
                            room_id = get_idroom_by_idplayer(data22)
                            packetspam = self.spam_room(room_id, player_id)
                            clients.send(self.GenResponsMsg(f"[C][B][00ff00]{format_text(f'Processing request for {fix_num(player_id)}!')}", uid))
                            
                            for _ in range(99):
                                threading.Thread(target=socket_client.send, args=(packetspam,)).start()
                            
                            clients.send(self.GenResponsMsg(f"[C][B][00FF00]{format_text('Request Successful')}", uid))
                        else:
                            clients.send(self.GenResponsMsg(f"[C][B][FF00FF]{format_text('The player is not in a room')}", uid))
                    else:
                        clients.send(self.GenResponsMsg(f"[C][B][FF00FF]{format_text('Please enter a valid player ID!')}", uid))
                else:
                    clients.send(self.GenResponsMsg(f"[C][B][FF00FF]{format_text('Please enter a player ID!')}", uid))

            if "1200" in hex_data[:4] and b"/spam" in data:
                command_split = re.split("/spam", str(data))
                if len(command_split) > 1:
                    player_id = command_split[1].split('(')[0].strip()
                    json_result = get_available_room(hex_data[10:])
                    parsed_data = json.loads(json_result)
                    uid = parsed_data["5"]["data"]["1"]["data"]
                    clients.send(self.GenResponsMsg(f"{generate_random_color()}{format_text('Sending friend requests...')}", uid))
                    
                    message = send_spam(player_id)
                    clients.send(self.GenResponsMsg(message, uid))

            if "1200" in hex_data[:4] and b"/visit" in data:
                command_split = re.split("/visit", str(data))
                if len(command_split) > 1:
                    player_id = command_split[1].split('(')[0].strip()
                    json_result = get_available_room(hex_data[10:])
                    parsed_data = json.loads(json_result)
                    uid = parsed_data["5"]["data"]["1"]["data"]
                    clients.send(self.GenResponsMsg(f"{generate_random_color()}{format_text('Sending 1000 visits to')} {fix_num(player_id)}...", uid))
                    
                    message = send_visits(player_id)
                    clients.send(self.GenResponsMsg(message, uid))

            if "1200" in hex_data[:4] and b"/info" in data:
                try:
                    command_split = re.split("/info", str(data))
                    json_result = get_available_room(hex_data[10:])
                    parsed_data = json.loads(json_result)
                    sender_id = parsed_data["5"]["data"]["1"]["data"]

                    if len(command_split) <= 1 or not command_split[1].strip():
                        clients.send(self.GenResponsMsg(f"[C][B][FF0000]{format_text('Please enter a valid player ID!')}", sender_id))
                    else:
                        uids = re.findall(r"\b\d{5,15}\b", command_split[1])
                        uid_to_check = uids[0] if uids else ""
                        
                        if not uid_to_check:
                            clients.send(self.GenResponsMsg(f"[C][B][FF0000]{format_text('Invalid Player ID!')}", sender_id))
                        else:
                            info_response = newinfo(uid_to_check)
                            if 'info' not in info_response or info_response['status'] != "ok":
                                clients.send(self.GenResponsMsg(f"[C][B][FF0000]{format_text('Wrong ID. Please Check Again')}", sender_id))
                            else:
                                infoo = info_response['info']
                                basic_info = infoo['basic_info']
                                clan_info = infoo.get('clan_info', "false")
                                
                                clan_info_text = f"\n{format_text('Player Not In Clan')}\n"
                                if clan_info != "false":
                                    clan_info_text = (
                                        f"{format_text('Clan Info:')}\n"
                                        f"[B][FFA500]• {format_text('Clan ID:')} [FFFFFF]{fix_num(clan_info['clanid'])}\n"
                                        f"[B][FFA500]• {format_text('Name:')} [FFFFFF]{clan_info.get('clanname', 'N/A')}\n"
                                        f"[B][FFA500]• {format_text('Members:')} [FFFFFF]{clan_info.get('livemember', 0)}\n"
                                        f"[B][FFA500]• {format_text('Level:')} [FFFFFF]{clan_info.get('guildlevel', 0)}\n"
                                    )
                                
                                message_info = (
                                    f"[C][B][00FF00]«--- {format_text('Player Info')} ---»\n"
                                    f"[B][FFA500]• {format_text('Name:')} [FFFFFF]{basic_info['username']}\n"
                                    f"[B][FFA500]• {format_text('Level:')} [FFFFFF]{basic_info['level']}\n"
                                    f"[B][FFA500]• {format_text('Server:')} [FFFFFF]{basic_info['region']}\n"
                                    f"[B][FFA500]• {format_text('Likes:')} [FFFFFF]{fix_num(basic_info['likes'])}\n"
                                    f"[B][FFA500]• {format_text('Bio:')} [FFFFFF]{basic_info.get('bio', 'No bio').replace('|', ' ')}\n"
                                    f"{clan_info_text}"
                                    f"[C][B][00FF00]«--- {format_text('End Info')} ---»"
                                )
                                clients.send(self.GenResponsMsg(message_info, sender_id))
                except Exception as e:
                    print(f"Unexpected Error in /info: {e}")
                    clients.send(self.GenResponsMsg(f"[C][B][FF0000]{format_text('An unexpected error occurred!')}", sender_id))
            
            if "1200" in hex_data[:4] and b"/bio" in data:
                try:
                    command_split = re.split("/bio", str(data))
                    json_result = get_available_room(hex_data[10:])
                    parsed_data = json.loads(json_result)
                    sender_id = parsed_data["5"]["data"]["1"]["data"]
                    uids = re.findall(r"\b\d{5,15}\b", command_split[1])
                    uid_to_check = uids[0] if uids else ""
                    if not uid_to_check:
                         clients.send(self.GenResponsMsg(f"[C][B][FF0000]{format_text('Invalid Player ID!')}", sender_id))
                    else:
                        info_response = newinfo(uid_to_check)
                        if info_response['status'] == "ok":
                            bio = info_response['info']['basic_info'].get('bio', "No bio available").replace("|", " ")
                            clients.send(self.GenResponsMsg(bio, sender_id))
                        else:
                            clients.send(self.GenResponsMsg(f"[C][B][FF0000]{format_text('Wrong ID Please Check Again')}", sender_id))
                except Exception as e:
                     print(f"Unexpected Error in /bio: {e}")

            if "1200" in hex_data[:4] and b"/likes" in data:
                json_result = get_available_room(hex_data[10:])
                parsed_data = json.loads(json_result)
                uid = parsed_data["5"]["data"]["1"]["data"]
                clients.send(self.GenResponsMsg(f"{generate_random_color()}{format_text('Processing Your Request')}", uid))
                
                command_split = re.split("/likes", str(data))
                player_id = command_split[1].split('(')[0].strip()
                likes_response = send_likes(player_id)
                clients.send(self.GenResponsMsg(likes_response['message'], uid))
            
            if "1200" in hex_data[:4] and b"/check" in data:
                try:
                    command_split = re.split("/check", str(data))
                    json_result = get_available_room(hex_data[10:])
                    parsed_data = json.loads(json_result)
                    uid = parsed_data["5"]["data"]["1"]["data"]
                    clients.send(self.GenResponsMsg(f"{generate_random_color()}{format_text('Checking Ban Status...')}", uid))
                    
                    if len(command_split) > 1:
                        player_id = command_split[1].split('(')[0].strip()
                        banned_status = check_banned_status(player_id)
                        status = banned_status.get('status', 'Unknown')
                        player_name = banned_status.get('player_name', 'Unknown')
                        
                        response_message = (
                            f"{generate_random_color()}{format_text('Player Name:')} {player_name}\n"
                            f"{format_text('Player ID:')} {fix_num(player_id)}\n"
                            f"{format_text('Status:')} {status}"
                        )
                        clients.send(self.GenResponsMsg(response_message, uid))
                except Exception as e:
                    print(f"Error in /check command: {e}")
                    clients.send(self.GenResponsMsg(f"[C][B][FF0000]{format_text('An error occurred.')}", uid))

            if "1200" in hex_data[:4] and b"/help" in data:
                json_result = get_available_room(hex_data[10:])
                parsed_data = json.loads(json_result)
                uid = parsed_data["5"]["data"]["1"]["data"]
                
                help_msg_1 = (
                    f"[C][B][FFFFFF]{format_text('Create Trio Squad:')}\n[FF8C00]➥ /3\n\n"
                    f"[FFFFFF]{format_text('Create Quintet Squad:')}\n[FF0000]➥ /5\n\n"
                    f"[FFFFFF]{format_text('Create Sextet Squad:')}\n[9932CC]➥ /6\n\n"
                    f"[FFFFFF]{format_text('Show Player Info:')}\n[00FF00]➥ /info <id>\n\n"
                    f"[FFFFFF]{format_text('Show Player Bio:')}\n[00FF00]➥ /bio <id>\n\n"
                    f"[FFFFFF]{format_text('Chat With ai:')}\n[00FF00]➥ /ai <ask>\n\n"
                    f"[FFFFFF]{format_text('Invite Player to Squad:')}\n[4169E1]➥ /inv <id> <size>\n\n"
                    f"[FFFFFF]{format_text('Spam Join Requests:')}\n[FFFF00]➥ /x <id>\n\n"
                    f"[FFFFFF]{format_text('Spam Room Join:')}\n[00FFFF]➥ /room <id>"
                )
                help_msg_2 = (
                    f"[C][B][FFFFFF]{format_text('Check Player Ban Status:')}\n[FFA500]➥ /check <id>\n\n"
                    f"[FFFFFF]{format_text('Check Player Activity:')}\n[A52A2A]➥ /status <id>\n\n"
                    f"[FFFFFF]{format_text('Add 100 Likes to Player:')}\n[00FF00]➥ /likes <id>\n\n"
                    f"[FFFFFF]{format_text('Lag Team by Code:')}\n[b3ff00]➥ /lag <team_code> <1-3>\n\n"
                    f"[FFFFFF]{format_text('Intense Lag Attack:')}\n[ff0000]➥ /attack <team_code>\n\n"
                    f"[FFFFFF]{format_text('Force Bot to Solo Mode:')}\n[00ffdd]➥ /solo\n\n"
                    f"[FFFFFF]{format_text('Show Developer Info:')}\n[4169E1]➥ /dev\n\n"
                    f"[FFFFFF]{format_text('Send Spam friend request:')}\n[00FF00]➥ /spam <id>\n\n"
                    f"[FFFFFF]{format_text('Get 1000 account visit:')}\n[00FF00]➥ /visit <id>\n\n"
                    f"[FFFFFF]{format_text('Force Start by Team Code:')}\n[FFA500]➥ /go <team_code>\n\n"
                   
                    f"[FFFFFF]{format_text('©DEVELOPER :')}\n[FFA500]➥ NIROB X CODX..!!"
                )
                clients.send(self.GenResponsMsg(help_msg_1, uid))
                time.sleep(0.5)
                clients.send(self.GenResponsMsg(help_msg_2, uid))

            if "1200" in hex_data[:4] and b"/ai" in data:
                i = re.split("/ai", str(data))[1]
                sid = str(i).split("(\\x")[0].strip()
                # IMPORTANT: Replace with your actual Google AI API Key
                api_key = "AIzaSyAjF76dmiyPbGL6eXA5Df5F8PG9WkQWSpY"
                response = requests.post(
                    f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}",
                    headers={"Content-Type": "application/json"},
                    json={"contents": [{"parts": [{"text": sid}]}]},
                )
                if response.status_code == 200:
                    ai_data = response.json()
                    ai_response = ai_data['candidates'][0]['content']['parts'][0]['text']
                    json_result = get_available_room(hex_data[10:])
                    parsed_data = json.loads(json_result)
                    uid = parsed_data["5"]["data"]["1"]["data"]
                    clients.send(self.GenResponsMsg(ai_response, uid))
                else:
                    print("Error with AI API:", response.status_code, response.text)

            if '1200' in hex_data[:4] and b'/lag' in data:
                try:
                    split_data = re.split(rb'/lag', data)
                    command_parts = split_data[1].split(b'(')[0].decode().strip().split()
                    json_result = get_available_room(hex_data[10:])
                    parsed_data = json.loads(json_result)
                    uid = parsed_data['5']['data']['1']['data']
                    
                    if not command_parts:
                        clients.send(self.GenResponsMsg(f"[C][B][FF0000]{format_text('Please provide a team code.')}", uid))
                        continue

                    room_id = command_parts[0]
                    repeat_count = int(command_parts[1]) if len(command_parts) > 1 and command_parts[1].isdigit() else 1
                    repeat_count = min(repeat_count, 3) # Max 3 times
                    
                    clients.send(self.GenResponsMsg(f"[C][B][32CD32]{format_text(f'Starting lag process. Will repeat {repeat_count} times.')}", uid))
                    
                    for i in range(repeat_count):
                        if repeat_count > 1:
                             clients.send(self.GenResponsMsg(f"[C][B][FFA500]{format_text(f'Running batch {i + 1} of {repeat_count}...')}", uid))
                        
                        for _ in range(50): # Reduced for stability
                            join_teamcode(socket_client, room_id, key, iv)
                            time.sleep(0.01)
                            socket_client.send(self.leave_s())
                            time.sleep(0.01)
                        
                        if repeat_count > 1 and i < repeat_count - 1:
                            time.sleep(1)

                    clients.send(self.GenResponsMsg(f"[C][B][00FF00]{format_text('All lag batches finished!')}", uid))
                except Exception as e:
                    print(f"An error occurred during /lag: {e}")

            if "1200" in hex_data[:4] and b"/solo" in data:
                json_result = get_available_room(hex_data[10:])
                parsed_data = json.loads(json_result)
                uid = parsed_data["5"]["data"]["1"]["data"]

                socket_client.send(self.leave_s())
                sleep(1)
                socket_client.send(self.changes(1))
                clients.send(self.GenResponsMsg(f"[C][B][00FF00]{format_text('Successfully left the group.')}", uid))
            
            if '1200' in hex_data[:4] and b'/attack' in data:
                try:
                    split_data = re.split(rb'/attack', data)
                    command_parts = split_data[1].split(b'(')[0].decode().strip().split()
                    json_result = get_available_room(hex_data[10:])
                    parsed_data = json.loads(json_result)
                    uid = parsed_data['5']['data']['1']['data']
                    
                    if not command_parts:
                        clients.send(self.GenResponsMsg(f"[C][B][FF0000]{format_text('Please provide a team code.')}", uid))
                        continue

                    team_code = command_parts[0]
                    clients.send(self.GenResponsMsg(f"[C][B][FFA500]{format_text(f'Starting an intensive attack on {team_code}...')}", uid))

                    start_packet = self.start_autooo()
                    leave_packet = self.leave_s()

                    attack_start_time = time.time()
                    while time.time() - attack_start_time < 45:
                        join_teamcode(socket_client, team_code, key, iv)
                        socket_client.send(start_packet)
                        socket_client.send(leave_packet)
                        time.sleep(0.15)

                    clients.send(self.GenResponsMsg(f"[C][B][00FF00]{format_text(f'Attack on team {team_code} completed!')}", uid))
                except Exception as e:
                    print(f"An error occurred in /attack: {e}")

            if "1200" in hex_data[:4] and b"/go" in data:
                try:
                    split_data = re.split(rb'/go', data)
                    command_parts = split_data[1].split(b'(')[0].decode().strip().split()
                    json_result = get_available_room(hex_data[10:])
                    parsed_data = json.loads(json_result)
                    uid = parsed_data['5']['data']['1']['data']
                    
                    if not command_parts:
                        clients.send(self.GenResponsMsg(f"[C][B][FF0000]{format_text('Please provide a team code.')}", uid))
                        continue

                    team_code = command_parts[0]
                    spam_count = int(command_parts[1]) if len(command_parts) > 1 and command_parts[1].isdigit() else 15
                    spam_count = min(spam_count, 50)
                    
                    clients.send(self.GenResponsMsg(f"[C][B][FFA500]{format_text('Joining lobby to force start...')}", uid))
                    
                    join_teamcode(socket_client, team_code, key, iv)
                    time.sleep(2)
                    
                    clients.send(self.GenResponsMsg(f"[C][B][FF0000]{format_text(f'Spamming start command {spam_count} times!')}", uid))
                    
                    start_packet = self.start_autooo()
                    for _ in range(spam_count):
                        socket_client.send(start_packet)
                        time.sleep(0.1)

                    clients.send(self.GenResponsMsg(f"[C][B][00FF00]{format_text('Force start process finished.')}", uid))
                except Exception as e:
                    print(f"An error occurred in /go: {e}")

            if "1200" in hex_data[:4] and b"/add" in data:
                split_data = re.split(rb'/add', data)
                room_data = split_data[1].split(b'(')[0].decode().strip().split()
                json_result = get_available_room(hex_data[10:])
                parsed_data = json.loads(json_result)
                uid = parsed_data["5"]["data"]["1"]["data"]

                if len(room_data) >= 2:
                    iddd = room_data[0]
                    numsc1 = room_data[1]
                    if int(numsc1) < 3 or int(numsc1) > 6:
                        clients.send(self.GenResponsMsg(f"[C][B][FF0000]{format_text('Usage: /add <uid> <Squad Type 3-6>')}", uid))
                    else:
                        numsc = int(numsc1) - 1
                        socket_client.send(self.skwad_maker())
                        sleep(1)
                        socket_client.send(self.changes(int(numsc)))
                        
                        socket_client.send(self.invite_skwad(iddd))
                        socket_client.send(self.invite_skwad(uid))
                        clients.send(self.GenResponsMsg(f"[C][B][00ff00]{format_text('Accept The Invite Quickly!')}", uid))
                        
                        leaveee1 = True
                        while leaveee1:
                            if leaveee:
                                sleep(5)
                                socket_client.send(self.leave_s())
                                leaveee = False
                                leaveee1 = False
                                clients.send(self.GenResponsMsg(f"[C][B][FF00FF]{format_text('Success!')}", uid))
                            elif pleaseaccept:
                                socket_client.send(self.leave_s())
                                leaveee1 = False
                                pleaseaccept = False
                                clients.send(self.GenResponsMsg(f"[C][B][FF00FF]{format_text('Please accept the invite')}", uid))
                else:
                    clients.send(self.GenResponsMsg(f"[C][B][FF00FF]{format_text('Usage: /add <uid> <Squad Type 3-6>')}", uid))


    # ... (The rest of the authentication and connection logic remains the same) ...
    def parse_my_message(self, serialized_data):
        MajorLogRes = MajorLoginRes_pb2.MajorLoginRes()
        MajorLogRes.ParseFromString(serialized_data)
        
        timestamp = MajorLogRes.kts
        key = MajorLogRes.ak
        iv = MajorLogRes.aiv
        BASE64_TOKEN = MajorLogRes.token
        timestamp_obj = Timestamp()
        timestamp_obj.FromNanoseconds(timestamp)
        timestamp_seconds = timestamp_obj.seconds
        timestamp_nanos = timestamp_obj.nanos
        combined_timestamp = timestamp_seconds * 1_000_000_000 + timestamp_nanos
        return combined_timestamp, key, iv, BASE64_TOKEN

    def GET_PAYLOAD_BY_DATA(self,JWT_TOKEN , NEW_ACCESS_TOKEN,date):
        token_payload_base64 = JWT_TOKEN.split('.')[1]
        token_payload_base64 += '=' * ((4 - len(token_payload_base64) % 4) % 4)
        decoded_payload = base64.urlsafe_b64decode(token_payload_base64).decode('utf-8')
        decoded_payload = json.loads(decoded_payload)
        NEW_EXTERNAL_ID = decoded_payload['external_id']
        SIGNATURE_MD5 = decoded_payload['signature_md5']
        now = datetime.now()
        now =str(now)[:len(str(now))-7]
        formatted_time = date
        payload = bytes.fromhex("1a13323032352d30372d30323031313a30323a3531220966726565206669726528013a07312e3131342e32422c416e64726f6964204f5320372e312e32202f204150492d323320284e32473438482f373030323530323234294a0848616e6468656c645207416e64726f69645a045749464960c00c68840772033332307a1f41524d7637205646507633204e454f4e20564d48207c2032343635207c203480019a1b8a010f416472656e6f2028544d292036343092010d4f70656e474c20455320332e319a012b476f6f676c657c31663361643662372d636562342d343934622d383730622d623164616364373230393131a2010c3139372e312e31322e313335aa0102656eb201203939366136323964626364623339363462653662363937386635643831346462ba010134c2010848616e6468656c64ca011073616d73756e6720534d2d473935354eea014066663930633037656239383135616633306134336234613966363031393531366530653463373033623434303932353136643064656661346365663531663261f00101ca0207416e64726f6964d2020457494649ca03203734323862323533646566633136343031386336303461316562626665626466e003daa907e803899b07f003bf0ff803ae088004999b078804daa9079004999b079804daa907c80403d204262f646174612f6170702f636f6d2e6474732e667265656669726574682d312f6c69622f61726de00401ea044832303837663631633139663537663261663465376665666630623234643964397c2f646174612f6170702f636f6d2e6474732e667265656669726574682d312f626173652e61706bf00403f804018a050233329a050a32303139313138363933a80503b205094f70656e474c455332b805ff7fc00504e005dac901ea0507616e64726f6964f2055c4b71734854394748625876574c6668437950416c52526873626d43676542557562555551317375746d525536634e30524f3751453141486e496474385963784d614c575437636d4851322b7374745279377830663935542b6456593d8806019006019a060134a2060134b2061e40001147550d0c074f530b4d5c584d57416657545a065f2a091d6a0d5033")
        payload = payload.replace(b"2025-07-02 11:02:51", str(now).encode())
        payload = payload.replace(b"ff90c07eb9815af30a43b4a9f6019516e0e4c703b44092516d0defa4cef51f2a", NEW_ACCESS_TOKEN.encode("UTF-8"))
        payload = payload.replace(b"996a629dbcdb3964be6b6978f5d814db", NEW_EXTERNAL_ID.encode("UTF-8"))
        payload = payload.replace(b"7428b253defc164018c604a1ebbfebdf", SIGNATURE_MD5.encode("UTF-8"))
        PAYLOAD = payload.hex()
        PAYLOAD = encrypt_api(PAYLOAD)
        PAYLOAD = bytes.fromhex(PAYLOAD)
        whisper_ip, whisper_port, online_ip, online_port = self.GET_LOGIN_DATA(JWT_TOKEN , PAYLOAD)
        return whisper_ip, whisper_port, online_ip, online_port
    
    def dec_to_hex(ask):
        ask_result = hex(ask)
        final_result = str(ask_result)[2:]
        if len(final_result) == 1:
            final_result = "0" + final_result
            return final_result
        else:
            return final_result
    def convert_to_hex(PAYLOAD):
        hex_payload = ''.join([f'{byte:02x}' for byte in PAYLOAD])
        return hex_payload
    def convert_to_bytes(PAYLOAD):
        payload = bytes.fromhex(PAYLOAD)
        return payload
    def GET_LOGIN_DATA(self, JWT_TOKEN, PAYLOAD):
        url = "https://clientbp.common.ggbluefox.com/GetLoginData"
        headers = {
            'Expect': '100-continue', 'Authorization': f'Bearer {JWT_TOKEN}', 'X-Unity-Version': '2018.4.11f1',
            'X-GA': 'v1 1', 'ReleaseVersion': 'OB50', 'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)', 'Host': 'clientbp.common.ggbluefox.com',
            'Connection': 'close', 'Accept-Encoding': 'gzip, deflate, br',
        }
        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = requests.post(url, headers=headers, data=PAYLOAD, verify=False)
                response.raise_for_status()
                x = response.content.hex()
                json_result = get_available_room(x)
                parsed_data = json.loads(json_result)
                whisper_address = parsed_data['32']['data']
                online_address = parsed_data['14']['data']
                online_ip = online_address[:-6]
                whisper_ip = whisper_address[:-6]
                online_port = int(online_address[-5:])
                whisper_port = int(whisper_address[-5:])
                return whisper_ip, whisper_port, online_ip, online_port
            except requests.RequestException as e:
                print(f"Request failed: {e}. Attempt {attempt + 1} of {max_retries}. Retrying...")
                time.sleep(2)
        print("Failed to get login data after multiple attempts.")
        return None, None, None, None

    def guest_token(self,uid , password):
        url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        headers = {"Host": "100067.connect.garena.com", "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 10;en;EN;)", "Content-Type": "application/x-www-form-urlencoded", "Accept-Encoding": "gzip, deflate, br", "Connection": "close",}
        data = {"uid": f"{uid}", "password": f"{password}", "response_type": "token", "client_type": "2", "client_secret": client_secret, "client_id": "100067",}
        response = requests.post(url, headers=headers, data=data)
        data = response.json()
        NEW_ACCESS_TOKEN = data['access_token']
        NEW_OPEN_ID = data['open_id']
        OLD_ACCESS_TOKEN = "ff90c07eb9815af30a43b4a9f6019516e0e4c703b44092516d0defa4cef51f2a"
        OLD_OPEN_ID = "996a629dbcdb3964be6b6978f5d814db"
        time.sleep(0.2)
        data = self.TOKEN_MAKER(OLD_ACCESS_TOKEN , NEW_ACCESS_TOKEN , OLD_OPEN_ID , NEW_OPEN_ID,uid)
        return data
        
    def TOKEN_MAKER(self,OLD_ACCESS_TOKEN , NEW_ACCESS_TOKEN , OLD_OPEN_ID , NEW_OPEN_ID,id):
        headers = {
            'X-Unity-Version': '2018.4.11f1', 'ReleaseVersion': 'OB50', 'Content-Type': 'application/x-www-form-urlencoded',
            'X-GA': 'v1 1', 'Content-Length': '928', 'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
            'Host': 'loginbp.common.ggbluefox.com', 'Connection': 'Keep-Alive', 'Accept-Encoding': 'gzip'
        }
        data = bytes.fromhex('1a13323032352d30372d30323031313a30323a3531220966726565206669726528013a07312e3131342e32422c416e64726f6964204f5320372e312e32202f204150492d323320284e32473438482f373030323530323234294a0848616e6468656c645207416e64726f69645a045749464960c00c68840772033332307a1f41524d7637205646507633204e454f4e20564d48207c2032343635207c203480019a1b8a010f416472656e6f2028544d292036343092010d4f70656e474c20455320332e319a012b476f6f676c657c31663361643662372d636562342d343934622d383730622d623164616364373230393131a2010c3139372e312e31322e313335aa0102656eb201203939366136323964626364623339363462653662363937386635643831346462ba010134c2010848616e6468656c64ca011073616d73756e6720534d2d473935354eea014066663930633037656239383135616633306134336234613966363031393531366530653463373033623434303932353136643064656661346365663531663261f00101ca0207416e64726f6964d2020457494649ca03203734323862323533646566633136343031386336303461316562626665626466e003daa907e803899b07f003bf0ff803ae088004999b078804daa9079004999b079804daa907c80403d204262f646174612f6170702f636f6d2e6474732e667265656669726574682d312f6c69622f61726de00401ea044832303837663631633139663537663261663465376665666630623234643964397c2f646174612f6170702f636f6d2e6474732e667265656669726574682d312f626173652e61706bf00403f804018a050233329a050a32303139313138363933a80503b205094f70656e474c455332b805ff7fc00504e005dac901ea0507616e64726f6964f2055c4b71734854394748625876574c6668437950416c52526873626d43676542557562555551317375746d525536634e30524f3751453141486e496474385963784d614c575437636d4851322b7374745279377830663935542b6456593d8806019006019a060134a2060134b2061e40001147550d0c074f530b4d5c584d57416657545a065f2a091d6a0d5033')
        data = data.replace(OLD_OPEN_ID.encode(), NEW_OPEN_ID.encode())
        data = data.replace(OLD_ACCESS_TOKEN.encode(), NEW_ACCESS_TOKEN.encode())
        d = encrypt_api(data.hex())
        Final_Payload = bytes.fromhex(d)
        URL = "https://loginbp.ggblueshark.com/MajorLogin"

        RESPONSE = requests.post(URL, headers=headers, data=Final_Payload, verify=False)
        
        if RESPONSE.status_code == 200 and len(RESPONSE.text) > 10:
            combined_timestamp, key, iv, BASE64_TOKEN = self.parse_my_message(RESPONSE.content)
            whisper_ip, whisper_port, online_ip, online_port = self.GET_PAYLOAD_BY_DATA(BASE64_TOKEN, NEW_ACCESS_TOKEN, 1)
            self.key = key
            self.iv = iv
            return BASE64_TOKEN, key, iv, combined_timestamp, whisper_ip, whisper_port, online_ip, online_port
        return False
    
    def get_tok(self):
        global g_token
        result = self.guest_token(self.id, self.password)
        if not result:
            print(f"Failed to get token for ID: {self.id}")
            return None, None, None

        token, key, iv, Timestamp, whisper_ip, whisper_port, online_ip, online_port = result
        g_token = token
        
        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            account_id = decoded.get('account_id')
            encoded_acc = hex(account_id)[2:]
            hex_value = dec_to_hex(Timestamp)
            BASE64_TOKEN_ = token.encode().hex()
            
            head_len_hex = hex(len(encrypt_packet(BASE64_TOKEN_, key, iv)) // 2)[2:]
            
            zeros_map = {9: '0000000', 8: '00000000', 10: '000000', 7: '000000000'}
            zeros = zeros_map.get(len(encoded_acc), '00000000')

            head = f'0115{zeros}{encoded_acc}{hex_value}00000{head_len_hex}'
            final_token = head + encrypt_packet(BASE64_TOKEN_, key, iv)
            
            self.connect(final_token, 'anything', key, iv, whisper_ip, whisper_port, online_ip, online_port)
            return final_token, key, iv
        except Exception as e:
            print(f"Error processing token for ID {self.id}: {e}")
            return None, None, None

# ... আপনার সমস্ত বর্তমান কোড ...

import subprocess
import psutil
import time
import sys
import os
import json
import logging
import threading

# ... আপনার সমস্ত বর্তমান কোড ...

def restart_script():
    """স্ক্রিপ্টটি রিস্টার্ট করে - Android compatible version"""
    python = sys.executable
    script_path = os.path.abspath(sys.argv[0])
    
    print("রিস্টার্ট করা হচ্ছে...")
    
    # Android-compatible রিস্টার্ট পদ্ধতি
    try:
        # বর্তমান প্রক্রিয়াটি বন্ধ করে নতুন করে শুরু করে
        os.execl(python, python, script_path)
    except Exception as e:
        print(f"রিস্টার্ট করতে সমস্যা: {e}")
        # বিকল্প পদ্ধতি
        subprocess.Popen([python, script_path])
        sys.exit(0)

def check_script_alive():
    """সরলীকৃত স্ক্রিপ্ট জীবিততা পরীক্ষা"""
    script_name = os.path.basename(__file__)
    current_pid = os.getpid()
    
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if (proc.info['cmdline'] and 
                script_name in ' '.join(proc.info['cmdline']) and 
                proc.info['pid'] != current_pid):
                return True
        except:
            pass
    return False

def monitor_script():
    """মূল স্ক্রিপ্ট মনিটর করে"""
    script_name = os.path.basename(__file__)
    check_count = 0
    
    while True:
        time.sleep(10)
        check_count += 1
        
        # প্রতি 10 চেক পর পর লগ মেসেজ
        if check_count % 10 == 0:
            print(f"মনিটরিং active: {script_name} চলছে...")
        
        # যদি প্রধান থ্রেড না থাকে তবে রিস্টার্ট
        active_threads = threading.enumerate()
        main_thread_found = any('MainThread' in str(t) for t in active_threads)
        
        if not main_thread_found:
            print("মূল থ্রেড পাওয়া যায়নি, রিস্টার্ট করা হচ্ছে...")
            restart_script()

if __name__ == "__main__":
    print("স্ক্রিপ্ট শুরু হয়েছে...")
    
    # মনিটরিং থ্রেড শুরু করুন
    monitor_thread = threading.Thread(target=monitor_script, daemon=True)
    monitor_thread.start()
    
    try:
        # আপনার মূল স্ক্রিপ্টের বর্তমান কোড
        with open('account.json', 'r') as file:
            data = json.load(file)
        ids_passwords = list(data.items())
        
        def run_client(id, password):
            print(f"Starting client for ID: {id}")
            FF_CLIENT(id, password)
            
        threads = []
        num_threads = 1
        for i in range(min(num_threads, len(ids_passwords))):
            id, password = ids_passwords[i]
            thread = threading.Thread(target=run_client, args=(id, password))
            threads.append(thread)
            time.sleep(1)
            thread.start()

        for thread in threads:
            thread.join()
            
    except Exception as e:
        print(f"ত্রুটি 발생: {e}")
        print("1 সেকেন্ড পর রিস্টার্ট করা হবে...")
        time.sleep(1)
        restart_script()
    
    # স্ক্রিপ্ট সম্পূর্ণ হলে স্বয়ংক্রিয় রিস্টার্ট
    print("স্ক্রিপ্ট সম্পন্ন হয়েছে, রিস্টার্ট করা হচ্ছে...")
    time.sleep(1)
    restart_script()