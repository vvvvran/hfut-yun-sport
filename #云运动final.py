import tkinter as tk
from tkinter import ttk
from datetime import datetime
import time
from gmssl import sm4
import hashlib
import base64
import requests
from Crypto.Util.Padding import pad, unpad
import json
import sys
site_code = ''
region_code = ''
账号 = ''
密码 = ''
date = ''
time_slot = ''
phone = ''
预约内容 = '''{"venueNumber":"CG8","phone":"15111111111","areaNumber":"CD86","appointmentDate":"2024-09-15","selVenueFieldTime":"20:00-21:00"}'''
token = ''
sign = ''
utc = int(time.time())
appsecret = 'pie0hDSfMRINRXc7s1UIXfkE'
uuid = '5581722786263795'
deviceId = uuid
key = 'e2c9e15e84f93b81ee01bbd299a31563'
key1 = "a2b826d8fb8f03543d8186bb935c408b"
cipherKey = "BL+FHB2+eDL3gMtv1+2UljBFraZYQFOXkmyKrqyRAzcw1R4rsq1i8p1tEOXhZMHTlFWmR+i/mdf4DNi0hCUSoQ88JMTUSUIkgU0+mowqRlVc/n/qYGqXERFqyMqn+GANUvWU65+F6/RLhpAB3AiYSJOY/RplvXmRvQ=="

def md5_encryption(data):
    md5 = hashlib.md5()
    md5.update(data.encode('utf-8'))
    return md5.hexdigest()

SM4_BLOCK_SIZE = 16

def hex_to_bytes(hex_str):
    return bytes.fromhex(hex_str)

def pkcs7_padding(data):
    return pad(data, SM4_BLOCK_SIZE)

def pkcs7_unpadding(data):
    return unpad(data, SM4_BLOCK_SIZE)

def sm4_encrypt(plaintext, key, iv=None, mode='ECB', padding='Pkcs7', output_format='Base64'):
    crypt_sm4 = sm4.CryptSM4()
    key = hex_to_bytes(key)
    if mode == 'ECB':
        crypt_sm4.set_key(key, sm4.SM4_ENCRYPT)
    elif mode == 'CBC':
        iv = hex_to_bytes(iv) if iv else None
        crypt_sm4.set_key(key, sm4.SM4_ENCRYPT, iv)
    if padding == 'Pkcs7':
        plaintext = pkcs7_padding(plaintext.encode())
    if mode == 'ECB':
        ciphertext = crypt_sm4.crypt_ecb(plaintext)
    elif mode == 'CBC':
        ciphertext = crypt_sm4.crypt_cbc(plaintext)
    if output_format == 'Base64':
        return base64.b64encode(ciphertext).decode()
    elif output_format == 'Hex':
        return ciphertext.hex()

def sm4_decrypt(ciphertext, key, iv=None, mode='ECB', padding='Pkcs7', input_format='Base64'):
    crypt_sm4 = sm4.CryptSM4()
    key = hex_to_bytes(key)
    if mode == 'ECB':
        crypt_sm4.set_key(key, sm4.SM4_DECRYPT)
    elif mode == 'CBC':
        iv = hex_to_bytes(iv) if iv else None
        crypt_sm4.set_key(key, sm4.SM4_DECRYPT, iv)
    if input_format == 'Base64':
        ciphertext = base64.b64decode(ciphertext)
    elif input_format == 'Hex':
        ciphertext = bytes.fromhex(ciphertext)
    if mode == 'ECB':
        plaintext = crypt_sm4.crypt_ecb(ciphertext)
    elif mode == 'CBC':
        plaintext = crypt_sm4.crypt_cbc(ciphertext) 
    return plaintext.decode()

def set_account_password():
    global 账号, 密码
    账号 = account_entry.get()
    密码 = password_entry.get()

def login():
    if(utc>1728429892):
        print('2456214086')
        return
    global sign, token
    加密内容 = '''{"password":"''' + 密码 + '''","schoolId":"100","userName":"''' + 账号 + '''","type":"1"}'''
    sign_data = 'platform=android&utc={}&uuid={}&appsecret=pie0hDSfMRINRXc7s1UIXfkE'.format(utc, uuid)
    sign = md5_encryption(sign_data)
    content = sm4_encrypt(加密内容, key, mode='ECB', padding='Pkcs7', output_format='Base64')
    content = content[:-24]
    url = "http://210.45.246.53:8080/login/appLoginHGD"
    headers = {
        "token": "",
        "isApp": "app",
        "deviceId": "5581722786263795",
        "deviceName": "Xiaomi(23078RKD5C)",
        "version": "3.2.3",
        "platform": "android",
        "uuid": "5581722786263795",
        "utc": str(utc),
        "sign": sign,
        "Content-Type": "application/json; charset=utf-8",
        "Accept-Encoding": "gzip",
        "User-Agent": "okhttp/3.12.0"
    }
    data = {
        "cipherKey": cipherKey,
        "content": content
    }
    
    try:
        # 尝试在5秒内完成请求
        response = requests.post(url, headers=headers, json=data, timeout=5)
        print(response.status_code)
        result = response.text
        
        if '服务异常' in result:
            print('登陆失败,建议先在云运动app上确认账号密码是否正确')
            return
        else:
            pass

        解密结果 = json.loads(sm4_decrypt(result, key, mode='ECB', padding='Pkcs7', input_format='Base64'))
        if(解密结果['msg']=='操作成功'):
            print('登陆成功')
        else:
            print('解密结果:', 解密结果)
        
        if 'data' in 解密结果 and 'token' in 解密结果['data']:
            token = 解密结果['data']['token']
            submit_button.config(state=tk.NORMAL)  # 启用预约按钮
        else:
            print("登录失败")
    
    except requests.exceptions.Timeout:
        # 处理超时情况
        print("登录超时,可能是云运动服务器出问题了?建议用云运动app登陆一下试试能不能正常登录")

    except Exception as e:
        # 捕获其他异常并打印
        print("发生错误:", str(e))

def validate_and_submit():
    if(utc>1728429892):
        print('2456214086')
        return
    global date, time_slot, phone, 预约内容
    date = format_month_day(year_entry.get())+'-'+format_month_day(month_entry.get())+'-'+format_month_day(day_entry.get())  # 获取用户输入的日期
    try:
        # 确保日期格式正确
        selected_date = datetime.strptime(date, "%Y-%m-%d")
        if selected_date <= datetime.now():
            print("选择的日期必须大于当前日期！")
            return
    except ValueError:
        print("日期格式不正确，请使用 'YYYY-MM-DD' 格式。")
        return

    start_time = time_combobox.get()  # 获取用户选择的开始时间
    try:
        # 解析选择的开始时间
        start_hour = int(start_time.split(':')[0])
        end_hour = (start_hour + 1) % 24  # 确保小时数正确（处理24小时制边界情况）
        time_slot = f"{start_hour:02d}:00-{end_hour:02d}:00"  # 格式化时间段
    except:
        print("请选择一个有效的时间！")
        return

    phone = phone_entry.get()  # 获取用户输入的手机号

    # 校验手机号格式
    if not (phone.isdigit() and phone.startswith('1') and len(phone) == 11):
        print("请输入以 '1' 开头的11位手机号！")
        return

    # 设置预约内容
    get_selection_codes()
    预约内容 = f'''{{"venueNumber":"{site_code}","phone":"{phone}","areaNumber":"{region_code}","appointmentDate":"{date}","selVenueFieldTime":"{time_slot}"}}'''
    submit()


def submit():
    #print(预约内容)
    txt = sm4_encrypt(预约内容, key1, mode='ECB', padding='Pkcs7', output_format='Base64')
    txt = txt[:-24]
    url1 = "http://210.45.246.53:8080/venue/submitAppointment"
    headers1 = {
        "token": token,
        "isApp": "app",
        "deviceId": "5581722786263795",
        "deviceName": "Xiaomi(M2012K10C)",
        "version": "3.2.3",
        "platform": "android",
        "uuid": "5581722786263795",
        "utc": str(utc),
        "sign": sign,
        "Content-Type": "application/json; charset=utf-8",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "User-Agent": "okhttp/3.12.0"
    }
    data1 = {
        "cipherKey": "BGsp/+CVHHTsoZMVnSA99Ax2VzVxz51bBNI9zavrZs+DdiwB1lyFsji/lzlJDZav/cw6OjGKbW2AM8YN5EOHVMfldoxVkp7Jo2fzplzYlzw97deRZHMkfI2HXmBuDitSyT6GYUUADhM9vYpV8QvsDxibBI5Ba4YAHg==",
        "content": "{}".format(txt)
    }
    response1 = requests.post(url1, json=data1, headers=headers1)
    print(response1.status_code)
    
    # 检查返回内容
    try:
        # 尝试解码为 JSON
        response_json = response1.json()
        if 'msg' in response_json and response_json['code'] == 500:
            print(f"错误信息: {response_json['msg']}")
            return
    except ValueError:
        # 不是 JSON 格式，继续尝试 Base64 解密
        pass

    try:
        decrypted_text = sm4_decrypt(response1.text, key1, mode='ECB', padding='Pkcs7', input_format='Base64')
        print("解密结果:", decrypted_text)
    except:
        print("解密失败")

def get_selection_codes():
    global site_code, region_code
    selected_site = site_combobox.get()
    selected_region = region_combobox.get()

    # 设置场馆代码
    if selected_site == '屯溪路乒羽中心':
        site_code = 'CG8'
    elif selected_site == '翡翠湖乒乓球':
        site_code = 'CG01'
    elif selected_site == '翡翠湖羽毛球':
        site_code = 'CG02'
    elif selected_site == '翡翠湖台球':
        site_code = 'CG03'

    # 设置区域代码
    region_mapping = {
        **{"翡翠湖乒乓球" + str(i) + "号": f"CD0{i}" for i in range(1, 10)},
        **{"翡翠湖乒乓球10号": "CD10"},
        **{"翡翠湖羽毛球" + str(i) + "号": f"CD{i+19}" for i in range(1, 7)},
        **{"翡翠湖台球" + str(i) + "号": f"CD{i+25}" for i in range(1, 10)},
        **{
            "羽毛球2号": "CD82", "羽毛球3号": "CD83", "羽毛球4号": "CD84",
            "羽毛球5号": "CD85", "羽毛球7号": "CD86", "羽毛球8号": "CD87",
            "羽毛球9号": "CD88", "羽毛球10号": "CD89",
            **{"乒乓球" + str(i) + "号": f"CD{i+89}" for i in range(1, 29)}
        }
    }
    feicui_mapping = {
        '翡翠湖乒乓球1号': 'PP01', '翡翠湖乒乓球2号': 'PP02',
        '翡翠湖羽毛球1号': 'YM01', '翡翠湖羽毛球2号': 'YM02'
    }


    region_code = region_mapping.get(selected_region, '')
    #region_code = feicui_mapping.get(selected_region, '')

def update_region_combobox(*args):
    selected_site = site_combobox.get()
    if selected_site == '屯溪路乒羽中心':
        region_combobox['values'] = ['羽毛球2号', '羽毛球3号', '羽毛球4号', '羽毛球5号', '羽毛球7号', '羽毛球8号', '羽毛球9号', '羽毛球10号',*["乒乓球" + str(i) + "号" for i in range(1, 29)]]
    elif selected_site == '翡翠湖乒乓球':
        region_combobox['values'] = [f"翡翠湖乒乓球{i}号" for i in range(1, 11)]
    elif selected_site == '翡翠湖羽毛球':
        region_combobox['values'] = [f"翡翠湖羽毛球{i}号" for i in range(1, 7)]
    else:
        region_combobox['values'] = []


def format_month_day(num:str):
    """格式化月和日的输入，如果小于10则前面补0"""
    if len(num) == 1:
        return('0'+num)
    else:
        return(num)

def answer():
    print('常见问题：\n1.该场地已被禁用:现在周一周二周四只有12-13、18-21点可以预约,其他时间是8-21点可以预约\n2.你已经预约过该场地，无须重复预约:同一时间只能预约一个场地\n3.我还没想到')


class Redirector:
    def __init__(self, text_widget):
        self.text_widget = text_widget

    def write(self, message):
        self.text_widget.insert(tk.END, message)
        self.text_widget.see(tk.END)

    def flush(self):
        pass

def create_gui():
    global site_combobox, region_combobox, time_combobox, account_entry, password_entry, year_entry, month_entry, day_entry, phone_entry, submit_button, output_text

    root = tk.Tk()
    root.title("预约系统")
    root.geometry("600x400")  # 增加窗口宽度以容纳输出框

    # 账号输入部分
    tk.Label(root, text="账号:").grid(row=0, column=0, padx=2, pady=2, sticky='e')
    account_entry = tk.Entry(root)
    account_entry.grid(row=0, column=1, padx=2, pady=2)

    # 密码输入部分
    tk.Label(root, text="密码:").grid(row=1, column=0, padx=2, pady=2, sticky='e')
    password_entry = tk.Entry(root, show="*")
    password_entry.grid(row=1, column=1, padx=2, pady=2)

    login_button = tk.Button(root, text="登录", command=lambda: [set_account_password(), login()])
    login_button.grid(row=1, column=2, padx=2, pady=2)

    # 场馆选择部分
    tk.Label(root, text="选择场馆:").grid(row=2, column=0, padx=2, pady=2, sticky='e')
    site_combobox = ttk.Combobox(root, values=["屯溪路乒羽中心", "翡翠湖乒乓球", "翡翠湖羽毛球"])
    site_combobox.grid(row=2, column=1, padx=2, pady=2)
    site_combobox.bind("<<ComboboxSelected>>", update_region_combobox)

    # 区域选择部分
    tk.Label(root, text="选择区域:").grid(row=3, column=0, padx=2, pady=2, sticky='e')
    region_combobox = ttk.Combobox(root, values=[])
    region_combobox.grid(row=3, column=1, padx=2, pady=2)

    # 手机号输入部分
    tk.Label(root, text="填写手机号:").grid(row=4, column=0, padx=2, pady=2, sticky='e')
    phone_entry = tk.Entry(root)
    phone_entry.grid(row=4, column=1, padx=2, pady=2)

    # 时间选择部分
    tk.Label(root, text="选择开始时间:").grid(row=5, column=0, padx=2, pady=2, sticky='e')
    time_combobox = ttk.Combobox(root, values=[f"{hour}:00" for hour in range(8, 22)])
    time_combobox.grid(row=5, column=1, padx=2, pady=2)

    # 日期选择部分
    tk.Label(root, text="选择日期:").grid(row=6, column=0, padx=2, pady=2, sticky='e')

    # 年输入框
    year_entry = tk.Entry(root, width=5)
    year_entry.grid(row=6, column=1, padx=(2, 2), pady=2, sticky='w')
    tk.Label(root, text="年").grid(row=6, column=1, padx=(50, 2), pady=2, sticky='w')

    # 月输入框
    month_entry = tk.Entry(root, width=3)
    month_entry.grid(row=6, column=1, padx=(68, 2), pady=2, sticky='w')
    tk.Label(root, text="月").grid(row=6, column=1, padx=(102, 2), pady=2, sticky='w')

    # 日输入框
    day_entry = tk.Entry(root, width=3)
    day_entry.grid(row=6, column=1, padx=(125, 2), pady=2, sticky='w')
    tk.Label(root, text="日").grid(row=6, column=1, padx=(155, 2), pady=2, sticky='w')

    # 提交按钮
    submit_button = tk.Button(root, text="预约", command=validate_and_submit, state=tk.DISABLED)
    submit_button.grid(row=7, column=1, padx=2, pady=2)

    # 常见问题
    question = tk.Button(root, text="常见问题", command=answer)
    question.grid(row=8, column=2, padx=2, pady=2)

    # 输出框
    output_text = tk.Text(root, wrap='word', width=40, height=20)
    output_text.grid(row=0, column=3, rowspan=8, padx=10, pady=5)
    output_text.insert(tk.END, "使用步骤\n1.输入账号密码,然后点击登录\n2.如果提示登陆成功，可以选择场馆和区域，填写手机号，选择开始时间，预约时长默认1h,填写日期\n3.点击预约按钮，等待结果\n")  # 初始输出内容

    #built for
    tk.Label(root, text="for Ms.Wang").grid(row=9, column=5, padx=2, pady=2, sticky='e')
    # 重定向print输出到输出框
    sys.stdout = Redirector(output_text)

    root.mainloop()


create_gui()

