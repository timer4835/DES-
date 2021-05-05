# !/usr/bin/python3
# --coding:utf-8--
# des加密主文件
from DES_BOX import *
import re   #引入正则表达式               
import base64
import struct
import os


filepaths = []

#进行文件读写操作
def write_in_file(str_mess):
    try:
        f = open('DES.txt','w',encoding='utf-8')
        f.write(str_mess)
        f.close()
        print("字符串加密成功！")
    except IOError:
        print('字符串加解密出错！！！')

def read_out_file():
    try:
        f = open('DES.txt','r',encoding = 'utf-8')
        mess = f.read()
        f.close()
        print("字符串解密成功！")
        #print(mess)
        return mess
    except IOError:
        print('字符串加解密出错！！！')

def write_file(str,str_filename):
    try:
        f = open(str_filename,'w',encoding='utf-8')
        f.write(str)
        f.close
        print(str_filename+'文件写入成功！')
    except IOError:
        print(str_filename+'文件写入错误！')

def read_file(str_filename):
    try:
        f = open(str_filename,'r',encoding = 'utf-8')
        s = f.read()
        f.close
        print(str_filename+'文件读取成功！')
        #print('文件内容为：')
        #print(s)
        return s
    except IOError:
        print(str_filename+'文件读取错误！')


#进行文件夹递归读取

def all_files_path(rootDir):                    
    for root, dirs, files in os.walk(rootDir):           # walk方法返回一个三元组，分别代表根目录、文件夹、文件
        for file in files:                  # 遍历文件
            file_path = os.path.join(root, file)         # 拼接文件路径，用于获取文件绝对路径  
            filepaths.append(file_path)            # 将文件路径添加进列表
            #print(file_path)
        for dir in dirs[:-1]:                   # 遍历目录下的子目录
            dir_path = os.path.join(root, dir)                # 获取子目录路径
            all_files_path(dir_path)           # 递归调用

'''
def all_files_path(rootDir): 
    for root,dirs,files in os.walk(rootDir):
        for file in files:
            filepaths.append(os.path.join(root,file)+"\n")            # 将文件路径添加进列表
'''

#字符串转化为二进制
def str2bin(message):
    res = ""
    for i in message:  #对每个字符进行二进制转化
        tmp = bin(ord(i))[2:]  #字符转成ascii，再转成二进制，并去掉前面的0b，取0b后面的字符
        for j in range(0,8-len(tmp)):   #补齐8位，不足8位的字符数
            tmp = '0'+ tmp   #在前面补0
        res += tmp      #将转换成功的字符追加到res后面
    #print(res)
    return res


#二进制转化为字符串
def bin2str(bin_str):
    res = ""
    tmp = re.findall(r'.{8}',bin_str)  #先匹配8个任意字符，然后每8位为一个元组，最后返回一个元组列表
    for i in tmp:
        res += chr(int(i,2))  #先将字符串i转换为10进制，然后通过ord的逆函数chr将十进制数转换为unicode字符串形式，并追加到res中
    return res
    # print("未经过编码的加密结果:"+res)
    # print("经过base64编码:"+str(base64.b64encode(res.encode('utf-8')),'utf-8'))


#IP盒处理
def ip_change(bin_str):
    res = ""
    for i in IP_table:
        res += bin_str[i-1]     #数组下标i-1
    return res


#IP逆盒处理
def ip_re_change(bin_str):
    res = ""
    for i in IP_re_table:
        res += bin_str[i-1]
    return res

#E盒置换
def e_str(bin_str):
    res = ""
    for i in E:
        res += bin_str[i-1]
    return res


#字符串异或操作
def str_xor(my_str1,my_str2):  #str，key
    res = ""
    for i in range(0,len(my_str1)):     #根据位数进行循环异或
        xor_res = int(my_str1[i],10)^int(my_str2[i],10) #变成10进制是转化成字符串 2进制与10进制异或结果一样，都是1,0
        if xor_res == 1:
            res += '1'
        if xor_res == 0:
            res += '0'
    return res


#循环左移操作
def left_turn(my_str,num):
    left_res = my_str[num:len(my_str)]  #将最左边的num个字符移到右边          
    left_res =  left_res+my_str[0:num]
    return left_res


#秘钥的PC-1置换
def change_key1(my_key):
    res = ""
    for i in PC_1:  #PC_1盒上的元素表示位置    只循环64次
        res += my_key[i-1]     #将密钥按照PC_1的位置顺序排列，
    return res

#秘钥的PC-2置换
def change_key2(my_key):
    res  = ""
    for i in PC_2:
        res += my_key[i-1]
    return res


#S盒过程
def s_box(my_str):
    res = ""
    c = 0
    for i in range(0,len(my_str),6):    #步长为6，表示分6为一组
        now_str = my_str[i:i+6]    #第i个分组
        row = int(now_str[0]+now_str[5],2)   #b1b6 =r   第r行
        col = int(now_str[1:5],2)   #第c列
        #第几个s盒的第row*16+col个位置的元素
        num = bin(S[c][row*16 + col])[2:]   #c为第几个S盒，由于bin输出有可能不是4位str类型的值，所以才有下面的循环并且加上字符0，用于补足4位
        for g in range(0,4-len(num)):
            num = '0'+ num
        res += num
        c  += 1
    return res


#P盒置换
def p_box(bin_str):
    res = ""
    for i in  P:
        res += bin_str[i-1]
    return res



#f函数的实现
def fun_f(bin_str,key):
    first_output = e_str(bin_str)   #位选择函数将32位待加密str拓展位48位
    second_output = str_xor(first_output,key)  #将48位结果与子密钥Ki按位模2加    得到的结果分为8组（6*8）
    third_output = s_box(second_output)    #每组6位缩减位4位   S盒置换
    last_output = p_box(third_output)     #P盒换位处理  得到f函数的最终值
    return last_output



#生成16轮的密钥列表
def gen_key(key):
    key_list = []
    divide_output = change_key1(key)    #PC-1置换，取48位有效位
    key_C0 = divide_output[0:28]    #分为左28位和有28位，C0和D0
    key_D0 = divide_output[28:]
    for i in SHIFT:   #shift左移位数
        key_c = left_turn(key_C0,i)
        key_d = left_turn(key_D0,i)
        key_output = change_key2(key_c + key_d)     #PC-2置换，结果则为需要的密钥
        key_list.append(key_output)     #将密钥结果追加到列表中
    return key_list




def des_encrypt_one(bin_message,bin_key): #64位二进制加密的测试
    #bin_message = deal_mess(str2bin(message))
    mes_ip_bin = ip_change(bin_message)  #ip转换
    #bin_key = input_key_judge(str2bin(key))
    key_lst = gen_key(bin_key)   #生成子密钥
    mes_left = mes_ip_bin[0:32]
    mes_right = mes_ip_bin[32:]
    for i in range(0,15):
        mes_tmp = mes_right  #暂存右边32位
        f_result = fun_f(mes_tmp,key_lst[i])   #右32位与k的f函数值
        mes_right = str_xor(f_result,mes_left)  #f函数的结果与左边32位异或   作为下次右边32位
        mes_left = mes_tmp   #上一次的右边直接放到左边
    f_result = fun_f(mes_right,key_lst[15])  #第16次不用换位，故不用暂存右边
    mes_fin_left = str_xor(mes_left,f_result)
    mes_fin_right = mes_right
    fin_message = ip_re_change(mes_fin_left + mes_fin_right)   #ip的逆
    return fin_message   #返回单字符的加密结果

##64位二进制解密的测试,秘钥反过来
def des_decrypt_one(bin_mess,bin_key):
    mes_ip_bin = ip_change(bin_mess)
    #bin_key = input_key_judge(str2bin(key))
    key_lst = gen_key(bin_key)
    cipher_left = mes_ip_bin[0:32]
    cipher_right = mes_ip_bin[32:]
    lst = range(1,16)   #循环15次
    for i in lst[::-1]:   #表示逆转列表调用
        mes_tmp = cipher_right
        cipher_right = str_xor(cipher_left,fun_f(cipher_right,key_lst[i]))
        cipher_left = mes_tmp
    fin_left = str_xor(cipher_left,fun_f(cipher_right,key_lst[0]))
    fin_right = cipher_right
    fin_output  = fin_left + fin_right
    bin_plain = ip_re_change(fin_output)
    res = bin2str(bin_plain)
    return res


#简单判断以及处理信息分组
def deal_mess(bin_mess):
    """
    :param bin_mess: 二进制的信息流
    :return: 补充的64位信息流
    """
    ans = len(bin_mess)
    if ans % 64 != 0:
        for i in range( 64 - (ans%64)):           #不够64位补充0
            bin_mess += '0'
    return bin_mess


#查看秘钥是否为64位
def input_key_judge(bin_key):
    """
    全部秘钥以补0的方式实现长度不满足64位的
    :param bin_key:
    """
    ans = len(bin_key)
    if len(bin_key) < 64:
        if ans % 64 != 0:
            for i in range(64 - (ans % 64)):  # 不够64位补充0
                bin_key += '0' 
    return bin_key


def all_message_encrypt(message,key):
        bin_mess = deal_mess(str2bin(message)) #得到明文的二进制比特流  64的倍数
        res = ""
        bin_key = input_key_judge(str2bin(key))   #得到密钥得二进制比特流 64的倍数
        tmp = re.findall(r'.{64}',bin_mess)    #单词加密只能实现8个字符，匹配为每64一组的列表
        for i in tmp:
            res += des_encrypt_one(i,bin_key)  #将每个字符加密后的结果再连接起来
        return res



def all_message_decrypt(message,key):
    bin_mess = deal_mess(str2bin(message))
    res = ""
    bin_key = input_key_judge(str2bin(key))
    tmp = re.findall(r'.{64}',bin_mess)
    for i in tmp:
        res += des_decrypt_one(i,bin_key)
    return res



def file_message_encrypt(message,key):
        bin_mess = deal_mess(message) #得到明文的二进制比特流  64的倍数
        res = ""
        bin_key = input_key_judge(str2bin(key))   #得到密钥得二进制比特流 64的倍数
        tmp = re.findall(r'.{64}',bin_mess)    #单词加密只能实现8个字符，匹配为每64一组的列表
        for i in tmp:
            res += des_encrypt_one(i,bin_key)  #将每个字符加密后的结果再连接起来
        return res


def file_message_decrypt(message,key):
    bin_mess = deal_mess(message)
    res = ""
    bin_key = input_key_judge(str2bin(key))
    tmp = re.findall(r'.{64}',bin_mess)
    for i in tmp:
        res += des_decrypt_one(i,bin_key)
    return res

def get_mode():
    print("请输入序号，选择对应的功能：")
    print("1.使用DES加密字符串    2.使用DES解密字符串   3.使用DES加密文件   4.使用DES解密文件   5.使用DES加密文件夹    6.使用DES解密文件夹")   
    mode = input()
    if mode == '1':
        print("请输入要加密的信息，输入字符串不能为空：")
        message = input().replace(' ','')       #去掉空格
        print("请输入你的秘钥：")
        key = input().replace(' ','')
        s = all_message_encrypt(message,key)
        out_mess = bin2str(s)
        print("加密过后的内容:"+ out_mess)
        write_in_file(out_mess)         #将加密后的内容回写到文件中
        #print(type(out_mess))
        # base_out_mess = base64.b64encode(out_mess.encode('utf-8'))
        # print("Base64编码过后:"+ base_out_mess.decode())
    elif mode == '2':
        print("请输入你的秘钥：")
        key = input().replace(' ', '')
        message = read_out_file()       #从文件中读取要解密的内容
        s = all_message_decrypt(message, key)
        #out_mess = bin2str(s)
        print("解密后的信息："+ s)
    elif mode == '3':
        print('请输入要加密的文件名：')
        filename = input()
        #print(type(filename))
        print('请输入你的秘钥：')
        key = input().replace(' ','')
        #print(key)
        message = read_file(filename)
        #print(message[1:])
        #s = all_message_encrypt(message[1:],key) 
        s = all_message_encrypt(message,key)
        write_file(bin2str(s),filename)
        #print(bin2str('1111111011111111'))
    elif mode == '4':
        print('请输入要解密的文件名：')
        filename = input()
        print('请输入你的秘钥：')
        key = input().replace(' ','')
        s = all_message_decrypt(read_file(filename),key)
        write_file(s,filename)
    elif mode == '5':
        #filepaths = []              #初始化文件路径列表
        #filepaths.clear()           #清空文件列表
        print('请输入要加密的文件夹路径：')
        dir = input()
        all_files_path(dir)         #对文件夹路径下的文件进行读取
        #print('所有要加密的文件：')
        print('请输入你的密钥：')
        key = input().replace(' ','')
        #print(key)
        for file_name in filepaths:          #对文件进行循环加密
            message = read_file(file_name)
            #s = all_message_encrypt(message[1:],key) 
            s = all_message_encrypt(message,key)
            write_file(bin2str(s),file_name)
        #print(filepaths)
    elif mode == '6':
        #filepaths = []              #初始化文件路径列表
        filepaths.clear()           #清空文件列表
        #global filepaths
        #filepaths = []
        print('请输入要解密的文件夹路径：')
        dir = input()
        all_files_path(dir)         #对文件夹路径下的文件进行读取
        #print('所有要解密的文件：')
        print('请输入你的密钥：')
        key = input().replace(' ','')
        for file_name in filepaths:          #对文件进行循环解密
            s = all_message_decrypt(read_file(file_name),key)
            write_file(s,file_name)
        #print(filepaths)
    else:
        print("请重新输入！")



if __name__ == '__main__':
    while True:
        get_mode()
