from des_table import *


def hex_to_bin(hex_string):  # 输入格式化函数,hex_string:十六进制字符串，返回一个64位二进制字符串
    temp = bin(int(hex_string, 16))[2:]
    for i in range(64 - len(temp)):
        temp = '0' + temp
    return temp


def ip_replace(plain):  # ip置换函数，plain:输入字符串，返回一个字符串
    result = ""
    for i in IP_table:
        result += plain[i - 1]
    return result


def inv_ip_replace(plain):  # 逆ip置换函数，plain：字符串，返回一个字符串
    result = ""
    for i in inv_IP_table:
        result += plain[i - 1]
    return result


def left_shift(string, num):  # 循环左移函数,string：字符串，num：左移位数，返回一个字符串
    return string[num:] + string[:num]


def extend(right):  # E-盒置换，right：输入的（通常是右半部分）的字符串，返回一个字符串
    result = ""
    for i in E:
        result += right[i - 1]
    return result


def xor(a, b):  # 字符串异或函数，a,b:输入的字符串，返回一个字符串
    result = ""
    for i in range(len(a)):
        temp = int(a[i], 2) ^ int(b[i], 2)
        if temp == 1:
            result += '1'
        else:
            result += '0'
    return result


def s_box(string):  # S盒替换函数，string：输入的字符串，返回一个字符串
    result = ""
    c = 0
    for i in range(0, len(string), 6):
        new_string = string[i:i + 6]
        row = int(new_string[0] + new_string[5], 2)
        col = int(new_string[1:5], 2)
        num = bin(S[c][row][col])[2:]
        for j in range(4 - len(num)):  # 位数不足时补充
            num = '0' + num
        result += num
        c += 1
    return result


def p_box(string):  # p盒置换函数,string:输入的字符串，返回一个字符串
    result = ""
    for i in P:
        result += string[i - 1]
    return result


def f(right, key):  # f函数，right:输入的明文（通常是右半部分），key：轮密钥，返回一个字符串
    after_e = extend(right)
    after_xor = xor(after_e, key)
    after_s_box = s_box(after_xor)
    return p_box(after_s_box)


def change_key(key, mode):  # PC置换，key:密钥，mode:选择盒的种类，0代表PC-1,1代表PC-2,返回一个字符串
    result = ""
    for i in PC[mode]:
        result += key[i - 1]
    return result


def generate_key(key):  # 轮密钥生成函数，key:初始密钥，返回一组轮密钥
    result = []
    replacement = change_key(key, 0)
    c = replacement[:28]
    d = replacement[28:]
    for i in SHIFT:
        c = left_shift(c, i)
        d = left_shift(d, i)
        new_key = change_key(c + d, 1)
        result.append(new_key)

    return result


def des(input_text, key, is_encode=True):  # DES加解密函数，input_text:输入明（密）文，key:密钥，is_encode:是否为加密，返回密（明）文
    after_ip = ip_replace(input_text)
    left = after_ip[:32]
    right = after_ip[32:]
    key_list = generate_key(key)
    if not is_encode:
        key_list.reverse()
    for i in range(16):
        temp = right
        right = xor(f(right, key_list[i]), left)
        left = temp
    result = inv_ip_replace(right + left)
    return result


def main():
    plain = hex_to_bin('0123456789abcdef')
    key = hex_to_bin('1f1571c947d9e859')
    print(hex(int(des(plain, key), 2)))
    key = hex_to_bin('3abb72cbe0204027')
    plain = hex_to_bin('0000000000000000')
    print(hex(int(des(plain, key), 2)))
    key = hex_to_bin('bcca87bb9320ef40')
    cipher = hex_to_bin('0123456789abcdef')
    print(hex(int(des(cipher, key, False), 2)))
    key = hex_to_bin('da84835804145016b')
    cipher = hex_to_bin('72ae4683e14940cd')
    print(hex(int(des(cipher, key, False), 2)))


if __name__ == '__main__':
    main()
