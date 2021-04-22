from des_table import *


def hex_to_bin(hex_string):  # 输入格式化函数,hex_string:十六进制字符串，返回一个64位二进制字符串
    temp = bin(int(hex_string, 16))[2:]
    for i in range(64 - len(temp)):
        temp = '0' + temp
    return temp


def loop_str(string, times=14):  # 字符串生成函数，string:重复单元，times：重复次数，返回一个字符串
    result = ''
    for i in range(times):
        result += string
    return result


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


# 逆PC-1置换，key：PC-1后密钥，dic:逆PC字典，reverse:是否反校验位，返回逆PC后结果
def inv_change_key(key, dic, reverse=False):
    result = ''
    flag = 0
    for j in range(64):
        if (j + 1) % 8 == 0 and j != 0:  # 校验位判定
            if flag % 2 == 1:
                result += '1' if reverse else '0'
            else:
                result += '0' if reverse else '1'
            flag = 0
        else:
            result += key[dic[j + 1]]
            if key[dic[j + 1]] == '1':
                flag += 1
    result = "{:016X}".format(int(result, 2))
    print(result)
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


def inv_PCs():  # 逆PC-1字典生成函数
    result = {}
    for i in range(0, 56):
        result[PC[0][i]] = i
    return result


def weak_key(inv_dict):  # 弱密钥生成函数，inv_dict:逆PC-1字典，返回一组弱密钥
    result = []
    c = []
    d = []
    for i in range(2):
        c.append(loop_str(str(i), 28))
        d.append(loop_str(str(i), 28))
    for c_key in c:
        for d_key in d:
            result.append(inv_change_key(c_key + d_key, inv_dict))
            result.append(inv_change_key(c_key + d_key, inv_dict, True))
    return result


def half_weak_key(inv_dict):  # 半弱密钥生成函数，inv_dict:逆PC-1字典，返回成对的半弱密钥
    result = []
    c = []
    d = []
    for i in range(4):
        c.append(loop_str('{:02b}'.format(i)))
        d.append(loop_str('{:02b}'.format(i)))
    pair = {c[0]: c[0], c[1]: c[2], c[2]: c[1], c[3]: c[3]}
    for i in range(4):
        for j in range(4):
            if i == 2:  # 删去重复以及弱密钥
                continue
            elif (i == 0 and j == 0) or (i == 0 and j == 3) or (i == 3 and j == 0) or (i == 3 and j == 3):
                continue
            elif (i == 0 and j == 2) or (i == 3 and j == 2):
                continue
            else:
                a = inv_change_key(c[i] + d[j], inv_dict)
                b = inv_change_key(pair[c[i]] + pair[d[j]], inv_dict)
                result.append([a, b])
    return result


def main():

    PC_inv = inv_PCs()
    print("weak key")
    wk = weak_key(PC_inv)
    print("half_weak_key")
    hwk = half_weak_key(PC_inv)
    plain = hex_to_bin('02468aceeca86420')
    print("weak key test")
    for key in wk:
        temp_key = hex_to_bin(key)
        print(key+"加密："+'{:016X}'.format(int(des(plain, temp_key), 2)))
        print(key+"自加密验证：" +
              '{:016X}'.format(int(des(des(plain, temp_key), temp_key), 2)))
    print("half weak key test")
    for i in range(6):
        temp_a = hex_to_bin(hwk[i][0])
        temp_b = hex_to_bin(hwk[i][1])
        print(hwk[i][0]+"加密："+hex(int(des(plain, temp_a), 2)))
        print(hwk[i][1]+"加密验证："+hex(int(des(des(plain, temp_a), temp_b), 2)))


if __name__ == '__main__':
    main()
