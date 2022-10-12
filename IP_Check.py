import requests
from bs4 import BeautifulSoup
from jsonpath import jsonpath
from time import sleep
from prettytable import PrettyTable
import argparse
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def ip_shudi(ip):
    url = "https://www.ipshudi.com/" + ip + ".htm"
    web = requests.get(url)
    bs = BeautifulSoup(web.content, 'lxml')
    item = bs.find('tbody').find_all('span')
    info = []
    for i in item:
        info.append(i.text)
    return info


def ip_chinaz(ip):
    url = "https://ip.tool.chinaz.com/" + ip
    web = requests.get(url)
    bs = BeautifulSoup(web.content, 'lxml')
    item = bs.find('span', class_='Whwtdhalf w45-0 lh45').find('em').text
    item = item.split()
    info = []
    for i in item:
        info.append(i)
    return info


def ip_threatbook(ip):
    url = "https://api.threatbook.cn/v3/scene/ip_reputation"
    query = {
        "apikey": "",
        "resource": ip,
        "lang": "zh"
    }
    item = query.items()
    key, value = list(item)[0]
    if key == "apikey" and value != "":
        response = requests.request("GET", url, params=query)
        result = response.json()
        a2 = jsonpath(result, "$..severity")  # 严重级别
        a3 = jsonpath(result, "$..is_malicious")  # 是否恶意IP
        a4 = jsonpath(result, "$..confidence_level")  # 可信度
        a5 = ",".join(jsonpath(result, "$..judgments")[0])  # 威胁类型
        a6 = "-".join(jsonpath(result, "$..location.*")[0:3])  # IP归属地
        a7 = jsonpath(result, "$..update_time")  # 最近更新时间
        a8 = jsonpath(result, "$..scene")  # 应用场景
        info = [ip, *a2, *a3, *a4, a5, a6, *a7, *a8]
        return info
    else:
        print("未设置微步API，前往第38行设置API")


def domain_138(ip):
    try:
        headers = {
            'User-Agent': "Mozilla/5.0 (Windows NT 6.1; rv:2.0.1) Gecko/20100101 Firefox/4.0.1"
        }
        url = "https://ipchaxun.com/" + ip + "/"
        web = requests.post(url, headers=headers)
        bs = BeautifulSoup(web.content, 'lxml')
        try:
            item = bs.find('span', class_='date').find_next_sibling().text
        except:
            item = "暂无结果"
        return item
    except:
        item = 0
        return item


def ip_whois(domain):
    url = "https://api.devopsclub.cn/api/whoisquery"
    query = {
        "domain": domain,  # 你要查询域名
        "type": "json",  # 数据类型
        "standard": "true"
    }
    response = requests.request("POST", url, params=query, verify=False)
    result = response.json()
    a = jsonpath(result, "$..status")  # 返回状态
    a1 = jsonpath(result, "$...contactEmail")  # 联系邮箱
    a2 = jsonpath(result, "$...contactPhone")  # 联系电话
    a3 = jsonpath(result, "$...domainName")  # 域名
    a5 = jsonpath(result, "$...expirationTime")  # 过期时间
    a6 = jsonpath(result, "$...registrant")  # 联系人
    a7 = jsonpath(result, "$...registrar")  # 注册商
    a10 = jsonpath(result, "$...updatedDate")  # 更新时间
    info = [a3[0], a1[0], a2[0], a5[0], a6[0], a7[0], a10[0], a[0]]
    return info


def ip1_out_put(ip):
    x = PrettyTable()
    info = ip_shudi(ip)
    if len(info) == 1:
        x.title = 'IP属地 ipshudi.com'
        x.field_names = ["IP", "归属地"]
        x.add_row([ip, info[0]])
        print(x)
    elif len(info) == 2:
        x.title = 'IP属地 ipshudi.com'
        x.field_names = ["IP", "归属地", "运营商"]
        x.add_row([ip, info[0], info[1]])
        print(x)
    elif len(info) == 3:
        x.title = 'IP属地 ipshudi.com'
        x.field_names = ["IP", "归属地", "运营商", "网络类型"]
        x.add_row([ip, info[0], info[1], info[2]])
        print(x)
    sleep(1)


def ip2_out_put(ip):
    x = PrettyTable()
    info = ip_chinaz(ip)
    if len(info) == 1:
        x.title = '站长工具 chinaz.com'
        x.field_names = ["IP", "归属地"]
        x.add_row([ip, info[0]])
        print(x)
    elif len(info) == 2:
        x.title = '站长工具 chinaz.com'
        x.field_names = ["IP", "归属地", "运营商"]
        x.add_row([ip, info[0], info[1]])
        print(x)
    elif len(info) == 3:
        x.title = '站长工具 chinaz.com'
        x.field_names = ["IP", "归属地", "运营商", "网络类型"]
        x.add_row([ip, info[0], info[1], info[2]])
        print(x)
    sleep(1)


def domain_out_put(ip):
    if domain_138(ip) != 0:
        x = PrettyTable()
        info = domain_138(ip)
        x.title = '域名信息查询'
        x.field_names = ["IP", "历史绑定域名"]
        x.add_row([ip, info])
        print(x)
        sleep(1)
    else:
        print("域名查询失败")


def whois_out_put(ip):
    if domain_138(ip) != "暂无结果":
        x = PrettyTable()
        info = ip_whois(domain_138(ip))
        x.title = '域名WHOIS信息'
        x.field_names = ["域名", "联系邮箱", "联系电话", "过期时间", "联系人", "注册商", "更新时间"]
        x.add_row([info[0], info[1], info[2], info[3], info[4], info[5], info[6]])
        print(x)


def threatbook(ip):
    x = PrettyTable()
    info = ip_threatbook(ip)
    x.title = '微步情报'
    x.field_names = ["IP", "严重级别", "是否恶意IP", "可信度", "威胁类型", "ip归属地", "最近更新时间", "应用场景"]
    x.add_row([info[0], info[1], info[2], info[3], info[4], info[5], info[6], info[7]])
    print(x)
    sleep(1)


def out_put_csv():
    a = 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', metavar='target', help='查询单个IP', default='')
    parser.add_argument('-f', metavar='file', help='按文件查询多个IP', default='')
    parser.add_argument('-wb', help='使用微步查询,t使用 f不使用，默认f不使用', choices=['t', 'f'], default='f')
    parser.add_argument('-o', metavar='output', help='输出xls文件', default='')
    args = parser.parse_args()
    target = args.t
    file = args.f
    weibu = args.wb
    out_put = args.o
    if target != "" and file == "":
        if weibu == "t":
            ip1_out_put(target)
            ip2_out_put(target)
            threatbook(target)
            domain_out_put(target)
            whois_out_put(target)
        else:
            ip1_out_put(target)
            ip2_out_put(target)
            domain_out_put(target)
            whois_out_put(target)
    if file != "" and target == "":
        filename = file
        with open(filename) as f:
            for line in f:
                line = line.replace('\n', '')
                if weibu == "t":
                    ip1_out_put(line)
                    ip2_out_put(line)
                    threatbook(line)
                    domain_out_put(line)
                    whois_out_put(line)
                else:
                    ip1_out_put(line)
                    ip2_out_put(line)
                    domain_out_put(line)
                    whois_out_put(line)
                print('\n')
