# !/use/bin/python3
# _*_ coding:utf-8 _*_
# __author__ : __ajiang__
# 2020/7/3
import hashlib
import json
import time
import requests
from flask import Flask, request, abort, render_template
import xmltodict

# 使用的测试号
WECHART_TOKEN = 'iscast'
WECHART_APPID = 'wx50c2069ecf6ed864'
WECHART_APPSECRET = 'c967f09d50b3c8c02caf90c591a02831'

app = Flask(__name__)


@app.route('/wechart8000', methods=['GET', 'POST'])
def wechart():
    """对接微信公众号服务"""
    # 对接微信服务器发送的参数
    signature = request.args.get('signature')
    timestamp = request.args.get('timestamp')
    nonce = request.args.get('nonce')

    # 校验参数
    if not all([signature, timestamp, nonce]):
        abort(400)

    # 按照微信流程进行签名
    li = [WECHART_TOKEN, timestamp, nonce]
    # 按照字典序排序
    li.sort()
    # 拼接字符串
    tmp_str = "".join(li)
    # 进行sha1加密
    sign = hashlib.sha1(tmp_str.encode('utf8')).hexdigest()
    # 将自己生成的签名与请求的签名对比，如果相同，则请求来自微信服务器
    if signature != sign:
        # 消息不是来自微信
        abort(403)
    else:
        # 表示是微信发送的请求
        if request.method == 'GET':
            # 'GET'请求表示第一次接入服务器的时候的验证请求
            echostr = request.args.get('echostr')
            if not echostr:
                abort(400)
            return echostr

        elif request.method == 'POST':
            # 表示微信服务器转发消息过来
            # 微信发送的数据是一个xml格式的数据
            try:
                xml_str = request.data
                if not xml_str:
                    abort(400)
                # 对xml 的数据进行解析
                xml_dict = xmltodict.parse(xml_str)
                xml_dict = xml_dict.get('xml')
                # 提取消息类型
                msg_type = xml_dict.get('MsgType')
                resp_dict = {
                    "xml": {
                        "ToUserName": xml_dict.get('FromUserName'),
                        "FromUserName": xml_dict.get('ToUserName'),
                        "CreateTime": int(time.time()),
                        "MsgType": 'text',
                        "Content": u'你好呀'
                    }
                }
                # 根据类型构造返回的消息
                if msg_type == 'text':
                    resp_dict = {
                        "xml": {
                            "ToUserName": xml_dict.get('FromUserName'),
                            "FromUserName": xml_dict.get('ToUserName'),
                            "CreateTime": int(time.time()),
                            "MsgType": 'text',
                            "Content": xml_dict.get('Content')
                        }
                    }
                elif msg_type == 'event':
                    if xml_dict.get('Event') == 'subscribe':
                        resp_dict = {
                            "xml": {
                                "ToUserName": xml_dict.get('FromUserName'),
                                "FromUserName": xml_dict.get('ToUserName'),
                                "CreateTime": int(time.time()),
                                "MsgType": 'text',
                                "Content": u'感谢关注'
                            }
                        }

                # 将字典转化成xml字符串
                resp_xml_str = xmltodict.unparse(resp_dict)
                # 将消息传给微信服务器
                return resp_xml_str
            except Exception as e:
                print(e)


@app.route('/wechart8000/index')
def index():
    # 从微信给传的数据里面拿数据
    # 1、获取code
    code = request.args.get('code')
    if not code:
        return u'缺少code参数'

    print(code, 'code')

    # 拼凑请求微信服务器的URL ,获取access_token
    url = 'https://api.weixin.qq.com/sns/oauth2/access_token?appid=%s&secret=%s&code=%s&grant_type=authorization_code' % \
          (WECHART_APPID, WECHART_APPSECRET, code)

    # 获取微信返回的数据
    response = requests.get(url)
    json_str = response.text
    print(json_str, 'json_str')
    resp_dict = json.loads(json_str)
    print(resp_dict, 'resp_dict')
    # 提取access_token
    if 'errcode' in resp_dict:
        return u'获取access_token失败'

    access_token = resp_dict.get('access_token')
    print(access_token, 'access_token')
    openid = resp_dict.get('openid')
    print(openid, 'openid')
    # 向微信服务器发送http请求，获取用户资料数据
    url = "https://api.weixin.qq.com/sns/userinfo?access_token=%s&openid=%s&lang=zh-CN" % (access_token, openid)

    # 获取微信返回的用户数据
    try:
        response = requests.get(url)
        response.encoding = 'UTF-8'
        json_str = response.text
        print(json_str, 'json_str')
        user_dict = json.loads(json_str)
        print(user_dict, 'user_dict')
        # 提取access_token
        if 'errcode' in user_dict:
            return u'获取用户信息失败'
        else:
            return render_template('index.html', user=user_dict)
    except Exception as e:
        print(e)
        return u'获取用户信息失败'


if __name__ == '__main__':
    app.run(port=8000, debug=True)
