# Mysite

毕业设计——网站前后端开发 <br>
指导老师：陈双平




# 功能

## Hash计算

* MD5
* SHA-1
* SHA-2-224
* SHA-2-256
* SHA-2-384
* SHA-2-512

## Hash查询（Reverse-Lookup）
前端&API 支持

## 编码/解码

### Base
* Base16
* Base32
* Base64
* Base85
<!-- -->
### Standard
* Hex
* URL
* Quoted-Printable
* HTML
* Punycode
<!-- -->
### Misc
* UUencode
* XXencode
* AAencode
* JJencode
* BubbleBabble
* JSFuck
* Brainfuck
* 社会主义核心价值观

## API
### Hash 计算
    Method: POST
    URI: /api/hash
    
    Parameters:
        hash_input
            type: str
            Note: 哈希计算的输入

        hash_action:
            type: str
            Note: 这个参数是固定的，值必须为：'Get Hash Result'

Testing (Windows Powershell) <br>

    $Uri = 'http://localhost:8888/api/hash'
    $Form = @{
    hash_input = 'asdf'
    hash_action = 'Get Hash Result'
    }
    $Resp = Invoke-WebRequest -Uri $Uri -Method Post -Body $Form
    $Resp.Content



### Hash 反查询
    Method: POST
    URI: /api/hash
    
    Parameters:
        hash_input
            type: str
            Note：哈希反查询的输入(Hex 格式)

        hash_action:
            type: str
            Note: 这个参数是固定的，值必须为：'Reverse Lookup'

Testing (Windows Powershell) <br>

    $Uri = 'http://localhost:8888/api/hash'
    $Form = @{
    hash_input = '912ec803b2ce49e4a541068d495ab570'
    hash_action = 'Reverse Lookup'
    }
    $Resp = Invoke-WebRequest -Uri $Uri -Method Post -Body $Form
    $Resp.Content

### 加解码
    Method: POST
    URI: /api/encode_decode
    
    Parameters:
        encode_decode_input
            type: str
            Note：加解码的输入

        encode_or_decode:
            type: str
            Note: 这个参数是固定的，值必须为：'Encode' 或 'Decode'

        encode_decode_algorithm:
            type: str
            Note: 加解码的算法，种类见上文

Testing (Windows Powershell) <br>

    $Uri = "http://localhost:8888/api/encode_decode"
    $Form = @{
    encode_decode_input = '912ec803b2ce49e4a541068d495ab570'
    encode_or_decode = 'Encode'
    encode_decode_algorithm = 'Base64'
    }
    $Resp = Invoke-WebRequest -Uri $Uri -Method Post -Body $Form
    $Resp.Content

### RSA 密钥对生成
    Method: GET
    URI: /api/gen_rsa_key
    
    Parameters:
        None

Testing (Windows Powershell) <br>

    $Uri = "http://localhost:8888/api/gen_rsa_key"
    $Resp = Invoke-WebRequest -Uri $Uri -Method Get
    $Resp.Content

### 域名反查
    Method: POST
    URI: /api/ip_lookup
    
    Parameters:
        ip
            type: str
            Note: 要查询的IP

Testing (Windows Powershell) <br>

    $Uri = "http://localhost:8888/api/ip_lookup"
    $Form = @{
    ip = '220.181.38.148'
    }
    $Resp = Invoke-WebRequest -Uri $Uri -Method Post -Body $Form
    $Resp.Content

### 代理服务
    Method: GET/POST
    URI: /proxy/<URL>
    
    Parameters:
        The parameters you want to send to the target URL

# 组件

## 后端

Django + SQLite/MariaDB

## 前端

HTML+Javascript+CSS  
采用Bootstrap框架 https://getbootstrap.com/  
主题：Pixel https://appseed.us/django/django-pixel-bootstrap-uikit

# TODO
- [x] 解耦
- [ ] ~~API文档（前端）~~
- [ ] 前端美化
- [x] 大素数生成
- [x] 域名反查
- [x] 代理服务

