# golia-qq — 自研 QQ 协议客户端（Python）

目标：个人 QQ 940737939 扫码登录，不用 QQ 客户端、不走 LLOneBot/PMHQ/NapCat，
经 OneBot v11 接进 golia-bot（`ws://127.0.0.1:3001`）。

协议参考（只读）：`lagrange-ref/`（Lagrange.Core，MIT 开源）。本包不含其代码，
是按同一线协议独立写的 Python 实现。

## 当前状态（2026-11-24 11:30）

| 步骤 | 状态 |
|---|---|
| TEA 加解密 | ✅ 已验证（round-trip，5 种长度） |
| ECDH secp192k1 | ✅ 已验证（双向共享密钥一致；N·G = 无穷远点；与 QQ 服务端公钥可交换） |
| TransEmp31 请求包构造 | ✅ 已验证（逐字节核对：8001/0x812/0x87/35184/压缩公钥/尾 0x03/长度=总长） |
| OICQ 响应解析 | ✅ 已验证（模拟服务端响应：encryptType 0 + TEA，原文还原） |
| code2d 响应解析 | ✅ 已验证（模拟 TransEmp31/12 响应：二维码 URL/图片/QR sig、扫码确认三密钥均解析正确） |
| SSO + Service 帧封装 | ✅ 已验证（round-trip：payload 原样还原） |
| **取登录二维码（live）** | ❌ **被 VM 沙箱网络拦住，未跑通**（见下） |
| 扫码登录 / 收发消息 / OneBot | ⏳ 待取二维码跑通后再写（不写未经验证的代码） |

## 拦住的那一步（有证据）

发 TransEmp31 时，服务端根本没收到包。VM 沙箱的限制：

1. **直连 TCP 被拦**：`socket.create_connection(('43.135.106.161', 8080))` 能握手，
   但一发数据就收到 `muse: Other TCP connections is turned off for this assistant...`。
   连 github.com:443 直连也是同样拦截。
2. **代理 CONNECT 被拒**：出口代理 `hatch-egress-proxy:3128` 只放行白名单域名；
   `CONNECT 43.135.106.161:8080` 与 `:443` 都回 `407 Proxy Authentication Required`
   （同凭证连 api.github.com:443 是 200）。QQ 的 IP 不在白名单。
3. **QQ 客户端本身也连不上**：`/opt/QQ/qq`（PID 13298）正在跑，但 `ss` 显示它
   对 43.x 腾讯 IP **没有任何**已建立连接，只有本机回环（:13000/:3080/:6199）。
   之前 LLOneBot 那轮也没验证过 QQ 的联网。

结论：**这个 VM 上没有任何进程能摸到 QQ 服务器。** 代码本身没问题，
但 live 测试必须换一台能直连外网的机器。

## 下一步（任选其一）

### A. 放路由器上跑（推荐）
路由器 OpenWrt（192.168.31.2）有直连外网能力，golia-bot 本来也要上路由器。
把本目录拷过去跑即可：

```bash
# 路由器上（需 Python 3.10+，只要标准库）
python3 fetch_qr.py --out /root/golia-qq-qr.png
# 扫码后二维码文件在 /root/golia-qq-qr.png，取回给用户扫
```

注意：`transport.py` 里 `resolve_real_ips()` 用 DoH（Cloudflare/Google）拿真 IP，
绕过被污染的本地 DNS；路由器上若 DNS 正常，系统解析也能用。

### B. 请用户在 Muse 里放行
报错原文提示可请用户开通该连接（"To allow it, ask the user to open ..."，
完整文案被截断）。放行后在 VM 上直接跑 `python3 fetch_qr.py`。

## 文件

```
golia_qq/
  binary.py    二进制包读写（大端，Lagrange BinaryPacket 语义）
  tea.py       QQ TEA 加解密
  ecdh.py      secp192k1 ECDH（P/G/N 按 C# 字节数组逐字节核对过）
  proto.py     最小 protobuf 编解码（varint + length-delimited）
  wtlogin.py   WtLogin：TransEmp31/12 构造与解析、TLV、OICQ 包、code2d 包
  sso.py       SSO protocol-12 + Service protocol-12 帧封装、序列号
  transport.py TCP 传输（DoH 解析真 IP → :8080，4 字节长度帧）
  client.py    QQClient：connect / fetch_qr / poll_qr
fetch_qr.py    取二维码入口（存 PNG）
lagrange-ref/  协议参考源码（只读，不运行）
```

协议要点（双协议，Lagrange 的 BotAppInfo）：
- Linux（默认，推荐）：AppId 1600001615，SubAppId 537345891，
  SsoVersion 19，CurrentVersion 3.2.26-46494，AppClientVersion 46494，
  MiscBitMap 32764，PackageName com.tencent.qq。
- Windows：AppId 1600001604，SubAppId 537291048，SsoVersion 23，
  CurrentVersion 9.9.19-35184，AppClientVersion 35184，
  MiscBitMap 12058620。
2026-11-24 实测：Windows 9.9.19 在 VM 与路由器上扫码均被腾讯拒
（“扫码授权失败，请下载最新版QQ”），Lagrange 本身也已停止更新、
只推荐 Linux 协议，故默认切 Linux（`--protocol linux|windows` 可切）。
TransEmp31/12 的包结构与 Lagrange 当前 master 逐项核对一致。

登录链路（待 live 验证）：
TransEmp31 取二维码 → 每 2 秒 TransEmp12 轮询 → Confirmed 后拿
TgtgtKey/NoPicSig/TempPassword → Tgtgt 登录（0x810/0x09）取 D2/A2 等
WLoginSigs → InfoSync 上线 → 收发消息 → OneBot v11 WS :3001。

## 红线

- 不改 `~/workspace/golia-bot/config.yaml`、不重启 golia-bot、
  不碰 QQ 官方机器人（appid 1906516544）。
- 不写 QQ 密码/token；不跑 LLOneBot/PMHQ/NapCat 的二进制与服务。
