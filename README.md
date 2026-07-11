# Cloudflare Proxy

приложение которое поднимает локальный
SOCKS5-прокси через GitHub Actions и Cloudflare Quick Tunnel.

После подключения прокси доступен по умолчанию здесь:

```text
127.0.0.1:1081 socks5
```

## Видео для настройки 

https://youtu.be/6s2y27yczBg

## полезные сылки 

https://chromewebstore.google.com/detail/proxy-switchyomega-3-zero/pfnededegaaopdmhkdmcofjmoldfiped

https://www.proxifier.com/download/

## Проверка прокси

```powershell
curl.exe --socks5-hostname 127.0.0.1:1081 --max-time 20 -I https://www.cloudflare.com/
```

Ожидается HTTP `200`.

## Telegram
https://t.me/hidmyname

@oleg23585
