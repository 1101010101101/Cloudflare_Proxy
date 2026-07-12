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

стати если будите использовать proxifier там при какихто случаях придётся перезагружать приложение которым вы пользуесесь чтобы получить доступ в интернет на нём 
и осторожней с proxifier там гит хаб закроет акшионс через 6 чисов после его создания корче если у вас совсем попал инет лучше закрыть proxifier он находится в тре

## Проверка прокси

```powershell
curl.exe --socks5-hostname 127.0.0.1:1081 --max-time 20 -I https://www.cloudflare.com/
```

Ожидается HTTP `200`.

## Telegram
https://t.me/hidmyname

@oleg23585
