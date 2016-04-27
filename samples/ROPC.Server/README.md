# Usuage

Run `dotnet watch` in the `ROPC.Server` directory. Then make the following request your favorite web debugging proxy (e.g. Fiddler / Postman.)

## Request

```
POST http://localhost:5000/connect/token HTTP/1.1
User-Agent: Fiddler
Host: localhost:5000
Content-Type: application/x-www-form-urlencoded
Content-Length: 63

grant_type=password&username=test@test.com&password=Testing123!

```

## Response

```
HTTP/1.1 200 OK
Cache-Control: no-cache
Date: Wed, 27 Apr 2016 01:29:36 GMT
Pragma: no-cache
Content-Length: 863
Content-Type: application/json;charset=UTF-8
Expires: -1
Server: Kestrel

{"token_type":"Bearer","access_token":"eyJhbGciOiJSUzI1NiIsImtpZCI6IjNEVVlEU05MTEw5LVRIODBLQk9NSC1VWU84QU1aTllfT0FETkJNSVAiLCJ0eXAiOiJKV1QifQ.eyJBc3BOZXQuSWRlbnRpdHkuU2VjdXJpdHlTdGFtcCI6ImNjY2EwMmYxLTg5OWQtNDY0MC04NTQxLTFhMDk2ZjA3MDZjYyIsImp0aSI6IjE5N2VlNTkxLWNmM2YtNDJmOC05YTBiLWU0MDc5ZjQ1ZTBmMSIsInVzYWdlIjoiYWNjZXNzX3Rva2VuIiwic3ViIjoiZjFhY2U2NzMtNWI0Ni00MDY2LTk3Y2EtYTg3ODVjOGQ4N2I1IiwibmJmIjoxNDYxNzIwNTc3LCJleHAiOjE0NjE3MjQxNzcsImlhdCI6MTQ2MTcyMDU3NywiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo1MDAwLyJ9.z_XdrvGWSj71DutdeFDaq-GtL-aOCT1otOk-YgWwymmXEB6O4MqKkVxlFS7Ux_BD31xQR5Ge84y-sniwbn4s16oOe5VT1g7uqRvSzXYKiCYo40SOJ6gVemkJDru6tDfxbTCwEuBxLH_mC-6jNBH4vdEXhbz-ZCcb9PS_Z3xQgazBYC4blx8EE5SUaYLD4uT5g5YFpfcuGl7r5V2LOp1LxzIl_yAi-weeZsKdfzMHcDM3_xszhYQCaMedS8ld9icBzhMS5Nr5zoRZzrhejz7_XsWZW2QiOmJStUO_FL1ki-GpLlfiKrSWKREMKndtCRCrt3jJscpmahluEEP8_UHaAg","expires_in":"3600"}

```