# Usuage

Run `dotnet watch` in the `ROPC.Server` directory. Then run the following POST in Fiddler or your favorite web debugging proxy.

## POST

POST http://localhost:5000/connect/token HTTP/1.1
User-Agent: Fiddler
Host: localhost:5000
Content-Type: application/x-www-form-urlencoded
Content-Length: 63

grant_type=password&username=test@test.com&password=Testing123!