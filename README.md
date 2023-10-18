# volume-webhook-go-example
Volume Webhook consumer with signature verification in Golang

This example utilises the ```godotenv``` package to acess the *.env* file.   
To use it please install:   
```go get github.com/joho/godotenv```

Change the value of the PEM_URL in .env file to reflect the correct environment.   

SANDBOX: https://api.sandbox.volumepay.io/.well-known/signature/pem   
LIVE: https://api.volumepay.io/.well-known/signature/pem