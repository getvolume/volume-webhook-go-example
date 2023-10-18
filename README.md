# volume-webhook-go-example
Volume Webhook consumer with signature verification in Golang

This example utilises the ```godotenv``` package to acess the *.env* file.   
To use it please install:   
```go get github.com/joho/godotenv```

Change the value of the PEM_URL in .env file to reflect the correct environment.   

SANDBOX: https://api.sandbox.volumepay.io/.well-known/signature/pem   
LIVE: https://api.volumepay.io/.well-known/signature/pem



An example curl with a valid signature for integration env: 
```
curl --location --request PUT 'http://localhost:8080/webhook' \
--header 'Authorization: SHA256withRSA moZlAYs5TF/0ULF5H4hAQJbfGXQbgK7dEqgpPYbOnR0myHnLyeMGNSea3vNT9d5jiVQ326eWzzryKREvLqqIpvowhSjESfaQ0iBOAy31OZGrXooh/DQqfz3tI5Q/1JhQu3cpXjNVJyZ+2bZ63Ub+9dZucKjs5dcYmo6moB33uM+ErZtgix9q9brffNBIIjWMfH7+5wBuTdSysmbPjK6i9p8qJEoZtiJUVg3DGga/ykg5f/ncYCVBb+aNCDowLCb+UGwOtZHP7B8a+KkfHs6jcOvBqafy2TfZiRLVlILl0groyIxJAF3RHvk0F5F7H5Ziu6IHJHVIVsb/rnQ5MBfYpA==' \
--header 'Content-Type: application/json' \
--header 'Accept: application/json' \
--data-raw '{"paymentId":"4056d633-0d4c-4c11-aeb1-439022033d5a","merchantPaymentId":"3905","paymentStatus":"FAILED","errorDescription":null,"paymentRequest":{"amount":1900.25,"currency":"GBP","reference":"3905"},"paymentRefundData":null,"paymentMetadata":null}'
```