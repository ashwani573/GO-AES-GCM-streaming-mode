# GO-AES-GCM-streaming-mode
WHY ?
Current Golang standard library does not support AES-GCM algorithm as streaming mode as openssl provides.
Calling openssl library function from Golang have CGO calls overhead and impact performance.
This library provide support of following algorithms:
AES-GCM, AES-CBC, AES-ECB, TDES-CBC and TDES-ECB
