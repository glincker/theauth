---
"@glinr/theauth": minor
---

Add `vonageOtpSender` and `plivoOtpSender` next to `twilioOtpSender`. All SMS senders now time out after 10 seconds (`timeoutMs`) and their errors carry only the HTTP status and the vendor error code, no response body, so phone numbers and codes cannot reach logs.
