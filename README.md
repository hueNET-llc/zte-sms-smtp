# zte-sms-smtp #
An SMS SMTP relay for ZTE modems. Tested with a ZTE MF79U 4G USB modem.

Configuration is done via environment variables

## Environment Variables ##
```
LOG_LEVEL                       -   Logging verbosity (default: "20"), levels: 10 (debug) / 20 (info) / 30 (warning) / 40 (error) / 50 (critical)

MODEM_IP                        -   ZTE modem IP (i.e. "10.1.0.1") (str)
MODEM_PASSWORD                  -   ZTE modem web UI password (str)
MODEM_SMS_INBOX_FETCH_INTERVAL  -   ZTE modem SMS inbox fetch interval in seconds (int, optional, default: "30")
MODEM_DELETE_SMS                -   Delete SMS messages after reading to prevent the inbox from filling up (bool, optional, default: "True")

SMTP_HOST                       -   SMTP server address/IP (str)
SMTP_PORT                       -   SMTP server port (int, optional, default: "25")
SMTP_USERNAME                   -   SMTP login username (str, optional)
SMTP_PASSWORD                   -   SMTP login password (str, optional)
SMTP_TLS                        -   Use SMTP TLS (bool, optional, default: "False")
SMTP_SENDER                     -   SMTP sender address (str)
SMTP_RECIPIENTS                 -   SMTP recipient(s) list separated by commas or a single address (i.e. "test@mail.com,test2@mail.com" or "test@mail.com") (str)
SMTP_SUBJECT_PREFIX             -   Prefix text to the subject field (str, optional)
```

## blacklist.json ##
Used for blacklisting words/phrases and numbers using case-sensitive regex

Example:
```
{
    "words": ["meuplano\.tim\.com\.br"],
    "numbers": ["TIMInforma"]
}
```