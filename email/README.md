# Outbound email

Shared transport for existing Postbox HTTP delivery and Selectel SMTP. Templates,
recipient verification, preferences, queue storage and retry policy belong to
the consuming service. There are no automatic retries or provider failover.

```yaml
provider: selectel
selectel:
  username: "${SELECTEL_SMTP_USERNAME}"
  password: "${SELECTEL_SMTP_PASSWORD}"
```

The consuming config loader expands environment variables. Defaults are
`smtp.mail.selcloud.ru`, implicit TLS on port 1127 and a 10s total send timeout.
`tls_mode: starttls` selects required STARTTLS and defaults to port 1126. Explicit
host/port settings support tests and future deployment choices. Certificates
must verify against system roots; there is no insecure or plaintext option.
Selectel's [SMTP setup](https://docs.selectel.ru/email-service/configure-send-mail-via-ssmtp/)
documents AUTH LOGIN. Only Postbox and Selectel are selectable in this slice.

`provider: postbox` uses a nested `postbox` section with the existing Postbox
schema. Authenticated redirects are rejected. New transport configuration
requires an HTTPS endpoint without userinfo, query or fragment; this is also
validated when loading the legacy authn `email_otp.postbox` configuration. `postbox.Client.SendEmail` remains available;
`SendEmailWithReceipt` adds the optional provider-assigned message identifier.

Messages have one recipient, text/HTML alternatives, a subject of at most 256
bytes and a combined body limit of 1MiB. SMTP currently supports conventional
ASCII envelope addresses and Unicode display names/subjects/UTF-8 bodies.
Postbox uses its Simple API and supplies its own Message-ID. SMTP uses the
caller-supplied `Message.ID`, or generates one if omitted. IDs do not establish
idempotency at a mail provider or recipient.

`Receipt` means transport acceptance, not delivery to an inbox. `SendError`
exposes only a safe stage, numeric protocol status and outcome:

- `Rejected`: permanent rejection or invalid message/configuration.
- `Retryable`: no acceptance was established and a retry may be appropriate.
- `Unknown`: the message may have been accepted; another send can duplicate it.

Final SMTP DATA acceptance stays successful even if QUIT subsequently fails.
Reply bodies, passwords, recipient addresses and message contents are excluded
from error text. Resolve unknown outcomes through service policy rather than
blind failover. Real provider accounts, DNS verification, quotas and mailbox
delivery require a separate controlled integration pilot.
