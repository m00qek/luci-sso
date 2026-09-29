```bash
uclient-fetch -q -O - --no-check-certificate 'https://127.0.0.1/cgi-bin/luci-sso?action=enabled'
# Expected: {"enabled": true}
```

`{"enabled": false}` means SSO is turned off. An HTTP 500 error instead of JSON means SSO is turned on but the configuration was rejected; the log line `Configuration rejected: …` before `[500] CONFIG_ERROR` names the option.
