# Agent key requests

Off by default. Set `BROKER_ALLOW_KEY_REQUESTS=1` on a broker process and
that agent gets one extra tool, `broker_request_credential`.

## What it does

- The agent supplies a lowercase credential name, a short reason (at most
  200 characters) and optionally a provider id from the broker's own table.
- The broker opens the key manager in the operator's browser, pre-filled
  with the name, the reason and, for a known provider, the address and key
  style. A banner says which agent asked and why.
- The tool result tells the agent only that a window opened. Nothing is
  added until the operator presses the button, and the operator chooses who
  may use the key.
- Requests are limited to one per credential per 10 minutes and five an
  hour per process. Each request writes a content-free `REQUEST_KEY` audit
  line.

## What the agent never gets

- The page address or its session token.
- Anything typed into the page.
- The key, in any form.
- A say in the base URL. Addresses and key styles come from the broker's
  provider table, never from the agent, so it cannot steer a key to a host
  of its choosing. An unknown provider leaves the address blank for the
  operator to fill in.

## What it trusts

- The operator reading the banner before pasting a key. The reason text is
  the agent's words, shown as plain text.
- The same loopback and token model as the key manager itself.
- The broker loads keys when it starts, so without hot reload the operator
  restarts the MCP client after saving.

## When to leave it off

Leave it off for any agent you would not want opening windows on your
machine. The brief for this project keeps it off for every real agent until
the operator decides otherwise.
