# Hot reload

Off by default. Set `BROKER_HOT_RELOAD=1` on a broker process and it picks
up key manager changes without a restart.

## What it does

- The key manager writes a small marker file (`.broker-reload` beside the
  policy, or `BROKER_RELOAD_MARKER`) after every change it makes: a new or
  replaced key, a new API, a changed grant, an import.
- A broker with hot reload on compares the marker before each request. When
  it changed, the broker reloads the policy and rebuilds its secrets for its
  own identity only.
- A reload that fails (invalid policy, or a policy that no longer lists the
  broker's identity) keeps the previous working state and writes a `RELOAD`
  audit line saying so. The broker is never left half loaded.
- The same marker value is never retried in a loop. The next change gets a
  new marker and a new attempt.

## What it trusts

- Whoever can write the policy folder. That is exactly the trust the broker
  places in the policy file at start-up, so hot reload adds no new party.
- It cannot change which agent the process is. `BROKER_AGENT_ID` is fixed
  at launch.
- Credential values that came from the environment are kept in memory from
  the first load, because the broker scrubs them from `process.env` after
  reading them. A reload reuses those values; it cannot read fresh
  environment variables.

## The pause switch is separate

The pause switch is always live and needs no reload. Hot reload only
affects the policy and secrets.

## When to leave it off

Leave it off when the policy folder is shared with anything you do not
fully trust, or when you prefer that every policy change goes through a
deliberate restart. Without it, restart the MCP client after saving a key.
