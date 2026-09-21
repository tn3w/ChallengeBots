# ChallengeBots

Discord bot that makes new members solve an hCaptcha before they get a role,
keeping raids and scam bots out. Includes a web dashboard for server managers.

## How it works

1. A server manager creates a verification message with `/create role:@Verified`
   or in the dashboard (channel, role, embed title, text, color, footer).
2. A member clicks **Verify** and gets a personal link, valid for 20 minutes.
3. After solving the hCaptcha the bot assigns the role right away.

## Setup

1. Create a Discord application with a bot. Add `<BASE_URL>/auth` as OAuth2 redirect.
2. Create an [hCaptcha](https://www.hcaptcha.com/) site.
3. Configure and run:

```bash
cp .env.example .env    # fill in the values
pip install -r requirements.txt
python main.py
```

| Variable | Meaning |
| --- | --- |
| `DISCORD_TOKEN` | bot token |
| `CLIENT_ID`, `CLIENT_SECRET` | OAuth2 credentials for dashboard login |
| `SECRET_KEY` | session signing key, keep stable across restarts |
| `BASE_URL` | public URL used in verification links |
| `HOST`, `PORT` | web server bind address, default `0.0.0.0:5000` |
| `HCAPTCHA_SITE_KEY`, `HCAPTCHA_SITE_SECRET` | hCaptcha keys (test keys if unset) |

Run behind a reverse proxy with HTTPS in production. Data lives in `verification.db`.

## Permissions

- The bot needs **Manage Roles**, and its role must be above the verification role.
- `/create` and the dashboard require **Administrator** or **Manage Server**.

## Web routes

| Route | Purpose |
| --- | --- |
| `/` | landing page |
| `/dashboard[/<guild_id>]` | manage verification messages |
| `/verify#<verification_id>.<token>` | captcha page for members |
| `/api/user`, `/api/servers`, `/api/guild/<id>` | dashboard data |
| `POST /api/guild/<id>/verification` | create a message |
| `PUT`, `DELETE /api/guild/<id>/verification/<verification_id>` | edit or delete |
| `/api/verify-tokens`, `POST /api/complete-verification` | captcha flow |

## Development

```bash
npm install && npm run format    # prettier for templates
```

## License

[Apache-2.0](LICENSE)
