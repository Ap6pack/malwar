# Threat Research Automation Pipeline

Automated weekly threat intelligence discovery and publication system for OpenClaw/ClawHub supply-chain security.

## Overview

This pipeline:
1. **Scans weekly** for new/changed skills in ClawHub
2. **Detects novel threat campaigns** using pattern clustering
3. **Auto-generates research articles** from campaign data
4. **Sends responsible disclosure** to ClawHub (72-hour embargo)
5. **Publishes to blog** (canonical source)
6. **Notifies researchers** (Unit 42, Bitdefender, etc.)
7. **Posts to community** (Hacker News, Reddit, etc.)

**Result:** Original threat intelligence published first, beating other researchers.

## Architecture

```
Weekly Trigger (Monday 2am UTC)
    ↓
Scan ClawHub (incremental: only new/changed skills)
    ↓
Compare to previous snapshot
    ↓
Threat Pattern Detection (cluster by naming, rules, publisher)
    ↓
Identify Novel Campaigns (not in known campaigns DB)
    ↓
Generate Article (template + campaign data)
    ↓
Commit to Blog Repo
    ↓
Send Responsible Disclosure Email (72hr embargo)
    ↓
Create GitHub Issue (tracking + status)
    ↓
Notify Threat Researchers (email + social)
    ↓
Post to Hacker News (manual or automated)
    ↓
Track Platform Response & Remediation
```

## Setup Instructions

### 1. Configure Secrets (GitHub)

Add these secrets to your GitHub repository (`Settings > Secrets > Actions`):

#### Discord Webhook (for notifications)

```
DISCORD_WEBHOOK: https://discord.com/api/webhooks/[your-webhook-id]/[your-webhook-token]
```

To create a Discord webhook:
1. Open your Discord server
2. Right-click channel → "Edit Channel"
3. "Integrations" → "Webhooks" → "New Webhook"
4. Copy the webhook URL

#### Email Configuration (for disclosure & researcher outreach)

```
MAIL_SERVER: smtp.gmail.com  (or your mail provider)
MAIL_PORT: 587
MAIL_USER: contact@veritasandaequitas.com
MAIL_PASS: [your-app-password]
```

**For Gmail:**
1. Enable 2FA on your account
2. Generate an "App Password" (not your regular password)
3. Use the app password in MAIL_PASS

**For other providers (SendGrid, AWS SES, etc.):**
- SendGrid: `MAIL_SERVER=smtp.sendgrid.net`, port `587`, user `apikey`
- AWS SES: Configure via IAM credentials (see AWS docs)

### 2. Customize Researcher List

Edit `data/researchers.yml` to add/remove researchers:

```yaml
researchers:
  - name: "Your Researcher Name"
    email: "researcher@example.com"
    focus: "Supply chain security"
    reach: "High/Very High/Medium"
    notes: "Optional notes"
```

### 3. Set Disclosure Contact

The disclosure email is sent from `contact@veritasandaequitas.com`. Update this in:
- `.github/workflows/threat-research.yml` (line ~180)
- `scripts/article-generator.py` (default parameter)

### 4. Verify Blog Structure

Articles are auto-published to `docs/blog/_posts/YYYY-MM-DD-campaign-name.md`.

Ensure the folder exists:
```bash
mkdir -p docs/blog/_posts
```

## Running the Pipeline

### Automatic (Daily)
The workflow runs every day at 2am UTC automatically, checking for new/changed skills since the last run.

### Manual (On-demand)
To trigger manually:
```bash
gh workflow run threat-research.yml
```

Or use the GitHub web UI: "Actions" → "Weekly Threat Research & Intelligence" → "Run workflow"

## How It Works

### Campaign Detection

The threat detector groups new flagged skills by:
- **Naming pattern** (e.g., `oo-*`, `linkfox-*`, `tianapi-*`)
- **Publisher** (empty/suspicious publishers)
- **Rules triggered** (most common rule IDs)
- **Verdict distribution** (MALICIOUS vs SUSPICIOUS ratio)

A novel campaign is flagged if:
- It has 5+ skills following a new pattern
- The pattern doesn't exist in `data/campaigns.yml`
- It represents a coordinated attack (not random malicious skills)

### Article Generation

Articles are generated from a template using campaign data:
- Campaign name, pattern, skill count
- Verdict distribution and top rules
- Sample skills and examples
- Threat analysis and recommendations

Template: `scripts/article-generator.py`

### Responsible Disclosure

When a novel campaign is detected:
1. **Immediate:** Email sent to ClawHub security team with:
   - Campaign details
   - Full skill list
   - 72-hour embargo notice
   - Research publication timeline

2. **72 hours later:** If no response:
   - Blog article published
   - Email sent to threat researchers
   - GitHub issue created for tracking
   - Researchers notified via email

3. **Community:** After 72 hours:
   - Optional: Post to Hacker News
   - Optional: Share on Reddit/Twitter
   - Track platform response

### Database Management

`data/campaigns.yml` tracks known campaigns to avoid duplicate reports:

```yaml
campaigns:
  - name: "Campaign-OO-APITROJ"
    pattern: "oo-*"
    count: 242
    first_detected: "2026-07-16"
    published: true
    published_url: "..."
```

When a new scan runs, the detector compares patterns to this DB. If the pattern already exists, it's not re-reported.

## Monitoring

### Discord Notifications

You'll receive notifications at key steps:
1. **Detection Complete** - "Found X novel campaigns"
2. **Articles Published** - "Committed to blog"
3. **Disclosure Sent** - "Email sent to ClawHub (72hr embargo)"
4. **Completion** - Summary of all steps

### GitHub Issues

Each detection creates an issue for tracking:
- Campaign details
- Status checkboxes (publication, disclosure, researcher notification)
- Campaign data in JSON format
- Deadline for ClawHub response

### Logs

Detailed logs available in GitHub Actions:
- Threat detection output
- Article generation
- Git commits
- Email send results

## Customization

### Change Scan Schedule

Edit `.github/workflows/threat-research.yml`, line `~9`:

```yaml
schedule:
  - cron: "0 2 * * 1"  # Monday 2am UTC
  # Change to your preferred time:
  # "0 0 * * *" = Daily at midnight UTC
  # "0 10 * * 0" = Sunday at 10am UTC
```

[Cron syntax](https://crontab.guru/)

### Add Custom Rules to Detection

Edit `scripts/threat-detector.py`:
- `detect_naming_pattern()` - Add custom pattern recognition
- `is_novel_campaign()` - Customize novelty criteria (currently 5+ skills)

### Customize Email Templates

Edit `.github/workflows/threat-research.yml`, the `send-disclosure` step:
- Change email body
- Add/remove recipients
- Customize embargo window

## Troubleshooting

### Workflow doesn't run
- Check secrets are set: `Settings > Secrets > Actions`
- Check schedule syntax: https://crontab.guru
- Check branch is `main` or the configured default branch

### Emails not sending
- Verify `MAIL_SERVER`, `MAIL_PORT`, `MAIL_USER`, `MAIL_PASS` are correct
- For Gmail: ensure you're using an app password, not your regular password
- Check email logs in GitHub Actions workflow output

### Articles not publishing
- Ensure `docs/blog/_posts/` folder exists
- Check git config (user.name, user.email) in workflow
- Verify branch push permissions

### Discord notifications not arriving
- Verify `DISCORD_WEBHOOK` is correct
- Check Discord server webhook permissions
- Ensure webhook is not revoked

## Example Output

When a novel campaign is detected:

**Discord Notification:**
```
🚨 Novel Threat Campaign Detected
Found 1 novel threat campaigns
Articles published to blog and committed to repository
Responsible disclosure email sent to ClawHub
```

**GitHub Issue:**
```
🚨 Novel Threat Campaign: 1 Skills Detected

Campaign Detection Report
Detection Date: 2026-07-23
Novel Campaigns: 1

Status
- [ ] Blog articles published
- [ ] Responsible disclosure email sent
...
```

**Blog Article:**
Published to `docs/blog/_posts/2026-07-23-campaign-*.md`

**Email (ClawHub):**
```
[SECURITY] Novel Threat Campaign Detected - 72hr Disclosure Window

We have discovered a novel malware campaign in your marketplace...
[72 hours to respond before public disclosure]
```

## Next Steps

1. **Set up secrets** (Discord, email)
2. **Run manual test**: `gh workflow run threat-research.yml`
3. **Check results** in Discord and GitHub Issues
4. **Customize researchers list** (`data/researchers.yml`)
5. **Schedule goes live** next Monday at 2am UTC

---

**Questions?** Check GitHub Actions logs for detailed output.
