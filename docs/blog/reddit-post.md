# Reddit post — Vigil

## Title

I built an open-source, self-hosted SOC tool where the AI has to cite its evidence

## Body

Hey all, I just released Vigil, an open-source (Apache-2.0), self-hosted tool for cloud security monitoring.

It pulls audit logs from GCP, AWS, Azure, Datadog and New Relic, flags suspicious activity with plain rules, then has an AI agent investigate each incident. A human makes the final call.

The AI never gets your credentials, sensitive data is masked by default, and every verdict must cite events it actually retrieved or it's rejected. Works with local Ollama too.

It's pre-1.0, and only GCP is live-tested so far. Would love to hear what would stop you from using it.

https://github.com/OneLab-X/vigil

---

## Posting notes

- **Good fits:** r/selfhosted, r/devsecops, r/cybersecurity (use its self-promo thread) and r/googlecloud. Skip r/netsec, which doesn't allow product promotion.
- **Say it's your project**, and answer comments for the first couple of hours.
