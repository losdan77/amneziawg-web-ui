# Service routing data

The `openai.txt`, `anthropic.txt`, `tiktok.txt` and `youtube.txt` files are
unmodified source lists from
[v2fly/domain-list-community](https://github.com/v2fly/domain-list-community),
commit `275abb3bfb908a7883f1e839a62424e6cd8cd184`, retrieved on 2026-10-20.
They are distributed under the MIT license reproduced in `LICENSE`.

- [OpenAI](https://github.com/v2fly/domain-list-community/blob/275abb3bfb908a7883f1e839a62424e6cd8cd184/data/openai)
- [Anthropic](https://github.com/v2fly/domain-list-community/blob/275abb3bfb908a7883f1e839a62424e6cd8cd184/data/anthropic)
- [TikTok](https://github.com/v2fly/domain-list-community/blob/275abb3bfb908a7883f1e839a62424e6cd8cd184/data/tiktok)
- [YouTube](https://github.com/v2fly/domain-list-community/blob/275abb3bfb908a7883f1e839a62424e6cd8cd184/data/youtube)

`strava.txt` is a locally maintained list reviewed on 2026-10-21. It covers
`strava.com` and its subdomains (including the API documented by
[Strava](https://developers.strava.com/docs/reference/)), plus the exact asset
hosts `d21y75miwcfqoq.cloudfront.net` and `d3nn82uaxijpm6.cloudfront.net`
referenced by the [official Strava homepage](https://www.strava.com/).
These are hostname rules, not provider IP ranges or a `cloudfront.net` wildcard.
Shared Google/Apple sign-in and unrelated third-party domains remain local.
Strava is opt-in; missing saved selections retain the original four services.

`service_domains.py` preserves suffix, exact-host and regex semantics. It omits
entries marked `@ads` and the distinct OpenAI-category products `sora.com` and
`crixet.com`. Selecting ChatGPT or Codex enables the same OpenAI domains because
both products use `chatgpt.com` and shared authentication/API hosts; domain
routing cannot distinguish encrypted URL paths on the same hostname.

The small exact-host authentication/static additions come from the official
[OpenAI network recommendations](https://help.openai.com/en/articles/9247338-network-recommendations-for-chatgpt-errors-on-web-and-apps).
Some authentication, challenge, attestation or voice hosts are shared with other
applications. Those particular hosts follow the selected service; entire Google,
Cloudflare, Azure, Apple and WorkOS domain trees or address ranges do not.

`chatgpt-voice.json` is the list of individual IPv4 addresses published by OpenAI
at https://openai.com/chatgpt-voice.json, retrieved on 2026-10-20. It is used only
with UDP destination port 3478 and only when ChatGPT is selected. STUN packets do
not contain a service hostname. The official network recommendations identify
this feed as the voice service's address source.

These snapshots are bundled for deterministic offline startup. They are not
silently downloaded or changed while generating a configuration. Updating the
catalog means reviewing a new upstream snapshot, preserving the license,
checking changes for broad shared-provider rules, updating the revision/date,
and running the catalog and routing tests.

The architecture was informed by [Karing's routing guide](https://karing.app/ru/tutorial/diversion)
and [DNS guide](https://karing.app/ru/app-manual/dns): a service rule set, DNS/FakeIP
association and connection sniffing, followed by a choice of outbound. Karing
itself uses a modified sing-box core. No Karing application source is copied.
