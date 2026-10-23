#!/usr/bin/env python3
"""
wirewatch intel: geolocation, network owner (ASN) and website categories.

* Downloads DB-IP Lite country and ASN databases (CC BY 4.0, monthly) and
  optionally the city database, into /var/lib/wirewatch/intel.db.
* Downloads UT1 category lists (CC BY-SA 4.0, weekly).
* Every minute, looks up every new IP seen by the collector and categorizes
  every new hostname (DNS, TLS SNI, HTTP Host).

Standard library only.
"""
import csv
import gzip
import io
import ipaddress
import os
import re
import signal
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from datetime import date, timedelta

DB_PATH = os.environ.get("WW_DB", "/var/lib/wirewatch/wirewatch.db")
INTEL_DB = os.environ.get("WW_INTEL_DB", "/var/lib/wirewatch/intel.db")
GEO_DETAIL = os.environ.get("WW_GEO_DETAIL", "country")          # country | city
UT1_BASE = os.environ.get("WW_UT1_BASE", "https://raw.githubusercontent.com/olbat/ut1-blacklists/master/blacklists")
UT1_LISTS = [c.strip() for c in os.environ.get("WW_CATEGORY_LISTS",
    "adult,mixed_adult,audio-video,radio,social_networks,chat,dating,gambling,games,shopping,press,webmail,"
    "vpn,residential-proxies,doh,dynamic-dns,remote-control,filehosting,download,malware,phishing,"
    "cryptojacking,bitcoin,publicite,shortener,jobsearch,sports,bank,financial,update,ai,hacking,warez,"
    "stalkerware,drogue,celebrity,manga,blog,forums,ddos").split(",") if c.strip()]
OVERRIDES = os.environ.get("WW_CATEGORY_OVERRIDES", "/etc/wirewatch/categories.conf")
UT1_REFRESH_DAYS = int(os.environ.get("WW_UT1_REFRESH_DAYS", "7"))
ENRICH_SECONDS = int(os.environ.get("WW_INTEL_INTERVAL", "60"))
DBIP_BASE = os.environ.get("WW_DBIP_BASE", "https://download.db-ip.com/free").rstrip("/")
UA = "wirewatch/1.0 (+https://db-ip.com attribution)"

# UT1 list -> category shown in the dashboard
UT1_CATEGORY = {
    "adult": "Adult", "mixed_adult": "Adult", "audio-video": "Streaming & entertainment",
    "radio": "Streaming & entertainment", "celebrity": "Streaming & entertainment", "manga": "Streaming & entertainment",
    "social_networks": "Social media", "chat": "Chat & messaging", "dating": "Dating", "gambling": "Gambling",
    "games": "Gaming", "shopping": "Shopping", "press": "News", "webmail": "Webmail", "vpn": "VPN & proxy",
    "residential-proxies": "VPN & proxy", "doh": "Encrypted DNS", "dynamic-dns": "Dynamic DNS",
    "remote-control": "Remote access", "filehosting": "File sharing", "download": "Downloads",
    "malware": "Malware & phishing", "phishing": "Malware & phishing", "cryptojacking": "Crypto mining",
    "bitcoin": "Crypto mining", "publicite": "Advertising & tracking", "shortener": "URL shortener",
    "jobsearch": "Job search", "sports": "Sports", "bank": "Finance & banking", "financial": "Finance & banking",
    "update": "Software updates", "ai": "AI", "hacking": "Hacking", "warez": "Piracy", "stalkerware": "Stalkerware",
    "drogue": "Drugs", "blog": "Blogs & forums", "forums": "Blogs & forums", "ddos": "Hacking",
}
# when a domain is in several UT1 lists, the riskier one wins
UT1_PRIORITY = ["malware", "phishing", "cryptojacking", "stalkerware", "ddos", "hacking", "adult", "mixed_adult",
                "gambling", "drogue", "warez", "dating", "residential-proxies", "vpn", "remote-control", "doh"]

# Curated rules. These beat UT1 because UT1 has no categories for business services, CDNs or telemetry.
BUILTIN = """
Social media: tiktok.com tiktokv.com tiktokcdn.com tiktokcdn-us.com tiktokcdn-eu.com tiktokv.us tiktokw.us tiktok.us
  ttwstatic.com ttlivecdn.com byteoversea.com byteoversea.net ibytedtos.com ibyteimg.com bytedance.com bytedance.net
  muscdn.com musical.ly capcut.com facebook.com facebook.net fbcdn.net fbsbx.com fb.com instagram.com cdninstagram.com
  threads.net threads.com snapchat.com snap.com sc-cdn.net snapkit.com snap-dev.net x.com twitter.com twimg.com t.co
  linkedin.com licdn.com pinterest.com pinimg.com reddit.com redd.it redditmedia.com redditstatic.com tumblr.com
  bsky.app bsky.network nextdoor.com truthsocial.com
Chat & messaging: whatsapp.com whatsapp.net discord.com discord.gg discordapp.com discordapp.net discord.media
  telegram.org t.me signal.org messenger.com wechat.com weixin.qq.com line.me viber.com kik.com
Streaming & entertainment: netflix.com nflxvideo.net nflximg.net nflxext.com nflxso.net youtube.com googlevideo.com
  ytimg.com youtu.be youtube-nocookie.com hulu.com hulustream.com disneyplus.com disney-plus.net dssott.com bamgrid.com
  max.com hbomax.com hbo.com primevideo.com aiv-cdn.net aiv-delivery.net pv-cdn.net twitch.tv ttvnw.net jtvnw.net
  spotify.com scdn.co spotifycdn.com pandora.com soundcloud.com sndcdn.com peacocktv.com paramountplus.com cbsivideo.com
  pluto.tv tubi.tv tubitv.com roku.com crunchyroll.com vimeo.com vimeocdn.com iheart.com siriusxm.com music.apple.com
  tv.apple.com kick.com rumble.com dailymotion.com
Gaming: steampowered.com steamcommunity.com steamstatic.com steamcontent.com epicgames.com epicgames.dev
  unrealengine.com xboxlive.com xbox.com playstation.com playstation.net sonyentertainmentnetwork.com nintendo.com
  nintendo.net riotgames.com leagueoflegends.com roblox.com rbxcdn.com ea.com origin.com blizzard.com battle.net
  minecraft.net mojang.com supercell.com
Productivity & collaboration: office.com office.net office365.com microsoft365.com sharepoint.com onedrive.com
  onedrive.live.com outlook.com outlook.office.com outlook.office365.com teams.microsoft.com teams.cdn.office.net
  skype.com lync.com onenote.com zoom.us zoom.com zoomgov.com slack.com slack-edge.com slack-msgs.com webex.com
  gotomeeting.com goto.com dropbox.com dropboxapi.com box.com boxcdn.net docusign.com docusign.net adobe.com
  adobesign.com atlassian.com atlassian.net notion.so monday.com asana.com trello.com smartsheet.com
  workspace.google.com docs.google.com drive.google.com meet.google.com mail.google.com calendar.google.com
Microsoft services: microsoft.com microsoftonline.com msftauth.net msauth.net msftidentity.com live.com live.net
  windows.net windows.com azure.com azureedge.net azurefd.net msecnd.net msedge.net bing.com bing.net
  msn.com aka.ms dynamics.com businesscentral.dynamics.com powerapps.com powerbi.com intune.microsoft.com
  manage.microsoft.com microsoftaffiliates.com msidentity.com microsoftazuread-sso.com
Apple services: apple.com icloud.com icloud-content.com mzstatic.com apple-dns.net aaplimg.com cdn-apple.com
  apple-cloudkit.com push.apple.com itunes.apple.com appleid.apple.com
Google services: google.com googleapis.com gstatic.com gvt1.com gvt2.com googleusercontent.com ggpht.com
  android.com withgoogle.com
Cloud & CDN: akamai.net akamaiedge.net akamaihd.net akamaized.net akamaitechnologies.com edgekey.net edgesuite.net
  cloudfront.net amazonaws.com awsstatic.com aws.amazon.com fastly.net fastlylb.net fastly-edge.com cloudflare.com
  cloudflare.net cloudflare-dns.com cdn77.org llnwd.net lldns.net edgecastcdn.net azureedge.net b-cdn.net jsdelivr.net
  unpkg.com cdnjs.cloudflare.com digitaloceanspaces.com linode.com akamai.com
Advertising & tracking: doubleclick.net googleadservices.com googlesyndication.com google-analytics.com
  googletagmanager.com googletagservices.com adnxs.com adsrvr.org criteo.com criteo.net taboola.com outbrain.com
  scorecardresearch.com quantserve.com amazon-adsystem.com ads.linkedin.com analytics.tiktok.com pubmatic.com
  rubiconproject.com openx.net casalemedia.com moatads.com adsafeprotected.com doubleverify.com hotjar.com
  segment.io segment.com mixpanel.com amplitude.com branch.io appsflyer.com adjust.com app-measurement.com
  crashlytics.com
Telemetry & diagnostics: events.data.microsoft.com vortex.data.microsoft.com telemetry.microsoft.com
  watson.telemetry.microsoft.com metrics.icloud.com xp.apple.com sentry.io newrelic.com nr-data.net datadoghq.com
  browser-intake-datadoghq.com
Software updates: windowsupdate.com update.microsoft.com delivery.mp.microsoft.com dl.delivery.mp.microsoft.com
  swcdn.apple.com swdist.apple.com mesu.apple.com updates.cdn-apple.com gs.apple.com ubuntu.com canonical.com
  snapcraft.io debian.org raspberrypi.com raspberrypi.org dl.google.com update.googleapis.com mozilla.net
  download.mozilla.org adobe.io jamfcloud.com
Security: crowdstrike.com sentinelone.net sentinelone.com defender.microsoft.com wdcp.microsoft.com
  smartscreen.microsoft.com smartscreen-prod.microsoft.com sophos.com sophosxl.net mimecast.com proofpoint.com
  pphosted.com umbrella.com opendns.com zscaler.net zscaler.com malwarebytes.com eset.com kaspersky.com
  ocsp.digicert.com digicert.com letsencrypt.org lencr.org sectigo.com globalsign.com godaddy.com
  ocsp.apple.com ocsp2.apple.com valid.apple.com ocsp.pki.goog pki.goog
Search: duckduckgo.com search.yahoo.com yahoo.com ecosia.org search.brave.com
AI: openai.com chatgpt.com oaiusercontent.com oaistatic.com anthropic.com claude.ai claude.com gemini.google.com
  bard.google.com perplexity.ai copilot.microsoft.com character.ai midjourney.com huggingface.co
Shopping: amazon.com media-amazon.com ssl-images-amazon.com ebay.com ebayimg.com walmart.com walmartimages.com
  target.com etsy.com etsystatic.com temu.com kwcdn.com shein.com ltwebstatic.com aliexpress.com alicdn.com
  wish.com bestbuy.com homedepot.com lowes.com costco.com
News: cnn.com foxnews.com nytimes.com nyt.com washingtonpost.com wsj.com bbc.com bbc.co.uk reuters.com apnews.com
  nbcnews.com cbsnews.com abcnews.go.com npr.org usatoday.com bloomberg.com nola.com theadvocate.com wwltv.com
Finance & banking: paypal.com paypalobjects.com venmo.com chase.com bankofamerica.com wellsfargo.com capitalone.com
  americanexpress.com discover.com fidelity.com schwab.com vanguard.com coinbase.com robinhood.com intuit.com
  quickbooks.intuit.com
VPN & proxy: nordvpn.com expressvpn.com surfshark.com protonvpn.com privateinternetaccess.com tunnelbear.com
  windscribe.com hola.org psiphon.ca tailscale.com tailscale.io zerotier.com
Remote access: teamviewer.com anydesk.com logmein.com logmeininc.com screenconnect.com connectwise.com splashtop.com
  remotedesktop.google.com rustdesk.com
"""

CC = """AD:Andorra:EU|AE:United Arab Emirates:AS|AF:Afghanistan:AS|AG:Antigua and Barbuda:NA|AI:Anguilla:NA|AL:Albania:EU|AM:Armenia:AS|AO:Angola:AF|AQ:Antarctica:AN|AR:Argentina:SA|AS:American Samoa:OC|AT:Austria:EU|AU:Australia:OC|AW:Aruba:NA|AX:Åland Islands:EU|AZ:Azerbaijan:AS|BA:Bosnia and Herzegovina:EU|BB:Barbados:NA|BD:Bangladesh:AS|BE:Belgium:EU|BF:Burkina Faso:AF|BG:Bulgaria:EU|BH:Bahrain:AS|BI:Burundi:AF|BJ:Benin:AF|BL:Saint Barthélemy:NA|BM:Bermuda:NA|BN:Brunei:AS|BO:Bolivia:SA|BQ:Bonaire, Sint Eustatius and Saba:NA|BR:Brazil:SA|BS:Bahamas:NA|BT:Bhutan:AS|BV:Bouvet Island:AN|BW:Botswana:AF|BY:Belarus:EU|BZ:Belize:NA|CA:Canada:NA|CC:Cocos (Keeling) Islands:AS|CD:DR Congo:AF|CF:Central African Republic:AF|CG:Congo:AF|CH:Switzerland:EU|CI:Côte d'Ivoire:AF|CK:Cook Islands:OC|CL:Chile:SA|CM:Cameroon:AF|CN:China:AS|CO:Colombia:SA|CR:Costa Rica:NA|CU:Cuba:NA|CV:Cape Verde:AF|CW:Curaçao:NA|CX:Christmas Island:AS|CY:Cyprus:AS|CZ:Czechia:EU|DE:Germany:EU|DJ:Djibouti:AF|DK:Denmark:EU|DM:Dominica:NA|DO:Dominican Republic:NA|DZ:Algeria:AF|EC:Ecuador:SA|EE:Estonia:EU|EG:Egypt:AF|EH:Western Sahara:AF|ER:Eritrea:AF|ES:Spain:EU|ET:Ethiopia:AF|FI:Finland:EU|FJ:Fiji:OC|FK:Falkland Islands (Malvinas):SA|FM:Micronesia:OC|FO:Faroe Islands:EU|FR:France:EU|GA:Gabon:AF|GB:United Kingdom:EU|GD:Grenada:NA|GE:Georgia:AS|GF:French Guiana:SA|GG:Guernsey:EU|GH:Ghana:AF|GI:Gibraltar:EU|GL:Greenland:NA|GM:Gambia:AF|GN:Guinea:AF|GP:Guadeloupe:NA|GQ:Equatorial Guinea:AF|GR:Greece:EU|GS:South Georgia and the South Sandwich Islands:SA|GT:Guatemala:NA|GU:Guam:OC|GW:Guinea-Bissau:AF|GY:Guyana:SA|HK:Hong Kong:AS|HM:Heard Island and McDonald Islands:AN|HN:Honduras:NA|HR:Croatia:EU|HT:Haiti:NA|HU:Hungary:EU|ID:Indonesia:AS|IE:Ireland:EU|IL:Israel:AS|IM:Isle of Man:EU|IN:India:AS|IO:British Indian Ocean Territory:AS|IQ:Iraq:AS|IR:Iran:AS|IS:Iceland:EU|IT:Italy:EU|JE:Jersey:EU|JM:Jamaica:NA|JO:Jordan:AS|JP:Japan:AS|KE:Kenya:AF|KG:Kyrgyzstan:AS|KH:Cambodia:AS|KI:Kiribati:OC|KM:Comoros:AF|KN:Saint Kitts and Nevis:NA|KP:North Korea:AS|KR:South Korea:AS|KW:Kuwait:AS|KY:Cayman Islands:NA|KZ:Kazakhstan:AS|LA:Laos:AS|LB:Lebanon:AS|LC:Saint Lucia:NA|LI:Liechtenstein:EU|LK:Sri Lanka:AS|LR:Liberia:AF|LS:Lesotho:AF|LT:Lithuania:EU|LU:Luxembourg:EU|LV:Latvia:EU|LY:Libya:AF|MA:Morocco:AF|MC:Monaco:EU|MD:Moldova:EU|ME:Montenegro:EU|MF:Saint Martin (French part):NA|MG:Madagascar:AF|MH:Marshall Islands:OC|MK:North Macedonia:EU|ML:Mali:AF|MM:Myanmar:AS|MN:Mongolia:AS|MO:Macau:AS|MP:Northern Mariana Islands:OC|MQ:Martinique:NA|MR:Mauritania:AF|MS:Montserrat:NA|MT:Malta:EU|MU:Mauritius:AF|MV:Maldives:AS|MW:Malawi:AF|MX:Mexico:NA|MY:Malaysia:AS|MZ:Mozambique:AF|NA:Namibia:AF|NC:New Caledonia:OC|NE:Niger:AF|NF:Norfolk Island:OC|NG:Nigeria:AF|NI:Nicaragua:NA|NL:Netherlands:EU|NO:Norway:EU|NP:Nepal:AS|NR:Nauru:OC|NU:Niue:OC|NZ:New Zealand:OC|OM:Oman:AS|PA:Panama:NA|PE:Peru:SA|PF:French Polynesia:OC|PG:Papua New Guinea:OC|PH:Philippines:AS|PK:Pakistan:AS|PL:Poland:EU|PM:Saint Pierre and Miquelon:NA|PN:Pitcairn:OC|PR:Puerto Rico:NA|PS:Palestine:AS|PT:Portugal:EU|PW:Palau:OC|PY:Paraguay:SA|QA:Qatar:AS|RE:Réunion:AF|RO:Romania:EU|RS:Serbia:EU|RU:Russia:EU|RW:Rwanda:AF|SA:Saudi Arabia:AS|SB:Solomon Islands:OC|SC:Seychelles:AF|SD:Sudan:AF|SE:Sweden:EU|SG:Singapore:AS|SH:Saint Helena, Ascension and Tristan da Cunha:AF|SI:Slovenia:EU|SJ:Svalbard and Jan Mayen:EU|SK:Slovakia:EU|SL:Sierra Leone:AF|SM:San Marino:EU|SN:Senegal:AF|SO:Somalia:AF|SR:Suriname:SA|SS:South Sudan:AF|ST:Sao Tome and Principe:AF|SV:El Salvador:NA|SX:Sint Maarten (Dutch part):NA|SY:Syria:AS|SZ:Eswatini:AF|TC:Turks and Caicos Islands:NA|TD:Chad:AF|TF:French Southern Territories:AN|TG:Togo:AF|TH:Thailand:AS|TJ:Tajikistan:AS|TK:Tokelau:OC|TL:Timor-Leste:AS|TM:Turkmenistan:AS|TN:Tunisia:AF|TO:Tonga:OC|TR:Turkey:AS|TT:Trinidad and Tobago:NA|TV:Tuvalu:OC|TW:Taiwan:AS|TZ:Tanzania:AF|UA:Ukraine:EU|UG:Uganda:AF|UM:United States Minor Outlying Islands:OC|US:United States:NA|UY:Uruguay:SA|UZ:Uzbekistan:AS|VA:Vatican City:EU|VC:Saint Vincent and the Grenadines:NA|VE:Venezuela:SA|VG:Virgin Islands, British:NA|VI:Virgin Islands, U.S.:NA|VN:Vietnam:AS|VU:Vanuatu:OC|WF:Wallis and Futuna:OC|WS:Samoa:OC|XK:Kosovo:EU|YE:Yemen:AS|YT:Mayotte:AF|ZA:South Africa:AF|ZM:Zambia:AF|ZW:Zimbabwe:AF"""
# Country centroids (Google DSPL canonical countries, Apache 2.0) for map placement in country mode
CENTROIDS = {}
for _e in """AD:42.55:1.60|AE:23.42:53.85|AF:33.94:67.71|AG:17.06:-61.80|AI:18.22:-63.07|AL:41.15:20.17|AM:40.07:45.04|AN:12.23:-69.06|AO:-11.20:17.87|AQ:-75.25:-0.07|AR:-38.42:-63.62|AS:-14.27:-170.13|AT:47.52:14.55|AU:-25.27:133.78|AW:12.52:-69.97|AZ:40.14:47.58|BA:43.92:17.68|BB:13.19:-59.54|BD:23.68:90.36|BE:50.50:4.47|BF:12.24:-1.56|BG:42.73:25.49|BH:25.93:50.64|BI:-3.37:29.92|BJ:9.31:2.32|BM:32.32:-64.76|BN:4.54:114.73|BO:-16.29:-63.59|BR:-14.24:-51.93|BS:25.03:-77.40|BT:27.51:90.43|BV:-54.42:3.41|BW:-22.33:24.68|BY:53.71:27.95|BZ:17.19:-88.50|CA:56.13:-106.35|CC:-12.16:96.87|CD:-4.04:21.76|CF:6.61:20.94|CG:-0.23:15.83|CH:46.82:8.23|CI:7.54:-5.55|CK:-21.24:-159.78|CL:-35.68:-71.54|CM:7.37:12.35|CN:35.86:104.20|CO:4.57:-74.30|CR:9.75:-83.75|CU:21.52:-77.78|CV:16.00:-24.01|CX:-10.45:105.69|CY:35.13:33.43|CZ:49.82:15.47|DE:51.17:10.45|DJ:11.83:42.59|DK:56.26:9.50|DM:15.41:-61.37|DO:18.74:-70.16|DZ:28.03:1.66|EC:-1.83:-78.18|EE:58.60:25.01|EG:26.82:30.80|EH:24.22:-12.89|ER:15.18:39.78|ES:40.46:-3.75|ET:9.14:40.49|FI:61.92:25.75|FJ:-16.58:179.41|FK:-51.80:-59.52|FM:7.43:150.55|FO:61.89:-6.91|FR:46.23:2.21|GA:-0.80:11.61|GB:55.38:-3.44|GD:12.26:-61.60|GE:42.32:43.36|GF:3.93:-53.13|GG:49.47:-2.59|GH:7.95:-1.02|GI:36.14:-5.35|GL:71.71:-42.60|GM:13.44:-15.31|GN:9.95:-9.70|GP:17.00:-62.07|GQ:1.65:10.27|GR:39.07:21.82|GS:-54.43:-36.59|GT:15.78:-90.23|GU:13.44:144.79|GW:11.80:-15.18|GY:4.86:-58.93|GZ:31.35:34.31|HK:22.40:114.11|HM:-53.08:73.50|HN:15.20:-86.24|HR:45.10:15.20|HT:18.97:-72.29|HU:47.16:19.50|ID:-0.79:113.92|IE:53.41:-8.24|IL:31.05:34.85|IM:54.24:-4.55|IN:20.59:78.96|IO:-6.34:71.88|IQ:33.22:43.68|IR:32.43:53.69|IS:64.96:-19.02|IT:41.87:12.57|JE:49.21:-2.13|JM:18.11:-77.30|JO:30.59:36.24|JP:36.20:138.25|KE:-0.02:37.91|KG:41.20:74.77|KH:12.57:104.99|KI:-3.37:-168.73|KM:-11.88:43.87|KN:17.36:-62.78|KP:40.34:127.51|KR:35.91:127.77|KW:29.31:47.48|KY:19.51:-80.57|KZ:48.02:66.92|LA:19.86:102.50|LB:33.85:35.86|LC:13.91:-60.98|LI:47.17:9.56|LK:7.87:80.77|LR:6.43:-9.43|LS:-29.61:28.23|LT:55.17:23.88|LU:49.82:6.13|LV:56.88:24.60|LY:26.34:17.23|MA:31.79:-7.09|MC:43.75:7.41|MD:47.41:28.37|ME:42.71:19.37|MG:-18.77:46.87|MH:7.13:171.18|MK:41.61:21.75|ML:17.57:-4.00|MM:21.91:95.96|MN:46.86:103.85|MO:22.20:113.54|MP:17.33:145.38|MQ:14.64:-61.02|MR:21.01:-10.94|MS:16.74:-62.19|MT:35.94:14.38|MU:-20.35:57.55|MV:3.20:73.22|MW:-13.25:34.30|MX:23.63:-102.55|MY:4.21:101.98|MZ:-18.67:35.53|NA:-22.96:18.49|NC:-20.90:165.62|NE:17.61:8.08|NF:-29.04:167.95|NG:9.08:8.68|NI:12.87:-85.21|NL:52.13:5.29|NO:60.47:8.47|NP:28.39:84.12|NR:-0.52:166.93|NU:-19.05:-169.87|NZ:-40.90:174.89|OM:21.51:55.92|PA:8.54:-80.78|PE:-9.19:-75.02|PF:-17.68:-149.41|PG:-6.31:143.96|PH:12.88:121.77|PK:30.38:69.35|PL:51.92:19.15|PM:46.94:-56.27|PN:-24.70:-127.44|PR:18.22:-66.59|PS:31.95:35.23|PT:39.40:-8.22|PW:7.51:134.58|PY:-23.44:-58.44|QA:25.35:51.18|RE:-21.12:55.54|RO:45.94:24.97|RS:44.02:21.01|RU:61.52:105.32|RW:-1.94:29.87|SA:23.89:45.08|SB:-9.65:160.16|SC:-4.68:55.49|SD:12.86:30.22|SE:60.13:18.64|SG:1.35:103.82|SH:-24.14:-10.03|SI:46.15:15.00|SJ:77.55:23.67|SK:48.67:19.70|SL:8.46:-11.78|SM:43.94:12.46|SN:14.50:-14.45|SO:5.15:46.20|SR:3.92:-56.03|ST:0.19:6.61|SV:13.79:-88.90|SY:34.80:39.00|SZ:-26.52:31.47|TC:21.69:-71.80|TD:15.45:18.73|TF:-49.28:69.35|TG:8.62:0.82|TH:15.87:100.99|TJ:38.86:71.28|TK:-8.97:-171.86|TL:-8.87:125.73|TM:38.97:59.56|TN:33.89:9.54|TO:-21.18:-175.20|TR:38.96:35.24|TT:10.69:-61.22|TV:-7.11:177.65|TW:23.70:120.96|TZ:-6.37:34.89|UA:48.38:31.17|UG:1.37:32.29|US:37.09:-95.71|UY:-32.52:-55.77|UZ:41.38:64.59|VA:41.90:12.45|VC:12.98:-61.29|VE:6.42:-66.59|VG:18.42:-64.64|VI:18.34:-64.90|VN:14.06:108.28|VU:-15.38:166.96|WF:-13.77:-177.16|WS:-13.76:-172.10|XK:42.60:20.90|YE:15.55:48.52|YT:-12.83:45.17|ZA:-30.56:22.94|ZM:-13.13:27.85|ZW:-19.02:29.15""".split("|"):
    _c, _la, _lo = _e.split(":")
    CENTROIDS[_c] = (float(_la), float(_lo))
CONTINENTS = {"EU": "Europe", "AS": "Asia", "AF": "Africa", "NA": "North America", "SA": "South America",
              "OC": "Oceania", "AN": "Antarctica"}
COUNTRIES = {}
for _e in CC.split("|"):
    _c, _n, _k = _e.split(":")
    COUNTRIES[_c] = (_n, _k)

def log(*a):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), *a, flush=True)

def load_rules(text):
    rules = {}
    cat = None
    for line in text.splitlines():
        if not line.strip() or line.strip().startswith("#"):
            continue
        if not line.startswith(" ") and ":" in line:
            cat, line = line.split(":", 1)
            cat = cat.strip()
        for d in line.split():
            rules[d.lower().strip(".")] = cat
    return rules

BUILTIN_RULES = load_rules(BUILTIN)

def load_overrides():
    """categories.conf lines: `example.com = Category` (suffix match)."""
    rules = {}
    try:
        with open(OVERRIDES) as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if "=" in line:
                    d, c = (x.strip() for x in line.split("=", 1))
                    if d and c:
                        rules[d.lower().strip(".")] = c
    except FileNotFoundError:
        pass
    return rules

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS ip_info (ip TEXT PRIMARY KEY, scope TEXT, cc TEXT, country TEXT, continent TEXT,
  region TEXT, city TEXT, asn INTEGER, org TEXT, looked_up REAL, lat REAL, lon REAL);
CREATE TABLE IF NOT EXISTS name_cat (name TEXT PRIMARY KEY, category TEXT, source TEXT, matched TEXT);
CREATE INDEX IF NOT EXISTS ip_info_cc ON ip_info(cc);
CREATE INDEX IF NOT EXISTS name_cat_cat ON name_cat(category);
"""

# ------------------------------------------------------------ downloads ---
def fetch(url, timeout=300):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()

def months_back(n):
    d = date.today().replace(day=1)
    for _ in range(n):
        yield d.strftime("%Y-%m")
        d = (d - timedelta(days=1)).replace(day=1)

def ip_key(ip):
    """Sortable key: v4 as integer, v6 as 32-char hex (SQLite integers are only 64-bit)."""
    a = ipaddress.ip_address(ip)
    return (4, int(a)) if a.version == 4 else (6, format(int(a), "032x"))

def import_ranges(con, table, rows_iter, ncols):
    """Loads (start, end, *values) ranges into <table>4 and <table>6 via staging tables, then swaps."""
    cols = ", ".join(f"c{i} TEXT" for i in range(ncols))
    for v, kt in ((4, "INTEGER"), (6, "TEXT")):
        con.execute(f"DROP TABLE IF EXISTS {table}{v}_new")
        con.execute(f"CREATE TABLE {table}{v}_new (start {kt} PRIMARY KEY, end {kt}, {cols}) WITHOUT ROWID")
    batch = {4: [], 6: []}
    n = 0
    ph = ",".join("?" * (ncols + 2))
    for row in rows_iter:
        try:
            v, s = ip_key(row[0]); _, e = ip_key(row[1])
        except ValueError:
            continue
        batch[v].append((s, e, *row[2:2 + ncols]))
        n += 1
        if len(batch[v]) >= 50000:
            con.executemany(f"INSERT OR REPLACE INTO {table}{v}_new VALUES ({ph})", batch[v]); batch[v] = []
    for v in (4, 6):
        if batch[v]:
            con.executemany(f"INSERT OR REPLACE INTO {table}{v}_new VALUES ({ph})", batch[v])
    for v in (4, 6):
        con.execute(f"DROP TABLE IF EXISTS {table}{v}")
        con.execute(f"ALTER TABLE {table}{v}_new RENAME TO {table}{v}")
    con.commit()
    return n

def update_geo(con, force=False):
    want = "city" if GEO_DETAIL == "city" else "country"
    have = dict(con.execute("SELECT k, v FROM meta").fetchall())
    if not force and have.get("geo_month") == date.today().strftime("%Y-%m") and have.get("geo_kind") == want:
        return
    for month in months_back(3):
        if not force and have.get("geo_month") == month and have.get("geo_kind") == want:
            return                       # already have the newest available
        try:
            log(f"downloading DB-IP {want} lite {month}")
            raw = fetch(f"{DBIP_BASE}/dbip-{want}-lite-{month}.csv.gz")
            log(f"downloading DB-IP asn lite {month}")
            asn = fetch(f"{DBIP_BASE}/dbip-asn-lite-{month}.csv.gz")
        except Exception as e:
            log(f"DB-IP {month} not available ({e}); trying the month before")
            continue
        rdr = csv.reader(io.TextIOWrapper(gzip.GzipFile(fileobj=io.BytesIO(raw)), encoding="utf-8", errors="replace"))
        if want == "city":   # start,end,continent,country,region,city,lat,lon
            n = import_ranges(con, "geo", ((r[0], r[1], r[3], r[4], r[5], r[6], r[7]) for r in rdr if len(r) >= 8), 5)
        else:                # start,end,country
            n = import_ranges(con, "geo", ((r[0], r[1], r[2], "", "") for r in rdr if len(r) >= 3), 3)
        rdr = csv.reader(io.TextIOWrapper(gzip.GzipFile(fileobj=io.BytesIO(asn)), encoding="utf-8", errors="replace"))
        m = import_ranges(con, "asn", ((r[0], r[1], r[2], r[3]) for r in rdr if len(r) >= 4), 2)
        con.execute("INSERT OR REPLACE INTO meta VALUES ('geo_month', ?)", (month,))
        con.execute("INSERT OR REPLACE INTO meta VALUES ('geo_kind', ?)", (want,))
        con.execute("DELETE FROM ip_info")       # re-resolve everything with the new data
        con.commit()
        con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        log(f"DB-IP {month}: {n} location ranges, {m} ASN ranges")
        return
    log("could not download DB-IP data; will retry later")

def update_ut1(con, force=False):
    have = dict(con.execute("SELECT k, v FROM meta").fetchall())
    last = float(have.get("ut1_updated", 0))
    if not force and time.time() - last < UT1_REFRESH_DAYS * 86400 and have.get("ut1_lists") == ",".join(UT1_LISTS):
        return
    con.execute("DROP TABLE IF EXISTS ut1_new")
    con.execute("CREATE TABLE ut1_new (domain TEXT PRIMARY KEY, list TEXT) WITHOUT ROWID")
    rank = {l: i for i, l in enumerate(UT1_PRIORITY)}
    total = 0
    for lst in UT1_LISTS:
        if lst not in UT1_CATEGORY:
            log(f"unknown UT1 list {lst!r}, skipping")
            continue
        data = b""
        try:
            data = fetch(f"{UT1_BASE}/{lst}/domains")
        except urllib.error.HTTPError as e:
            if e.code != 404:
                log(f"UT1 {lst}: {e}"); continue
            parts, i = [], 0            # large lists are split into domains.0, domains.1, ...
            while True:
                try:
                    parts.append(fetch(f"{UT1_BASE}/{lst}/domains.{i}")); i += 1
                except Exception:
                    break
            data = b"".join(parts)
        except Exception as e:
            log(f"UT1 {lst}: {e}"); continue
        batch = []
        for line in data.decode("utf-8", "replace").splitlines():
            d = line.strip().lower().strip(".")
            if not d or d.startswith("#") or " " in d:
                continue
            try:
                ipaddress.ip_address(d)
                continue                 # IP entries aren't hostnames
            except ValueError:
                pass
            batch.append((d, lst))
            if len(batch) >= 50000:
                _ut1_insert(con, batch, rank); total += len(batch); batch = []
        if batch:
            _ut1_insert(con, batch, rank); total += len(batch)
        log(f"UT1 {lst}: loaded")
    if total == 0:
        con.execute("DROP TABLE ut1_new")
        log("UT1 download produced no domains; keeping the previous lists")
        return
    con.execute("DROP TABLE IF EXISTS ut1")
    con.execute("ALTER TABLE ut1_new RENAME TO ut1")
    con.execute("INSERT OR REPLACE INTO meta VALUES ('ut1_updated', ?)", (str(time.time()),))
    con.execute("INSERT OR REPLACE INTO meta VALUES ('ut1_lists', ?)", (",".join(UT1_LISTS),))
    con.execute("DELETE FROM name_cat")
    con.commit()
    con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    log(f"UT1: {total} domain entries")

_RANK_SQL = "CASE {} " + " ".join(f"WHEN '{l}' THEN {i}" for i, l in enumerate(UT1_PRIORITY)) + " ELSE 99 END"

def _ut1_insert(con, batch, rank):
    # when a domain is on several lists, keep the riskier one
    con.executemany(f"""INSERT INTO ut1_new VALUES (?, ?) ON CONFLICT(domain) DO UPDATE SET list = excluded.list
                        WHERE {_RANK_SQL.format('excluded.list')} < {_RANK_SQL.format('ut1_new.list')}""", batch)

# ------------------------------------------------------------- lookups ---
def lookup_range(con, table, ip):
    try:
        v, k = ip_key(ip)
    except ValueError:
        return None
    try:
        r = con.execute(f"SELECT * FROM {table}{v} WHERE start <= ? ORDER BY start DESC LIMIT 1", (k,)).fetchone()
    except sqlite3.OperationalError:
        return None
    return r[2:] if r and r[1] >= k else None

def scope_of(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid"
    if a.is_multicast:
        return "multicast"
    if a.is_loopback or a.is_link_local:
        return "local"
    if a.version == 4 and a in ipaddress.ip_network("100.64.0.0/10"):
        return "cgnat"
    if a.is_private:
        return "private"
    if a.is_reserved or a.is_unspecified or (a.version == 4 and int(a) == 0xFFFFFFFF):
        return "reserved"
    return "public"

def enrich_ips(con):
    new = [r[0] for r in con.execute("""
        SELECT ip FROM (SELECT dst ip FROM ww.flows UNION SELECT src FROM ww.flows)
        WHERE ip NOT IN (SELECT ip FROM ip_info) LIMIT 20000""")]
    out, now = [], time.time()
    for ip in new:
        scope = scope_of(ip)
        cc = country = continent = region = city = org = ""
        asn = lat = lon = None
        if scope == "public":
            g = lookup_range(con, "geo", ip)
            if g:
                cc, region, city = (g[0] or "").upper(), g[1] or "", g[2] or ""
                if cc in ("ZZ", "--"):
                    cc = ""
                country, ck = COUNTRIES.get(cc, (cc, ""))
                continent = CONTINENTS.get(ck, "")
                if len(g) >= 5 and g[3] not in (None, ""):
                    try:
                        lat, lon = float(g[3]), float(g[4])
                    except (TypeError, ValueError):
                        pass
                if lat is None and cc in CENTROIDS:
                    lat, lon = CENTROIDS[cc]
            a = lookup_range(con, "asn", ip)
            if a:
                try:
                    asn = int(a[0])
                except (TypeError, ValueError):
                    asn = None
                org = a[1] or ""
        out.append((ip, scope, cc, country, continent, region, city, asn, org, now, lat, lon))
    con.executemany("INSERT OR REPLACE INTO ip_info VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", out)
    con.commit()
    return len(out)

def suffixes(name):
    parts = name.split(".")
    return [".".join(parts[i:]) for i in range(len(parts) - 1)]

def categorize(con, name, overrides):
    n = name.lower().strip(".")
    sfx = suffixes(n)
    for s in sfx:
        if s in overrides:
            return overrides[s], "your rules", s
    for s in sfx:
        if s in BUILTIN_RULES:
            return BUILTIN_RULES[s], "built-in", s
    try:
        for s in sfx:
            r = con.execute("SELECT list FROM ut1 WHERE domain = ?", (s,)).fetchone()
            if r:
                return UT1_CATEGORY.get(r[0], r[0]), "UT1", s
    except sqlite3.OperationalError:
        pass
    if n.endswith((".local", ".lan", ".home.arpa", ".internal", ".in-addr.arpa", ".ip6.arpa")) or "." not in n:
        return "Local network", "built-in", ""
    return "", "", ""

def enrich_names(con, overrides):
    new = [r[0] for r in con.execute("""
        SELECT n FROM (SELECT lower(name) n FROM ww.names UNION SELECT qname FROM ww.dns_queries)
        WHERE n IS NOT NULL AND n <> '' AND n NOT IN (SELECT name FROM name_cat) LIMIT 20000""")]
    rows = [(n, *categorize(con, n, overrides)) for n in new]
    con.executemany("INSERT OR REPLACE INTO name_cat VALUES (?,?,?,?)", rows)
    con.commit()
    return len(rows)

# ------------------------------------------------------------------ main ---
def main():
    con = sqlite3.connect(f"file:{INTEL_DB}", uri=True, timeout=60)
    con.executescript("PRAGMA journal_mode=WAL;" + SCHEMA)
    cols = {r[1] for r in con.execute("PRAGMA table_info(ip_info)")}
    if "lat" not in cols:                         # upgrade: add map coordinates and re-resolve
        con.execute("ALTER TABLE ip_info ADD COLUMN lat REAL")
        con.execute("ALTER TABLE ip_info ADD COLUMN lon REAL")
        con.execute("DELETE FROM ip_info")
        con.commit()
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    ov_mtime = None
    last_downloads = 0
    attached = False
    while not stop.is_set():
        try:
            if time.time() - last_downloads > 6 * 3600:
                update_geo(con)
                update_ut1(con)
                last_downloads = time.time()
            try:
                ino = os.stat(DB_PATH).st_ino
            except OSError:
                ino = None
            if attached and ino != attached:          # database was deleted or replaced (e.g. cleared)
                con.execute("DETACH DATABASE ww")
                attached = False
            if not attached:
                if ino is None:
                    log("waiting for the collector database"); stop.wait(30); continue
                con.execute("ATTACH DATABASE ? AS ww", (f"file:{DB_PATH}?mode=ro",))
                attached = ino
            try:
                m = os.path.getmtime(OVERRIDES)
            except OSError:
                m = 0
            if m != ov_mtime:
                if ov_mtime is not None:
                    con.execute("DELETE FROM name_cat"); con.commit()
                    log("category overrides changed; recategorizing")
                ov_mtime = m
            ips = enrich_ips(con)
            names = enrich_names(con, load_overrides())
            if ips or names:
                log(f"enriched {ips} IPs, {names} names")
            con.execute("INSERT OR REPLACE INTO meta VALUES ('enriched', ?)", (str(time.time()),)); con.commit()
        except Exception as e:
            log(f"intel error: {type(e).__name__}: {e}")
        stop.wait(ENRICH_SECONDS)

if __name__ == "__main__":
    main()
