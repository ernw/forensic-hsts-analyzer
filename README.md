# Forensic HSTS Analyzer

Tool to analyze HSTS caches during file system analysis.

## What is HSTS?

HSTS (HTTP Strict Transport Security, https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security) is a mechanism to make browsing the Internet a little more secure. If a user opens a website for the first time, the server sends a special header together with the response. This server header tells the browser that in future it should connect to this domain only via HTTPS (which means encrypted communication). The header contains information about how long the browser should remember the presence of the HSTS header (expiry time) and whether subdomains are included (if true, the browser will connect to subdomains via HTTPS by default, as well).

## Why is it relevant for computer forensics or incident analysis?

Obviously, the browser has to remember that it visited a website before and that the HSTS header was sent. It also has to remember when the HSTS information will expire.

By analyzing the information from the HSTS cache, it is possible to find evidence about what domains were contacted by the browser and when and why. Please keep in mind that the browser stores HSTS data for domains that it *contacted*. The reason for contacting a domain can be for example that a user browsed the website, but it can also be that a resource was (implicitly) loaded from a domain when a user visited a website on another domain. There are also domains that browsers contact because of built-in functionality, such as update checks etc. This means, if you see an HSTS entry in the cache, you cannot always tell whether a contact to a domain happened on purpose or was side effect of another action.

This README documents the behaviour of different software in storing, maintaining and deleting cached HSTS data.

The purpose of ```fha.py``` is to have a unified tool that translates the different cache formats into CSV outputs that are easily readable and processable by other software and people. In the end, it is easier to focus on the content of the cache, include the data into timelines and look for evidence of website visits. Furthermore, for the Chrome HSTS cache format, this tool provides an easy to use functionality to translate hashed (unreadable) domain names into readable domain names.

## Supported browsers / software

This tool supports the HSTS cache format of Firefox, Chrome, Safari, wget, libsoup, and curl. However, not only Firefox and Chrome make use of their formats. As a result, several other software is supported.

### Firefox format

* Firefox (tested versions: 85-88)
* Thunderbird (tested version: 78.10)
* Forks of Firefox or Thunderbird

### Chrome format

* Chrome
* Chromium (tested versions: 89, 90)
* Edge (Chrome-based)
* Other browsers that make use of the Chrome engine
* Visual Studio Code
* Microsoft Teams (at least the Linux desktop app, tested version: 1.4.00.7556 on Debian)
* Other software that makes use of Chrome

### wget

* wget (tested version: 1.21)

### libsoup

* Software that uses Gnome libsoup (tested version: 2.4).

### Safari

* Safari

### curl

* curl (starting with version 7.74.0)

## The different HSTS cache formats

### Firefox

The cached data is stored in the file ```SiteSecurityServiceState.txt``` in the profile directory of a Firefox profile (on Linux e.g. ```~/.mozilla/<profile>/```). This file also stores information about cached HPKP information (https://en.wikipedia.org/wiki/HTTP_Public_Key_Pinning).

The file is a simple text file with max. 1024 lines. Each line is a cached HSTS or HPKP header. This means only 1024 HSTS/HPKP entries can be cached.

A line contains 4 fields that are separated by a tab (\t).

The first field is the domain followed by a colon, followed by either "HSTS" (for a cached HSTS header) or "HPKP" (for a cached HPKP header), e.g.:

```ernw-research.de:HSTS```

In newer versions of Firefox cache partitioning was introduced to make it harder to track users across the Internet. Therefore, newer entries contain a partition key that tells us what domain caused the browser to connect to this domain, e.g.:

```
ernw-research.de^partitionKey=%28http%2Cernw.de%29:HSTS
ernw-research.de^partitionKey=%28http%2Ctroopers.de%29:HSTS
```

This means, there can be more than one entry for a domain, depending on the websites that caused the connection to a domain. However, we always only see the domain, no subdomains (e.g. "ernw.de" instead of "static.ernw.de").

The second field contains an integer saying on how many different days this domain was contacted (starting with 0). This is not the number of total visits of the website.

The third field contains an integer telling us when this domain was last contacted. This integer is the number of days since the Unix epoch (1970-01-01). This means, we do not know the exact time of the last visit; we just can pin it to a day.

The fourth field contains a comma-separated list. This list contains 4 more fields:

The first sub-field is an integer. This integer is the expiry time in milliseconds since the Unix epoch. By looking at this value and looking at the actual HSTS server header returned when contacting a certain domain, we can compute the exact timestamp of the last visit. (This is only true if the HSTS expiration time was not changed by the server admin in the meantime.)

The second sub-field is an integer. It represents the security policy: "unset" (0), "set" (1), "knockout" (2), "negative" (3).

The third sub-field is an integer. It represents whether subdomains are included: false (0), true (1).

The fourth sub-field seems to be always "2" in case of a cached HSTS entry, or the HPKP fingerprint in case of a cached HPKP entry.

A complete HSTS entry may look like this:

```static.ernw.de^partitionKey=%28http%2Cernw.de%29:HSTS   2       18710   1632353039875,1,1,2```

This tells us that static.ernw.de was contacted because the user browsed ernw.de and something (e.g. an image or another resource) was loaded from static.ernw.de and the HSTS header on static.ernw.de was observed. This happened on three different days. The last visit was on the 18710th day after 1970-01-01 (which is 2021-03-24). The entry will expire on 2021-09-22 23:23:59 UTC. Since static.ernw.de has (currently) an expiration time of 15768000 seconds (182.5 days) set, we can compute the likely last visit at 2021-03-24 11:23:59 UTC. Security policy is "set". Subdomains are included.

A complete HPKP entry may look like this:

```packages.debian.org:HPKP        28      18212   1578750016762,1,0,br+Uf2+rkmMOzm4/4dHqwGyRXuGk1LC9DdGPIS0iPuU=0RzGS6yWFFS8w3jZZjWuXYwUXfELYh7KxcTmtlw0EMs=```

(Please note that HPKP is not supported by Firefox anymore. However, HPKP entries were not removed from the cache when support was removed.)

Additional note:

In my tests, I also found an entry with a ```firstPartyDomain``` set. This may also containg useful information about the origin of a connection:

```shavar.services.mozilla.com^firstPartyDomain=safebrowsing.86868755-6b82-4842-b301-72671a0db32e.mozilla:HSTS     533     18715   1648558326270,1,1,2```

Another hint: If you access example.com which has the includeSubdomains flag set, and later you access subdomain.example.com, you will end with two HSTS entries: one for example.com and one for subdomain.example.com.

#### Removing cached entries

When clearing the history in Firefox, the default selection is: "Browsing & Download History", "Cookies", "Active Logins", "Cache", "Form & Search History". This selection does not affect the HSTS cache. The HSTS cache is only affected if the check box is marked at "Site Preferences".

Of course, one can simply open the ```SiteSecurityServiceState.txt``` and remove the entries that one likes to remove.

If a visit to a domain was cleared from the history, but previous visits are still in the history (because only e.g. the history of the last hour was cleared), the HSTS entry will be removed from the cache, although there are still visits to that website in the history.

This means, if you see a visit to a HSTS-enabled website in the history, but not an entry in the HSTS cache, parts of the history might have been cleared in between.

#### Example output

```
$ ./fha.py -f firefox ~/.mozilla/firefox/7pif3n5f.default/SiteSecurityServiceState.txt
domain,accessed_via,type,number_days_with_visit,last_visit,last_visit_human_readable_utc,last_visit_uncertainty,expiry,expiry_human_readable_utc,security_policy,include_subdomains,hpkp_fingerprint
cdn.cookielaw.org,slack.com,HSTS,0,1618185600,2021-04-12T00:00:00,86400,1649749912.667,2022-04-12T07:51:52.667000,set,true,2
cdn.cookielaw.org,leo.org,HSTS,13,1617840000,2021-04-08T00:00:00,86400,1649426539.402,2022-04-08T14:02:19.402000,set,true,2
cdn.cookielaw.org,cisco.com,HSTS,3,1615334400,2021-03-10T00:00:00,86400,1646929377.076,2022-03-10T16:22:57.076000,set,true,2
cdn.cookielaw.org,dhl.de,HSTS,10,1616716800,2021-03-26T00:00:00,86400,1648302581.533,2022-03-26T13:49:41.533000,set,true,2
cdn.cookielaw.org,,HSTS,88,1618185600,2021-04-12T00:00:00,86400,1644310855.537,2022-02-08T09:00:55.537000,set,true,2
```

We see that cdn.cookielaw.org was contacted several times because several visited pages (accessed_via column) included resources from there. However, e.g. for "leo.org" we only see this domain, although the connection was caused by a visit of "dict.leo.org". We can tell the day when the cookielaw domain was last contacted (last_visit column) because of the visit of another domain (e.g. 2021-04-08 for leo.org); and we can guess that it happened at 16:02 CEST based on the expiration timestamp (expiry column).

We also see that there is a general entry for the cookielaw domain. The last_visit column is updated whenever cdn.cookielaw.org is contacted and even if another entry is updated. However, the expiry column is not updated. (This might be because of the introduction of cache partitioning and this entry will be removed at 2022-02-08 and not added again. When removing it manually, it will not show up again.)


### Chrome

The Chrome HSTS cache is located in a file called ```TransportSecurity``` in the profile directory. It is a JSON file.

The domain names are not stored in plain text in this file. Instead a strange method of hashing and encoding was used:
At first all the dots (".") in a domain are removed and every "chunk" of the domain is prepended with the length of the chunk (as a single-byte char) and a null-byte is appended at the end, e.g.:

```www.ernw-research.de --> \x03www\x0dernw-research\x02de\x00```

Afterwards, the resulting string is hashed using SHA256 and the result is encoded using base64.

This means, that the encoded domains in this JSON cannot be transformed into the original domains. The only way to find at least some plain text domains is to use something like "rainbow tables" that you can create from the browser history and other lists of domains that you found somewhere or generated in some way.

There are two versions of the ```TransportSecurity``` file:

The first version is a simple map of objects. The keys are the hashed domain names and the object content contains the expiration time of the entry, the mode (usually "force-https"), whether subdomains should be included, and the timestamp of observation of the HSTS header (the last connection/visit). Example:

```
{
   "Bbqws1yaoTGSVHBHdVsgYKShFKmTIkr/BunFN7b0RJM=": {
      "expiry": 1648121369.992017,
      "mode": "force-https",
      "sts_include_subdomains": true,
      "sts_observed": 1616585369.992022
   },
[...]
}
```

The second version contains an object with the keys: "version" (with value 2), "expect_ct" (which was always empty in my tests) and "sts", which contains a list of cached HSTS entries. The HSTS entries hold the same information as in version 1, but the hashed domain is included in the object content as "host". Example:

```
{
    "expect_ct": [],
    "sts": [ {
        "expiry": 1648560662.366791,
        "host": "AL60vi3nfqIwRH6Bo/oePIoCtDLUtzax9sxy2uIXVc4=",
        "mode": "force-https",
        "sts_include_subdomains": true,
        "sts_observed":1617024662.366804
        },
        [...]
    ],
    "version": 2
}
```

Hint: If you access example.com which has the includeSubdomains flag set, and later you access subdomain.example.com, you will end with two HSTS entries: one for example.com and one for subdomain.example.com.

#### Removing cached entries

When clearing the history in Chrome, you have to select "Cached images and files" in the "Clear browsing data..." dialog, so that entries are removed from file. Clearing the history does not delete entries from this file, however, it will get harder to translate the hashed domain names to the plaintext domain names.

You can also use the special pages ```chrome://net-internals/#hsts``` to query the ```TransportSecurity``` file, or to remove entries. (You can also add new entries manually.) Or you remove the full cache here: ```chrome://net-internals/#dns``` by clicking "Clear host cache".

Of course, one can simply open the ```TransportSecurity``` and remove the entries that one likes to remove.

#### Example output

```
$ ./fha.py -u ~/.config/chromium/Default/History -u ~/.mozilla/firefox/<id>.default/places.sqlite -f chrome ~/.config/chromium/Default/TransportSecurity
domain,encoded_domain,mode,observed,observed_human_readable_utc,expiry,expiry_human_readable_utc,include_subdomains
packages.debian.org,YBswcLuyIQIveNw2apK1UKBiQuYHj8rujIbk3XpADEA=,force-https,1617182633.716768,2021-03-31T09:23:53.716768,1632734633.716763,2021-09-27T09:23:53.716763,false
www.debian.org,iTca8SBpHaKYTUpvXoTxIrE6e6ClACYxbfYMD34LeDM=,force-https,1617182634.482686,2021-03-31T09:23:54.482686,1632734634.482676,2021-09-27T09:23:54.482676,false
,kYxWDeIDVgesBS02XkmPRTIpB0nkimBvKZESXctn8eA=,force-https,1586444881.519969,2020-04-09T15:08:01.519969,1617980881.519956,2021-04-09T15:08:01.519956,false
```

The command uses the Chromium and Firefox histories to translate the hashed domains into plain text. However, it did not succeed for the third entry.

We see that the Debian domains were *last* contacted on 2021-03-31 11:23 CEST. The HSTS entry is cached for about half a year.

The third domain (youtube.com) was *last* contaced on 2020-04-09 17:08 CEST. However, the domain does not appear in the Chrome history, which means that either the history was cleared afterwards, or the domain was contacted implicitly (e.g. via an embedded video on another page).

### wget

The format is easy to read and can be found in ```~/.wget-hsts```. Example:

```
# HSTS 1.0 Known Hosts database for GNU Wget.
# Edit at your own risk.
# <hostname>    <port>  <incl. subdomains>  <created>   <max-age>
git.io  0   1   1583232968  31536000
```

### libsoup

libsoup (https://wiki.gnome.org/Projects/libsoup) is an "HTTP client/server library for GNOME".

I found a ```hsts-storage.sqlite``` in ```~/.local/share/webkitgtk/``` which seems to be used/created by Eclipse, which internally seems to use libsoup. There might be other software that uses it, but I did not find a lot of information about it on the Internet.

It contains a single database table "soup_hsts_policies" with the columns "host", "max_age", "expiry", and "include_subdomains", which is self-explainatory. (https://lazka.github.io/pgi-docs/Soup-2.4/classes/HSTSPolicy.html)


### Safari

Safari uses the ```plist``` format to store HSTS data in ```~/Library/Cookies/HSTS.plist```. This tools uses the ```python3-plist``` to parse the file format into arrays and maps.

The data got the following structure:
```
{
    'HSTS Store Schema Version': <sversion>,
    'HSTS Content Version': <cversion>,
    'HSTS Preload Entries Signature': <some kind of signature>,
    'com.apple.CFNetwork.defaultStorageSession': {
        '<domain>': {
            'Include Subdomains': True,
            'Create Time': <timestamp>,
            'Expiry': <timestamp>,
            'HSTS Host': True
        }
        [...]
}
```

The 'HSTS Store Schema Version' was always ```3``` in my samples.

The 'HSTS Content Version' was always ```10``` in my samples.

The 'HSTS Preload Entries Signature' is some kind of signature that was always ```1a10b4aa92ff232a82f19a3f3866948be25b709b7cc869427f0320c9ca1f4ded``` in my samples.

The actual cache is in 'com.apple.CFNetwork.defaultStorageSession'. The key for the entries is the domain name. If subdomains are included, 'Include Subdomains' is present and set to True; but if they are not included, this key is missing. The create time timestamp and the expiry timestamp look like Unix timestamps, however, they have an offset of 11323 days to the actual correct Unix timestamp. The 'HSTS Host' entry is always present and set to True.

When a site is revisited, the timestamps are not updated. So it is only possible to tell when a page was visited the first time.

There are some prefilled/predefined domains (about 700 in my sample) that were not caused by visiting pages, but seem to be some kind of HSTS preload list. The expiry timestamp is set to infinity. This means, all entries not having an actual timestamp as expiry are preloaded. The creation timestamp of those entries matches the timestamp the entries were added to the ```HSTS.plist``` file. When such a preload domain is visited for the first time, the create time timestamp and the expiry timestamp are updated.

#### Removing cached entries

Removing the ```HSTS.plist``` file will remove the cache. Also, when the history is cleared, the HSTS entries for the affected domains are removed from the cache. If a domain was preloaded into the cache, the preloaded entry will be restored.

If a visit to a domain was cleared from the history, but previous visits are still in the history (because only e.g. the history of the last hour was cleared), the HSTS entry will be removed from the cache, although there are still visits to that website in the history.

This means, if you see a visit to a HSTS-enabled website in the history, but not an entry in the HSTS cache, parts of the history might have been cleared in between.

#### Example output

```
$ ./fha.py -f safari ~/Library/Cookies/HSTS.plist
hostname,include_subdomains,created,created_human_readable_utc,expiry,expiry_human_readable_utc
ernw.de,true,1617952889.8829021,2021-04-09T07:21:29.882902,1633720889.882901,2021-10-08T19:21:29.882901
ernw-research.de,true,1617952887.602666,2021-04-09T07:21:27.602666,1633720887.602664,2021-10-08T19:21:27.602664
idmsa.apple.com,true,1617952608.364369,2021-04-09T07:16:48.364369,,
appleid.apple.com,true,1617952608.364362,2021-04-09T07:16:48.364362,,
itunes.apple.com,true,1617953942.944494,2021-04-09T07:39:02.944494,1649489942.944493,2022-04-09T07:39:02.944493
myinfo.apple.com,true,1617952608.364365,2021-04-09T07:16:48.364365,,
apps.apple.com,true,1617953943.662924,2021-04-09T07:39:03.662924,1649489943.662924,2022-04-09T07:39:03.662924
iforgot.apple.com,true,1617952608.364372,2021-04-09T07:16:48.364372,,
```

The output shows, that ernw.de, ernw-research.de, itunes.apple.com and apps.apple.com were contacted by Safari. The created column shows that they were *first* contacted on 2021-04-09 after 09:21 CEST. The ERNW entries show that the HSTS entry is cached for about half a year, while the Apple entries are cached for a year.

The other Apple domains were not contacted, but loaded into the built-in preload list on 2021-04-09 09:16 CEST.

### curl

Curl started supporting HSTS with version 7.74.0 in late 2020. However, so far this feature is not enabled by default and it is very likely that your version does not support HSTS yet.

The format is very simplistic (https://curl.se/libcurl/c/CURLOPT_HSTS.html):
For every cached entry, there is one line in the cache file.
The domain comes first, preceded by a '.' if subdomains are included. The expiration time stamp follows after a timestamp and has the format "YYYYMMDD HH:mm:ss" and is stored in UTC.


Example:

```
.ernw.de 2022-01-01 12:00:00
troopers.de 2022-01-01 10:00:00
```

The first line enables HSTS for ernw.de and subdomains until January 1st, 2022 1PM (CET). The second line enables HSTS only for troopers.de, until January 1st, 2022 11AM (CET).

## How to use the tool?

The tool can be used to analyze a Firefox, Chrome, Safari, wget, libsoup or curl HSTS cache. Use the ```-f``` (or ```--format```) option to tell what format you want to use. The output of the tool is simple CSV. The first line will tell you the column name, but you can disable this with ```--no-header```.

As described above, you need some kind of rainbow table to translate the hashed domain names into a readable version. To do so, you can use the ```-u``` option to provide one or more browser history files (either Firefox places.sqlite or Chrome History file) or one or more precalculated mappings (```-m``` option). You may also mix ```-m``` and ```-u```.

In order to precalculate the mappings, you can use the ```--create-chrome-map``` option together with either a browser history file or a simple newline-separated text file containing domains. During the map creation, the tool will also create hashes of other (sub)domains: If e.g. ```www.subdomain.example.com``` is in your list, the hashes for ```www.subdomain.example.com```, ```subdomain.example.com```, ```example.com``` and ```com``` are added to the map.

There is a precalculated ```default.map``` file in ```./lists``` which is used by the tool by default. It contains a list of different CDN domains and other often used pages. Please note, that this list is only a guess. If you want to have domains included in ```default.map```, please open an issue in this repo.

You can use the built-in ```--get-preload-list``` to retrieve the Chromium HSTS preload list from Chromium's Github repository and create a map file, for example:

```
./fha.py --get-preload-list ../lists/preload.map
```

You can also run the tool with the ```--check-hsts``` option. This will append a column ```actual_hsts``` to the CSV output. The tool will send a HEAD request to every domain in the cache to retrieve the actual HSTS header as returned by the server. If there is more than one HSTS header in the response (which should not happen but occurs now and then; the first should be used by the user agent), all of the headers are included here, separated by " - ". The tool will connect to ```https://<domain>/``` and will follow any redirect (as long as the redirect does not leave the domain). The HSTS of the last server response (that does not redirect) is shown. This option might cause connections to malicious domains, depending on the content of the HSTS cache.

## License

The tool fha.py (Forensic HSTS Analyzer) is licensed under GPL v3 (see LICENSE file). © Copyright 2021 Florian Bausch.

## Resources

If you want to read more:

* https://securityboulevard.com/2019/12/hsts-for-forensics-you-can-run-but-you-cant-use-http/
* https://security.stackexchange.com/questions/139692/what-are-the-columns-in-firefoxs-sitesecurityservicestate-txt
* https://business.blogthinkbig.com/breaking-out-hsts-and-hpkp-on-firefox/
