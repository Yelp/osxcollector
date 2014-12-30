[![Build Status](https://travis-ci.org/Yelp/osxcollector.svg)](https://travis-ci.org/Yelp/osxcollector)

# OSXCollector Manual
OSXCollector is a forensic evidence collection & analysis toolkit for OSX.

#### Forensic Collection
The collection script runs on a potentially infected machine and outputs a JSON file that describes the target machine. OSXCollector gathers information from plists, sqlite databases and the local filesystem.

#### Forensic Analysis
Armed with the forensic collection, an analyst can answer the question like:
* _Is this machine infected?_
* _How'd that malware get there?_
* _How can I prevent and detect further infection?_

Yelp automates the analysis of most OSXCollector runs converting OSXCollector output into an easily readable and actionable summary of _just the suspicious stuff_.

## Performing Collection
`osxcollector.py` is a single Python file that runs without any dependencies on a standard OSX machine. This makes it really easy to run collection on any machine - no fussing with brew, pip, config files, or environment variables. Just copy the single file onto the machine and run it.

`sudo osxcollector.py` is all it takes.

```shell
$ sudo osxcollector.py
Wrote 35394 lines.
Output in osxcollect-2014_12_21-08_49_39.tar.gz
```

The JSON output of the collector, along with some helpful files like system logs, has been bundled into a .tar.gz for handoff to an analyst.

`osxcollector.py` also has a lot of useful options to change how collection works:
* `-i INCIDENT_PREFIX`/`--id=INCIDENT_PREFIX`:
  Sets an identifier which is used as the prefix of the output file. The default value is `osxcollect`.
  ```shell
  $ sudo osxcollector.py -i IncontinentSealord
  Wrote 35394 lines.
  Output in IncontinentSealord-2014_12_21-08_49_39.tar.gz
  ```
  Get creative with incident names, it makes it easier to laugh through the pain.

* `-p ROOTPATH`/`--path=ROOTPATH`:
  Sets the path to the root of the filesystem to run collection on. The default value is `/`. This is great for running collection on the image of a disk.
  ```shell
  $ sudo osxcollector.py -p '/mnt/powned'
  ```

* `-s SECTION`/`--section=SECTION`:
  Runs only a portion of the full collection. Can be specified more than once. The full list of sections is:
  * `version`
  * `system_info`
  * `kext`
  * `startup`
  * `applications`
  * `quarantines`
  * `downloads`
  * `chrome`
  * `firefox`
  * `safari`
  * `accounts`
  * `mail`

  ```shell
  $ sudo osxcollector.py -s 'startup' -s 'downloads'
  ```

* `-d`/`--debug`:
  Enables verbose output and python breakpoints. If something is wrong with OSXCollector, try this.

  ```shell
  $ sudo osxcollector.py -d
  ```

## Details of Collection
The collector outputs a `.tar.gz` containing all the collected artifacts. The archive contains a JSON file with the majority of information.  Additionally, a set of useful logs from the target system logs are included.

#### Common Keys

##### Every Record
Each line of the JSON file records 1 _piece of information_.  There are some common keys that appear in every JSON record:
* `osxcollector_incident_id`: A unique ID shared by every record.
* `osxcollector_section`: The _section_ or type of data this record holds.
* `osxcollector_subsection`: The _subsection_ or more detailed descriptor of the type of data this record holds.

##### File Records
For records representing files there are a bunch of useful keys:
* `ctime`: The file creation time.
* `mtime`: The file modified time.
* `file_path`: The absolute path to the file.
* `md5`: MD5 hash of the file contents.
* `sha1`: SHA1 hash of the file contents.
* `sha2`: SHA2 hash of the file contents.

For records representing downloaded files:
* `xattr-wherefrom`: A list containing the source and referrer URLs for the downloaded file.
* `xattr-quarantines`: A string describing which application downloaded the file.

##### Sqllite Records
For records representing a row of a sqllite database:
* `osxcollector_table_name`: The table name the row comes from.
* `osxcollector_db_path`: The absolute path to the sqllite file.

For records that represent data associated with a specific user:
* `osxcollector_username`: The name of the user

#### Timestamps
OSXCollector attempts to convert timestamps to human readable date/time strings in the format `YYYY-mm-dd hh:MM:ss`. It uses heuristics to automatically identify various timestamps:
* seconds since epoch
* milliseconds since epoch
* seconds since 2001-01-01
* seconds since 1601-01-01

#### Sections
##### `version` section

The current version of OSXCollector.

##### `system_info` section

Collects basic information about the system:

 - system name
 - node name
 - release
 - version
 - machine

##### `kext` section

Collects the Kernel extensions from:
- `/System/Library/Extensions`
- `/Library/Extensions`

##### `startup` section

Collects information about the
[LaunchAgents](https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man5/launchd.plist.5.html),
LaunchDaemons, ScriptingAdditions,
[StartupItems](https://developer.apple.com/library/mac/documentation/macosx/conceptual/bpsystemstartup/chapters/StartupItems.html)
and other login items from:

 - `/System/Library/LaunchAgents`
 - `/System/Library/LaunchDaemons`
 - `/Library/LaunchAgents`
 - `~/Library/LaunchAgents`
 - `/Library/LaunchDaemons`
 - `/System/Library/ScriptingAdditions`
 - `/Library/ScriptingAdditions`
 - `/System/Library/StartupItems`
 - `/Library/StartupItems`
 - `~/Library/Preferences/com.apple.loginitems.plist`

More information about the Max OS X startup can be found here:
http://www.malicious-streams.com/article/Mac_OSX_Startup.pdf

##### `applications` section

Hashes installed applications and gathers install history from:

 - `/Applications`
 - `~/Applications`
 - `/Library/Receipts/InstallHistory.plist`

##### `quarantines` section

Quarantines are basically the info necessary to show the 'Are you sure you wanna
run this?' when a user is trying to open a file downloaded from the internet.
For some more details, checkout the Apple Support explanation of Quarantines:
http://support.apple.com/kb/HT3662

This section collects also information from XProtect hash-based malware check
for quarantines files. The plist is at:
`/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/XProtect.plist`

XProtect also add minimum versions for Internet Plugins. That plist is at:
`/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/XProtect.meta.plist`

##### `downloads` section

Hashes all users' downloaded files from:

 - `~/Downloads`
 - `~/Library/Mail Downloads`
 - `~/Library/Containers/com.apple.mail/Data/Library/Mail Downloads`

##### `chrome` section

Collects following information from Google Chrome web browser:

 - History
 - Archived History
 - Cookies
 - Login Data
 - Top Sites
 - Web Data

This data is extracted from `~/Library/Application Support/Google/Chrome/Default`

##### `firefox` section

Collects information from the different SQLite databases in a Firefox profile:

 - Cookies
 - Downloads
 - Form History
 - History
 - Signons
 - Permissions
 - Addons
 - Extension
 - Content Preferences
 - Health Report
 - Webapps Store

This information is extracted from `~/Library/Application Support/Firefox/Profiles`

For more details about Firefox profile folder see
http://kb.mozillazine.org/Profile_folder_-_Firefox

##### `safari` section

Collects information from the different plist and SQLite databases in a Safari
profile:

 - Downloads
 - History
 - Databases
 - Local Storage

##### `accounts` section
Collects information about users' accounts:

 - system admins: `/private/var/db/dslocal/nodes/Default/groups/admin.plist`
 - system users: `/private/var/db/dslocal/nodes/Default/users`
 - social accounts: `~/Library/Accounts/Accounts3.sqlite`
 - users' recent items: `~/Library/Preferences/com.apple.recentitems.plist`

##### `mail` section
Hashes files in the mail app directories:

 - `~/Library/Mail`
 - `~/Library/Mail Downloads`

## Basic Manual Analysis
Forensic analysis is a bit of art and a bit of science. Every analyst will see a bit of a different story when reading the output from OSXCollector. That's part of what makes analysis fun.

Generally, collection is performed on a target machine because something is hinky: anti-virus found a file it doesn't like, deep packet inspect observed a callout, endpoint monitoring noticed a new startup item. The details of this initial alert - a file path, a timestamp, a hash, a domain, an IP, etc. - that's enough to get going.

#### Timestamps
Simply grepping a few minutes before and after a timestamp works great:

```shell
$ cat INCIDENT32.json | grep '2014-01-01 11:3[2-8]'
```

#### Browser History
It's in there. A tool like [jq](http://stedolan.github.io/jq/) can be very helpful to do some fancy output:

```shell
$ cat INCIDENT32.json | grep '2014-01-01 11:3[2-8]' | jq 'select(has("url"))|.url'
```

#### A Single User
```shell
$ cat INCIDENT32.json | jq 'select(.osxcollector_username=="ivanlei")|.'
```

## Automated Analysis
The `osxcollector.output_filters` package contains filters that process and transform the output of OSXCollector. The goal of filters is to make it easy to analyze OSXCollector output.

Each filter has a single purpose. They do one thing and they do it right.

#### Running Filters in a VirtualEnv
Unlike `osxcollector.py` filters have dependencies that aren't already installed on a new Mac. The best solution for ensure dependencies can be found is to use virtualenv.

To setup a virtualenv for the first time use:
```shell
$ sudo pip install virtualenv
$ virtualenv --system-site-packages venv_osxcollector
$ source ./venv_osxcollector/bin/activate
$ sudo pip install -r ./requirements-dev.txt
```

#### Filter Configuration
Many filters require configuration, like API keys or details on a blacklist. The configuration for filters is done in a YAML file. The file is named `osxcollector.yaml`. The filter will look for the config file in:
- The current directory.
- The user's home directory
- The path pointed to by the environment variable OSXCOLLECTOR_CONF

A sample config is included. Make a copy and then modify if for yourself:
```shell
$ cp osxcollector.yaml.example osxcollector.yaml
$ emacs osxcollector.yaml
```

#### Basic Filters
Using combinations of these basic filters, an analyst can figure out a lot of what happened without expensive tools, without threat feeds and fancy APIs.

##### FindDomainsFilter
`osxcollector.output_filters.find_domains.FindDomainsFilter` attempts to find domain names in OSXCollector output. The domains are added to the line with the key `osxcollector_domains`.

FindDomainsFilter isn't too useful on it's own but it's super powerful when chained with filters like `FindBlacklistedFilter` and or `osxcollector.output_filters.virustotal.lookup_domains.LookupDomainsFilter`.

Run it as:
```shell
$ cat RomeoCredible.json | \
    python -m osxcollector.output_filters.find_domains
```

To see lines where domains have been added try:
```shell
$ jq 'select(has("osxcollector_domains"))'
```

##### FindBlacklistedFilter
`osxcollector.output_filters.find_blacklisted.FindBlacklistedFilter` reads a set of blacklists from the `osxcollector.yaml` and marks any lines with values on the blacklist. The BlacklistFilter is flexible and allows you to compare the OSXCollector output against multiple blacklists.

You _really should_ create blacklists for domains, file hashes, file names, and any known hinky stuff.

Configuration Keys:
* `blacklist_name`: [REQUIRED] the name of the blacklist.
* `blacklist_keys`: [REQUIRED] get the value of these keys and compare against the blacklist. These can be of the form `a.b` to look at `b` in `{"a": {"b": "foo"}}`
* `blacklist_file_path`: [REQUIRED] path to a file with the actual values to blacklist
* `blacklist_is_regex`: [REQUIRED] should the values in the blacklist file be treated as regex
* `blacklist_is_domains`: [OPTIONAL] interpret values as domains and do some smart regex and subdomain stuff with them.

Run it as:
```shell
$ cat RiddlerBelize.json | \
    python -m osxcollector.output_filters.find_blacklisted
```

To see lines matching a blacklist try:
```shell
$ jq 'select(has("osxcollector_blacklist"))'
```

##### RelatedFilesFilter
`osxcollector.output_filters.related_files.RelatedFilesFilter` takes an initial set of file paths, names, or terms. It breaks this input into individual file and directory names and then searches for these terms across the entire OSXCollector output. The filter is smart and ignores common terms like `bin` or `Library` as well as ignoring usernames.

This filter is great for figuring out how `evil_invoice.pdf` landed up on a machine. It'll find browser history, quarantines, email messages, etc. related to a file.

Run it as:
```shell
$ cat CanisAsp.json | \
    python -m osxcollector.output_filters.related_files
```

To see related lines try:
```shell
$ jq 'select(.osxcollector_related=="files")'
```

##### ChromeHistoryFilter
`osxcollector.output_filters.chome_history.ChromeHistoryFilter` builds a really nice Chrome browser history sorted in descending time order. This output is comparable to looking at the history tab in the browser but actually contains _more_ info. The `core_transition` and `page_transition` keys explain whether the user got to the page by clicking a link, through a redirect, a hidden iframe, etc.

Run it as:
```shell
$ cat PrinceCrazy.json | \
    python -m osxcollector.output_filters.chrome_history
```

To see Chrome browser history:
```shell
$ jq 'select(.osxcollector_browser_history=="chrome")'
```

This is great mixed with a grep in a certain time window, like maybe the 5 minutes before that hinky download happened.

##### FirefoxHistoryFilter
`osxcollector.output_filters.firefox_history.FirefoxHistoryFilter` builds a really nice Firefox browser history sorted in descending time order. It's a lot like the `ChromeHistoryFilter`.

Run it as:
```shell
$ cat CousingLobe.json | \
    python -m osxcollector.output_filters.firefox_history
```

To see Firefox browser history:
```shell
$ jq 'select(.osxcollector_browser_history=="firefox")'
```

#### Threat API Filters
By taking the output of OSXCollector and looking up further info with OpenDNS and VirusTotal APIs, Yelp enhances the output with useful info. These APIs aren't free but they are useful.

Using these filters as examples, it would be possible to integrate with additional free or premium threat APIs. `osxcollector.output_filters.base_filters.threat_feed.ThreatFeedFilter` has most of the plumbing for hooking up to arbitrary APIs.

##### OpenDNS RelatedDomainsFilter
`osxcollector.output_filters.opendns.related_domains.RelatedDomainsFilter` takes an initial set of domains and IPs and then looks up domains related to them with the OpenDNS Umbrella API.

Often an initial alert contains a domain or IP your analysts don't know anything about. However, by gathering the 2nd generation related domains, familiar _friends_ might appear. When you're lucky, those related domains land up being the download source for some downloads you might have overlooked.

Run it as:
```shell
$ cat NotchCherry.json | \
    python -m osxcollector.output_filters.find_domains | \
    python -m osxcollector.output_filters.opendns.related_domains
```

To see what it found:
```shell
$ jq 'select(.osxcollector_related=="domains")'
```

##### OpenDNS LookupDomainsFilter
`osxcollector.output_filters.opendns.lookup_domains.LookupDomainsFilter` lookups domain reputation and threat information with the OpenDNS Umbrella API. It adds information about _suspicious_ domains to the output lines.

The filter uses a heuristic to determine what is _suspicious_. It can create false positives but usually a download from a domain marked as _suspicious_ is a good lead.

Run it as:
```shell
$ cat GladElegant.json | \
    python -m osxcollector.output_filters.find_domains | \
    python -m osxcollector.output_filters.opendns.lookup_domains
```

To see what it found:
```shell
$ jq 'select(has("osxcollector_opendns"))'
```

##### VirusTotal LookupDomainsFilter
`osxcollector.output_filters.virustotal.lookup_domains.LookupDomainsFilter` lookups domain reputation and threat information with the VirusTotal API. It adds information about _suspicious_ domains to the output lines. It's a lot like the OpenDNS filter of the same name.

The filter uses a heuristic to determine what is _suspicious_. It can create a lot of false positives but also provides good leads.

Run it as:
```shell
$ cat PippinNightstar.json | \
    python -m osxcollector.output_filters.find_domains | \
    python -m osxcollector.output_filters.virustotal.lookup_domains
```

To see what it found:
```shell
$ jq 'select(has("osxcollector_vtdomain"))'
```

##### VirusTotal LookupHashesFilter
`osxcollector.output_filters.virustotal.lookup_hashes.LookupHashesFilter` lookups hashes with the VirusTotal API. This basically finds anything VirusTotal knows about which is a huge timesaver. There's pretty much no false positives here, but there's also no chance of detecting unknown stuff.

Run it as:
```
$ cat PippinNightstar.json | \
    python -m osxcollector.output_filters.virustotal.lookup_hashes
```

To see what it found:
```shell
$ jq 'select(has("osxcollector_vthash"))'
```

#### AnalyzeFilter - The One Filter to Rule Them All
`osxcollector.output_filters.analyze.AnalyzeFilter` is Yelp's _one filter to rule them all_. It chains all the previous filters into one monster analysis. The results, enhanced with blacklist info, threat APIs, related files and domains, and even pretty browser history is written to a new output file.

Then _Very Readable Output Bot_ takes over and prints out an easy-to-digest, human-readable, nearly-English summary of what it found. It's basically equivalent to running:
```shell
$ cat SlickApocalypse.json | \
    python -m osxcollector.output_filters.find_domains | \
    python -m osxcollector.output_filters.related_files | \
    python -m python -m osxcollector.output_filters.opendns.related_domains | \
    python -m osxcollector.output_filters.opendns.lookup_domains | \
    python -m osxcollector.output_filters.virustotal.lookup_domains | \
    python -m osxcollector.output_filters.virustotal.lookup_hashes | \
    python -m osxcollector.output_filters.chrome_history | \
    python -m osxcollector.output_filters.firefox_history | \
    tee analyze_SlickApocalypse.json | \
    jq 'select('
      'has("osxcollector_vthash" or'
      'has("osxcollector_vtdomain") or'
      'has("osxcollector_opendns") or'
      'has("osxcollector_blacklist") or'
      'has("osxcollector_related"))'
```
and then letting a wise-cracking analyst explain the results to you. The _Very Readable Output Bot_ even suggests hashes and domains to add to blacklists.

This thing is the real deal and our analysts don't even look at OSXCollector output until after they've run the `AnalyzeFilter`.

## Contributing to OSXCollector
We encourage you to extend the functionality of OSXCollector to suit your needs.

#### Testing OSXCollector
A collection of tests for osxcollector is provided under the `tests` directory. In order to run these tests you must install [tox](https://pypi.python.org/pypi/tox):
```shell
$ sudo pip install tox
```

To run this suit of tests, `cd` into `osxcollector` and enter:
```shell
$ make test
```

#### Development Tips
The functionality of OSXCollector is stored in a single file: `osxcollector.py`.

Ensure that all of the osxcollector tests pass before editing the source code. You can run the tests using: `make test`

After making changes to the source code, run `make test` again to verify that your changes did not break any of the tests.

## License
This work is licensed under the GNU General Public License and a derivation of [https://github.com/jipegit/OSXAuditor](https://github.com/jipegit/OSXAuditor)
