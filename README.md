# OSXCollector Manual
OSXCollector is a forensice evidence collection & analysis toolkit for OSX.

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
The `osxcollector.output_filters` package contains filters that process and transform the output of OSXCollector. The goal of filters is to make it easier to understand output.

Each filter has a single purpose. They do one thing and they do it right.

#### Running Filters
Unlike `osxcollector.py` filters have dependencies that aren't already installed on a new Mac. The best solution for ensure dependencies can be found is to use virtualenv.

To setup a virtualenv for the first time use:
```
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

#### DomainsFilter
`osxcollector.output_filters.domains` attempts to find domain names in a line. Any domains that are found are added to the line with the key `osxcollector_domains`. Run it as:
```
$ cat INCIDENT32.json | python -m osxcollector.output_filters.domains | jq 'select(has("osxcollector_domains"))'
```

#### ChromeHistoryFilter
`osxcollector.output_filters.chome_history` builds a really nice Chrome browser history sorted in descending time order. Run it as:
```
$ cat INCIDENT32.json | python -m osxcollector.output_filters.chrome_history | jq 'select(.osxcollector_section=="chrome" and .osxcollector_subsection=="history" and .osxcollector_table_name =="visits")'
```

#### FirefoxHistoryFilter
`osxcollector.output_filters.firefox_history` builds a really nice Firefox browser history sorted in descending time order. Run it as:
```
$ cat INCIDENT32.json | python -m osxcollector.output_filters.firefox_history | jq 'select(.osxcollector_section=="firefox" and .osxcollector_subsection=="history" and .osxcollector_table_name =="moz_places")'
```

#### OpenDNSFilter
`osxcollector.output_filters.opendns` lookups domains with OpenDNS. Domains associated with suspicious categories are futher enhanced with additional OpenDNS data. Run it as:
```
$ cat INCIDENT32.json | python -m osxcollector.output_filters.domains | python -m osxcollector.output_filters.opendns | jq 'select(has("osxcollector_opendns"))'
```

#### VTHashesFilter
`osxcollector.output_filters.virustotal_hashes` lookups md5 hashes with VirusTotal. Run it as:
```
$ cat INCIDENT32.json | python -m osxcollector.output_filters.virustotal_hashes | jq 'select(has("osxcollector_vt_hashes"))'
```

#### BlacklistFilter
`osxcollector.output_filters.blacklist` reads a set of blacklists from the `osxcollector.yaml` and marks any lines with values on the blacklist. The BlacklistFilter allows for multiple blacklists to be compared against at once. Each blacklists requires:
 - blacklist_name, A name
 - blacklist_keys, JSON paths. These can be of the form "a.b" to look at "b" in {"a": {"b": "foo"}}
 - value_file, the path to a file containing values considered blacklisted. Any line starting with # is skipped
 - blacklist_is_regex, should values in the file be treated as Python regex

Run it as:
```shell
$ cat INCIDENT32.json | python -m osxcollector.output_filters.blacklist | jq 'select(has("osxcollector_blacklist"))'
```

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

Please note that tox will fail to run if osxcollector is stored under a path containing white spaces.
  Bad Path  -> "/path/to/my files/osxcollector"
  Good Path -> "/path/to/my_files/osxcollector"

#### Development Tips
The functionality of OSXCollector is stored in a single file: `osxcollector.py`.

Ensure that all of the osxcollector tests pass before editing the source code. You can run the tests using: `make test`

After making changes to the source code, run `make test` again to verify that your changes did not break any of the tests.

## License
This work is licensed under the GNU General Public License and a derivation of [https://github.com/jipegit/OSXAuditor](https://github.com/jipegit/OSXAuditor)
