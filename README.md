![osxcollector](https://raw.githubusercontent.com/Yelp/osxcollector/master/osx-github.png)

[![Stories in Ready](https://badge.waffle.io/Yelp/osxcollector.png?label=ready&title=Ready)](https://waffle.io/Yelp/osxcollector)
[![Stories in In Progress](https://badge.waffle.io/Yelp/osxcollector.png?label=in%20progress&title=In%20Progress)](https://waffle.io/Yelp/osxcollector)
[![Build Status](https://travis-ci.org/Yelp/osxcollector.svg)](https://travis-ci.org/Yelp/osxcollector)
[![PyPI](https://img.shields.io/pypi/v/osxcollector.svg)](https://pypi.python.org/pypi/osxcollector)

# OSXCollector Manual
OSXCollector is a forensic evidence collection & analysis toolkit for OSX.

#### Forensic Collection
The collection script runs on a potentially infected machine and outputs a JSON file that describes the target machine. OSXCollector gathers information from plists, SQLite databases and the local file system.

#### Forensic Analysis
Armed with the forensic collection, an analyst can answer the question like:
* _Is this machine infected?_
* _How'd that malware get there?_
* _How can I prevent and detect further infection?_

Yelp automates the analysis of most OSXCollector runs converting its output into an easily readable and actionable summary of _just the suspicious stuff_. Check out [OSXCollector Output Filters project](https://github.com/Yelp/osxcollector_output_filters) to learn how to make the most of the automated OSXCollector output analysis.

## Performing Collection
[`osxcollector.py`](https://raw.githubusercontent.com/Yelp/osxcollector/master/osxcollector/osxcollector.py) is a single Python file that runs without any dependencies on a standard OSX machine. This makes it really easy to run collection on any machine - no fussing with brew, pip, config files, or environment variables. Just copy the single file onto the machine and run it:

`sudo osxcollector.py` is all it takes.

```shell
$ sudo osxcollector.py
Wrote 35394 lines.
Output in osxcollect-2014_12_21-08_49_39.tar.gz
```

If you have just cloned the GitHub repository, `osxcollector.py` is inside `osxcollector/` directory, so you need to run it as:

```shell
$ sudo osxcollector/osxcollector.py
```

**IMPORTANT:** please make sure that `python` command on your Mac OS X machine uses the default Python interpreter shipped with the system and is not overridden, e.g. by the Python version installed through brew. OSXCollector relies on a couple of native Python bindings for OS X libraries, which might be not available in other Python versions than the one originally installed on your system.
Alternatively, you can run `osxcollector.py` explicitly specifying the Python version you would like to use:

```shell
$ sudo /usr/bin/python2.7 osxcollector/osxcollector.py
```

The JSON output of the collector, along with some helpful files like system logs, has been bundled into a .tar.gz for hand-off to an analyst.

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
  Runs only a portion of the full collection. Can be specified more than once. The full list of sections and subsections is:
  * `version`
  * `system_info`
  * `kext`
  * `startup`
    * `launch_agents`
    * `scripting_additions`
    * `startup_items`
    * `login_items`
  * `applications`
    * `applications`
    * `install_history`
  * `quarantines`
  * `downloads`
    * `downloads`
    * `email_downloads`
    * `old_email_downloads`
  * `chrome`
    * `history`
    * `archived_history`
    * `cookies`
    * `login_data`
    * `top_sites`
    * `web_data`
    * `databases`
    * `local_storage`
    * `preferences`
  * `firefox`
    * `cookies`
    * `downloads`
    * `formhistory`
    * `history`
    * `signons`
    * `permissions`
    * `addons`
    * `extension`
    * `content_prefs`
    * `health_report`
    * `webapps_store`
    * `json_files`
  * `safari`
    * `downloads`
    * `history`
    * `extensions`
    * `databases`
    * `localstorage`
    * `extension_files`
  * `accounts`
    * `system_admins`
    * `system_users`
    * `social_accounts`
    * `recent_items`
  * `mail`
  * `full_hash`

  ```shell
  $ sudo osxcollector.py -s 'startup' -s 'downloads'
  ```

* `-c`/`--collect-cookies`:
  Collect cookies' value.
  By default OSXCollector does not dump the value of a cookie, as it may contain sensitive information (e.g. session id).

* `-l`/`--collect-local-storage`:
  Collect the values stored in web browsers' local storage.
  By default OSXCollector does not dump the values as they may contain sensitive information.

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
* `atime`: The file accessed time.
* `ctime`: The file creation time.
* `mtime`: The file modified time.
* `file_path`: The absolute path to the file.
* `md5`: MD5 hash of the file contents.
* `sha1`: SHA1 hash of the file contents.
* `sha2`: SHA2 hash of the file contents.

For records representing downloaded files:
* `xattr-wherefrom`: A list containing the source and referrer URLs for the downloaded file.
* `xattr-quarantines`: A string describing which application downloaded the file.

##### SQLite Records
For records representing a row of a SQLite database:
* `osxcollector_table_name`: The table name the row comes from.
* `osxcollector_db_path`: The absolute path to the SQLite file.

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

Quarantines are basically the info necessary to show the 'Are you sure you wanna run this?' when a user is trying to open a file downloaded from the Internet.
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
 - Extensions
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
 - Extensions
 - Content Preferences
 - Health Report
 - Webapps Store

This information is extracted from `~/Library/Application Support/Firefox/Profiles`

For more details about Firefox profile folder see
http://kb.mozillazine.org/Profile_folder_-_Firefox

##### `safari` section

Collects information from the different plists and SQLite databases in a Safari
profile:

 - Downloads
 - History
 - Extensions
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

##### `full_hash` section
Hashes all the files on disk. All of 'em. This does not run by default. It must be triggered with:
```shell
$ sudo osxcollector.py -s full_hash
```

## Basic Manual Analysis
Forensic analysis is a bit of art and a bit of science. Every analyst will see a bit of a different story when reading the output from OSXCollector. That's part of what makes analysis fun.

Generally, collection is performed on a target machine because something is hinky: anti-virus found a file it doesn't like, deep packet inspect observed a callout, endpoint monitoring noticed a new startup item. The details of this initial alert - a file path, a timestamp, a hash, a domain, an IP, etc. - that's enough to get going.

#### Timestamps
Simply greping a few minutes before and after a timestamp works great:

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
The [OSXCollector Output Filters project](https://github.com/Yelp/osxcollector_output_filters) contains filters that process and transform the output of OSXCollector. The goal of filters is to make it easy to analyze OSXCollector output.

#### Development Tips
The functionality of OSXCollector is stored in a single file: `osxcollector.py`. The collector should run on a naked install of OS X without any additional packages or dependencies.

Ensure that all of the OSXCollector tests pass before editing the source code. You can run the tests using: `make test`

After making changes to the source code, run `make test` again to verify that your changes did not break any of the tests.

## License
This work is licensed under the GNU General Public License and a derivation of [https://github.com/jipegit/OSXAuditor](https://github.com/jipegit/OSXAuditor)

## Blog post

* [OSXCollector: Forensic Collection and Automated Analysis for OS X](http://engineeringblog.yelp.com/2015/01/osxcollector-forensic-collection-and-automated-analysis-for-os-x.html) by Ivan Leichtling

## Presentations

* [OSXCollector: Automated forensic evidence collection & analysis for OS X](https://www.youtube.com/watch?v=l-lhyPcSd6I) by Kuba Sendor @ BruCON 0x07
* [Squashing Rotten Apples: Automated forensics & analysis for Mac OS X with OSXCollector](https://www.youtube.com/watch?v=XeeCO8moyeE) by Kuba Sendor @ BSides Manchester 2015
* [OSXCollector](http://macbrained.org/recap-august15-yelp/) by Ivan Leichtling @ Macbrained's August Meet-Up
* [OSXCollector - Automated Forensic Evidence Collection & Analysis for OS X](https://www.youtube.com/watch?v=Yqny1rMTfyY) by Ivan Leichtling @ OpenNSM
* [OSXCollector - Automated Forensic Evidence Collection & Analysis for OS X](https://www.youtube.com/watch?v=DfANq2ncaKU) by Ivan Leichtling @ Duo Tech Talk ([blog post](https://www.duosecurity.com/blog/duo-tech-talk-osxcollector-automated-forensic-evidence-collection-and-analysis-for-os-x))

## External Presentations

* [OSX Archaeology: Becoming Indiana Jones with OSXCollector and Strata](https://www.youtube.com/watch?v=9wvhOoXl2Os) by Chris Henderson & Justin Larson @ SAINTCon 2015

## Resources
Want to learn more about OS X forensics?
* [Sarah Edward's mac4n6.com](http://www.mac4n6.com/) - The best presentations on Mac forensics.

A couple of other interesting tools:
* [KnockKnock](https://github.com/synack/knockknock) - KnockKnock is a command line python script that displays persistent OS X binaries that are set to execute automatically at each boot.
* [Grr](https://github.com/google/grr) - Google Rapid Response: remote live forensics for incident response
* [osquery](https://github.com/facebook/osquery) - SQL powered operating system instrumentation, monitoring, and analytics
