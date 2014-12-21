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
  $ sudo osxcollector.py -p /mnt/powned
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
  $ sudo osxcollector.py -s startup -s downloads
  ```

* `-d`/`--debug`:
  Enables verbose output and python breakpoints. If something is wrong with OSXCollector, try this.

  ```shell
  $ sudo osxcollector.py -d
  ```

## Details of Collection
The collector outputs a `.tar.gz` containing all the collected artifacts. The archive contains a JSON file with the majority of information.  Additionally, a set of useful logs from the target system logs are included.

#### Common Keys

Each line of the JSON file records 1 _piece of information_.  There are some common keys that appear in every JSON record:
* `osxcollector_incident_id`: A unique ID shared by every record.
* `osxcollector_section`: The _section_ or type of data this record holds.
* `osxcollector_subsection`: The _subsection_ or more detailed descriptor of the type of data this record holds.

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

#### `version` section

The current version of OSXCollector.

#### `system_info` section

Collects basic information about the system:

 - system name
 - node name
 - release
 - version
 - machine

#### `kext` section

Collects the Kernel extensions from:
- `/System/Library/Extensions`
- '/Library/Extensions'

#### `startup` section

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

#### `applications` section

Hashes installed applications and gathers install history from:

 - `/Applications`
 - `~/Applications`
 - `/Library/Receipts/InstallHistory.plist`

#### `quarantines`

Quarantines are basically the info necessary to show the 'Are you sure you wanna
run this?' when a user is trying to open a file downloaded from the internet.
For some more details, checkout the Apple Support explanation of Quarantines:
http://support.apple.com/kb/HT3662

This section collects also information from XProtect hash-based malware check
for quarantines files. The plist is at:
`/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/XProtect.plist`

XProtect also add minimum versions for Internet Plugins. That plist is at:
`/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/XProtect.meta.plist`

#### `downloads` section

Hashes all users' downloaded files from:

 - `~/Downloads`
 - `~/Library/Mail Downloads`
 - `~/Library/Containers/com.apple.mail/Data/Library/Mail Downloads`

#### `chrome` section

Collects following information from Google Chrome web browser:

 - History
 - Archived History
 - Cookies
 - Login Data
 - Top Sites
 - Web Data

This data is extracted from `~/Library/Application Support/Google/Chrome/Default`

#### `firefox` section

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

#### `safari` section

Collects information from the different plist and SQLite databases in a Safari
profile:

 - Downloads
 - History
 - Databases
 - Local Storage

#### `accounts` section
Collects information about users' accounts:

 - system admins: `/private/var/db/dslocal/nodes/Default/groups/admin.plist`
 - system users: `/private/var/db/dslocal/nodes/Default/users`
 - social accounts: `~/Library/Accounts/Accounts3.sqlite`
 - users' recent items: `~/Library/Preferences/com.apple.recentitems.plist`

#### `mail` section
Hashes files in the mail app directories:

 - `~/Library/Mail`
 - `~/Library/Mail Downloads`

## Performing Analysis

## Automated Analysis

## Contributing to OSXCollector

## License
This work is licensed under the GNU General Public License and a derivation of [https://github.com/jipegit/OSXAuditor](https://github.com/jipegit/OSXAuditor)
