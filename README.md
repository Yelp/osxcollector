# OSXCollector
## how'd that malware get there?
That's the question you've got to answer for every OSX malware infection. We built OSXCollector to make that easy. Quickly parse its output to get an answer.

A typical infection might follow a path like:
 - a phishing email leads to a malicious download
 - once installed, the initial establishes persistence
 - then it reaches out on the network and pulls down additional payloads

With the output of OSXCollector we quickly correlate between browser history, startup items, downloads, and installed applications. It makes root causing an infection, collect IOCs, and get to the bottom of an infection.

## so what's it do
OSXCollector gathers information from plists, sqlite databases and the local filesystems to get the information for analyzing a malware infection. The output is JSON which makes it easy to process it further by other tools.

## usage
Tool is self contained in one script file [osxcollector](osxcollector/osxcollector.py).

Launch OSXCollector as root or it will be unable to read data from all accounts

`
sudo python osxcollector.py
`

Before running the tool make sure that your web browsers (Safari, Chrome or Firefox) are closed. Otherwise OS X Collector will not be able to access their diagnostic files for collecting the data.

### options
#### incident prefix
```
-i INCIDENT_PREFIX, --id=INCIDENT_PREFIX
                        [OPTIONAL] An identifier which will be added as a
                        prefix to the output file name.
```
For example:

`
sudo python osxcollector.py -i INCIDENT32
`

would create an output file named `INCIDENT32-2014_07_08-15_57_54.tar.gz`

#### output file name
```
 -o OUTPUT_FILE_NAME, --outputfile=OUTPUT_FILE_NAME
                        [OPTIONAL] Name of the output file. Default name uses
                        the timestamp. Try '/dev/stdout' for fun!
```

For example:

`
sudo python osxcollector.py -o collection_report
`

would create an output file named `collection_report.tar.gz`

#### root path
```
  -p ROOTPATH, --path=ROOTPATH
                        [OPTIONAL] Path to the OS X system to audit (e.g.
                        /mnt/xxx). The running system will be audited if not
                        specified.
```

For example:

`
sudo python osxcollector.py -p /Volumes/UNTITLED
`

would look in ` /Volumes/UNTITLED` as the root of the system to analyze.

#### section
```
  -s SECTION_LIST, --section=SECTION_LIST
                        [OPTIONAL] Just run the named section.  May be
                        specified more than once.
```

The full list of sections:
*  system_info
*  kext
*  startup
*  applications
*  quarantines
*  downloads
*  chrome
*  firefox
*  safari
*  accounts
*  mail

For example:

`
sudo python osxcollector.py -s startup -s downloads
`

would only collect the `startup` and `downloads` sections.

#### debug
```
  -d, --debug           [OPTIONAL] Enable verbose output and python
                        breakpoints.
```

If something's wrong with OSXCollector, try this.

## output
All output is stored in a .tar.gz.
Inside the archive is a JSON file with the majority of information.  Additionally, a copy of all system logs are included.

### common keys
Each line of the JSON file records 1 "piece of information".  There are some common keys in all lines:
```
osxcollector_incident_id    a unique id, same as the JSON filename
osxcollector_section        the section for this record
osxcollector_subsection     the subsection for this record
```

For records representing files:
```
ctime       file creation time
mtime       file modified time
file_path   path to the file
md5         md5 hash of the file
sha1        sha1 hash of the file
sha2        sha256 hash of the file
```

For records representing rows from a database:
```
osxcollector_table_name the database table name
osxcollector_db_path    path to the sqllite file
```

For records that represent data associated with a specific user:
```
osxcollector_username   the name of the user
```

### timestamps
OSXCollector attempts to convert timestamps to human readable date/time strings in the format `YYYY-mm-dd hh:MM:ss`. It uses heuristics to automatically identify various timestamps:
* seconds since epoch
* milliseconds since epoch
* seconds since 2001-01-01
* seconds since 1601-01-01

## details on data collection

### system_info
Collects basic information about the system:
 - system name
 - node name
 - release
 - version
 - machine

### kext
Collects the Kernel extensions from `/System/Library/Extensions`.

### startup

Collects information about the
[LaunchAgents](https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man5/launchd.plist.5.html),
LaunchDaemons, ScriptingAdditions,
[StartupItems](https://developer.apple.com/library/mac/documentation/macosx/conceptual/bpsystemstartup/chapters/StartupItems.html)
and other login items from:
 - /System/Library/LaunchAgents
 - /System/Library/LaunchDaemons
 - /Library/LaunchAgents
 - ~/Library/LaunchAgents
 - /Library/LaunchDaemons
 - /System/Library/ScriptingAdditions
 - /Library/ScriptingAdditions
 - /System/Library/StartupItems
 - /Library/StartupItems
 - ~/Library/Preferences/com.apple.loginitems.plist

More information about the Max OS X startup can be found here:
http://www.malicious-streams.com/article/Mac_OSX_Startup.pdf

### applications

Hashes installed applications and gathers install history from:
 - /Applications
 - ~/Applications
 - /Library/Receipts/InstallHistory.plist

### quarantines

Quarantines are basically the info necessary to show the 'Are you sure you wanna
run this?' when a user is trying to open a file downloaded from the internet.
For some more details, checkout the Apple Support explanation of Quarantines:
http://support.apple.com/kb/HT3662

This section collects also information from XProtect hash-based malware check
for quarantines files. The plist is at:
/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/XProtect.plist

XProtect also add minimum versions for Internet Plugins. That plist is at:
/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/XProtect.meta.plist

### downloads

Hashes all users' downloaded files from:
 - ~/Downloads
 - ~/Library/Mail Downloads
 - ~/Library/Containers/com.apple.mail/Data/Library/Mail Downloads

### chrome

Collects following information from Google Chrome web browser:
 - History
 - Archived History
 - Cookies
 - Login Data
 - Top Sites
 - Web Data

This data is extracted from ~/Library/Application Support/Google/Chrome/Default

### firefox

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

This information is extracted from ~/Library/Application Support/Firefox/Profiles

For more details about Firefox profile folder see
http://kb.mozillazine.org/Profile_folder_-_Firefox

### safari

Collects information from the different plist and SQLite databases in a Safari
profile:
 - Downloads
 - History
 - Databases
 - Local Storage

### accounts

Collects information about users' accounts:
 - system admins: /private/var/db/dslocal/nodes/Default/groups/admin.plist
 - system users: /private/var/db/dslocal/nodes/Default/users
 - social accounts: ~/Library/Accounts/Accounts3.sqlite
 - users' recent items: ~/Library/Preferences/com.apple.recentitems.plist

### mail

Hashes files in the mail app directories:
 - ~/Library/Mail
 - ~/Library/Mail Downloads

## tips on analyzing output
Exactly how Yelp uses the output from OSXCollector is a bit of our secret sauce but we'll share a bit. Assume you've got some starting information - a file path, a timestamp, a url, etc. - that's enough to get going.

### time stamps
Simply grepping a few minutes before and after a timestamp works great:

```
$ cat INCIDENT32.json | grep '2014-01-01 11:3[2-8]'
```

### browser history
It's in there. A tool like [jq](http://stedolan.github.io/jq/) can be very helpful to do some fancy output:
```
$ cat INCIDENT32.json | grep '2014-01-01 11:3[2-8]' | jq 'select(has("url"))|.url'
```

### just stuff about ivanlei
```
$ cat INCIDENT32.json | jq 'select(.osxcollector_username=="ivanlei")|.'
```

### visualizations to blow your mind
We're huge fans of ElasticSearch/Logstash/Kibana. They create an awesome pipeline for searching visualizing, and correlating JSON.

## license
This work is licensed under the GNU General Public License and a derivation of [https://github.com/jipegit/OSXAuditor](https://github.com/jipegit/OSXAuditor)
