# OSXCollector
## [Visit our wiki for more info!](https://github.com/Yelp/osxcollector/wiki)

## How'd that malware get there?

That's the question you've got to answer for every OSX malware infection. We built OSXCollector to make that easy. Quickly parse its output to get an answer.

A typical infection might follow a path like:

 1. a phishing email leads to a malicious download
 2. once installed, the initial establishes persistence
 3. then it reaches out on the network and pulls down additional payloads

With the output of OSXCollector we quickly correlate between browser history, startup items, downloads, and installed applications. It makes root causing an infection, collect IOCs, and get to the bottom of an infection.

## So what does it do?

OSXCollector gathers information from plists, sqlite databases and the local filesystems to get the information for analyzing a malware infection. The output is JSON which makes it easy to process it further by other tools.

[Visit our wiki for more info!](https://github.com/Yelp/osxcollector/wiki)

## License

This work is licensed under the GNU General Public License and a derivation of [https://github.com/jipegit/OSXAuditor](https://github.com/jipegit/OSXAuditor)
