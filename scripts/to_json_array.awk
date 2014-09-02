#!/usr/bin/awk -f
BEGIN { print "[" }
{ print $0, "," }
END { print "]" }

