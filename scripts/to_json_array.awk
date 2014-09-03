#!/usr/bin/awk -f
BEGIN { print "[" }
{
    if (NR != 1)
        printf ","
    print $0
}
END { print "]" }

