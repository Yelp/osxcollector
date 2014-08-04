.DELETE_ON_ERROR:

all:
	echo >&2 "Must specify target."

test:
	tox

clean:
	rm -rf build/ dist/ osxcollector.egg-info/ .tox/

.PHONY: all test test-osxcollector clean
