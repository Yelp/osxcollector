# -*- coding: utf-8 -*-
#
# ThreatFeedFilter is a base class to find suspicious IOC using some random API.
#
from osxcollector.output_filters.base_filters.output_filter import OutputFilter


class ThreatFeedFilter(OutputFilter):

    """A base class to find info on IOCs using some random API.

    Derrived classes need only to implement _lookup_iocs()

    It is assumed that the API uses an api_key stored in the config.
    """

    def __init__(self, ioc_key, output_key, lookup_when=None, suspicious_when=None, api_key=None):
        """Read API config

        Args:
            ioc_key: key for finding IOCs in the input
            output_key: key to use to add threat info to the output
            lookup_when: a boolean function to call to decide whether to try a lookup for a blob
            is_suspicious_when: a boolean function to call to decide whether a blob is already known to be suspicious
            api_key: name of the key in the 'api_key' section of config
        """
        super(ThreatFeedFilter, self).__init__()

        if api_key:
            self._api_key = self.config.get_config('api_key.{0}'.format(api_key))

        self._lookup_when = lookup_when
        self._is_suspicious_when = suspicious_when
        self._blobs_with_iocs = list()
        self._all_iocs = set()
        self._suspicious_iocs = set()
        self._threat_info_by_iocs = dict()

        self._ioc_key = ioc_key
        self._output_key = output_key

    def _lookup_iocs(self):
        """Caches the threat info for a set of IOCs into self._threat_info_by_iocs

        This is the only method a derived class needs to implement.
        The set of IOCs to lookup is self._all_iocs
        Anything to be added to the output should be stored in the dict self._threat_info_by_iocs which is keyed by IOC
        """
        raise NotImplementedError('Derived classes must implement _lookup_iocs')

    def filter_line(self, blob):
        """Accumulate IOCs to lookup with the ThreatFeed.

        Args:
            blob: A dict

        Returns:
            A Line or None
        """
        if self._ioc_key in blob and (not self._lookup_when or self._lookup_when(blob)):
            ioc_list = blob[self._ioc_key]
            if isinstance(ioc_list, basestring):
                ioc_list = [ioc_list]

            if len(ioc_list) > 10:
                return blob

            is_suspicious = self._is_suspicious_when and self._is_suspicious_when(blob)
            for ioc in ioc_list:
                if not len(ioc):
                    continue

                self._all_iocs.add(ioc)
                if is_suspicious:
                    self._suspicious_iocs.add(ioc)

            self._blobs_with_iocs.append(blob)
            return None
        else:
            return blob

    def end_of_lines(self):
        """Performs threat feed lookup on the IOCs and adds output to the stored Lines.

        Returns:
            An array of strings
        """
        self._all_iocs = sorted(list(self._all_iocs))
        self._suspicious_iocs = sorted(list(self._suspicious_iocs))

        self._lookup_iocs()
        self._add_threat_info_to_blobs()
        return self._blobs_with_iocs

    def _add_threat_info_to_blobs(self):
        """Adds threat info to blobs"""
        for blob in self._blobs_with_iocs:
            ioc_list = blob[self._ioc_key]
            if isinstance(ioc_list, basestring):
                ioc_list = [ioc_list]

            for ioc in ioc_list:
                threat_info = self._threat_info_by_iocs.get(ioc)
                if threat_info:
                    blob.setdefault(self._output_key, [])
                    blob[self._output_key].append(threat_info)
