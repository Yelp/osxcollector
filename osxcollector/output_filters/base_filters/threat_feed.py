# -*- coding: utf-8 -*-
#
# ThreatFeedFilter is a base class to find info on IOCs using some random API.
#
from osxcollector.output_filters.base_filters.output_filter import OutputFilter
from osxcollector.output_filters.util.config import config_get_deep


class ThreatFeedFilter(OutputFilter):

    """A base class to find info on IOCs using some random API.

    Derived classes need only to implement _lookup_iocs()
    If necessary, they should implement _should_add_threat_info_to_blob.

    It is assumed that the API uses an api_key stored in the config.
    """

    def __init__(self, ioc_key, output_key, lookup_when=None, name_of_api_key=None, **kwargs):
        """Configure the ThreatFeedFilter.

        Args:
            ioc_key: A string key to look for in each line of OSXCollector output.
                The value of this key is the potential IOC to lookup in a threat feed.
            output_key: A string key which is added to output lines and contains the result of threat feed lookups.
            lookup_when: A boolean function to call to decide whether to perform a lookup on a line.
                Use lookup_when to limit which IOCs are looked up.
            name_of_api_key: A string name of the key in the 'api_key' section of config.
        """
        super(ThreatFeedFilter, self).__init__(**kwargs)

        if name_of_api_key:
            self._api_key = config_get_deep('api_key.{0}'.format(name_of_api_key))

        self._lookup_when = lookup_when
        self._blobs_with_iocs = list()
        self.ioc_set = set()

        self._ioc_key = ioc_key
        self._output_key = output_key

    def _lookup_iocs(self, all_iocs):
        """Looks up threat info for IOCs.

        This is the only method a derived class needs to implement.

        Args:
            all_iocs: An enumerable of strings representing all IOCs to lookup.
        Returns:
            A dict of the form {ioc_value: threat_info}
        """
        raise NotImplementedError('Derived classes must implement _lookup_iocs')

    def _should_add_threat_info_to_blob(self, blob, threat_info):
        """Threat info is only added to a blob if this returns True.

        Override this method in derived classes to correlate threat_info and blob data.

        For example, the ShadowServer filter looks up SHA1 hashes. Since SHA1 hashes for different files collide, the ShadowServer
        filter overrides _should_add_threat_info_to_blob and verifies that the filename in the blob matches the filename in the threat
        info.

        Args:
            blob: A dict of data representing a line of output from OSXCollector
            threat_info: A dict of threat info.
        Returns:
            boolean
        """
        return True

    def filter_line(self, blob):
        """Accumulate IOCs to lookup with the ThreatFeed.

        Args:
            blob: A dict representing one line of output from OSXCollector.
        Returns:
            A dict or None
        """
        if self._ioc_key in blob and (not self._lookup_when or self._lookup_when(blob)):
            ioc_list = blob[self._ioc_key]
            if isinstance(ioc_list, basestring):
                ioc_list = [ioc_list]

            if len(ioc_list) > 10:
                return blob

            for ioc in ioc_list:
                if not len(ioc):
                    continue

                self.ioc_set.add(ioc)

            self._blobs_with_iocs.append(blob)
            return None
        else:
            return blob

    def end_of_lines(self):
        """Performs threat feed lookup on the IOCs and adds output to the stored Lines.

        Returns:
            An enumerable of dicts
        """
        if self.ioc_set:
            self._add_threat_info_to_blobs()
        return self._blobs_with_iocs

    def _add_threat_info_to_blobs(self):
        """Adds threat info to blobs.

        Args:
            all_threat_info: A dict of the form {ioc_value: threat_info}
        """
        self.ioc_set = sorted(list(self.ioc_set))
        all_threat_info = self._lookup_iocs(self.ioc_set)
        for blob in self._blobs_with_iocs:
            ioc_list = blob[self._ioc_key]
            if isinstance(ioc_list, basestring):
                ioc_list = [ioc_list]

            for ioc in ioc_list:
                info = all_threat_info.get(ioc)
                if not info:
                    continue

                if self._should_add_threat_info_to_blob(blob, info):
                    blob.setdefault(self._output_key, [])
                    blob[self._output_key].append(info)
