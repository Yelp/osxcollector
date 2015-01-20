# -*- coding: utf-8 -*-
from StringIO import StringIO

import testify as T
from mock import patch

from osxcollector.output_filters.exceptions import BadDomainError
from osxcollector.output_filters.util.error_messages import write_error_message
from osxcollector.output_filters.util.error_messages import write_exception


class StdErrTestCase(T.TestCase):

    """Mocks out sys.stderr"""

    @T.setup_teardown
    def setupStringIO(self):
        self._stringio = StringIO()
        with patch('sys.stderr', self._stringio):
            yield


class WriteExceptionTest(StdErrTestCase):

    def test_simple_exception(self):
        try:
            raise Exception()
        except Exception as e:
            write_exception(e)

        output = self._stringio.getvalue()
        T.assert_equal(0, output.find('[ERROR]'))

    def test_specific_exception(self):
        try:
            raise BadDomainError()
        except Exception as e:
            write_exception(e)

        output = self._stringio.getvalue()
        T.assert_equal(0, output.find('[ERROR] BadDomainError'))

    def test_exception_message(self):
        try:
            raise BadDomainError('Look for me in validation')
        except Exception as e:
            write_exception(e)

        output = self._stringio.getvalue()
        T.assert_equal(0, output.find('[ERROR] BadDomainError Look for me in validation'))


class WriteErrorMessageTest(StdErrTestCase):

    def test_write_error_message(self):
        message = 'Look for me in validation'
        expected = '[ERROR] Look for me in validation\n'

        write_error_message(message)

        output = self._stringio.getvalue()
        T.assert_equal(output, expected)
