
import unittest
from unittest.mock import patch
from config.config import Config


class TestConfig(unittest.TestCase):

    def setUp(self):
        self.patcher = patch('yaml.safe_load')
        self.mock_safe_load = self.patcher.start()
        self.sample_config = {
            'test': 100,
            'empty_value': '',
            'false_value': False,
            'zero_value': 0,
            'paths': {
                'database': '/var/db/app.sqlite',
                'logfile': '/var/log/app.log'
            },
            "custom": {"custom": {"custom": 123}},
            'section_only': {
                'key1': 'value1'
            }
        }
        self.mock_safe_load.return_value = self.sample_config

        Config._self = None
        self.config = Config()

    def tearDown(self):
        self.patcher.stop()

    def test_baseline(self):
        self.assertEqual(self.config.get('test'), 100)
        self.assertEqual(self.config.get('test', ""), 100)
        self.assertEqual(self.config.get('false_value'), False)
        self.assertEqual(self.config.get('empty_value'), "")
        self.assertEqual(self.config.get('zero_value'), 0)
        self.assertEqual(self.config.get('paths', 'database'), '/var/db/app.sqlite')
        self.assertEqual(self.config.get('custom', 'custom'), {"custom": 123})

    def test_invalid_inputs(self):
        self.assertEqual(self.config.get('paths', 'blah'), {})
        self.assertEqual(self.config.get('blah', 'blah'), {})
        with self.assertRaises(TypeError):
            self.assertEqual(self.config.get('blahblahblah', {}), {})
            self.assertEqual(self.config.get({}, {}), {})
            self.assertEqual(self.config.get(0, {}), {})
            self.assertEqual(self.config.get('test', None), 100)

    def test_empty_inputs(self):
        self.assertEqual(self.config.get('', ''), {})


if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = loader.discover('tests')

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
