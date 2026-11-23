"""Test suite the builder images run inside the container."""

import unittest

from greeting import greeting


class GreetingTest(unittest.TestCase):
    def test_hello(self):
        self.assertEqual(greeting("world"), "hello, world")


if __name__ == "__main__":
    unittest.main()
