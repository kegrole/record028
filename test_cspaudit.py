import importlib.util
import os
import unittest


def load_tests(loader, standard_tests, pattern):
    test_path = os.path.join(os.path.dirname(__file__), "tests", "test_cspaudit.py")
    spec = importlib.util.spec_from_file_location("tests_cspaudit", test_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    standard_tests.addTests(loader.loadTestsFromModule(module))
    return standard_tests


if __name__ == "__main__":
    unittest.main()
