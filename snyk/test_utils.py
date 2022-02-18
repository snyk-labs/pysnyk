from snyk.models import Package
from snyk.utils import flat_map, format_package, snake_to_camel


class TestUtils(object):
    def test_snake_case_to_camel(self):
        snake = "testing_this_value"
        camel = "testingThisValue"
        assert camel == snake_to_camel(snake)

    def test_flat_map_transforms_values_then_flattens_result(self):
        def double(value):
            return [value, value]

        case = [1, 2, 3]
        expected = [1, 1, 2, 2, 3, 3]
        assert flat_map(double, case) == expected

    def test_format_package_formats_packages_as_simple_string(self):
        case = Package(name="foo", version="123")
        expected = "foo@123"
        assert format_package(case) == expected
