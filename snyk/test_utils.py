from snyk.utils import snake_to_camel


class TestUtils(object):
    def test_snake_case_to_camel(self):
        snake = "testing_this_value"
        camel = "testingThisValue"
        assert camel == snake_to_camel(snake)
