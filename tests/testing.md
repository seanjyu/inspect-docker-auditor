## Testing

Tests for this project were done through pytest. There are two main test categories, with docker and without docker. Note the non docker tests contains unit tests and integration tests whereas the the docker tests contains all three. 
<!-- A full summary/breakdown of the individual tests can be found in the [test readme](). -->

The following code snippets show how to run the tests.
```
# Run tests that do not require docker
pytest -m "no_docker"

# Run tests that require docker
pytest -m "docker"

# Run all tests
pytest
```


<!-- # Tests Summary
WIP
## Conftest
#### sample_config_yaml
Pytest fixture that contains a basic inspect-docker-auditor config.

#### sample_terminate_on_violation_config_yaml
Pytest fixture that has terminate on violation set to true.
## Unit Tests
### test_auditor.py
#### test_init_loads_valid_configuration
 -->
