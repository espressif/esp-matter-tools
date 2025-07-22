### Development Guide

#### Create Virtual Environment

It's recommended to use a virtual environment to isolate your development dependencies:

```
python -m venv venv
source venv/bin/activate
```

#### Install Development Dependencies

Install the required dependencies listed in requirements.txt:

```
python3 -m pip install -r requirements.txt
```

#### Enable Development Mode

Development mode allows you to run the latest version of esp-matter-mfg-tool from the repository.
If you are making any changes to the tool then in order to test the changes please follow the below steps.

```
cd tools/mfg_tool
python3 -m pip install -e .
```

This will install esp-matter-mfg-tool's dependencies and create an executable script wrappers in the user’s bin
directory. The wrappers will run the scripts found in the git working directory directly, so any time the working
directory contents change it will pick up the new versions.

### Running Unit Tests

To run the test suite, install test dependencies and execute tests using pytest:

#### Install Test Dependencies

```
python3 -m pip install -r requirements-test.txt
```

#### Run Tests

Recommanded to use log-cli-level=info to see all subtests.

```
python -m pytest tests/ -v -s --log-cli-level=INFO
```
