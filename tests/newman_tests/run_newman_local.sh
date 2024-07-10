#!/bin/bash
################################################################################################
#Script Name	: run_newman_tests.sh
#Description	: This script runs newman tests for RESC API
#Author         : Repository Scanner
#Email          : resc@nl.abnamro.com
################################################################################################
echo "*** Running Newman Tests ***"
NO_COLOR="\033[0m"
GREEN="\033[38;5;010m"
YELLOW="\033[38;5;011m"
RED="\033[38;5;9m"

if [[ $PWD == *"tests"* ]]; then
    printf "${RED}ERROR: Running in the wrong directory${NO_COLOR}\n"
    echo "INFO:  This should be executed at the base of the repository."
    echo ""
    exit 1;
fi

# Print image versions to be used for testing
path=$(command -v newman)
if [ ! -x "$path" ]; then
    printf "${RED}ERROR: newman not found${NO_COLOR}\n"
    echo "INFO:  please install"
    printf "${YELLOW}       npm install -g newman${NO_COLOR}\n"
    echo ""
    exit 1;
fi

timeout 1 bash -c 'cat < /dev/null > /dev/tcp/localhost/8000' 2> /dev/null
retval=$?
if [ $retval -ne 0 ]; then
    printf "${RED}ERROR: resc-backend is not running on localhost:8000${NO_COLOR}\n"
    echo "INFO:  plase run:"
    printf "${YELLOW}       python3 src/resc_backend/resc_web_service/local.py${NO_COLOR}\n"
    echo ""
    exit 1;
fi

# Running RESC Database container
python test_data/remove_test_data.py
alembic upgrade head
python test_data/insert_test_data.py

# Clean up
function cleanUp() {
  echo "*** Running Clean Up: Removing test artifacts ***"
  rm -f $PWD/gitleaks.toml
  rm -f $PWD/test.env
}

# Running Newman Tests
echo "*** Downloading latest gitleaks.toml rule file ***"
curl https://raw.githubusercontent.com/zricethezav/gitleaks/master/config/gitleaks.toml > gitleaks.toml
cp tests/newman_tests/test.env .

# Stops on Newman test failure
set -e

function onExit {
    if [ "$?" != "0" ]; then
        printf "${RED}Newman Tests failed${NO_COLOR}\n";
        cleanUp
        exit 1;
    else
        printf "${GREEN}Newman Tests passed${NO_COLOR}\n";
        cleanUp
    fi
}
trap onExit EXIT;

newman run --color on ./tests/newman_tests/RESC_web_service.postman_collection.json  --verbose --env-var "baseUrl=http://0.0.0.0:8000" --bail

