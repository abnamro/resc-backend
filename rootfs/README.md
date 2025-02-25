# Root File System

You can place here files that will be copied directly at the root of the container before executing any commands.
This is useful if you are working behind a corporate proxy to set-up root CA, pip configuration etc...

The Dockerfile will also call /init.sh if this one exists. This script allows you to set up your base.