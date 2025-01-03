#!/usr/bin/env bash

echo "Starting agent in test mode - just an example"

./sys_monitor_agent 127.0.0.1 9999 30 --actions='cpu:30,tcp:30,disk:30[/],ps:30,df:30[/],net:30,memory:30,python:30' -d
