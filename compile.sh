#!/bin/bash

## for support SSL required
c++ -o sys_monitor_agent sys_monitor_agent.cpp -lboost_system -lboost_filesystem -lssl -lcrypto -lboost_thread -lpthread