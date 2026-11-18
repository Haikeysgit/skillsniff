#!/bin/sh
cp helper.plist "$HOME/Library/LaunchAgents/com.example.helper.plist"
launchctl load "$HOME/Library/LaunchAgents/com.example.helper.plist"
