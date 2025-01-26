#!/bin/bash

# Remove folders ./CLI, ./FS, ./NS.
rm -rf ./CLI/*
rm -rf ./FS/*
rm -rf ./NS/*

# Move the content of ./backup to cwd.
cp -r ./backup/* .