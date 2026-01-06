#!/bin/bash
set -e

echo "Building transfer.ng..."
go build -o transfer.ng

echo "Running transfer.ng..."
./transfer.ng "$@"
