#!/bin/bash

TARGET_SCRIPT="$1"
shift

for ((i = 1; i <= 1000; i++)); do
    echo -e "\nRunning '$TARGET_SCRIPT $@' iteration $i...\n"
    
    ./$TARGET_SCRIPT $@
    
    # Check the exit status of the previous command
    if [ $? -ne 0 ]; then
        echo "Iteration $i failed. Stopping execution."
        exit 1
    fi
    
    echo -e "\nIteration $i completed successfully.\n"
done

echo "All 1000 iterations completed successfully."
