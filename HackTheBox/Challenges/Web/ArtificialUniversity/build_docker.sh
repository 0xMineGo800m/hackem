#!/bin/bash
# Stop and remove any existing container with the same name
docker stop web_artificial_university 2>/dev/null && docker rm web_artificial_university 2>/dev/null

# Build the Docker image
docker build --tag=web_artificial_university .

# Use me when you want to capture wireshark stuff! Comment out the rest!
# docker run --rm -it --network host --name=web_artificial_university web_artificial_university

# Run the container in detached mode, exposing port 1337
docker run -p 1337:1337 --rm --name=web_artificial_university -dit web_artificial_university

# Attach an interactive shell
docker exec -it web_artificial_university /bin/bash