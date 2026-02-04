#!/bin/bash

sudo apt install nodejs npm
npm install

chmod +x bin/chat-server
chmod +x bin/chat-client

sudo ln -s $(pwd)/bin/chat-server /usr/local/bin/chat-server
sudo ln -s $(pwd)/bin/chat-client /usr/local/bin/chat-client