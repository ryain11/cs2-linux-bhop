# Cs2 bhop for linux

A simple internal CS2 bhop program for linux achieved by hooking CreateMove.

## Features

- Minimal gui made with Imgui
- Toggle button to enable/disable bhopping
- Uninject button to uninject and close the program

## Usage

Run the start.sh file in the repository.

## Building from source

- Linux
- Linux headers
- Glibc headers
- C++20 or later
- Make
- GLFW

## Installation

Step-by-step instructions to get the development environment running:

```bash
# Clone the repository
git clone --depth 1 https://github.com/ryain11/cs2-linux-bhop.git
cd cs2-linux-bhop

# Build the project
make

```

## Contributing

I am currently looking for a way to use the protobuf structures to minimize the jumps missed. If you have a way to do it, or want to improve something else, pull requests are welcome.
