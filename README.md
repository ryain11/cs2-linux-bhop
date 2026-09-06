# Cs2 bhop for linux

A simple internal cs2 bhop program for linux achieved my hooking CreateMove.

## WARNING

If the offsets shifted and the program is not working. You can read "Getting Offsets" to find the offsets and update them manually. Or you can wait for a new commit.

## Getting offsets

Open CS2 and run the cs2_dumper file in the console. Wait around 10 second and the offsets will be printed. Input those offsets into offsets.h located in src/headers/

## Features

- Minimal gui made with Imgui
- Toggle button to enable/disable bhopping
- Uninject button to uninject and close the program

## Usage

Run the start.sh file in the repository.

## Building from source

- Linux
- Linux headers
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
make all

```

## Contributing

I am currently looking for a way to use the protobuf structures to minimize the jumps missed. If you have a way to do it, or want to improve something else, pull requests are welcome.
