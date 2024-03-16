# Volatility Contest 2023

This directory contains plugins and files related to the Volatility contest 2023. Here is the summary, taken from the official results : 

### check_ftrace Plugin

Function Tracer, ftrace, is a framework intended to help developers determine what is happening within the kernel. It is typically used for debugging and performance analysis. It has also been abused by rootkits to hide artifacts on a system. This plugin allows investigators to detect these hooks and provide further context for investigation.

### check_unlinked_modules Plugin

Removing objects from linked lists has been a common technique leveraged by rootkits to hide resources from sysadmin tools on the live machine. By leveraging a “regex mask”, this plugin scans memory for unlinked modules. The documentation also describes how this technique could be expanded to other structures found in the symbol table.

### check_tracepoints Plugin

Within the Linux kernel, a tracepoint provides a hooking mechanism to call a function that can be provided at runtime. They are typically used for tracing and performance analysis, but they can and have been abused by rootkits in the wild. This plugin enumerates the tracepoint arrays and looks for tracepoints with a probe attached. This plugin allows investigators to find tracepoint control flow changes that may have been added to the system.

## Usage

Place the desired plugins in `volatility3/volatility3/plugins/linux/`. You may need to create the `linux/` directory, if it did not exist beforehand.  
See `Abyss_Watcher_Volatility_contest_2023.pdf` for details and context.

## Results

https://volatilityfoundation.org/the-2023-volatility-plugin-contest-results-are-in/

