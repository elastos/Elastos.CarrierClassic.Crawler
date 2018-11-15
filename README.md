Carrier Crawler
===============

## Summary

elacrawler is a Elastos Carrier network crawler.

## How crawler works

The carrier crawler crawls the Carrier network with multiple concurrent instances (default 5 crawlers), allowing the connection by sending **get_nodes** requests to (and get responses from) the number of active Carrier nodes on the network.

When a cralwer instance comletes it's mission, a log file containing all space separated IP addresses that it found is created in {currentdate} under your config data directory, with the name {timestamp}.lst.

## IP2Location

IP2Location supports to reveal the geological location for crawled carrier nodes. With IP2Location, the geological depoloyment of almost all active nodes of whole carrier network can vividly demenstrated.

Please refer to [ip2location.com](https://www.ip2location.com/) to download ip2location database before IP2Location enabled.

## Config Profile

The list of config items and their description is briefly profiled below:

#### 1. internval
The allowing least interval value in munites for the next cralwer to begin crawling carrier nodes.

#### 2. timeout
The timeout value in seconds for the **get nodes** request to crawler.

#### 3. data_dir
This data directory stores carrier node cached data itself and all dumped files of cralwed carrier nodes information.

#### 4. log\_level and log\_file
The level value and the file path to for logging.

#### 5. ip2location_database
The location of ip2location database relative to current config file.

#### 6. bootstraps
The bootstrap nodes list.

## Build from source

With CMake installed, use the following commands to conduct the whole build steps:

```shell
$ git clone https://github.com/elastos/Elastos.NET.Carrier.Cralwer
$ cd build
$ mkdir macos
$ cmake -DCMAKE_INSTALL_PREFIX=dist ../..
$ make install
```

## Run

Use commands to run crawler after installation:
```shell
$ cd dist/bin
$ ./elacrawler -c ../etc/carrier/crawler.conf
```

## Contribution

We welcome contributions to the Elastos Carrier Project.

## Acknowledgments

A sincere thank you to all teams and projects that we rely on directly or indirectly.

## License
MIT
