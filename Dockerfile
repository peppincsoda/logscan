FROM ubuntu:latest AS builder

RUN apt-get update
RUN apt-get install -y g++ make cmake pkg-config
RUN apt-get install -y libhyperscan-dev libpcre3-dev libgtest-dev

WORKDIR /usr/src/gtest
RUN cmake CMakeLists.txt && make && make install

RUN apt-get install -y git

WORKDIR /root/
RUN git clone https://github.com/peppincsoda/logscan.git
RUN mkdir logscan_build
WORKDIR /root/logscan_build/
RUN cmake -G "Unix Makefiles" ../logscan && make && make test

CMD /bin/bash


FROM ubuntu:latest AS prod

RUN apt-get update
RUN apt-get install -y libhyperscan4 libpcre3

COPY --from=builder /root/logscan_build/logscan_cli/logscan_cli /root/logscan_cli

CMD /bin/bash
