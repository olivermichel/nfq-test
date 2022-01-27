## Netfilter Queue Basic Example

[Netfilter Queue project website](https://www.netfilter.org/projects/libnetfilter_queue/index.html)

Install required packages (for Ubuntu 20.04):

    apt-get install libnfnetlink-dev libnetfilter-queue-dev

Compile the test program:

    mkdir build
    cd build
    cmake -DCMAKE_BUILD_TYPE=Release ..
    make

Configure INPUT and OUTPUT rules to intercept packets to/from UDP port 5566 and send to netfilter queue 0:

    iptables -A INPUT -p udp --dport 5566 -j NFQUEUE --queue-num 0 --queue-bypass
    iptables -A OUTPUT -p udp --sport 5566 -j NFQUEUE --queue-num 0 --queue-bypass

Display current rules for INPUT/OUTPUT:

    iptables -L INPUT
    iptables -L OUTPUT

Remove previously configured rules:

    iptables -D INPUT -p udp --dport 5566 -j NFQUEUE --queue-num 0
    iptables -D OUTPUT -p udp --sport 5566 -j NFQUEUE --queue-num 0

Run:

    build/nfq_test

Start test UDP server

    nc -ul 0.0.0.0 5566

Send packets from other host:

    nc -u <IP> 5566
