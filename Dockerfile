FROM python:3.6.7

LABEL contributor="Shrivatsan N R <nrshrivatsan@outlook.com>"
LABEL maintainer="Dimitrios Mavrommatis <jim.mavrommatis@gmail.com>"

RUN apt-get update
RUN apt-get install -y g++ gcc python3 python3-setuptools python3-dev traceroute python3-pip libssl-dev libffi-dev

COPY lib /traixroute/lib
COPY README.rst /traixroute/
COPY setup/requirements.txt /traixroute/
COPY setup.py /traixroute/

WORKDIR /traixroute

RUN pip3 --no-cache-dir install -r requirements.txt
RUN python lib/traixroute/downloader/install_scamper.py install_scamper.py
RUN python setup.py install

RUN traixroute -u -process

WORKDIR /root/traixroute

RUN rm -rf /traixroute && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["bash"]
