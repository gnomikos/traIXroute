LABEL traixroute="latest"
LABEL authors="Shrivatsan N R"
FROM python
RUN pip3 install traixroute &&\
  scamper-install
