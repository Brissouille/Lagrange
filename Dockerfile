From python:3

# Install tools
RUN apt-get install git

# Clone z3 project
RUN git clone https://github.com/Z3Prover/z3.git z3

# Compiling the z3 sources files
WORKDIR z3
RUN python3 scripts/mk_make.py
WORKDIR build
RUN make
RUN make install

# Install z3 python binding
RUN pip3 install z3

WORKDIR python

# Add all file in Lagrange
COPY *.py ./Lagrange/
COPY Cipher/*.py ./Lagrange/Cipher/
COPY Hash/*.py ./Lagrange/Hash/


# Execute this function when the container is launched
#CMD [ "python3", "clefs_test.py" ]
