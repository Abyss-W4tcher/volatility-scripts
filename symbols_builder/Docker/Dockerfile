FROM golang:alpine AS dwarf2json_builder

RUN apk add git && git clone https://github.com/volatilityfoundation/dwarf2json.git
WORKDIR /go/
RUN cd dwarf2json/ && go build

FROM alpine:latest 
COPY --from=dwarf2json_builder /go/dwarf2json/dwarf2json /usr/bin/dwarf2json

RUN apk update
RUN apk add wget nano ripgrep rpm2cpio cpio dpkg
