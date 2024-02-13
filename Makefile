EXECUTABLE=vhost-brute
WINDOWS=$(EXECUTABLE).exe
LINUX=$(EXECUTABLE)
GIT_HASH=$(shell git rev-parse --short HEAD)

install: linux
	mv $(LINUX) ${GOPATH}/bin

build: windows linux

windows:
	env GOOS=windows go build -v -o $(WINDOWS) -ldflags="-s -w -X main.git_hash=${GIT_HASH}" .

linux:
	env GOOS=linux go build -v -o $(LINUX) -ldflags="-s -w -X main.git_hash=${GIT_HASH}" .

clean:
	rm -f $(WINDOWS) $(LINUX) 
