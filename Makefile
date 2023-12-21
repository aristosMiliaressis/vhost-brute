EXECUTABLE=vhost-brute
WINDOWS=$(EXECUTABLE).exe
LINUX=$(EXECUTABLE)

install: build
	mv $(LINUX) ${GOPATH}/bin

build: windows linux

windows:
	env GOOS=windows go build -v -o $(WINDOWS) -ldflags="-s -w" ./cmd/vhost-brute/main.go

linux:
	env GOOS=linux go build -v -o $(LINUX) -ldflags="-s -w" ./cmd/vhost-brute/main.go

clean:
	rm -f $(WINDOWS) $(LINUX) 
