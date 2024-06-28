all: check fmt build

build :
	go build -x -trimpath ./

fmt :
	gofmt -w *.go

check :
	go vet ./...

test : check
	go test -v ./...

clean :
	rm sandfly-entropyscan || true
