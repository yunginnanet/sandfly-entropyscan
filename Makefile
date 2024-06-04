all: check fmt build

build :
	go build -x -trimpath ./

fmt :
	gofmt -w *.go

check :
	go vet ./...

clean :
	rm sandfly-entropyscan || true
