all:
	docker-compose build
	docker-compose up

test:
	go run test.go

goadd:
	go mod tidy

