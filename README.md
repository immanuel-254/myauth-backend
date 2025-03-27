Make sure you have the following tools:
    1. sqlc
    2. a_h/templ

Step 1: cd auth && sqlc generate && cd .. && cd blog && sqlc generate && cd ..
Step 2: templ generate
Step 3: Create a .env file and fill in the Constants based on the example.env
Step 4: go build -trimpath -ldflags="-s -w"

There are two commands when running the app:
    1. runserver
    2. createadmin
